use async_trait::async_trait;

use crate::obligations::{
    apply_masks_to_rows, apply_watermark_to_resultset, build_mask_index,
};
use crate::{
    Column, ExecuteMode, GatewayCommand, GatewayResponse, GatewayResult, GatewayValue, Obligations,
    ProtocolKind, SessionState,
};

/// Translates one client wire protocol into protocol-neutral gateway messages.
pub trait FrontendProtocolAdapter: Send {
    fn protocol(&self) -> ProtocolKind;

    fn decode(
        &mut self,
        frame: &[u8],
        session: &mut SessionState,
    ) -> GatewayResult<Vec<GatewayCommand>>;

    fn encode(
        &mut self,
        response: GatewayResponse,
        session: &SessionState,
    ) -> GatewayResult<Vec<Vec<u8>>>;

    /// Column-count / RowDescription phase of a result set (A2).
    fn encode_resultset_header(
        &mut self,
        columns: &[Column],
        session: &SessionState,
    ) -> GatewayResult<Vec<Vec<u8>>>;

    /// One or more data rows (A2 window).
    fn encode_resultset_rows(
        &mut self,
        columns: &[Column],
        rows: &[Vec<GatewayValue>],
        session: &SessionState,
    ) -> GatewayResult<Vec<Vec<u8>>>;

    /// Trailing EOF / CommandComplete / ReadyForQuery (A2).
    fn encode_resultset_footer(
        &mut self,
        columns: &[Column],
        total_rows: usize,
        session: &SessionState,
    ) -> GatewayResult<Vec<Vec<u8>>>;
}

/// Progressive client write sink used by the PEP for A2 back-pressure.
#[async_trait]
pub trait ResponseWriter: Send {
    async fn write_packets(&mut self, packets: Vec<Vec<u8>>) -> GatewayResult<()>;
}

/// Collects packets into a `Vec` (tests / non-streaming callers).
pub struct CollectingWriter {
    pub packets: Vec<Vec<u8>>,
}

impl CollectingWriter {
    pub fn new() -> Self {
        Self {
            packets: Vec::new(),
        }
    }

    pub fn into_packets(self) -> Vec<Vec<u8>> {
        self.packets
    }
}

impl Default for CollectingWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ResponseWriter for CollectingWriter {
    async fn write_packets(&mut self, packets: Vec<Vec<u8>>) -> GatewayResult<()> {
        self.packets.extend(packets);
        Ok(())
    }
}

/// Executes neutral gateway messages against one backend database protocol.
#[async_trait]
pub trait BackendConnector: Send + Sync {
    fn protocol(&self) -> ProtocolKind;

    async fn execute_with_mode(
        &self,
        command: GatewayCommand,
        session: &mut SessionState,
        mode: ExecuteMode,
    ) -> GatewayResult<GatewayResponse>;

    async fn execute(
        &self,
        command: GatewayCommand,
        session: &mut SessionState,
    ) -> GatewayResult<GatewayResponse> {
        self.execute_with_mode(command, session, ExecuteMode::Materialized)
            .await
    }
}

/// Encode a result set in windows, writing each phase through `writer` (A2).
///
/// Rows are drained window-by-window so earlier row memory can be released
/// before later windows are encoded. Socket-backed `ResponseWriter`s provide
/// TCP back-pressure between windows.
pub async fn write_resultset_windowed<W: ResponseWriter + ?Sized>(
    frontend: &mut dyn FrontendProtocolAdapter,
    session: &SessionState,
    columns: Vec<Column>,
    rows: Vec<Vec<GatewayValue>>,
    window_rows: usize,
    writer: &mut W,
) -> GatewayResult<()> {
    write_resultset_windowed_with_obligations(
        frontend,
        session,
        columns,
        rows,
        window_rows,
        None,
        writer,
    )
    .await
}

/// A06/A07: windowed encode with **in-place mask per window** before encoding.
///
/// When `obligations` is set:
/// - `max_rows` truncates first
/// - each window is masked then encoded (no second full unmasked copy)
/// - watermark applied once before encoding (may add a column)
///
/// Peak temporary growth is ~window-sized for mask work, not 2× full result.
pub async fn write_resultset_windowed_with_obligations<W: ResponseWriter + ?Sized>(
    frontend: &mut dyn FrontendProtocolAdapter,
    session: &SessionState,
    mut columns: Vec<Column>,
    mut rows: Vec<Vec<GatewayValue>>,
    window_rows: usize,
    obligations: Option<&Obligations>,
    writer: &mut W,
) -> GatewayResult<()> {
    let window = window_rows.max(1);

    if let Some(obl) = obligations {
        if let Some(max) = obl.max_rows {
            let max = max as usize;
            if rows.len() > max {
                rows.truncate(max);
            }
        }
        if let Some(wm) = &obl.watermark {
            apply_watermark_to_resultset(&mut columns, &mut rows, wm);
        }
    }

    let mask_idx = obligations
        .map(|o| build_mask_index(&columns, &o.column_masks))
        .unwrap_or_default();

    let total = rows.len();
    writer
        .write_packets(frontend.encode_resultset_header(&columns, session)?)
        .await?;

    while !rows.is_empty() {
        let take = window.min(rows.len());
        let mut chunk: Vec<Vec<GatewayValue>> = rows.drain(..take).collect();
        if !mask_idx.is_empty() {
            apply_masks_to_rows(&mut chunk, &mask_idx);
        }
        let packets = frontend.encode_resultset_rows(&columns, &chunk, session)?;
        // Drop chunk after encode so peak is header+one window of packets.
        drop(chunk);
        writer.write_packets(packets).await?;
    }

    writer
        .write_packets(frontend.encode_resultset_footer(&columns, total, session)?)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Column, GatewayValue};

    struct FakeFrontend {
        header_calls: usize,
        row_calls: usize,
        footer_calls: usize,
    }

    impl FrontendProtocolAdapter for FakeFrontend {
        fn protocol(&self) -> ProtocolKind {
            ProtocolKind::MySql
        }
        fn decode(
            &mut self,
            _frame: &[u8],
            _session: &mut SessionState,
        ) -> GatewayResult<Vec<GatewayCommand>> {
            Ok(vec![])
        }
        fn encode(
            &mut self,
            _response: GatewayResponse,
            _session: &SessionState,
        ) -> GatewayResult<Vec<Vec<u8>>> {
            Ok(vec![])
        }
        fn encode_resultset_header(
            &mut self,
            columns: &[Column],
            _session: &SessionState,
        ) -> GatewayResult<Vec<Vec<u8>>> {
            self.header_calls += 1;
            Ok(vec![vec![columns.len() as u8]])
        }
        fn encode_resultset_rows(
            &mut self,
            _columns: &[Column],
            rows: &[Vec<GatewayValue>],
            _session: &SessionState,
        ) -> GatewayResult<Vec<Vec<u8>>> {
            self.row_calls += 1;
            Ok(vec![vec![rows.len() as u8]])
        }
        fn encode_resultset_footer(
            &mut self,
            _columns: &[Column],
            total_rows: usize,
            _session: &SessionState,
        ) -> GatewayResult<Vec<Vec<u8>>> {
            self.footer_calls += 1;
            Ok(vec![vec![total_rows as u8]])
        }
    }

    #[tokio::test]
    async fn windowed_write_splits_rows() {
        let mut fe = FakeFrontend {
            header_calls: 0,
            row_calls: 0,
            footer_calls: 0,
        };
        let session = SessionState::default();
        let columns = vec![Column {
            name: "id".into(),
            data_type: "int".into(),
        }];
        let rows = (0..5)
            .map(|i| vec![GatewayValue::Integer(i)])
            .collect();
        let mut writer = CollectingWriter::new();
        write_resultset_windowed(&mut fe, &session, columns, rows, 2, &mut writer)
            .await
            .unwrap();
        assert_eq!(fe.header_calls, 1);
        assert_eq!(fe.row_calls, 3); // 2+2+1
        assert_eq!(fe.footer_calls, 1);
        assert_eq!(writer.packets.len(), 5);
        assert_eq!(writer.packets.last().unwrap(), &vec![5u8]);
    }

    #[tokio::test]
    async fn windowed_write_with_mask_obligation() {
        use crate::{MaskAlgorithm, MaskSpec, Obligations};

        let mut fe = FakeFrontend {
            header_calls: 0,
            row_calls: 0,
            footer_calls: 0,
        };
        let session = SessionState::default();
        let columns = vec![
            Column {
                name: "id".into(),
                data_type: "int".into(),
            },
            Column {
                name: "salary".into(),
                data_type: "int".into(),
            },
        ];
        let rows = vec![
            vec![GatewayValue::Integer(1), GatewayValue::Integer(100)],
            vec![GatewayValue::Integer(2), GatewayValue::Integer(200)],
            vec![GatewayValue::Integer(3), GatewayValue::Integer(300)],
        ];
        let mut obl = Obligations::default();
        obl.column_masks
            .push(MaskSpec::new("salary", MaskAlgorithm::Nullify, "m"));
        obl.max_rows = Some(2);
        let mut writer = CollectingWriter::new();
        write_resultset_windowed_with_obligations(
            &mut fe,
            &session,
            columns,
            rows,
            1,
            Some(&obl),
            &mut writer,
        )
        .await
        .unwrap();
        assert_eq!(fe.header_calls, 1);
        // max_rows=2 → two row windows
        assert_eq!(fe.row_calls, 2);
        assert_eq!(fe.footer_calls, 1);
        // footer carries total_rows after truncate
        assert_eq!(writer.packets.last().unwrap(), &vec![2u8]);
    }
}
