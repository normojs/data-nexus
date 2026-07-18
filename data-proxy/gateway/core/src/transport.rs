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

    /// A06: execute and optionally return a progressive row stream.
    ///
    /// Default implementation materializes via [`execute_with_mode`]. Backends
    /// that support true windowed decode override this for
    /// [`ExecuteMode::Streaming`] queries.
    async fn execute_outcome(
        &self,
        command: GatewayCommand,
        session: &mut SessionState,
        mode: ExecuteMode,
    ) -> GatewayResult<ExecuteOutcome> {
        let response = self.execute_with_mode(command, session, mode).await?;
        Ok(ExecuteOutcome::Complete(response))
    }
}

/// A06: progressive logical result from a backend (columns + row windows).
pub struct StreamingQuery {
    pub columns: Vec<Column>,
    pub stream: Box<dyn RowStream>,
}

/// A08: progressive same-protocol wire frames (backend TCP messages → client).
///
/// Each packet is a full frontend-ready frame (PostgreSQL: tag + len + body).
/// Callers must drain until [`WireStream::poll_packets`] returns `None`.
pub struct WireRelay {
    pub stream: Box<dyn WireStream>,
}

/// Yields wire packet batches from a backend passthrough session (A08).
#[async_trait]
pub trait WireStream: Send {
    /// Next batch of wire packets (up to `max_packets`). `None` = end of response.
    async fn poll_packets(
        &mut self,
        max_packets: usize,
    ) -> GatewayResult<Option<Vec<Vec<u8>>>>;
}

/// Outcome of a backend execute that may stream rows (A06) or wire frames (A08).
pub enum ExecuteOutcome {
    /// Fully materialized / wire / error response.
    Complete(GatewayResponse),
    /// Progressive logical rows; caller must drain `stream` before next command.
    Streaming(StreamingQuery),
    /// Progressive same-protocol wire frames (no logical ResultSet).
    WireRelay(WireRelay),
}

/// Yields logical row windows from a backend result (A06).
///
/// Implementations must keep the backend connection usable: if the consumer
/// stops early, `poll_window` should still be driven to completion or the
/// stream dropped only after draining remaining packets.
#[async_trait]
pub trait RowStream: Send {
    /// Next window of rows (up to `max_rows` in this window). `None` = end.
    async fn poll_window(
        &mut self,
        max_rows: usize,
    ) -> GatewayResult<Option<Vec<Vec<GatewayValue>>>>;
}

/// In-memory row stream used when a backend materializes first (fallback).
pub struct VecRowStream {
    rows: std::vec::IntoIter<Vec<GatewayValue>>,
}

impl VecRowStream {
    pub fn new(rows: Vec<Vec<GatewayValue>>) -> Self {
        Self {
            rows: rows.into_iter(),
        }
    }
}

#[async_trait]
impl RowStream for VecRowStream {
    async fn poll_window(
        &mut self,
        max_rows: usize,
    ) -> GatewayResult<Option<Vec<Vec<GatewayValue>>>> {
        let max_rows = max_rows.max(1);
        let mut out = Vec::with_capacity(max_rows);
        for _ in 0..max_rows {
            match self.rows.next() {
                Some(r) => out.push(r),
                None => break,
            }
        }
        if out.is_empty() {
            Ok(None)
        } else {
            Ok(Some(out))
        }
    }
}

/// Drain a progressive [`WireRelay`] to the client writer (A08).
///
/// Returns total payload bytes written (sum of packet lengths).
pub async fn write_wire_relay<W: ResponseWriter + ?Sized>(
    mut relay: WireRelay,
    writer: &mut W,
) -> GatewayResult<u64> {
    let mut total = 0u64;
    loop {
        match relay.stream.poll_packets(32).await? {
            None => break,
            Some(batch) if batch.is_empty() => continue,
            Some(batch) => {
                total = total.saturating_add(batch.iter().map(|p| p.len() as u64).sum::<u64>());
                writer.write_packets(batch).await?;
            }
        }
    }
    Ok(total)
}

/// O01: stats from windowed encode (Secure path observability).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamingEncodeStats {
    /// Rows encoded after max_rows truncation.
    pub total_rows: u64,
    /// Number of row windows encoded (mask applied per window when present).
    pub windows: u64,
    /// Approximate payload bytes of encoded row packets (not wire framing).
    pub encoded_bytes: u64,
    /// Rows that passed through a non-empty mask index.
    pub masked_rows: u64,
}

/// Encode a progressive [`StreamingQuery`] through `writer` (A06+A07).
///
/// Masks each window in place before encode; never holds a full unmasked copy
/// alongside encoded packets. Peak retained rows ≈ one window.
///
/// Returns [`StreamingEncodeStats`] for O01 Secure-path metrics.
pub async fn write_streaming_query_with_obligations<W: ResponseWriter + ?Sized>(
    frontend: &mut dyn FrontendProtocolAdapter,
    session: &SessionState,
    mut query: StreamingQuery,
    window_rows: usize,
    obligations: Option<&Obligations>,
    writer: &mut W,
) -> GatewayResult<StreamingEncodeStats> {
    let window = window_rows.max(1);
    let mut columns = query.columns;

    // Expand header once for watermark column mode before first encode.
    let wm = obligations.and_then(|o| o.watermark.as_ref());
    if let Some(wm) = wm {
        let mut empty: Vec<Vec<GatewayValue>> = Vec::new();
        apply_watermark_to_resultset(&mut columns, &mut empty, wm);
    }

    let mask_idx = obligations
        .map(|o| build_mask_index(&columns, &o.column_masks))
        .unwrap_or_default();
    let max_total = obligations.and_then(|o| o.max_rows);
    let header_width = columns.len();
    let has_masks = !mask_idx.is_empty();

    writer
        .write_packets(frontend.encode_resultset_header(&columns, session)?)
        .await?;

    let mut stats = StreamingEncodeStats::default();

    loop {
        if let Some(max) = max_total {
            if stats.total_rows >= max {
                while query.stream.poll_window(window).await?.is_some() {}
                break;
            }
        }
        let want = match max_total {
            Some(max) => ((max - stats.total_rows) as usize).min(window).max(1),
            None => window,
        };
        let Some(mut chunk) = query.stream.poll_window(want).await? else {
            break;
        };
        if has_masks {
            apply_masks_to_rows(&mut chunk, &mask_idx);
            stats.masked_rows += chunk.len() as u64;
        }
        if let Some(wm) = wm {
            // Per-window stamp so Column mode tokens align with expanded header.
            for row in chunk.iter_mut() {
                while row.len() < header_width {
                    // Watermark column is last for Column mode; suffix mode does not grow width.
                    if row.len() + 1 == header_width {
                        row.push(GatewayValue::String(wm.token.clone()));
                    } else {
                        row.push(GatewayValue::Null);
                    }
                }
                // Suffix mode: append marker to first string cell.
                if matches!(wm.mode, crate::WatermarkMode::Suffix) {
                    let marker = format!(" |wm={}", wm.token);
                    for cell in row.iter_mut() {
                        if let GatewayValue::String(s) = cell {
                            if !s.contains(" |wm=") {
                                s.push_str(&marker);
                            }
                            break;
                        }
                    }
                }
            }
        }
        stats.total_rows += chunk.len() as u64;
        stats.windows = stats.windows.saturating_add(1);
        let packets = frontend.encode_resultset_rows(&columns, &chunk, session)?;
        for p in &packets {
            stats.encoded_bytes = stats.encoded_bytes.saturating_add(p.len() as u64);
        }
        drop(chunk);
        writer.write_packets(packets).await?;
    }

    writer
        .write_packets(frontend.encode_resultset_footer(
            &columns,
            stats.total_rows as usize,
            session,
        )?)
        .await?;
    Ok(stats)
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
    let _ = write_resultset_windowed_with_obligations(
        frontend,
        session,
        columns,
        rows,
        window_rows,
        None,
        writer,
    )
    .await?;
    Ok(())
}

/// A06/A07: windowed encode with **in-place mask per window** before encoding.
///
/// When `obligations` is set:
/// - `max_rows` truncates first
/// - each window is masked then encoded (no second full unmasked copy)
/// - watermark applied once before encoding (may add a column)
///
/// Peak temporary growth is ~window-sized for mask work, not 2× full result.
/// Returns O01 [`StreamingEncodeStats`].
pub async fn write_resultset_windowed_with_obligations<W: ResponseWriter + ?Sized>(
    frontend: &mut dyn FrontendProtocolAdapter,
    session: &SessionState,
    mut columns: Vec<Column>,
    mut rows: Vec<Vec<GatewayValue>>,
    window_rows: usize,
    obligations: Option<&Obligations>,
    writer: &mut W,
) -> GatewayResult<StreamingEncodeStats> {
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
    let has_masks = !mask_idx.is_empty();

    let mut stats = StreamingEncodeStats {
        total_rows: rows.len() as u64,
        ..Default::default()
    };
    writer
        .write_packets(frontend.encode_resultset_header(&columns, session)?)
        .await?;

    while !rows.is_empty() {
        let take = window.min(rows.len());
        let mut chunk: Vec<Vec<GatewayValue>> = rows.drain(..take).collect();
        if has_masks {
            apply_masks_to_rows(&mut chunk, &mask_idx);
            stats.masked_rows += chunk.len() as u64;
        }
        stats.windows = stats.windows.saturating_add(1);
        let packets = frontend.encode_resultset_rows(&columns, &chunk, session)?;
        for p in &packets {
            stats.encoded_bytes = stats.encoded_bytes.saturating_add(p.len() as u64);
        }
        // Drop chunk after encode so peak is header+one window of packets.
        drop(chunk);
        writer.write_packets(packets).await?;
    }

    writer
        .write_packets(frontend.encode_resultset_footer(
            &columns,
            stats.total_rows as usize,
            session,
        )?)
        .await?;
    Ok(stats)
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
    async fn a08_write_wire_relay_drains_batches() {
        struct FakeWire {
            batches: std::vec::IntoIter<Vec<Vec<u8>>>,
        }

        #[async_trait]
        impl WireStream for FakeWire {
            async fn poll_packets(
                &mut self,
                _max_packets: usize,
            ) -> GatewayResult<Option<Vec<Vec<u8>>>> {
                Ok(self.batches.next())
            }
        }

        let relay = WireRelay {
            stream: Box::new(FakeWire {
                batches: vec![
                    vec![vec![b'Z', 0, 0, 0, 5, b'I']],
                    vec![vec![1, 2, 3], vec![4, 5]],
                ]
                .into_iter(),
            }),
        };
        let mut writer = CollectingWriter::new();
        let bytes = write_wire_relay(relay, &mut writer).await.unwrap();
        assert_eq!(bytes, 6 + 3 + 2);
        assert_eq!(writer.packets.len(), 3);
        assert_eq!(writer.packets[0][0], b'Z');
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

    #[tokio::test]
    async fn streaming_query_yields_windows_with_mask() {
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
            vec![GatewayValue::Integer(4), GatewayValue::Integer(400)],
        ];
        let mut obl = Obligations::default();
        obl.column_masks
            .push(MaskSpec::new("salary", MaskAlgorithm::Nullify, "m"));
        obl.max_rows = Some(3);
        let query = StreamingQuery {
            columns,
            stream: Box::new(VecRowStream::new(rows)),
        };
        let mut writer = CollectingWriter::new();
        let total = write_streaming_query_with_obligations(
            &mut fe,
            &session,
            query,
            2,
            Some(&obl),
            &mut writer,
        )
        .await
        .unwrap();
        assert_eq!(total.total_rows, 3);
        assert_eq!(total.windows, 2);
        assert_eq!(total.masked_rows, 3);
        assert!(total.encoded_bytes > 0);
        assert_eq!(fe.header_calls, 1);
        // windows of 2 then 1
        assert_eq!(fe.row_calls, 2);
        assert_eq!(fe.footer_calls, 1);
        assert_eq!(writer.packets.last().unwrap(), &vec![3u8]);
    }

    #[tokio::test]
    async fn a06_vec_row_stream_poll_window_sizes() {
        let rows = (0..5)
            .map(|i| vec![GatewayValue::Integer(i)])
            .collect::<Vec<_>>();
        let mut stream = VecRowStream::new(rows);
        let first = stream.poll_window(2).await.unwrap().unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(first[0][0], GatewayValue::Integer(0));
        let second = stream.poll_window(2).await.unwrap().unwrap();
        assert_eq!(second.len(), 2);
        let last = stream.poll_window(10).await.unwrap().unwrap();
        assert_eq!(last.len(), 1);
        assert!(stream.poll_window(1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a06_streaming_early_stop_drains_remaining_windows() {
        // max_rows truncates encode; producer/stream still drained so backends can
        // release leases (A06 drain contract).
        use crate::{MaskAlgorithm, MaskSpec, Obligations};

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
        let rows = (0..10)
            .map(|i| vec![GatewayValue::Integer(i)])
            .collect();
        let mut obl = Obligations::default();
        obl.max_rows = Some(3);
        obl.column_masks
            .push(MaskSpec::new("id", MaskAlgorithm::Nullify, "m"));
        let query = StreamingQuery {
            columns,
            stream: Box::new(VecRowStream::new(rows)),
        };
        let mut writer = CollectingWriter::new();
        let total = write_streaming_query_with_obligations(
            &mut fe,
            &session,
            query,
            4,
            Some(&obl),
            &mut writer,
        )
        .await
        .unwrap();
        assert_eq!(total.total_rows, 3);
        assert_eq!(total.masked_rows, 3);
        assert_eq!(fe.header_calls, 1);
        assert_eq!(fe.footer_calls, 1);
        assert!(fe.row_calls >= 1);
    }
}
