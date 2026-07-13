use async_trait::async_trait;

use crate::{GatewayCommand, GatewayResponse, GatewayResult, ProtocolKind, SessionState};

/// Classifies SQL text according to a database dialect without exposing a
/// dialect-specific AST to gateway core.
pub trait DialectParser: Send + Sync {
    fn dialect(&self) -> ProtocolKind;

    fn parse_query(&self, sql: String, session: &mut SessionState)
        -> GatewayResult<GatewayCommand>;
}

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
}

/// Executes neutral gateway messages against one backend database protocol.
#[async_trait]
pub trait BackendConnector: Send + Sync {
    fn protocol(&self) -> ProtocolKind;

    fn last_endpoint_label(&self) -> Option<String> {
        None
    }

    async fn execute(
        &self,
        command: GatewayCommand,
        session: &mut SessionState,
    ) -> GatewayResult<GatewayResponse>;
}

#[cfg(test)]
mod tests {
    use super::DialectParser;
    use crate::{GatewayCommand, GatewayResult, ProtocolKind, SessionState, TransactionState};

    struct TestDialectParser;

    impl DialectParser for TestDialectParser {
        fn dialect(&self) -> ProtocolKind {
            ProtocolKind::PostgreSql
        }

        fn parse_query(
            &self,
            sql: String,
            session: &mut SessionState,
        ) -> GatewayResult<GatewayCommand> {
            if sql.eq_ignore_ascii_case("begin") {
                session.transaction_state = TransactionState::Active;
                return Ok(GatewayCommand::Begin);
            }

            Ok(GatewayCommand::Query { sql })
        }
    }

    #[test]
    fn dialect_parser_classifies_sql_and_updates_session() {
        let parser = TestDialectParser;
        let mut session = SessionState::default();

        let command = parser.parse_query("BEGIN".into(), &mut session).unwrap();

        assert_eq!(parser.dialect(), ProtocolKind::PostgreSql);
        assert_eq!(command, GatewayCommand::Begin);
        assert_eq!(session.transaction_state, TransactionState::Active);
    }
}
