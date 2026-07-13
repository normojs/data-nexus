use async_trait::async_trait;

use crate::{GatewayCommand, GatewayResponse, GatewayResult, ProtocolKind, SessionState};

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

    async fn execute(
        &self,
        command: GatewayCommand,
        session: &mut SessionState,
    ) -> GatewayResult<GatewayResponse>;
}
