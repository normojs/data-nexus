// No-op OTel business metrics when feature `otel` is disabled.

use std::time::Duration;

pub fn record_command(
    _listener: &str,
    _service: &str,
    _frontend_protocol: &str,
    _backend_protocol: &str,
    _command_type: &str,
    _endpoint: &str,
    _outcome: &str,
    _duration: Duration,
) {
}
