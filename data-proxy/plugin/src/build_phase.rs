// Copyright 2022 SphereEx Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use gateway_core::{PluginContext, PluginDecision};

use crate::{
    circuit_break::{CircuitBreak, CircuitBreakLayer},
    concurrency_control::{ConcurrencyControl, ConcurrencyControlLayer},
    config,
    err::PluginError,
    layer::*,
};

/// concurrency control service, some logic may be added in the future, eg: metrics...
fn concurrency_control_phase(_input: String) -> Result<(), PluginError> {
    Ok(())
}

/// circuit break service, some logic may be added in the future, eg: metrics...
fn circuit_break_phase(_input: String) -> Result<(), PluginError> {
    Ok(())
}

#[derive(Clone)]
pub struct PluginPhase {
    pub concurrency_control: ConcurrencyControl<ServiceFn<fn(String) -> Result<(), PluginError>>>,
    pub circuit_break: CircuitBreak<ServiceFn<fn(String) -> Result<(), PluginError>>>,
}

impl PluginPhase {
    pub fn new(config: config::Plugin) -> PluginPhase {
        let concurrency_control = ServiceBuilder::new()
            .with_layer(ConcurrencyControlLayer::with_opt(config.concurrency_control))
            // issue https://users.rust-lang.org/t/puzzling-expected-fn-pointer-found-fn-item/46423/4
            .build(service_fn(concurrency_control_phase as fn(String) -> Result<(), PluginError>));

        let circuit_break = ServiceBuilder::new()
            .with_layer(CircuitBreakLayer::with_opt(config.circuit_break))
            .build(service_fn(circuit_break_phase as fn(String) -> Result<(), PluginError>));

        PluginPhase { concurrency_control, circuit_break }
    }

    /// Evaluate governance plugins using a protocol-neutral context.
    ///
    /// Matching still uses SQL/text extracted from `PluginContext` so existing
    /// regex rules keep working for MySQL and PostgreSQL commands.
    pub fn evaluate(&mut self, ctx: &PluginContext) -> Result<PluginDecision, PluginError> {
        let input = ctx.match_text().to_owned();

        if let Err(error) = self.circuit_break.handle(input.clone()) {
            return Ok(PluginDecision::reject(
                "circuit_break",
                error.to_string(),
            ));
        }

        match self.concurrency_control.handle(input) {
            Ok((idx, ())) => Ok(match idx {
                Some(idx) => PluginDecision::continue_with_permit(idx),
                None => PluginDecision::continue_default(),
            }),
            Err(error) => Ok(PluginDecision::reject("concurrency_control", error.to_string())),
        }
    }

    pub fn release_concurrency(&mut self, rule_idx: usize) {
        self.concurrency_control.add_permits(rule_idx);
    }
}

#[cfg(test)]
mod tests {
    use gateway_core::{CommandSummary, PluginContext, PluginDecision, ProtocolKind};

    use super::*;
    use crate::config::{CircuitBreak, ConcurrencyControl, Plugin};

    fn ctx(sql: &str) -> PluginContext {
        PluginContext {
            service: "orders".into(),
            client_protocol: ProtocolKind::MySql,
            user: Some("app".into()),
            database: Some("orders".into()),
            command: CommandSummary::Query { sql: sql.into() },
            route_plan: None,
        }
    }

    #[test]
    fn evaluate_rejects_circuit_break_match() {
        let mut phase = PluginPhase::new(Plugin {
            concurrency_control: None,
            circuit_break: Some(vec![CircuitBreak {
                regex: vec![r"(?i)for update".into()],
                case_insensitive: true,
            }]),
        });

        let decision = phase.evaluate(&ctx("select * from t for update")).unwrap();
        assert!(matches!(decision, PluginDecision::Reject { code, .. } if code == "circuit_break"));
    }

    #[test]
    fn evaluate_continues_for_unmatched_sql() {
        let mut phase = PluginPhase::new(Plugin {
            concurrency_control: Some(vec![ConcurrencyControl {
                regex: vec![r"^insert".into()],
                max_concurrency: 10,
                duration: std::time::Duration::from_secs(60),
            }]),
            circuit_break: None,
        });

        let decision = phase.evaluate(&ctx("select 1")).unwrap();
        assert_eq!(decision, PluginDecision::continue_default());
    }
}
