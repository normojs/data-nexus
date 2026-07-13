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

use std::{io::Error, time::Duration};

use gateway_core::ProtocolKind;

use crate::{
    build_phase::PluginPhase,
    circuit_break::CircuitBreakLayer,
    concurrency_control::ConcurrencyControlLayer,
    config,
    err::PluginError,
    layer::{service_fn, Service, ServiceBuilder},
    PluginContext, PluginDecision,
};

fn test_service(input: &str) -> Result<String, Error> {
    Ok(input.to_string())
}

#[test]
fn plugin_phase_handles_protocol_neutral_context() {
    let config = config::Plugin {
        concurrency_control: None,
        circuit_break: Some(vec![config::CircuitBreak {
            regex: vec![String::from(r"^drop")],
            case_insensitive: true,
        }]),
    };
    let mut phase = PluginPhase::new(config);

    let allowed = phase.circuit_break.handle(PluginContext::new(
        ProtocolKind::MySql,
        "COM_QUERY",
        "select 1",
    ));
    assert!(allowed.is_ok());

    let rejected = phase.circuit_break.handle(PluginContext::new(
        ProtocolKind::MySql,
        "COM_QUERY",
        "drop table t",
    ));
    assert!(rejected.is_err());
}

#[test]
fn plugin_phase_returns_decisions() {
    let config = config::Plugin {
        concurrency_control: Some(vec![config::ConcurrencyControl {
            regex: vec![String::from(r"^select")],
            max_concurrency: 0,
            duration: Duration::new(5, 0),
        }]),
        circuit_break: Some(vec![config::CircuitBreak {
            regex: vec![String::from(r"^drop")],
            case_insensitive: true,
        }]),
    };
    let mut phase = PluginPhase::new(config);

    let (_, allowed) = phase
        .handle(PluginContext::new(ProtocolKind::MySql, "COM_QUERY", "insert into t values (1)"))
        .unwrap();
    assert_eq!(allowed, PluginDecision::Continue);

    let (_, circuit_rejected) =
        phase.handle(PluginContext::new(ProtocolKind::MySql, "COM_QUERY", "drop table t")).unwrap();
    assert!(
        matches!(circuit_rejected, PluginDecision::Reject { reason } if reason.contains("audit plugin rejected"))
    );

    let (_, concurrency_rejected) =
        phase.handle(PluginContext::new(ProtocolKind::MySql, "COM_QUERY", "select 1")).unwrap();
    assert!(
        matches!(concurrency_rejected, PluginDecision::Reject { reason } if reason.contains("concurrency control plugin rejected"))
    );
}

#[test]
fn test_chain_concurrency_control_and_circuit_break() {
    let concurrency_control_config = vec![config::ConcurrencyControl {
        regex: vec![String::from(r"[A-Za-z]+$")],
        max_concurrency: 0,
        duration: Duration::new(5, 0),
    }];

    let circuit_break_config = vec![config::CircuitBreak {
        regex: vec![String::from(r"[A-Za-z]+")],
        case_insensitive: false,
    }];

    let mut wrap_svc = ServiceBuilder::new()
        .with_layer(ConcurrencyControlLayer::new(concurrency_control_config))
        .with_layer(CircuitBreakLayer::new(circuit_break_config))
        .build(service_fn(test_service));

    let res = wrap_svc.handle("abc");
    println!("{:?}", res);
    if let Err(e) = res {
        let e = e.downcast::<PluginError>().unwrap();
        assert_eq!(*e, PluginError::ConcurrencyControlPluginReject)
    }
}
