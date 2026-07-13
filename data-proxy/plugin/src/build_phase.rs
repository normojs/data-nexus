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

use crate::{
    circuit_break::{CircuitBreak, CircuitBreakLayer},
    concurrency_control::{ConcurrencyControl, ConcurrencyControlLayer},
    config,
    context::{PluginContext, PluginDecision},
    err::{BoxError, PluginError},
    layer::*,
};

/// concurrency control service, some logic may be added in the future, eg: metrics...
fn concurrency_control_phase(_input: PluginContext) -> Result<(), PluginError> {
    Ok(())
}

/// circuit break service, some logic may be added in the future, eg: metrics...
fn circuit_break_phase(_input: PluginContext) -> Result<(), PluginError> {
    Ok(())
}

#[derive(Clone)]
pub struct PluginPhase {
    pub concurrency_control:
        ConcurrencyControl<ServiceFn<fn(PluginContext) -> Result<(), PluginError>>>,
    pub circuit_break: CircuitBreak<ServiceFn<fn(PluginContext) -> Result<(), PluginError>>>,
}

impl PluginPhase {
    pub fn new(config: config::Plugin) -> PluginPhase {
        let concurrency_control = ServiceBuilder::new()
            .with_layer(ConcurrencyControlLayer::with_opt(config.concurrency_control))
            // issue https://users.rust-lang.org/t/puzzling-expected-fn-pointer-found-fn-item/46423/4
            .build(service_fn(
                concurrency_control_phase as fn(PluginContext) -> Result<(), PluginError>,
            ));

        let circuit_break = ServiceBuilder::new()
            .with_layer(CircuitBreakLayer::with_opt(config.circuit_break))
            .build(service_fn(circuit_break_phase as fn(PluginContext) -> Result<(), PluginError>));

        PluginPhase { concurrency_control, circuit_break }
    }

    pub fn handle(
        &mut self,
        context: PluginContext,
    ) -> Result<(Option<usize>, PluginDecision), BoxError> {
        if let Err(error) = self.circuit_break.handle(context.clone()) {
            return Ok((None, PluginDecision::Reject { reason: error.to_string() }));
        }

        match self.concurrency_control.handle(context) {
            Ok((permit_idx, _)) => Ok((permit_idx, PluginDecision::Continue)),
            Err(error) => Ok((None, PluginDecision::Reject { reason: error.to_string() })),
        }
    }
}
