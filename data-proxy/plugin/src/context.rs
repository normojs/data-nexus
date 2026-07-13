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

use gateway_core::ProtocolKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginContext {
    pub protocol: ProtocolKind,
    pub command: String,
    pub sql: String,
}

impl PluginContext {
    pub fn new(protocol: ProtocolKind, command: impl Into<String>, sql: impl Into<String>) -> Self {
        Self { protocol, command: command.into(), sql: sql.into() }
    }
}

impl AsRef<str> for PluginContext {
    fn as_ref(&self) -> &str {
        &self.sql
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginDecision {
    Continue,
    Reject { reason: String },
    Rewrite { sql: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_context_exposes_sql_for_legacy_regex_rules() {
        let context = PluginContext::new(ProtocolKind::MySql, "COM_QUERY", "select 1");

        assert_eq!(context.as_ref(), "select 1");
        assert_eq!(context.protocol, ProtocolKind::MySql);
        assert_eq!(context.command, "COM_QUERY");
    }
}
