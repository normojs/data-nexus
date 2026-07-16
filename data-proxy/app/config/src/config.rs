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

#![allow(dead_code)]
use std::{env, fs::File, io::prelude::*};

use api::config::Admin;
use clap::{value_parser, Arg, Command};
use gateway_core::{AdminAuthConfig, GatewayConfig, GatewayError};
use proxy::proxy::{ProxiesConfig, ProxyConfig, UniSQLNode, UniSQLNodes};
use serde::{Deserialize, Serialize};
use strategy::config::NodeGroup;
use tracing::trace;

use crate::env_const::*;

#[derive(Default, Clone)]
pub struct PisaProxyConfigBuilder {
    pub _local: bool,
    pub _config_path: String,
    pub _http_path: String,

    pub _log_level: String,
    pub _host: String,
    pub _port: String,
    pub _version: String,

    pub _deployed_ns: String,
    pub _deployed_name: String,
    pub _pisa_controller_host: String,
    pub _pisa_controller_svc: String,
    pub _pisa_controller_ns: String,

    pub _git_tag: String,
    pub _git_commit: String,
    pub _git_branch: String,
}

impl PisaProxyConfigBuilder {
    pub fn new() -> Self {
        PisaProxyConfigBuilder::default()
    }

    pub fn build_from_file(self, path: String) -> PisaProxyConfig {
        let config: PisaProxyConfig;
        let mut file = match File::open(path) {
            Err(e) => {
                eprintln!("{:?}", e);
                std::process::exit(-1);
            }
            Ok(file) => file,
        };

        let mut config_str = String::new();
        file.read_to_string(&mut config_str).unwrap();
        config = toml::from_str(&config_str).unwrap();
        config
    }

    pub fn build_from_http(
        self,
        path: String,
    ) -> Result<PisaProxyConfig, Box<dyn std::error::Error>> {
        let resp = reqwest::blocking::get(path)?.json::<PisaProxyConfig>()?;

        Ok(resp)
    }

    pub fn build_gateway_from_file(
        self,
        path: String,
    ) -> Result<GatewayConfigDocument, GatewayConfigLoadError> {
        let mut file = File::open(path).map_err(GatewayConfigLoadError::Io)?;
        let mut config_str = String::new();
        file.read_to_string(&mut config_str).map_err(GatewayConfigLoadError::Io)?;
        GatewayConfigDocument::from_toml(&config_str)
    }

    pub fn gateway_config_path(&self) -> Option<&str> {
        if self._local && !self._config_path.is_empty() {
            Some(self._config_path.as_str())
        } else {
            None
        }
    }

    pub fn collect_from_cmd(mut self) -> Self {
        let mut matches = Command::new("Pisa-Proxy")
            .subcommand(
                Command::new("sidecar")
                    .about("used for sidecar mode")
                    .arg(
                        Arg::new("pisa-controller-service")
                            .long("pisa-controller-service")
                            .help("Pisa Controller Service")
                            .default_value(DEFAULT_PISA_CONTROLLER_SERVICE)
                            .env(ENV_PISA_CONTROLLER_SERVICE)
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new("pisa-controller-namespace")
                            .long("pisa-controller-namespace")
                            .help("Pisa Controller Namespace")
                            .default_value(DEFAULT_PISA_CONTROLLER_NAMESPACE)
                            .env(ENV_PISA_CONTROLLER_NAMESPACE)
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new("pisa-controller-host")
                            .long("pisa-controller-host")
                            .help("Pisa Controller Host")
                            .default_value(DEFAULT_PISA_CONTROLLER_HOST)
                            .env(ENV_PISA_CONTROLLER_HOST)
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new("pisa-deployed-namespace")
                            .long("pisa-deployed-namespace")
                            .help("Namespace")
                            .default_value(DEFAULT_PISA_DEPLOYED_NAMESPACE)
                            .env(ENV_PISA_DEPLOYED_NAMESPACE)
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new("pisa-deployed-name")
                            .long("pisa-deployed-name")
                            .help("Name")
                            .default_value(DEFAULT_PISA_DEPLOYED_NAME)
                            .env(ENV_PISA_DEPLOYED_NAME)
                            .takes_value(true),
                    ),
            )
            .subcommand(
                Command::new("daemon").about("used for standalone mode").arg(
                    Arg::new("config")
                        .short('c')
                        .long("config")
                        .help("Config path")
                        .default_value(DEFAULT_LOCAL_CONFIG)
                        .takes_value(true),
                ),
            )
            .version(PisaProxyConfigBuilder::new().build_version()._version.as_str())
            .arg(
                Arg::new("host")
                    .short('h')
                    .long("host")
                    .help("Http host")
                    .default_value(DEFAULT_PISA_PROXY_ADMIN_LISTEN_HOST)
                    .value_parser(value_parser!(String))
                    .env(ENV_PISA_PROXY_ADMIN_LISTEN_HOST)
                    .takes_value(true),
            )
            .arg(
                Arg::new("port")
                    .short('p')
                    .long("port")
                    .help("Http port")
                    .default_value(DEFAULT_PISA_PROXY_ADMIN_LISTEN_PORT)
                    .value_parser(value_parser!(String))
                    .env(ENV_PISA_PROXY_ADMIN_LISTEN_PORT)
                    .takes_value(true),
            )
            .arg(
                Arg::new("loglevel")
                    .short('l')
                    .long("log-level")
                    .help("Log level")
                    .default_value(DEFAULT_PISA_PROXY_ADMIN_LOG_LEVEL)
                    .value_parser(value_parser!(String))
                    .env(ENV_PISA_PROXY_ADMIN_LOG_LEVEL)
                    .takes_value(true),
            )
            .subcommand_required(true)
            .get_matches();

        self._host = matches.get_one::<String>("host").unwrap().to_string();
        self._port = matches.get_one::<String>("port").unwrap().to_string();
        self._log_level = matches.get_one::<String>("loglevel").unwrap().to_string();

        let (name, cmd) = matches.remove_subcommand().expect("required");
        match (name.as_str(), cmd) {
            ("daemon", cmd) => {
                self._config_path = cmd.value_of("config").unwrap().to_string();
                self._local = true;
            }
            ("sidecar", cmd) => {
                self._pisa_controller_svc =
                    cmd.value_of("pisa-controller-service").unwrap().to_string();
                self._pisa_controller_ns =
                    cmd.value_of("pisa-controller-namespace").unwrap().to_string();
                self._pisa_controller_host =
                    cmd.value_of("pisa-controller-host").unwrap().to_string();
                if self._pisa_controller_host.is_empty() {
                    self._pisa_controller_host =
                        format!("{}.{}:8080", self._pisa_controller_svc, self._pisa_controller_ns);
                }
                self._deployed_ns = cmd.value_of("pisa-deployed-namespace").unwrap().to_string();
                self._deployed_name = cmd.value_of("pisa-deployed-name").unwrap().to_string();
            }
            (name, _) => {
                unimplemented!("this command '{}' is not supported", name);
            }
        }

        self
    }

    pub fn build_version(mut self) -> Self {
        self._git_tag = env::var(ENV_GIT_TAG).unwrap_or("".to_string());
        self._git_commit = env::var(ENV_GIT_COMMIT).unwrap_or(env!("VERGEN_GIT_SHA").to_string());
        self._git_branch =
            env::var(ENV_GIT_BRANCH).unwrap_or(env!("VERGEN_GIT_BRANCH").to_string());
        if !self._git_tag.is_empty() {
            self._version = format!("{}", self._git_tag);
        } else {
            self._version = format!("{}/{}", self._git_branch, self._git_commit);
        }
        self
    }

    pub fn build(self) -> PisaProxyConfig {
        let builder = PisaProxyConfigBuilder::new();
        let mut config: PisaProxyConfig = if self._local {
            builder.build_from_file(self._config_path)
        } else {
            let http_path = format!(
                "http://{}/apis/configs.database-mesh.io/v1alpha1/namespaces/{}/proxyconfigs/{}",
                self._pisa_controller_host, self._deployed_ns, self._deployed_name
            );
            builder.build_from_http(http_path).unwrap_or_default()
        };

        if !self._log_level.is_empty() {
            config.admin.log_level = self._log_level;
        }
        if !self._port.is_empty() {
            config.admin.port = self._port.parse::<u16>().unwrap();
        }
        if !self._host.is_empty() {
            config.admin.host = self._host;
        }

        if config.version.is_none() {
            // 从git获取版本
            config.version = Some(PisaProxyConfigBuilder::new().build_version()._version);
        }

        trace!("configs: {:#?}", config);
        config
    }

    pub fn build_gateway(self) -> Result<GatewayConfigDocument, GatewayConfigLoadError> {
        if !self._local {
            return Err(GatewayConfigLoadError::Unsupported(
                "loading v2 gateway config from controller is not implemented yet".into(),
            ));
        }

        let builder = PisaProxyConfigBuilder::new();
        let mut config = builder.build_gateway_from_file(self._config_path)?;

        if !self._log_level.is_empty() {
            config.admin.log_level = self._log_level;
        }
        if !self._port.is_empty() {
            config.admin.port = self._port.parse::<u16>().map_err(|error| {
                GatewayConfigLoadError::Validation(GatewayError::Configuration(format!(
                    "invalid admin port '{}': {}",
                    self._port, error
                )))
            })?;
        }
        if !self._host.is_empty() {
            config.admin.host = self._host;
        }

        if config.version.is_none() {
            config.version = Some(PisaProxyConfigBuilder::new().build_version()._version);
        }

        trace!("gateway configs: {:#?}", config);
        Ok(config)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PisaProxyConfig {
    pub admin: Admin,
    pub proxy: Option<ProxiesConfig>,
    pub node_group: Option<NodeGroup>,
    pub nodes: Option<UniSQLNodes>,
    #[deprecated(note = "废弃,统一使用node")]
    pub shardingsphere_proxy: Option<UniSQLNodes>,
    pub version: Option<String>,
}

impl PisaProxyConfig {
    pub fn new() -> Self {
        PisaProxyConfig::default()
    }
    pub fn get_proxy(&self) -> &Vec<ProxyConfig> {
        &self.proxy.as_ref().unwrap().config.as_ref().unwrap()
    }

    pub fn get_nodes(&self) -> &Vec<UniSQLNode> {
        &self.nodes.as_ref().unwrap().node.as_ref().unwrap()
    }

    pub fn get_admin(&self) -> &Admin {
        &self.admin
    }

    pub fn get_version(&self) -> &String {
        &self.version.as_ref().unwrap()
    }

    pub fn get_shardingsphere_proxy(&self) -> &Vec<UniSQLNode> {
        &self.shardingsphere_proxy.as_ref().unwrap().node.as_ref().unwrap()
    }
}

/// Native Data Nexus v2 configuration document.
///
/// The gateway topology is deliberately top-level so configuration files use
/// `[[listeners]]`, `[[services]]`, and `[[endpoints]]` directly. This is the
/// configuration shape consumed by the protocol-neutral gateway runtime.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GatewayConfigDocument {
    #[serde(default)]
    pub admin: Admin,
    /// Management-plane Admin API auth (not data-plane RBAC).
    #[serde(default)]
    pub admin_auth: AdminAuthConfig,
    #[serde(flatten)]
    pub gateway: GatewayConfig,
    pub version: Option<String>,
}

impl GatewayConfigDocument {
    pub fn from_toml(input: &str) -> Result<Self, GatewayConfigLoadError> {
        let document: Self = toml::from_str(input).map_err(GatewayConfigLoadError::Parse)?;
        document.gateway.validate().map_err(GatewayConfigLoadError::Validation)?;
        document.admin_auth.validate().map_err(GatewayConfigLoadError::Validation)?;
        Ok(document)
    }
}

#[derive(Debug)]
pub enum GatewayConfigLoadError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    Validation(GatewayError),
    Unsupported(String),
}

impl std::fmt::Display for GatewayConfigLoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "failed to read gateway configuration: {}", error),
            Self::Parse(error) => write!(formatter, "invalid gateway configuration: {}", error),
            Self::Validation(error) => {
                write!(formatter, "invalid gateway configuration: {}", error)
            }
            Self::Unsupported(message) => {
                write!(formatter, "unsupported gateway configuration source: {}", message)
            }
        }
    }
}

impl std::error::Error for GatewayConfigLoadError {}

#[cfg(test)]
mod test {
    use gateway_core::ProtocolKind;

    use super::*;

    #[test]
    #[ignore = "requires a live Pisa controller fixture"]
    fn test_build_from_http() {
        let mut builder = PisaProxyConfigBuilder::new();
        builder._host = "localhost:8080".to_string();
        builder._deployed_ns = "demotest".to_string();
        builder._deployed_name = "catalogue".to_string();
        let http_path = format!(
            "http://{}/apis/configs.database-mesh.io/v1alpha1/namespaces/{}/proxyconfigs/{}",
            builder._host, builder._deployed_ns, builder._deployed_name
        );
        let config: PisaProxyConfig = builder.build_from_http(http_path).unwrap();
        assert_eq!(config.admin.host, "0.0.0.0");
    }

    #[test]
    fn test_build_from_file() {
        let path = std::env::temp_dir()
            .join(format!("data-nexus-test-config-{}.toml", std::process::id()));
        std::fs::write(&path, include_str!("../../../examples/example-config.toml")).unwrap();

        let config: PisaProxyConfig =
            PisaProxyConfigBuilder::new().build_from_file(path.to_string_lossy().into_owned());
        let _ = std::fs::remove_file(path);

        assert_eq!(config.admin.host, "0.0.0.0");
    }

    #[test]
    fn parses_and_validates_native_gateway_config() {
        let config =
            GatewayConfigDocument::from_toml(include_str!("../../../examples/gateway-config.toml"))
                .unwrap();

        assert_eq!(config.gateway.listeners.len(), 1);
        assert_eq!(config.gateway.listeners[0].protocol, ProtocolKind::MySql);
        assert_eq!(config.gateway.services[0].backend_protocol, ProtocolKind::MySql);
        assert_eq!(config.gateway.endpoints.len(), 2);
        // S0: omitted [security] defaults to disabled shell.
        assert!(!config.gateway.security.enabled);
        assert!(config.gateway.security.fail_closed);
    }

    #[test]
    fn parses_security_shell_section() {
        let toml = r#"
version = "2"
[admin]
host = "0.0.0.0"
port = 8082
log_level = "INFO"
[security]
enabled = false
fail_closed = true
star_policy = "deny"
default_audit_level = "L0"
[security.pdp]
backend = "local"
[security.streaming]
window_rows = 64
[[security.rules]]
name = "deny-secret"
effect = "deny"
actions = ["select"]
tables = ["*.*.secret_*"]
columns = ["salary"]
[[listeners]]
name = "l1"
listen_addr = "0.0.0.0:1"
protocol = "mysql"
service = "s1"
[[services]]
name = "s1"
backend_protocol = "mysql"
endpoints = ["e1"]
plugin_policies = []
[[endpoints]]
name = "e1"
protocol = "mysql"
address = "127.0.0.1:3306"
weight = 1
"#;
        let config = GatewayConfigDocument::from_toml(toml).unwrap();
        assert!(!config.gateway.security.enabled);
        assert_eq!(config.gateway.security.streaming.window_rows, 64);
        assert_eq!(config.gateway.security.star_policy, "deny");
        assert_eq!(config.gateway.security.rules.len(), 1);
        assert_eq!(config.gateway.security.rules[0].name, "deny-secret");
        assert_eq!(
            config.gateway.security.rules[0].columns,
            vec!["salary".to_string()]
        );
    }

    #[test]
    fn parses_security_column_example_config() {
        let config = GatewayConfigDocument::from_toml(include_str!(
            "../../../examples/security-column-gateway-config.toml"
        ))
        .unwrap();
        assert!(config.gateway.security.enabled);
        assert_eq!(config.gateway.security.star_policy, "deny");
        assert!(config
            .gateway
            .security
            .rules
            .iter()
            .any(|r| r.name == "deny-employee-pii" && r.columns.contains(&"salary".into())));
    }

    #[test]
    fn rejects_invalid_security_shell() {
        let toml = r#"
version = "2"
[admin]
host = "0.0.0.0"
port = 8082
log_level = "INFO"
[security]
default_audit_level = "full"
[[listeners]]
name = "l1"
listen_addr = "0.0.0.0:1"
protocol = "mysql"
service = "s1"
[[services]]
name = "s1"
backend_protocol = "mysql"
endpoints = ["e1"]
plugin_policies = []
[[endpoints]]
name = "e1"
protocol = "mysql"
address = "127.0.0.1:3306"
weight = 1
"#;
        assert!(GatewayConfigDocument::from_toml(toml).is_err());
    }

    #[test]
    fn parses_and_validates_postgresql_gateway_config() {
        let config = GatewayConfigDocument::from_toml(include_str!(
            "../../../examples/postgresql-gateway-config.toml"
        ))
        .unwrap();

        assert_eq!(config.gateway.listeners.len(), 1);
        assert_eq!(config.gateway.listeners[0].protocol, ProtocolKind::PostgreSql);
        assert_eq!(config.gateway.services[0].backend_protocol, ProtocolKind::PostgreSql);
        assert_eq!(config.gateway.endpoints.len(), 2);
        assert!(config
            .gateway
            .endpoints
            .iter()
            .all(|endpoint| endpoint.protocol == ProtocolKind::PostgreSql));
    }

    #[test]
    fn parses_and_validates_dual_listener_gateway_config() {
        let config = GatewayConfigDocument::from_toml(include_str!(
            "../../../examples/dual-listener-gateway-config.toml"
        ))
        .unwrap();

        assert_eq!(config.gateway.listeners.len(), 2);
        assert_eq!(config.gateway.listeners[0].protocol, ProtocolKind::MySql);
        assert_eq!(config.gateway.listeners[1].protocol, ProtocolKind::PostgreSql);
        assert_eq!(config.gateway.services.len(), 2);
    }

    #[test]
    fn parses_and_validates_cross_protocol_mysql_to_pg_config() {
        let config = GatewayConfigDocument::from_toml(include_str!(
            "../../../examples/cross-protocol-mysql-to-pg.toml"
        ))
        .unwrap();

        assert_eq!(config.gateway.listeners.len(), 1);
        assert_eq!(config.gateway.listeners[0].protocol, ProtocolKind::MySql);
        assert_eq!(config.gateway.services[0].backend_protocol, ProtocolKind::PostgreSql);
        assert_eq!(
            config.gateway.services[0].translation_policy.as_deref(),
            Some("mysql-to-pg")
        );
        assert_eq!(config.gateway.translation_policies.len(), 1);
        assert!(config.gateway.translation_policies[0].enabled);
    }

    #[test]
    fn parses_and_validates_cross_protocol_pg_to_mysql_config() {
        let config = GatewayConfigDocument::from_toml(include_str!(
            "../../../examples/cross-protocol-pg-to-mysql.toml"
        ))
        .unwrap();

        assert_eq!(config.gateway.listeners[0].protocol, ProtocolKind::PostgreSql);
        assert_eq!(config.gateway.services[0].backend_protocol, ProtocolKind::MySql);
        assert_eq!(
            config.gateway.services[0].translation_policy.as_deref(),
            Some("pg-to-mysql")
        );
        assert!(config.gateway.translation_policies[0].enabled);
    }

    #[test]
    fn accepts_legacy_protocol_aliases_in_toml() {
        let toml = r#"
version = "2"
[admin]
host = "0.0.0.0"
port = 8082
log_level = "INFO"
[[listeners]]
name = "l1"
listen_addr = "0.0.0.0:1"
protocol = "my_sql"
service = "s1"
[[services]]
name = "s1"
backend_protocol = "my_sql"
endpoints = ["e1"]
plugin_policies = []
[[endpoints]]
name = "e1"
protocol = "MySQL"
address = "127.0.0.1:3306"
weight = 1
"#;
        let config = GatewayConfigDocument::from_toml(toml).unwrap();
        assert_eq!(config.gateway.listeners[0].protocol, ProtocolKind::MySql);
        assert_eq!(config.gateway.endpoints[0].protocol, ProtocolKind::MySql);
    }

    #[test]
    fn builds_native_gateway_config_from_file() {
        let path = std::env::temp_dir()
            .join(format!("data-nexus-gateway-config-{}.toml", std::process::id()));
        std::fs::write(&path, include_str!("../../../examples/gateway-config.toml")).unwrap();

        let config = PisaProxyConfigBuilder::new()
            .build_gateway_from_file(path.to_string_lossy().into_owned())
            .unwrap();
        let _ = std::fs::remove_file(path);

        assert_eq!(config.gateway.listeners[0].name, "orders-mysql");
    }
}
