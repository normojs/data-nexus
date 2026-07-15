// Copyright 2022 SphereEx Authors
//
// DEPRECATED experimental entrypoint. Use `main.rs` with v2 GatewayConfig only:
//   cargo run -p pisa -- --config examples/gateway-config.toml
//
// The legacy GatewayFactory::new(ProxyConfig, PisaProxyConfig) path has been removed.

fn main() {
    eprintln!(
        "data-nexus: main2 is deprecated. Use the default pisa binary with a v2 gateway config.\n\
Example: cargo run -p pisa -- --config examples/dual-listener-gateway-config.toml"
    );
    std::process::exit(2);
}
