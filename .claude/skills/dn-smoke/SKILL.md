---
name: dn-smoke
description: >
  Use when running or debugging Data Nexus smoke matrices, regression, CI smoke, l0,
  security-core, security-extended, cedar smoke, or after security/runtime changes need
  end-to-end verification. Also when user says 跑 smoke, 回归, smoke 失败, or toolchain/rustc issues.
---

# dn-smoke — Smoke 矩阵

## Overview

用钉死的 rustc 1.94.1 + 外置 target 跑 smoke；先清脏 proxy，再按组验证。

## Env (required)

```bash
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
export RUSTUP_TOOLCHAIN=1.94.1
export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:${PATH}"
export DN_SMOKE_KEEP_GOING="${DN_SMOKE_KEEP_GOING:-0}"
export DN_SMOKE_TIMEOUT_SECS="${DN_SMOKE_TIMEOUT_SECS:-1200}"
```

需要 Docker。启动前：

```bash
pkill -f '/debug/proxy' 2>/dev/null || true
```

## Groups

| 场景 | 命令 |
|------|------|
| 默认门禁 | `./examples/run-smoke-matrix.sh default` |
| 仅 L0 | `./examples/run-smoke-matrix.sh l0` |
| 安全核心 | `./examples/run-smoke-matrix.sh security-core` |
| 流式/透传 | `./examples/run-smoke-matrix.sh security-extended` |
| 全量（不含 cedar） | `./examples/run-smoke-matrix.sh all` |
| Cedar | 先 `cargo build -p data-proxy --bin proxy --features security-cedar`，再 `./examples/run-smoke-matrix.sh cedar`，最后 **重建默认二进制** |

```bash
cd data-proxy
./examples/run-smoke-matrix.sh <group>
```

用户可传 `$ARGUMENTS` 作为组名（默认 `default`）。

## Failures

1. 读 `/tmp/dn-smoke-*.log` 或脚本输出中的 gateway log
2. 常见：rustc 过旧；脏 proxy；schema 漂移（DROP+CREATE）；端口 8082/9088 占用
3. 修后只重跑失败组，再视情况 `default`
4. Cedar 跑完必须：`cargo build -p data-proxy --bin proxy`（无 feature）

## Fast unit path

```bash
cargo test -p gateway_core --lib <filter>
cargo test -p runtime_gateway --lib <filter>
```

规则：[`testing-smoke.md`](../../rules/testing-smoke.md)。
