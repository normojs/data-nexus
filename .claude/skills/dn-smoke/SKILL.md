---
name: dn-smoke
description: Run and debug Data Nexus smoke matrices with the correct rustc toolchain and external cargo target. Use when the user asks to run smoke, smoke matrix, regression, CI smoke, l0, security-core, security-extended, cedar smoke, or after security/runtime changes that need end-to-end verification.
---

# dn-smoke — Smoke 矩阵

## 环境（必设）

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

## 选组

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

## 失败处理

1. 读 `/tmp/dn-smoke-*.log` 或脚本输出中的 gateway log。  
2. 常见：  
   - rustc 过旧 → 检查 toolchain 1.94.1  
   - 脏 proxy → pkill  
   - schema 漂移 → seed 改为 DROP+CREATE  
   - 端口占用 → 清理 8082 / 9088  
3. 修代码后只重跑失败组，再视情况 `default`。  
4. Cedar 跑完必须：`cargo build -p data-proxy --bin proxy`（无 feature）。

## 单测捷径（改完先快测）

```bash
cargo test -p gateway_core --lib <filter>
cargo test -p runtime_gateway --lib <filter>
```

规则详见 [`.claude/rules/testing-smoke.md`](../../rules/testing-smoke.md)。
