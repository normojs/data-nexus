---
name: dn-stream
description: Workflow for true streaming, passthrough, mask/watermark on the result path, ResponseWriter, RowStream, and portal large-result work (todo A06–A10). Use when the user mentions 流式, streaming, passthrough, mask peak memory, ResultSet materialization, RowStream, execute_outcome, wire passthrough, or portal export memory. Prefer this over generic coding whenever result paths change.
---

# dn-stream — 真流式 / 透传 / 热路径

## 强制阅读

- [`.claude/rules/streaming-performance.md`](../../rules/streaming-performance.md)
- `todo.md` A06–A10 与 §3.6 诚实账

## 目标

```text
backend 窗口 → 义务 → encode 窗口 → socket
峰值 ≈ 窗口，不是 2× ResultSet
```

## 决策树

1. **同协议 + 无结果义务** → Wire / Passthrough（MySQL wire；PG 为消息级 Wire，非 TCP 帧中继）。  
2. **有 mask/水印/max_rows** → `Streaming` + `execute_outcome` / `write_streaming_query_with_obligations`；禁止仅 `apply_obligations_to_response` 全量。  
3. **跨协议** → Streaming 窗口 encode + 类型映射。  
4. **Portal** → 在 A09 完成前诚实：HTTP chunk ≠ backend 已流式。

## 落点

| 组件 | 文件 |
|------|------|
| RowStream / ExecuteOutcome / write_* | `gateway/core/src/transport.rs` |
| 窗口 mask | `gateway/core/src/obligations.rs` |
| PEP 消费流 | `runtime/gateway/src/core_engine.rs` |
| MySQL channel yield | `runtime/gateway/src/backend/mysql.rs` |
| Socket writer | `runtime/gateway/src/gateway.rs` |
| Portal | `http/src/http/mod.rs`（A09） |

## 实现检查清单

- [ ] 有义务时不会误走 Passthrough  
- [ ] 流提前结束是否 drain + 连接归还  
- [ ] encode 是否 `ResponseWriter`（非仅 CollectingWriter 生产路径）  
- [ ] 指标 `execute_path` / wire bytes 是否仍正确  
- [ ] 单测：窗口 mask、StreamingQuery、core_engine 不回归  
- [ ] 相关 smoke：`security-extended`（stream/passthrough）或 mask  

## 验证

```bash
export RUSTUP_TOOLCHAIN=1.94.1
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"

cargo test -p gateway_core --lib transport obligations
cargo test -p runtime_gateway --lib core_engine backend::mysql

cd data-proxy && ./examples/run-smoke-matrix.sh security-extended
# 或至少：smoke-security-stream / passthrough / mask
```

## 诚实账（提交信息里写清）

部分完成必须在 `todo.md` 标 **部分**，并在 commit body 写边界（例如：仅非事务 MySQL；PG Streaming 仍物化）。

收尾用 **dn-dod**。
