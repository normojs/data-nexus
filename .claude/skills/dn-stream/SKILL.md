---
name: dn-stream
description: >
  Use when changing result paths, true streaming, wire passthrough, mask/watermark peak memory,
  ResultSet materialization, RowStream, ExecuteOutcome, ResponseWriter, portal export memory,
  or todo A06–A10. Also when user mentions 流式, 透传, 物化, 窗口, or 峰值内存.
---

# dn-stream — 真流式 / 透传 / 热路径

## Overview

目标：`backend 窗口 → 义务 → encode 窗口 → socket`，峰值 ≈ 窗口，不是 2× ResultSet。

## Force-read

- [`.claude/rules/streaming-performance.md`](../../rules/streaming-performance.md)
- `todo.md` A06–A10 与 §3.6 诚实账

## Decision tree

1. **同协议 + 无结果义务** → Wire / Passthrough（MySQL 原包透传；PG 非事务 TCP 帧中继 `WireRelay`，事务内 re-encode）
2. **有 mask/水印/max_rows** → `Streaming` + `execute_outcome` / `write_streaming_query_with_obligations`；禁止仅 `apply_obligations_to_response` 全量
3. **事务内 Streaming** → producer 结束后必须写回 `txn_lease`（见 MySQL/PG backend）
4. **跨协议** → Streaming 窗口 encode + 类型映射
5. **Portal NDJSON** → A09：`Streaming` 时 backend 窗口 → HTTP；json/csv 仍物化

## Code map

| 组件 | 文件 |
|------|------|
| RowStream / ExecuteOutcome / write_* | `gateway/core/src/transport.rs` |
| 窗口 mask | `gateway/core/src/obligations.rs` |
| PEP 消费流 | `runtime/gateway/src/core_engine.rs` |
| MySQL channel yield | `runtime/gateway/src/backend/mysql.rs` |
| Socket writer | `runtime/gateway/src/gateway.rs` |
| Portal | `http/src/http/mod.rs`（A09） |

## Checklist

- [ ] 有义务时不会误走 Passthrough
- [ ] 流提前结束 drain + 连接归还
- [ ] encode 接 `ResponseWriter`（生产路径非仅 CollectingWriter）
- [ ] 指标 `execute_path` / wire bytes 仍正确
- [ ] 单测：窗口 mask、StreamingQuery、core_engine
- [ ] smoke：`security-extended` 或 stream/passthrough/mask

## Verify

```bash
export RUSTUP_TOOLCHAIN=1.94.1
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"

cargo test -p gateway_core --lib transport obligations
cargo test -p runtime_gateway --lib core_engine backend::mysql
cd data-proxy && ./examples/run-smoke-matrix.sh security-extended
```

## Honesty

部分完成必须在 `todo.md` 标 **部分**，commit body 写边界（例：仅非事务 MySQL；PG Streaming 仍物化）。收尾 **dn-dod**。
