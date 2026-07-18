---
paths: data-proxy/gateway/core/**/*.rs, data-proxy/runtime/gateway/**/*.rs, data-proxy/http/**/*.rs, **/transport.rs, **/core_engine.rs, **/obligations.rs, **/backend/**/*.rs, **/frontend/**/*.rs, **/portal*.rs
---

# 流式与热路径（强制补充）

与 [`data-nexus-development.md`](data-nexus-development.md) 配套。改 PEP、backend、portal 结果路径时必读。

## 目标态

```text
backend 行窗口 → 义务(mask/水印/max_rows) → encode 窗口 → socket 写出
峰值内存 ≈ 1～2 个窗口，而不是 2× 全量 ResultSet
```

## 路径选择

| 条件 | 路径 | 要求 |
|------|------|------|
| 同协议 + 无结果义务 + passthrough | Wire / 帧级 | 禁止无谓 `ResultSet` |
| 有 mask / 列删 / 水印 / max_rows | Streaming + 窗口义务 | 禁止「先全量再 `apply_obligations`」成为唯一路径 |
| 跨协议 | Streaming 窗口 encode | 禁止 Materialized 当生产默认 |

## 当前诚实边界（勿宣传为已完成）

- MySQL **Streaming**（含事务）：channel `RowStream`；事务内 producer 结束后写回 `txn_lease`。
- PostgreSQL **Streaming**（含事务）：`simple_query_raw` + channel；事务内同样还 lease。
- 并发：同一会话事务内 stream 未 drain 前不要再发下一条（producer 持有 lease）。
- Portal NDJSON（A09）：backend 返回 `Streaming` 时窗口 yield → HTTP chunk（`stream=backend_window`）；`Complete` 回退 B05b chunked；**json/csv 仍物化**有界 ResultSet。
- PG Passthrough（A08）：**非事务**专用 TCP session 原帧中继（`WireRelay` 边写）；**事务内**仍 `simple_query_raw` 再编码 Wire（池连接）。非 extended protocol。
- A07：`handle_frame_to_writer` + socket `ResponseWriter` 已接。
- A10 prepared：MySQL COM_STMT_EXECUTE → binary 行（含 DATE/DATETIME/TIME）；PG ParameterDescription + text 参数 Bind→Query；**Bind result_format=1 → binary DataRow**（int/bool/float/text/bytea；date/ts 未原生 binary）。

## 实现检查清单

改结果路径时自问：

1. 会不会迫使 `Vec<Vec<GatewayValue>>` 全量？会 → 设计 `RowStream` / 窗口或明确 cap。
2. 有义务时是否仍 `apply_obligations_to_response` 整包？→ 优先 `write_streaming_query_with_obligations` / encode 窗口 mask。
3. 是否接到 socket writer，而不是只 `CollectingWriter`？
4. 失败/提前结束是否 drain 流并归还连接？
5. todo §3.6 与 OBSERVABILITY 是否需要更新诚实账？

## 落点

```text
gateway/core     transport (RowStream, ExecuteOutcome, write_*_windowed*)
                 obligations (mask 窗口)
runtime/gateway  core_engine (execute_outcome, handle_frame_to_writer)
                 backend/mysql + backend/postgresql (channel RowStream, non-txn)
                 gateway.rs (MySqlSocketWriter / PgSocketWriter)
http             portal_execute_ndjson_streaming（A09）+ portal_execute_logical
```

详细任务 ID：`todo.md` A06–A10。实现时用 skill **dn-stream** 或 `/dn-stream`。
