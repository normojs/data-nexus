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

- MySQL **Streaming**（含事务）：channel `RowStream`；事务内 producer 结束后写回 `txn_lease`；smoke `max_rows`（**含 BEGIN..SELECT..COMMIT**）+ metrics `streaming`。
- PostgreSQL **Streaming**（含事务）：`simple_query_raw` + channel；事务内同样还 lease；smoke 事务内 max_rows 同路径。
- 并发：同一会话事务内 stream 未 drain 前不要再发下一条（producer 持有 lease）。
- Portal NDJSON（A09）：backend 返回 `Streaming` 时窗口 yield → HTTP chunk（`stream=backend_window`）；multi-row smoke **强制** backend_window；smoke 断言 **json/csv 无 backend_window（物化）**；`Complete` 回退 B05b chunked。
- PG Passthrough（A08）：idle pool（cap + TTL + SELECT 1 探测）+ 事务 `tcp_txn` 原帧中继；`endpoints[].ssl_mode` disable/prefer/require；**`ssl_ca_file` + `ssl_accept_invalid_certs`**（默认 true 兼容 MVP；生产可 `false` + CA PEM）。Streaming 仍用 pool。非 extended。
- A07：`handle_frame_to_writer` + socket `ResponseWriter` 已接。
- A10 prepared：MySQL COM_STMT_EXECUTE → backend **COM_STMT_PREPARE/EXECUTE 绑定**（连接级 stmt 缓存）+ binary 行解码 + **Streaming 窗口**（`QueryParams`/`Execute`）；PG Bind 保留 `$n` → `QueryParams` → prepare/bind + **连接级 Statement 缓存** + **Streaming 窗口**（`query_raw`）；result_format=1 → binary DataRow（含 date/ts/time）；非 TCP passthrough。

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
