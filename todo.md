# Data Nexus 后续开发计划

详细架构见：`docs/data-nexus-protocol-gateway-plan.md`

## 产品定位

Data Nexus = **数据库协议中转站**（不是单协议 MySQL proxy）。

- 前端协议、后端协议、SQL 方言、路由、治理插件解耦
- Phase A/B：同协议中转（MySQL↔MySQL、PostgreSQL↔PostgreSQL）
- Phase C：治理协议无关化
- Phase D：受控跨协议（明确 SQL 子集，默认关闭）

---

## 现状快照（2026-07）

### 已完成

- M0–M4：同协议 E2E、跨协议双向 smoke、MySQL AST dialect、PG structured dialect、tracing EnvFilter/JSON
- 可观测说明：`data-proxy/examples/OBSERVABILITY.md`

### 开放缺口（可选）

1. 完整 OpenTelemetry OTLP exporter（span 已就绪，见 OBSERVABILITY.md）
2. 管理 UI（`data-ui`）消费 Admin API
3. 更完整的 PostgreSQL AST crate（当前 structured classifier 已覆盖路由主路径）

---

## 路线总览

```text
M0  端到端可跑（同协议）     ✓
M1  去掉 legacy 双轨         ✓
M2  治理协议无关 + Admin     ✓
M3  受控跨协议               ✓
M4  方言 / 可观测深化        ✓
```

原则：

- 新代码只依赖 `gateway_core` 类型；legacy 只允许在明确标记的 bridge 里
- 配置错误 fail fast；请求错误只影响当前 session，禁止主路径 panic

---

## 验收跑法

| 场景 | 命令 |
|------|------|
| 同协议双 listener | `./data-proxy/examples/smoke-dual-listener.sh` |
| MySQL client → PG | `./data-proxy/examples/smoke-cross-protocol.sh` |
| PG client → MySQL | `./data-proxy/examples/smoke-cross-protocol-pg-to-mysql.sh` |

---

## M4：方言与可观测（完成）

- [x] PG→MySQL 标识符改写 + golden tests + 示例配置
- [x] MySQL AST dialect parser（`mysql_parser` + fallback）
- [x] PostgreSQL structured dialect（去注释、WITH/DML、FOR UPDATE、TABLE/VALUES）
- [x] structured spans：`gateway.handle_frame` / `gateway.command`
- [x] tracing：`RUST_LOG` / `DATA_NEXUS_LOG` EnvFilter + `DATA_NEXUS_LOG_FORMAT=json`
- [x] 双向跨协议 Docker smoke
- [ ] OTel OTLP exporter（可选，文档已说明接入点）

---

## 模块边界

```text
gateway/core     协议无关类型与 trait（禁止依赖 wire / parser）
runtime/gateway  编排 + runtime dialect（可依赖 mysql_parser）
frontend/*       握手 + decode/encode only
backend/*        连后端 + 执行 only
cmd/pisa         进程入口、日志 subscriber
http             Admin / metrics
```

---

## 暂不做

- [ ] 任意 MySQL/PostgreSQL 全量互转
- [ ] 继续在 `ProxyConfig` 上堆字段
- [ ] 用 `node_type` 字符串决定运行时行为
- [ ] 优先做管理 UI
- [ ] 默认构建硬依赖 OTel SDK

---

## 完成定义（Definition of Done）

1. 有对应示例 config 或集成测试
2. `cargo test`（相关 crate）通过
3. 不引入新的主路径 `unwrap()` / 字符串协议分支
4. 更新本文件；重大接口变更同步架构文档
