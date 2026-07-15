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

- M0–M3 主路径：同协议 E2E、v2-only、RoutePlan/Plugin、跨协议 translation + smoke
- PG→MySQL 标识符改写 + 反向示例配置
- MySQL AST `DialectParser`（runtime，失败回退 heuristic）
- structured tracing spans：`gateway.handle_frame` / `gateway.command`

### 开放缺口（可选 / 后续）

1. PostgreSQL AST dialect parser（当前 heuristic）
2. 完整 OTel exporter（当前 tracing span，可接 subscriber/OTLP）
3. 管理 UI（`data-ui`）消费 Admin API

---

## 路线总览

```text
M0  端到端可跑（同协议）     ✓
M1  去掉 legacy 双轨         ✓
M2  治理协议无关 + Admin     ✓
M3  受控跨协议               ✓
M4  深化（方言/可观测）      ✓（主项完成，PG AST / OTLP 可选）
```

原则：

- 新代码只依赖 `gateway_core` 类型；legacy 只允许在明确标记的 bridge 里
- 配置错误 fail fast；请求错误只影响当前 session，禁止主路径 panic

---

## M0–M3：已完成

详见 git 历史。验收：

- 同协议：`./data-proxy/examples/smoke-dual-listener.sh`
- 跨协议 MySQL→PG：`./data-proxy/examples/smoke-cross-protocol.sh`

---

## M4：方言与可观测（已完成主项）

- [x] PG→MySQL 标识符改写（`"x"` → `` `x` ``）+ golden tests
- [x] 示例配置：`examples/cross-protocol-pg-to-mysql.toml`
- [x] MySQL AST dialect parser（`runtime/gateway/src/dialect.rs`，`mysql_parser` + fallback）
- [x] core 路由 / translation 使用 runtime dialect
- [x] structured spans on `handle_frame` / command / backend execute
- [ ] PostgreSQL AST dialect（可选）
- [ ] OpenTelemetry exporter 接入（可选）

---

## 模块边界（开发时遵守）

```text
gateway/core     协议无关类型与 trait（禁止依赖 mysql/pg wire / parser）
runtime/gateway  编排 + runtime dialect（可依赖 mysql_parser）
frontend/*       握手 + decode/encode only
backend/*        连后端 + 执行 only
proxy/*          池、endpoint、strategy
plugin/*         PluginContext → PluginDecision
app/config       v2 解析与校验
http             Admin / metrics
```

---

## 暂不做

- [ ] 任意 MySQL/PostgreSQL 全量互转
- [ ] 继续在 `ProxyConfig` 上堆字段
- [ ] 用 `node_type` 字符串决定运行时行为
- [ ] 优先做管理 UI；先完成 runtime state + Admin API
- [ ] 一次性大搬家目录结构

---

## 完成定义（Definition of Done）

1. 有对应示例 config 或集成测试
2. `cargo test`（相关 crate）通过
3. 不引入新的主路径 `unwrap()` / 字符串协议分支
4. 更新本文件；重大接口变更同步 `docs/data-nexus-protocol-gateway-plan.md`
