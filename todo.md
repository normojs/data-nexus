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

- M0–M2 主路径：同协议 E2E、v2-only 配置、RoutePlan/Plugin/Dialect/metrics/audit/Admin reload
- dual-listener Docker smoke E2E
- M3：`translation_policy` + SQL 子集校验 + prepared 限制 + 结果类型映射 + MySQL→PG 保守改写 + core 执行路径接入 + golden tests

### 开放缺口（可选）

1. 完整 AST dialect parser（mysql_parser 等）
2. OTel structured trace
3. PostgreSQL→MySQL 改写深化（当前 passthrough + 类型映射）

---

## 路线总览

```text
M0  端到端可跑（同协议）     ✓
M1  去掉 legacy 双轨         ✓（主路径）
M2  治理协议无关 + Admin     ✓（主路径）
M3  受控跨协议（可选）       ✓（含 Docker smoke）
```

原则：

- 先打通 **同协议生产可用**，再做插件/分片/跨协议
- 新代码只依赖 `gateway_core` 类型；legacy 只允许在明确标记的 bridge 里
- 配置错误 fail fast；请求错误只影响当前 session，禁止主路径 panic

---

## M0–M2：已完成（摘要）

同协议 MySQL/PG E2E、v2 配置收敛、RoutePlan/PluginContext/DialectParser、metrics/audit、Admin reload、优雅关闭。详见 git 历史与 `docs/data-nexus-protocol-gateway-plan.md`。

验收跑法：`./data-proxy/examples/smoke-dual-listener.sh`

---

## M3：受控跨协议（已完成主路径）

前置：M0–M2 完成且同协议稳定。

- [x] `translation_policy` 配置，**默认关闭**（跨协议需显式 enabled policy）
- [x] 明确支持子集入口：SELECT/INSERT/UPDATE/DELETE（`check_translation_sql`）
- [x] 不支持的 DDL / 存储过程 / COPY / LOAD DATA / 厂商函数 → 明确错误
- [x] 结果类型映射表（`CanonicalDataType` / `map_column_type` / `map_response_types`）
- [x] prepared statement 限制（跨协议 Prepare/Execute/Close → Unsupported）
- [x] 实际跨协议执行路径（core `handle_frame`：校验 → 改写 → execute → 列类型映射）
- [x] 方言转换 golden tests（MySQL→PG：反引号、IFNULL、LIMIT offset）
- [x] 示例配置：`examples/cross-protocol-mysql-to-pg.toml`
- [x] 跨协议 Docker smoke（`examples/smoke-cross-protocol.sh`）
- [x] MySQL charset/collation → PG `client_encoding` 映射（跨协议 session 同步）

**不做**：任意方言全量互转。

可选后续：

- [ ] PG→MySQL 标识符/函数改写扩展
- [ ] 完整 AST parser 按 dialect 挂载
- [ ] structured trace（OpenTelemetry）

---

## 模块边界（开发时遵守）

```text
gateway/core     协议无关类型与 trait（禁止依赖 mysql/pg wire）
runtime/gateway  编排：listener、session、route、plugin 调用
frontend/*       握手 + decode/encode only
backend/*        连后端 + 执行 only
proxy/*          池、endpoint、strategy（逐步只认 core 类型）
plugin/*         输入 PluginContext，输出 PluginDecision
app/config       v2 解析与校验
http             Admin / metrics，不解析 SQL
```

---

## 暂不做

- [ ] 任意 MySQL/PostgreSQL 全量互转
- [ ] 继续在 `ProxyConfig` 上堆字段
- [ ] 用 `node_type` 字符串决定运行时行为
- [ ] 优先做管理 UI（`data-ui`）；先完成 runtime state + Admin API
- [ ] 一次性大搬家到 `backend/mysql` 目录结构（可后置，先接口正确）

---

## 完成定义（Definition of Done）

每个里程碑合并前：

1. 有对应示例 config 或集成测试
2. `cargo test`（相关 crate）通过
3. 不引入新的主路径 `unwrap()` / 字符串协议分支
4. 更新本文件勾选状态；重大接口变更同步 `docs/data-nexus-protocol-gateway-plan.md`
