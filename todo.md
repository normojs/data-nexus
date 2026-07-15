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

- [x] `gateway/core`：`ProtocolKind` / `GatewayCommand` / `GatewayResponse` / `SessionState` / `GatewayConfig`
- [x] v2 配置 schema：`listeners` / `services` / `endpoints` / `route_policies` / `auth_policies` / `plugin_policies`
- [x] 配置校验器 + 示例：`examples/gateway-config.toml`、`examples/postgresql-gateway-config.toml`
- [x] `MySqlFrontendProtocol` / `PostgreSqlFrontendProtocol`
- [x] `MySqlBackendConnector`（池化 simple query）/ `PostgreSqlBackendConnector`
- [x] `CoreGatewayConnection` + `CoreGatewayRuntimePlan`（`core_engine.rs`）
- [x] `GatewayFactory` 按 v2 listener 构建 runtime
- [x] v2 启动走 core accept：`start_core_listener` 同时支持 MySQL / PostgreSQL
- [x] 简单负载均衡 / 读写分离 route policy 协议无关化（core 路径）
- [x] Admin API 骨架：`/admin/listeners|services|endpoints|pools|sessions|reload` 等
- [x] metrics 维度：service / frontend protocol / backend protocol / endpoint（部分）
- [x] 协议名 canonical + 别名解析；v2 示例 / dual-listener / compose 本地后端
- [x] `RoutePlan` / `EndpointRef` 进入 gateway_core；core 路由输出 RoutePlan
- [x] `PluginContext` / `PluginDecision`；core 执行前插件评估
- [x] v2 `plugin_policies` → PluginPhase 自动装载
- [x] `DialectParser` 驱动 core 读写路由

### 关键缺口（阻塞可交付）

1. **`Listener.backend_type` / `node_type`** 仍在 proxy listener 结构（兼容字段，不决定协议）
2. **事务 FSM 仍绑定 MySQL `SessionAttr`**（legacy command service 路径；core 路径已不依赖）
3. **同协议端到端验收未闭环**：v2 MySQL / PG 真实客户端验收项仍未勾选（需 Docker）
4. **legacy `RouteStrategy::dispatch`** 仍返回 `Endpoint`（仅 legacy 路径）

---

## 路线总览

```text
M0  端到端可跑（同协议）     ← 当前最高优先
M1  去掉 legacy 双轨
M2  治理协议无关 + Admin 可用
M3  受控跨协议（可选）
```

原则：

- 先打通 **同协议生产可用**，再做插件/分片/跨协议
- 新代码只依赖 `gateway_core` 类型；legacy 只允许在明确标记的 bridge 里
- 配置错误 fail fast；请求错误只影响当前 session，禁止主路径 panic

---

## M0：同协议端到端可交付（1–2 周）

目标：v2 配置下，MySQL / PostgreSQL 客户端分别能稳定访问同协议后端。

### M0.1 打通 core 执行主路径

- [x] `GatewayRuntime::start()` 有 v2 core_plan 时默认走 `CoreGatewayConnection`（MySQL/PG 共用 core accept）
- [x] 补全 `MySqlBackendConnector`：连接池 + simple query + session attr 同步（prepare-execute 仍后续）
- [x] `PostgreSqlBackendConnector` simple query + 基础 session 同步已在 runtime accept 路径可用
- [x] listener accept → frontend handshake → `handle_frame` / command loop → backend → encode 主路径
- [x] 请求级错误转为客户端协议错误包（MySQL ERR / PG ErrorResponse）

### M0.2 会话与连接

- [x] MySQL/PG backend 连接池按 `EndpointConfig` 建池（core 路径；runtime 仍可能 bridge UniSQLNode）
- [x] session：core accept 路径同步 user/database/charset/autocommit；transaction 走 `SessionState`
- [x] 事务：BEGIN 延迟到首条语句；同一 `PoolConn` lease 贯穿事务；COMMIT/ROLLBACK 释放
- [ ] `TransFsm` 去掉对 `mysql_protocol::SessionAttr` 的直接依赖（legacy 路径仍用；core 路径已不依赖）

### M0.3 配置与示例

- [x] 统一协议名：canonical `mysql` / `postgresql`；兼容 `my_sql` / `postgre_sql` / `postgres` / `pg`
- [x] 示例配置改为 canonical；`dual-listener-gateway-config.toml` + `docker-compose.dev.yml`
- [x] 启动前校验：缺 listener/service/endpoint、协议不匹配、引用无效 fail fast

### M0.4 验收（必须全部通过）

- [ ] `mysql` 客户端经 Data Nexus 连 MySQL 后端：SELECT / 简单写 / 事务（需本地 Docker；见 `examples/smoke-dual-listener.sh`）
- [ ] `psql` 经 Data Nexus 连 PostgreSQL 后端：SELECT / 简单写 / 事务
- [x] MySQL listener 与 PostgreSQL listener 配置可同时存在（`dual-listener-gateway-config.toml` + 单元测试）
- [ ] 错误 SQL / 断后端时客户端收到协议错误，进程不退出
- [x] `/metrics` 标签模型可区分 service、frontend protocol、backend protocol、endpoint（单元测试）

**退出标准**：上述验收 + 单元测试覆盖 core route / protocol registry / config validate。  
**环境备注**：当前开发机无 docker/mysql/psql，真实客户端 E2E 待有 Docker 环境时跑 `examples/smoke-dual-listener.sh`。

---

## M1：去掉 legacy 双轨（1–2 周）

目标：runtime 只认 `GatewayConfig` + core 类型。

### M1.1 删除启动期派生

- [x] core accept 路径从 `core_plan` 构建 listener（不再用派生 ProxyConfig 驱动 accept）
- [x] 删除 `legacy_proxy_config_from_core_plan` / `legacy_nodes_from_core_plan`；v2 构造不再填充 `ProxyConfig`/`nodes`
- [x] `GatewayRuntime` 增加 `listener_name` / `pool_size` / `core_plan`；pool snapshot 从 core endpoints 取地址
- [x] `GatewayFactory` 仅接受 v2 `GatewayConfigDocument`；移除 `Legacy` 分支与 `GatewayFactory::new`

### M1.2 配置类型收敛

- [x] Factory/启动路径不再读写 `ProxyConfig` / `UniSQLNode`
- [x] 删除 `start_legacy_mysql` 与 `GatewayRuntime::{proxy_config,nodes,node_group}` 公共字段
- [ ] `Listener.node_type` / `backend_type` 字段仍存在（仅日志/兼容，不决定路由）
- [x] 旧 example-config（v1）标记废弃；文档/示例只写 v2

### M1.3 错误模型

- [x] 无 core_plan 时 `start()` fail fast（明确错误，不再走 legacy）
- [ ] 减少 `runtime/gateway`、`core_engine`、frontend/backend adapter 中的 `unwrap()`
- [x] 配置错误：启动失败；协议/SQL 错误：session 级（core 路径）

### M1.4 验收

- [x] gateway 相关测试只依赖 v2 config
- [x] `gateway.rs` 主路径不再引用 `UniSQLNode` / `ProxyConfig`（`Listener.backend_type` 仍兼容填充）
- [x] `GatewayRuntime` 公共 API 不再暴露 `ProxyConfig`

---

## M2：治理协议无关 + 可运维（2 周）

目标：LB / 读写分离 / 插件 / Admin 对 MySQL 与 PG 同样可用。

### M2.1 路由

- [x] 定义 `RoutePlan`：`Single` / `Broadcast` / `Sharded` / `Reject`（`gateway_core::route`）
- [x] Core 路由 `plan_command` 返回 `RoutePlan`；`handle_frame` 经 `apply_route_plan` 写入 session
- [x] 读写分离、simple LB 基于 `GatewayCommand` + `SessionState` 决策（core 路径）
- [ ] legacy `RouteStrategy::dispatch` 仍返回 `Endpoint`（仅 legacy command service）
- [ ] sharding rewrite 与 MySQL parser 解耦入口（可先 stub Reject）

### M2.2 插件

- [x] 定义 `PluginContext` / `CommandSummary`（service、协议、user、database、command、route_plan）
- [x] 定义 `PluginDecision`：`Continue` / `Reject` / `Rewrite { sql }`
- [x] `PluginPhase::evaluate(PluginContext)`：熔断/并发基于上下文 match_text（SQL）
- [x] 插件挂在 Core `handle_frame`：route → plugin → execute → encode（MySQL/PG 共用）
- [x] 从 v2 `plugin_policies` 自动装载 PluginPhase（`circuit_break`/`audit`/`concurrency_control` + regex 规则）

### M2.3 Parser / Dialect

- [x] 抽出 `DialectParser` trait + `HeuristicDialectParser`（`gateway_core::dialect`）
- [x] MySQL / PostgreSQL 默认 dialect 挂载到 core 读写路由
- [x] core 读路由不再内联 SQL 启发式，改走 `DialectParser::is_read_only`
- [ ] 完整 AST parser 按 dialect 挂载（mysql_parser 等，后续）

### M2.4 可观测与 Admin

- [ ] metrics / trace / audit 统一挂 core 层（每命令：协议、service、endpoint、latency、错误码）
- [ ] Admin 与真实 runtime 状态打通（listener 启停、pool snapshot、session 列表）
- [ ] `POST /admin/reload`：先 diff，再安全应用（新增/停止 listener、替换 route policy、刷新 endpoint）
- [ ] 补齐 shutdown：`stop()` 优雅关闭现有连接

### M2.5 验收

- [ ] 同一套 concurrency / circuit-break 策略在 MySQL 与 PG service 上行为一致
- [ ] Admin 可查看 listener / service / endpoint / pool / session
- [ ] reload 后错误配置被拒绝且不影响旧配置

---

## M3：受控跨协议（按需，2+ 周）

前置：M0–M2 完成且同协议稳定。

- [ ] `translation_policy` 配置，**默认关闭**
- [ ] 明确 MySQL→PostgreSQL、PostgreSQL→MySQL 支持的 SQL 子集（先 SELECT/简单 DML）
- [ ] 不支持的 DDL / 存储过程 / COPY / LOAD DATA / 厂商函数 → 明确错误
- [ ] 结果类型映射表 + prepared statement 限制规则
- [ ] 方言转换测试集（golden tests）

**不做**：任意方言全量互转。

---

## 建议迭代顺序（按 PR）

| 顺序 | PR 主题 | 依赖 |
|------|---------|------|
| 1 | 补全 MySQL backend connector + core accept 路径 | — |
| 2 | PG accept 路径与 MySQL 对齐 + 双 listener 集成测试 | 1 |
| 3 | SessionState 贯通 + TransFsm 解耦 MySQL | 1–2 |
| 4 | 删除 legacy ProxyConfig/UniSQLNode 派生 | 3 |
| 5 | RoutePlan + 读写分离/LB 收口 core | 4 |
| 6 | PluginContext / PluginDecision + 并发/熔断迁移 | 4–5 |
| 7 | DialectParser + metrics/audit 挂 core | 5–6 |
| 8 | Admin 与 runtime 状态 / reload diff | 4+ |
| 9 |（可选）translation_policy 与跨协议子集 | 6–7 |

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
)
