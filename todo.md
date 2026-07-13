# Data Nexus TODO

详细规划见：`docs/data-nexus-protocol-gateway-plan.md`

## 第一步：架构重塑

- [ ] 将 Data Nexus 从当前的 MySQL 代理实现，改造成协议无关的 Gateway Core + 前端协议适配器 + 后端连接器。
- [x] 明确 Gateway Core、FrontendProtocolAdapter、BackendConnector 三层边界。
- [x] 先定义协议无关接口和核心数据结构，再迁移现有 MySQL 实现。

## 产品目标

- [ ] 将 Data Nexus 定位为数据库协议中转站，而不只是 MySQL proxy。
- [ ] 支持不同客户端通过 Data Nexus 访问后端数据库，例如 MySQL client、JDBC MySQL、psql、PostgreSQL JDBC。
- [ ] 第一阶段优先支持同协议中转：MySQL -> MySQL、PostgreSQL -> PostgreSQL。
- [ ] 第二阶段再支持受控跨协议访问，例如 MySQL 客户端查询 PostgreSQL 后端的明确 SQL 子集。
- [ ] 明确前端协议、后端协议、SQL 方言、路由策略、治理插件必须解耦。

## Phase 0：稳定现状和配置边界

- [x] 不实现 v1 配置兼容层（项目尚未发布，直接采用 v2 配置）。
- [x] 新增 `core` crate，沉淀协议无关的核心类型。
- [x] 定义 `ProtocolKind`，替代 `node_type`、`backend_type` 等字符串驱动逻辑。
- [x] 定义 `GatewayCommand`，统一表示 query、prepare、execute、use database、transaction、ping、quit 等命令。
- [x] 定义 `GatewayResponse`，统一表示 OK、ERR、结果集、prepare response、流式响应等返回。
- [x] 定义 `SessionState`，统一表达 user、database、charset、autocommit、transaction state 等会话状态。
- [x] 定义 `GatewayConfig`，作为内部统一配置模型。
- [x] 新增 v2 config schema：`listeners`、`services`、`endpoints`、`route_policies`、`auth_policies`、`plugin_policies`。
- [x] 不实现 v1 config 到 `GatewayConfig` 的兼容转换。
- [x] 实现配置校验器，启动前检查协议、service、endpoint、route policy 引用是否有效。
- [x] 新增并校验 v2 Gateway 配置示例。

## Phase 1：抽出 MySQL 前端和后端

- [x] 将 `runtime/gateway` 中的 MySQL 协议处理抽成 `MySqlFrontendProtocol`。
- [x] 将 MySQL 后端连接和执行逻辑收口为 `MySqlBackendConnector`。
- [x] 让 `MySqlFrontendProtocol` 对接 `gateway_core::FrontendProtocolAdapter`。
- [x] 让 `MySqlBackendConnector` 对接 `gateway_core::BackendConnector`。
- [x] 新增 `GatewayRuntime` 运行时入口（当前内部仍复用迁移中的 MySQL 主链路）。
- [ ] 让 `GatewayRuntime` 只依赖 `GatewayCommand`、`GatewayResponse`、`SessionState` 等 core 类型。
- [x] 让 `PisaProxyFactory` 演进为 `GatewayFactory`。
- [x] 根据 `listener.protocol` 构建对应 frontend adapter。
- [x] 根据 `service.backend_protocol` 构建对应 backend connector。
- [ ] 保持现有 MySQL 代理功能行为不变。
- [x] 不保留旧 MySQL example config 的启动兼容，后续只支持 v2 Gateway 配置。

## Phase 2：PostgreSQL 同协议中转

- [ ] 补全 PostgreSQL frontend handshake。
- [ ] 实现 PostgreSQL frontend command decode。
- [ ] 实现 PostgreSQL response encode。
- [ ] 实现 PostgreSQL backend connector。
- [ ] 支持 PostgreSQL 后端连接池。
- [ ] 支持 PostgreSQL simple query 基础链路。
- [ ] 支持 PostgreSQL session 状态同步。
- [ ] 增加 PostgreSQL v2 example config。
- [ ] 支持 MySQL listener 和 PostgreSQL listener 同时存在。
- [ ] 在 metrics 中区分 service、frontend protocol、backend protocol、endpoint。

## Phase 3：治理能力协议无关化

- [ ] 将 simple load balance 改为协议无关。
- [ ] 将读写分离 route policy 改为协议无关。
- [ ] 将并发控制插件改为基于 `PluginContext`。
- [ ] 将熔断插件改为基于 `PluginContext`。
- [ ] 定义 `PluginDecision`，支持 continue、reject、rewrite。
- [ ] 定义 `RoutePlan`，支持 single、broadcast、sharded、reject。
- [ ] 将 `RouteStrategy::dispatch` 返回值升级为 `RoutePlan`。
- [ ] 抽出 `DialectParser` trait，让 MySQL/PostgreSQL parser 按 dialect 挂载。
- [ ] 将 sharding rewrite 和 SQL parser 解耦，避免强绑定 MySQL。
- [ ] 将 metrics、trace、audit 统一挂在 Gateway Core 层。

## Phase 4：受控跨协议访问

- [ ] 定义 `translation_policy` 配置，默认关闭跨协议翻译。
- [ ] 明确 MySQL -> PostgreSQL 支持的 SQL 子集。
- [ ] 明确 PostgreSQL -> MySQL 支持的 SQL 子集。
- [ ] 为不支持的 DDL、存储过程、COPY、LOAD DATA、vendor-specific function 返回明确错误。
- [ ] 建立 SQL 方言转换测试集。
- [ ] 建立跨协议结果类型映射规则。
- [ ] 建立跨协议 prepared statement 限制规则。

## 当前代码改造点

- [x] 将 `runtime/unisql` 改名或逐步替换为 `runtime/gateway`。
- [x] 将 `SQLProxy` 入口迁移为 `GatewayRuntime`。
- [x] 将 `PisaProxyFactory` 演进为 `GatewayFactory`，启动路径改为 `runtime_gateway::gateway::GatewayRuntime`。
- [x] 将 `GatewayFactory` 改为按 listener/service 构建 runtime。
- [ ] 拆分 `ProxyConfig`，避免一个结构同时承载监听、认证、后端、路由、插件和云端配置。
- [x] 新增 `ListenerConfig`。
- [x] 新增 `ServiceConfig`。
- [x] 新增 `EndpointConfig`。
- [x] 新增 `RoutePolicyConfig`。
- [x] 新增 `AuthPolicyConfig`。
- [x] 新增 `PluginPolicyConfig`。
- [ ] 将 `UniSQLNode` 替换为更通用的 `EndpointConfig`。
- [ ] 将 `node_type`、`backend_type` 字符串替换为 `ProtocolKind` enum。
- [ ] 将事务 FSM 与 `mysql_protocol::client::conn::SessionAttr` 解耦。
- [ ] 让 FSM 只负责事务状态和连接绑定决策。
- [ ] 将协议 session 到通用 `SessionState` 的转换放在 frontend adapter。
- [ ] 将插件接口从 `String` 输入升级为 `PluginContext`。
- [ ] 减少主链路中的 `unwrap()`，把请求级错误转换成客户端协议错误包。
- [x] 配置错误在启动阶段 fail fast，并输出明确错误信息。

## Admin API

- [ ] 新增 `POST /admin/reload`。
- [ ] 热更新前实现 config diff。
- [ ] 支持新增 listener。
- [ ] 支持替换 route policy。
- [ ] 支持刷新 endpoint pool。

## 验收标准

- [x] 不保留 v1 MySQL example config 的运行兼容（项目尚未发布）。
- [ ] v2 MySQL config 可以运行同样链路。
- [x] runtime 主路径不再依赖 `backend_type` 字符串。
- [ ] 配置错误能在启动时给出明确错误。
- [ ] MySQL 客户端可以通过 Data Nexus 连接 MySQL 后端。
- [ ] PostgreSQL 客户端可以通过 Data Nexus 连接 PostgreSQL 后端。
- [ ] MySQL listener 和 PostgreSQL listener 可以同时存在。
- [ ] `/metrics` 能区分 service、frontend protocol、backend protocol、endpoint。
- [ ] simple load balance、并发控制、熔断对 MySQL/PostgreSQL 都可用。
- [ ] Admin API 能查看 listener、service、endpoint、pool 状态。

## 暂不做

- [ ] 暂不做任意 MySQL/PostgreSQL 全量互转。
- [ ] 暂不继续在 `ProxyConfig` 上堆新字段。
- [ ] 暂不让 `node_type` 字符串决定运行时行为。
- [ ] 暂不优先做管理 UI，先完成 runtime state 和 admin API。
