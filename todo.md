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
  - [x] 将 v2 Gateway listener plan 到 legacy MySQL runtime 的适配收口到显式桥接层，避免转换逻辑散落在启动入口。
- [x] 让 `PisaProxyFactory` 演进为 `GatewayFactory`。
- [x] 根据 `listener.protocol` 构建对应 frontend adapter。
- [x] 根据 `service.backend_protocol` 构建对应 backend connector。
- [ ] 保持现有 MySQL 代理功能行为不变。
- [x] 不保留旧 MySQL example config 的启动兼容，后续只支持 v2 Gateway 配置。
- [x] 补齐 runtime shutdown handle，避免 `stop()` 空实现。

## Phase 2：PostgreSQL 同协议中转

- [x] 补全 PostgreSQL frontend handshake。
  - [x] `PostgreSqlFrontendProtocol` 新增 StartupMessage / SSLRequest / CancelRequest 解析，StartupMessage 会同步 `SessionState.user` 与 `SessionState.database`。
  - [x] 新增 trust-auth 启动响应编码：`AuthenticationOk`、`ParameterStatus`、`BackendKeyData`、`ReadyForQuery`；SSLRequest 当前明确返回 `N`。
  - [x] `cargo test -p runtime_gateway frontend::postgresql` 与 `cargo test -p runtime_gateway` 通过。
  - [x] 将 PostgreSQL listener socket 主循环接入 startup handshake 原语，启动后按 PostgreSQL frame 调用 `CoreGatewayConnection::handle_frame` 并写回响应。
  - [x] `cargo test -p runtime_gateway gateway::tests -- --nocapture` 覆盖 PostgreSQL socket startup + simple query 路径。
- [x] 实现 PostgreSQL frontend command decode。
  - [x] 新增 `PostgreSqlFrontendProtocol`，支持 PostgreSQL frontend `Q` simple query 与 `X` terminate 消息解码为 `GatewayCommand`。
  - [x] 新增 `PostgreSqlDialectParser`，将 PostgreSQL transaction SQL 归一为 `Begin` / `Commit` / `Rollback` 并维护 `SessionState.transaction_state`。
  - [x] `CoreGatewayRuntimePlan` 可按 PostgreSQL listener 构建 PostgreSQL frontend adapter；`cargo test -p runtime_gateway` 通过。
- [x] 实现 PostgreSQL response encode。
  - [x] `PostgreSqlFrontendProtocol::encode` 支持 `Ok`、`Error`、`Pong`、`Bye`，输出 PostgreSQL `CommandComplete` / `ErrorResponse` / `ReadyForQuery` 基础后端消息。
  - [x] `ResultSet` 编码为 PostgreSQL simple query 文本结果：`RowDescription`、`DataRow`、`CommandComplete(SELECT n)`、`ReadyForQuery`，覆盖 NULL、bool、数值、text、bytea hex 文本格式。
  - [x] `ReadyForQuery` 根据 `SessionState.transaction_state` 输出 `I` / `T` / `E` 事务状态字节；`Prepared` 仍保留显式 unsupported，等待 prepared statement 链路补齐。
  - [x] `cargo test -p runtime_gateway` 通过。
- [x] 实现 PostgreSQL backend connector。
  - [x] 新增 `PostgreSqlBackendConnector`，并让 `CoreGatewayRuntimePlan` 可以按 PostgreSQL service 构建它。
  - [x] `PostgreSqlBackendConnector` 覆盖 `Ping`、`Quit`、`UseDatabase`、`Begin`、`Commit`、`Rollback` 这类 core 状态命令。
  - [x] `postgresql_protocol` 新增 simple query 后端协议 primitive：Startup/Query/PasswordMessage 编码，以及 Authentication、ParameterStatus、BackendKeyData、RowDescription、DataRow、CommandComplete、ErrorResponse、ReadyForQuery 解码。
  - [x] `PostgreSqlBackendConnector` 支持基于 endpoint 的 PostgreSQL startup、AuthenticationOk/CleartextPassword、simple query 短连接执行，返回 `GatewayResponse::ResultSet` / `Ok` / `Error`；MD5/SCRAM auth 与连接池留后续补齐。
  - [x] `cargo test -p postgresql_protocol` 通过。
  - [x] `cargo test -p runtime_gateway` 通过，覆盖 PostgreSQL backend connector、mock backend simple query 与 core frame 串联。
- [x] 支持 PostgreSQL 后端连接池。
  - [x] `PostgreSqlBackendConnector` 内置按 endpoint 复用的已 startup TCP 连接池，simple query 与事务命令执行成功后归还连接。
  - [x] `BEGIN` / `COMMIT` / `ROLLBACK` 在配置 PostgreSQL endpoint 时走真实后端连接，未配置 endpoint 的单元测试路径保留 session-only 行为。
  - [x] PostgreSQL backend `ErrorResponse` 改为读到后续 `ReadyForQuery` 后再返回，避免错误响应污染可复用连接。
  - [x] PostgreSQL core backend 的 transaction dispatch 与连接池 lease 不再使用请求级 `unreachable!()` / `expect()`。
  - [x] `cargo test -p runtime_gateway postgresql` 通过，mock backend 覆盖同一后端连接连续执行 `BEGIN`、`select 1`、`COMMIT`。
- [x] 支持 PostgreSQL simple query 基础链路。
  - [x] frontend socket startup + query frame、core command dispatch、backend simple query 短连接、ResultSet response encode 已贯通；mock backend 测试覆盖 `select 1` 返回一行结果。
- [x] 支持 PostgreSQL session 状态同步。
  - [x] startup 阶段同步 `user`、`database`、`client_encoding`、`ReadyForQuery` 事务状态。
  - [x] simple query 响应阶段同步 `ParameterStatus` 与 `ReadyForQuery` 事务状态。
  - [x] `cargo test -p runtime_gateway postgresql` 通过，mock backend 覆盖 query 后 charset 与 transaction state 同步。
  - [x] PostgreSQL `BEGIN` / `COMMIT` / `ROLLBACK` 在有 endpoint 时通过同一后端连接复用执行；无 endpoint 时仍保持 core session-only 测试行为。
- [x] 增加 PostgreSQL v2 example config。
  - [x] `examples/gateway-config.toml` 新增 PostgreSQL listener/service/endpoint/auth/route/plugin 示例拓扑。
  - [x] `cargo test -p config parses_and_validates_native_gateway_config`、`rejects_invalid_native_gateway_config`、`pisa_proxy_config_accepts_native_gateway_config` 通过；`cargo test -p config -- --nocapture --test-threads=1` 仍被既有 `test_build_from_file` 的 `absolute_path` 缺文件问题挡住。
- [x] 支持 MySQL listener 和 PostgreSQL listener 同时存在。
  - [x] `cmd/pisa` 在 native gateway config 下遍历 `gateway.listeners`，按 listener 分别启动 `GatewayRuntime`。
  - [x] `GatewayRuntime::from_gateway_config` 可从同一份 v2 config 分别构建 MySQL listener runtime 与 PostgreSQL listener runtime。
  - [x] `cargo test -p runtime_gateway builds_mysql_and_postgresql_runtimes_from_same_v2_gateway_config` 通过。
- [ ] 在 metrics 中区分 service、frontend protocol、backend protocol、endpoint。

## Phase 3：治理能力协议无关化

- [x] 将 simple load balance 改为协议无关。
  - [x] `loadbalance` 抽出 `BalanceTarget`，`RandomWeighted` / `RoundRobinWeighted` / `BalanceType` 支持非 legacy endpoint 的加权目标。
  - [x] 新增 `EndpointConfig` 负载均衡测试，覆盖 PostgreSQL endpoint 配置目标。
  - [x] `cargo test -p loadbalance`、`cargo test -p strategy`、`cargo test -p runtime_gateway` 通过。
- [x] 将读写分离 route policy 改为协议无关。
  - [x] `ReadWriteEndpoint`、`RouteBalance`、`RulesMatch`、regex/generic rule matcher 支持泛型 balance target，默认保留 legacy endpoint 兼容。
  - [x] 新增 `EndpointConfig` 读写分离规则测试，覆盖 PostgreSQL endpoint 配置目标的 SELECT/INSERT 路由选择。
  - [x] `cargo test -p strategy` 与 `cargo test -p runtime_gateway` 通过。
- [x] 将并发控制插件改为基于 `PluginContext`。
- [x] 将熔断插件改为基于 `PluginContext`。
- [x] 定义 `PluginDecision`，支持 continue、reject、rewrite。
  - [x] `PluginPhase` 提供统一 decision 入口，MySQL 主链路通过该入口处理 continue/reject。
- [x] 定义 `RoutePlan`，支持 single、broadcast、sharded、reject。
  - [x] `CoreGatewayRuntimePlan` 根据 v2 service endpoints 生成协议无关 route plan。
- [x] 将 `RouteStrategy::dispatch` 返回值升级为 `RoutePlan`。
  - [x] legacy MySQL 主链路通过显式转换从 `RoutePlan::Single` 取回现有 endpoint，保留当前执行行为。
- [x] 抽出 `DialectParser` trait，让 MySQL/PostgreSQL parser 按 dialect 挂载。
  - [x] `gateway_core` 新增 `DialectParser`，用协议无关入口将 SQL 文本分类为 `GatewayCommand` 并维护 `SessionState`，不暴露具体 AST crate。
  - [x] MySQL frontend 挂载 `MySqlDialectParser`，`COM_QUERY` 通过 dialect parser 识别事务快捷命令与普通 query。
  - [x] `cargo test -p gateway_core` 与 `cargo test -p runtime_gateway` 通过。
- [x] 将 sharding rewrite 和 SQL parser 解耦，避免强绑定 MySQL。
  - [x] `strategy::rewrite` 新增 `DialectAst`，`ShardingRewriteInput` 不再直接暴露 `mysql_parser::ast::SqlStmt`，MySQL AST 通过 `DialectAst::MySql` 挂载。
  - [x] MySQL `ShardingRewrite` 对非 MySQL AST 返回显式 `UnsupportedDialectAst`，为后续 PostgreSQL rewrite 分支保留接口空间。
  - [x] `cargo test -p strategy` 与 `cargo test -p runtime_gateway` 通过。
- [ ] 将 metrics、trace、audit 统一挂在 Gateway Core 层。
  - [x] MySQL runtime SQL metrics 增加协议无关上下文标签：service、frontend_protocol、backend_protocol，v2 Gateway bridge 使用 listener/service plan 填充，legacy 路径保留兼容兜底。
  - [x] `cargo test -p runtime_gateway` 通过，覆盖 protocol-aware metrics label 与 v2 metrics context 构建。

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
- [x] 将 `node_type`、`backend_type` 字符串替换为 `ProtocolKind` enum。
  - [x] 移除 legacy `backend_type` 字段。
  - [x] 将 listener 运行时协议收敛为 `ProtocolKind`。
  - [x] 将 runtime `Endpoint.node_type` 类型收敛为 `ProtocolKind`。
  - [x] 将 legacy `UniSQLNode.node_type` 类型收敛为 `ProtocolKind`。
  - [x] 将 legacy `ProxyConfig.node_type` / `ProxyCloudConfig.node_type` 收敛到配置解析边界。
- [x] 将事务 FSM 与 `mysql_protocol::client::conn::SessionAttr` 解耦。
- [x] 让 FSM 只负责事务状态和连接绑定决策。
  - [x] 从 `TransFsm` 移除连接池取连接逻辑和 session 属性缓存，后端连接 ready/rebuild 逻辑迁移到 `runtime/gateway::backend_conn`。
  - [x] `cargo check -p runtime_gateway` 与 `cargo test -p runtime_gateway` 通过。
- [x] 将协议 session 到通用 `SessionState` 的转换放在 frontend adapter。
- [x] 将插件接口从 `String` 输入升级为 `PluginContext`。
- [ ] 减少主链路中的 `unwrap()`，把请求级错误转换成客户端协议错误包。
  - [x] 将 `GatewayRuntime` 启动监听、路由构建、legacy endpoint 协议解析中的关键 `unwrap()` 改为显式错误返回。
  - [x] 将 MySQL `COM_QUERY`、`COM_INIT_DB`、`COM_STMT_PREPARE` 文本 payload 的 UTF-8 `unwrap()` 改为协议错误返回。
  - [x] 将 MySQL metrics 采集前的 endpoint `unwrap()` 改为缺失 endpoint 时返回协议错误。
  - [x] 将 MySQL sharding rewriter 与 concurrency-control plugin 状态 `unwrap()` 改为显式错误返回。
  - [x] 将 MySQL FSM route dispatch、事务连接、session charset `unwrap()` 改为显式错误返回。
  - [x] 将 MySQL executor backend stream packet `unwrap()` 改为显式错误返回。
  - [x] 将 MySQL executor AVG 聚合改写时的 count/sum row part `unwrap()` 改为显式错误返回。
  - [x] 将 MySQL executor COUNT/SUM 聚合解码与 row part `unwrap()` 改为显式错误返回。
  - [x] 将 MySQL executor sharding sort 与 MIN/MAX 聚合解码、row part `unwrap()` 改为显式错误返回。
  - [x] 将 MySQL parser 顶层结果、client framed/session state、result/common stream 构造中的关键 `unwrap()` 改为显式错误或非 panic 路径。
  - [x] 将 MySQL client auth 握手包解析、auth switch、公钥认证中的关键 `unwrap()` 改为协议错误返回。
  - [x] 将 MySQL client/server stream TLS 升级与 Plain stream poll 中的关键 `unwrap()` 改为协议错误或 IO 错误返回。
  - [x] 将 MySQL server auth 握手响应中的用户名、认证数据、schema、插件名解析 `unwrap()` 改为协议错误返回。
  - [x] 将 MySQL binary row DATETIME/TIME 解码中的非法日期时间 panic 改为行解码错误返回。
  - [x] 将 MySQL length-encoded integer/string、packet header、column definition（含列集合包头与列增删遍历）、resultset column count、OK packet session state、row value 切片中的关键越界 panic 改为协议/行解码错误返回。
  - [x] 将 MySQL use database 响应断流/短包、sharding 列元数据缺失、rewrite 缺失数据源中的运行时 `unreachable!()` 改为显式错误返回。
  - [x] 移除 MySQL client codec 通过 `Deref`/`DerefMut` 访问 `auth_info` 的 panic 入口，缺失认证上下文时返回 `ProtocolError::ClientState`。
  - [ ] 继续清理 MySQL packet/session/parser 路径中的 `unwrap()`。
- [ ] 配置错误在启动阶段 fail fast，并输出明确错误信息。
  - [x] v2 Gateway 配置校验补齐 `frontend_protocols`，启动前检查 listener/service 前端协议匹配、空 topology、endpoint weight、route/plugin policy kind 等明确配置错误。

## Admin API

- [x] 恢复或重做配置查询 API。
- [x] 新增 `GET /admin/listeners`。
- [x] 新增 `GET /admin/services`。
- [x] 新增 `GET /admin/endpoints`。
- [x] 新增 `GET /admin/pools`。
  - [x] 当前先返回按 service-endpoint 展开的配置归属与 pool 观测字段，live idle/active 连接数等待 runtime state registry 接入。
- [x] 新增 `GET /admin/sessions`。
  - [x] 当前先返回空 session 集合，live session registry 接入后填充同一视图结构。
- [x] 新增 `POST /admin/reload`。
  - [x] 当前先做 v2 Gateway 配置校验并返回 diff 预览，`applied=false`；真正应用热更新等待 runtime state registry 接入。
- [x] 热更新前实现 config diff。
  - [x] `GatewayConfig::diff` 覆盖 listener/service/endpoint/route/auth/plugin policy 增删改，并输出 listener restart、endpoint pool refresh、route policy replacement 计划。
- [ ] 支持新增 listener。
  - [x] runtime 层新增 `GatewayRuntimeSupervisor`，可根据新旧 `GatewayConfig` 规划并启动新增 listener。
- [ ] 支持关闭 listener。
  - [x] `GatewayRuntime` 支持外部 shutdown signal，supervisor 可关闭已移除或需重建的 listener。
- [ ] 支持替换 route policy。
  - [x] supervisor reload plan 已能把 route policy 变化映射为相关 listener 重建；后续再接入更细粒度 live policy replacement。
- [ ] 支持刷新 endpoint pool。
  - [x] supervisor reload plan 已能把 service/endpoint 变化映射为相关 listener 重建；后续再接入 backend pool live refresh。

## 验收标准

- [x] 不保留 v1 MySQL example config 的运行兼容（项目尚未发布）。
- [ ] v2 MySQL config 可以运行同样链路。
- [x] runtime 主路径不再依赖 `backend_type` 字符串。
- [ ] 配置错误能在启动时给出明确错误。
- [ ] MySQL 客户端可以通过 Data Nexus 连接 MySQL 后端。
- [ ] PostgreSQL 客户端可以通过 Data Nexus 连接 PostgreSQL 后端。
- [ ] MySQL listener 和 PostgreSQL listener 可以同时存在。
- [ ] `/metrics` 能区分 service、frontend protocol、backend protocol、endpoint。
  - [x] SQL metrics label 已增加 service、frontend_protocol、backend_protocol、server(endpoint address)。
- [ ] simple load balance、并发控制、熔断对 MySQL/PostgreSQL 都可用。
- [ ] Admin API 能查看 listener、service、endpoint、pool 状态。

## 暂不做

- [ ] 暂不做任意 MySQL/PostgreSQL 全量互转。
- [ ] 暂不继续在 `ProxyConfig` 上堆新字段。
- [ ] 暂不让 `node_type` 字符串决定运行时行为。
- [ ] 暂不优先做管理 UI，先完成 runtime state 和 admin API。
