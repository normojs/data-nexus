# Data Nexus 协议中转站规划

## 目标定位

Data Nexus 的目标不只是 MySQL proxy，而是数据库协议中转站：

- 用户侧可以使用不同数据库客户端连接 Data Nexus，例如 MySQL client、JDBC MySQL、psql、PostgreSQL JDBC。
- Data Nexus 负责协议握手、认证、会话、路由、连接池、治理、观测和审计。
- 后端可以连接不同数据库实例，例如 MySQL、PostgreSQL，后续再扩展更多数据源。
- 第一阶段优先保证同协议中转：MySQL 客户端到 MySQL 后端、PostgreSQL 客户端到 PostgreSQL 后端。
- 第二阶段再做受控的跨协议/跨方言能力，例如 MySQL 客户端查询 PostgreSQL 后端，但只覆盖明确声明支持的 SQL 子集。

核心原则：前端协议、后端协议、SQL 方言、路由策略、治理插件必须解耦。

## 推荐架构

```text
client
  |
  v
Listener
  |
  v
FrontendProtocolAdapter
  - MySQL frontend
  - PostgreSQL frontend
  |
  v
Gateway Core
  - auth
  - session
  - command model
  - transaction state
  - route
  - policy/plugin
  - metrics/audit
  |
  v
BackendConnector
  - MySQL backend
  - PostgreSQL backend
  |
  v
database
```

### Listener 层

职责：

- 监听 TCP/TLS 地址。
- 根据配置绑定前端协议，不依赖后端数据库类型。
- 管理优雅关闭、连接限流、连接生命周期。

不应该做：

- 不解析 SQL。
- 不直接选择后端节点。
- 不持有业务路由配置细节。

### FrontendProtocolAdapter 层

职责：

- 处理客户端协议握手、认证和 capability 协商。
- 将协议命令解码成统一的 `GatewayCommand`。
- 将统一响应编码回客户端协议。
- 维护协议级 session，例如 charset、current database、prepared statement id 映射。

示例接口：

```rust
#[async_trait::async_trait]
pub trait FrontendProtocol {
    type Stream;

    async fn handshake(&self, stream: Self::Stream) -> Result<FrontendSession, GatewayError>;
    async fn next_command(&self, session: &mut FrontendSession) -> Result<GatewayCommand, GatewayError>;
    async fn send_response(
        &self,
        session: &mut FrontendSession,
        response: GatewayResponse,
    ) -> Result<(), GatewayError>;
}
```

### Gateway Core 层

职责：

- 用统一命令模型承接不同前端协议。
- 管理认证、权限、事务状态、连接租借、路由和治理插件。
- 将命令交给后端连接器执行。
- 收集 metrics、trace、audit。

推荐统一命令模型：

```rust
pub enum GatewayCommand {
    Query {
        sql: String,
        params: Vec<GatewayValue>,
    },
    Prepare {
        sql: String,
    },
    Execute {
        statement_id: StatementId,
        params: Vec<GatewayValue>,
    },
    CloseStatement {
        statement_id: StatementId,
    },
    UseDatabase {
        database: String,
    },
    Begin,
    Commit,
    Rollback,
    Ping,
    Quit,
    Raw {
        protocol: ProtocolKind,
        payload: bytes::Bytes,
    },
}
```

`Raw` 只用于暂时不能抽象的协议命令，不能成为主路径。

### BackendConnector 层

职责：

- 根据后端协议建立连接、认证、执行命令。
- 返回统一 `GatewayResponse` 或流式结果。
- 暴露能力，例如是否支持 prepare、transaction、schema switch、COPY、multi resultset。

示例接口：

```rust
#[async_trait::async_trait]
pub trait BackendConnector: Send + Sync {
    async fn connect(&self, endpoint: &Endpoint, session: &SessionState)
        -> Result<Box<dyn BackendConnection>, GatewayError>;
}

#[async_trait::async_trait]
pub trait BackendConnection: Send {
    async fn execute(&mut self, command: BackendCommand)
        -> Result<GatewayResponse, GatewayError>;

    async fn is_ready(&mut self) -> bool;
    async fn reset_session(&mut self, session: &SessionState) -> Result<(), GatewayError>;
}
```

## 配置模型改造

当前配置把 listener、proxy 用户、后端节点、路由、云端配置揉在 `proxy.config` 和 `nodes.node` 里。建议引入 v2 schema。

示例：

```toml
version = "0.2"

[admin]
host = "0.0.0.0"
port = 8082
log_level = "info"

[[listeners]]
name = "mysql-public"
bind = "0.0.0.0:3306"
protocol = "mysql"
service = "orders-mysql"

[[listeners]]
name = "postgres-public"
bind = "0.0.0.0:5432"
protocol = "postgresql"
service = "analytics-postgres"

[[services]]
name = "orders-mysql"
frontend_protocols = ["mysql"]
backend_protocol = "mysql"
auth_policy = "local-users"
route_policy = "orders-route"
plugin_policy = "default-sql-governance"

[[services]]
name = "analytics-postgres"
frontend_protocols = ["postgresql"]
backend_protocol = "postgresql"
auth_policy = "local-users"
route_policy = "analytics-route"

[[endpoints]]
name = "orders-primary"
protocol = "mysql"
host = "192.168.1.242"
port = 3306
database = "test"
username = "root"
password = "my-secret-pw"
role = "readwrite"
weight = 1

[[endpoints]]
name = "analytics-primary"
protocol = "postgresql"
host = "192.168.1.250"
port = 5432
database = "analytics"
username = "postgres"
password = "secret"
role = "readwrite"
weight = 1

[[route_policies]]
name = "orders-route"
type = "simple_loadbalance"
algorithm = "random"
endpoints = ["orders-primary"]

[[auth_policies]]
name = "local-users"
type = "static"

[[auth_policies.users]]
username = "app"
password = "app-secret"
databases = ["test", "analytics"]
```

配置迁移策略：

- 项目尚未发布，不保留当前 `proxy.config` 和 `nodes.node` schema 的兼容承诺。
- v2 `GatewayConfig` 是唯一目标配置模型，采用 `listeners`、`services`、`endpoints` 和 policy 集合直接表达拓扑。
- 旧配置类型随 MySQL runtime 迁移一并删除，不实现 v1 到 v2 的转换层。

## 当前代码不合适点

### 1. `GatewayRuntime` 仍承载迁移中的 MySQL 主链路

位置：`data-proxy/runtime/gateway/src/gateway.rs`

问题：

- `GatewayRuntime` 已替代 `SQLProxy`，MySQL 握手和命令循环已抽到 `frontend/mysql.rs`，MySQL 执行入口已收口为 `MySqlBackendConnector`。
- MySQL frontend/backend 已对接 `gateway_core::FrontendProtocolAdapter` 和 `gateway_core::BackendConnector`，并新增 v2 config 到 core connection 的 runtime bridge。
- `proxy_config.node_type` 只是字段，没有决定协议实现。
- PostgreSQL crate 存在，但没有进入运行时主链路；v2 bridge 会先明确返回 unsupported。

建议：

- 继续把 legacy MySQL accept loop 迁到 v2 runtime bridge。
- 继续让 `GatewayRuntime` 只依赖 core 层命令、响应和 session 模型。

### 2. `GatewayFactory` 还没有按 v2 拓扑构建 runtime

位置：`data-proxy/app/server/src/server.rs`

问题：

- `ProxyKind` 和 `backend_type` 基本失效。
- 当前启动路径已从 `PisaProxyFactory` 迁到 `GatewayFactory`，但仍从旧 `ProxyConfig` 构造单个 `GatewayRuntime`。

建议：

- 让 `GatewayFactory` 读取 v2 `listeners`、`services`、`endpoints`，按 listener/service 构建 runtime。
- 输入 `ListenerConfig + ServiceConfig + GatewayConfig`。
- 根据 `listener.protocol` 构建不同 frontend。

### 3. `ProxyConfig` 职责过重

位置：`data-proxy/proxy/src/proxy.rs`

问题：

- 同时包含监听地址、用户密码、默认 DB、后端类型、连接池、负载均衡、分片、读写分离、插件、cloud。
- 很多字段是 `String` 和默认空字符串，配置错误会被隐藏。
- `backend_type` 已废弃但仍在主要结构中。

建议拆成：

- `ListenerConfig`
- `ServiceConfig`
- `EndpointConfig`
- `RoutePolicyConfig`
- `AuthPolicyConfig`
- `PluginPolicyConfig`

协议类型使用 enum：

```rust
pub enum ProtocolKind {
    MySQL,
    PostgreSQL,
}
```

### 4. `UniSQLNode` 不能表达多后端能力

位置：`data-proxy/proxy/src/proxy.rs`

问题：

- `node_type` 是字符串。
- 字段默认按 MySQL 思维组织，例如 `db/user/password/version`。
- 缺少 TLS、connection timeout、server capability、dialect、pool policy 等后端元信息。

建议：

- 替换为 `EndpointConfig`。
- endpoint 只描述连接目标和能力，不承载路由逻辑。

### 5. 路由接口返回 `Endpoint`，无法表达协议和执行计划

位置：`data-proxy/proxy/strategy/src/route.rs`

问题：

- 当前 route 只返回单个 `Endpoint` 和 role。
- sharding 场景在 rewrite output 中再补 endpoint，耦合较重。
- 未来跨协议、分片、多后端聚合、只读副本降级都需要更丰富的 plan。

建议：

```rust
pub enum RoutePlan {
    Single { endpoint: EndpointRef },
    Broadcast { endpoints: Vec<EndpointRef> },
    Sharded { shards: Vec<ShardTarget> },
    Reject { reason: String },
}
```

### 6. 事务 FSM 绑定 MySQL session attrs

位置：`data-proxy/runtime/gateway/src/transaction_fsm.rs`

问题：

- `TransFsm` 直接依赖 `mysql_protocol::client::conn::SessionAttr`。
- 事务状态、session 状态和连接池状态混在一起。

建议：

- 抽出通用 `SessionState`。
- FSM 只负责事务和连接绑定决策。
- 协议 adapter 负责把 MySQL/PostgreSQL session 转成通用状态。

### 7. 插件接口过窄

位置：`data-proxy/plugin/src/build_phase.rs`

问题：

- 插件主接口接收 `String`。
- 缺少 request context、user、database、route plan、耗时、错误、response metadata。

建议：

```rust
pub struct PluginContext {
    pub service: String,
    pub client_protocol: ProtocolKind,
    pub user: String,
    pub database: Option<String>,
    pub command: GatewayCommandSummary,
    pub route_plan: Option<RoutePlan>,
}

pub enum PluginDecision {
    Continue,
    Reject { code: String, message: String },
    Rewrite { sql: String },
}
```

### 8. Admin HTTP 只读能力太少

位置：`data-proxy/http/src/http.rs`

问题：

- `/config` 被注释。
- 没有 listener、service、endpoint、pool、session、route policy 的状态查询。
- 动态配置更新没有生命周期配套。

建议优先增加：

- `GET /admin/listeners`
- `GET /admin/services`
- `GET /admin/endpoints`
- `GET /admin/pools`
- `GET /admin/sessions`
- `POST /admin/reload`

热更新必须先支持 diff，再决定新增 listener、关闭 listener、替换 route policy、刷新 endpoint pool。

### 9. 错误处理和 unwrap 太多

问题：

- 配置、协议包、连接池、路由中存在大量 `unwrap()`。
- 代理进程作为中转站，不能因为单个客户端请求或配置项直接 panic。

建议：

- 引入统一 `GatewayError`。
- 协议层错误转换成客户端协议错误包。
- 配置错误在启动前 fail fast。
- 请求级错误只影响当前 session。

## 模块演进建议

目标 workspace 结构：

```text
data-proxy/
  app/
    admin/              # HTTP admin API
    config/             # config v2 parse and validate
    server/             # process lifecycle
  core/
    src/
      command.rs        # GatewayCommand, GatewayResponse
      config.rs         # normalized GatewayConfig
      error.rs
      session.rs
      route.rs
      plugin.rs
  protocol/
    mysql/              # MySQL frontend/backend protocol primitives
    postgresql/         # PostgreSQL frontend/backend protocol primitives
  backend/
    mysql/
    postgresql/
  runtime/
    gateway/            # protocol-independent runtime
  proxy/
    endpoint/
    loadbalance/
    strategy/
```

为了降低一次性改造风险，可以先不移动文件，只新增 `core` crate，并让旧代码逐步依赖 core 类型。

## 分阶段路线

### Phase 0：稳定现状和配置边界

目标：

- 直接采用 v2 Gateway 配置，不实现 v1 兼容层。
- 新增 v2 config 类型与启动前校验，但先不启用所有能力。
- 把 `node_type/backend_type` 字符串替换路径设计好。

可交付：

- `core` crate。
- `GatewayConfig` normalized model。
- v2 Gateway 配置解析和校验。
- 配置校验器。

### Phase 1：抽出 MySQL frontend/backend

目标：

- 当前功能保持不变。
- MySQL 协议处理从 `runtime/gateway` 中拆成 adapter。
- runtime 不再直接 import `mysql_protocol`。

可交付：

- `MySqlFrontendProtocol`。
- `MySqlBackendConnector`。
- `GatewayRuntime`。
- 不保留旧 example config 兼容，后续只保证 v2 Gateway 配置启动。

### Phase 2：PostgreSQL 同协议中转

目标：

- 支持 PostgreSQL 客户端通过 Data Nexus 连接 PostgreSQL 后端。
- 先做基本 query、simple auth、session、pool、metrics。

可交付：

- PostgreSQL frontend handshake。
- PostgreSQL backend connector。
- v2 config 中配置 `protocol = "postgresql"` 的 listener 和 endpoint。

### Phase 3：治理能力协议无关化

目标：

- 读写分离、负载均衡、并发控制、熔断、metrics、audit 不再强依赖 MySQL。
- SQL parser 按 dialect 挂载。

可交付：

- `DialectParser` trait。
- `RoutePlan`。
- `PluginContext`。
- Admin API 查询 runtime 状态。

### Phase 4：受控跨协议访问

目标：

- 支持有限 SQL 子集的跨协议执行。
- 例如 MySQL frontend 到 PostgreSQL backend 的 SELECT/INSERT 基础映射。

限制：

- 不承诺所有 MySQL/PostgreSQL 方言互通。
- DDL、存储过程、COPY、LOAD DATA、vendor-specific function 默认不支持或需要显式开启。
- 每个 service 必须声明 `translation_policy`。

## 建议优先改的接口

优先级从高到低：

1. 新增 `ProtocolKind`、`GatewayCommand`、`GatewayResponse`、`SessionState`。
2. 新增 v2 config，直接作为唯一配置入口。
3. 将 `ProxyConfig` 拆出 `ListenerConfig` 和 `ServiceConfig`。
4. 将 `UniSQLNode` 替换为 `EndpointConfig`。
5. 将 `RouteStrategy::dispatch` 返回值升级为 `RoutePlan`。
6. 将 `PluginPhase` 接入 `PluginContext` 和 `PluginDecision`。
7. 给 runtime 增加 shutdown handle，补齐 `stop()`。
8. Admin HTTP 增加 runtime state API。

## 验收标准

第一阶段完成时：

- 旧 MySQL example config 能继续运行。
- 新 v2 MySQL config 能运行同样链路。
- runtime 主路径不再依赖 `backend_type` 字符串。
- 配置错误能在启动时给出明确错误。

第二阶段完成时：

- MySQL 客户端可以通过 Data Nexus 连 MySQL 后端。
- PostgreSQL 客户端可以通过 Data Nexus 连 PostgreSQL 后端。
- 两类 listener 可以同时存在。
- `/metrics` 能区分 service、frontend protocol、backend protocol、endpoint。

第三阶段完成时：

- 简单负载均衡、并发控制、熔断对 MySQL/PostgreSQL 都可用。
- route policy 和 plugin policy 可以按 service 配置。
- Admin API 能查看 listener、service、endpoint、pool 状态。

## 不建议现在做的事

- 不要一开始就做任意 MySQL/PostgreSQL 互转。SQL 方言差异很深，容易把核心代理链路拖乱。
- 不要继续在 `ProxyConfig` 上加字段。这个结构已经过载。
- 不要让 `node_type` 字符串决定运行时行为。协议类型应使用 enum 和显式 adapter registry。
- 不要把管理 UI 放在核心改造前面。先把 runtime state 和 admin API 做稳，前端再消费。
