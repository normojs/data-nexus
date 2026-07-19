# Data Nexus 技术架构与实现路线（2026）

**状态**：技术主文档（可迭代）  
**日期**：2026-07（2026-07-16：对齐树安 SQLDEV / 美创防水坝对标口径）  
**立场**：不背负历史实现包袱；以 **当前仓库能力为底座**，按 **2025–2026 业界成熟实践** 重新规划 L1 及以后  
**产品对标**：**美创数据防水坝**（防泄漏纵深）、**树安 SQLDEV**（[sqldev.info](https://sqldev.info/zh)，数据库堡垒/安全访问门户）— 能力矩阵见 `docs/data-security-roadmap.md` §3  
**关联**：

| 文档 | 关系 |
|------|------|
| `docs/data-nexus-protocol-gateway-plan.md` | L0 协议网关底座（保留） |
| `docs/data-security-roadmap.md` | 产品分期 S0–S6 + **竞品矩阵**（本文件给 **技术如何做**） |
| `docs/data-audit-architecture.md` | 审计/流式专项（本文件为 **总架构**，专项可收敛到此） |
| `docs/admin-rbac-design.md` | 管理面鉴权（与数据面 Subject **永久分离**） |
| `todo.md` | 执行看板 |

---

## 0. 一句话定位

```text
Data Nexus = 高性能数据库协议 PEP
           + 可分析的策略平面（PDP）
           + 流式结果义务执行（列/行筛选、动态脱敏）
           + 异步分级审计与冷归档
```

**能力目标（与树安 SQLDEV 公开主张同构，执行面不同）**：

| 主张 | SQLDEV（门户堡垒为主） | Data Nexus（协议 PEP 为主） |
|------|------------------------|-----------------------------|
| 数据访问 | Web 执行 DQL/DML/TCL/DDL | Wire 协议全语句类管控 + 可选 S6 门户 |
| 数据脱敏 | 动态脱敏（文档称结果侧引擎） | SecureStream 义务 mask / 可选改写 |
| 权限管控 | 库·对象·字段·行·时间维等 | Subject + PDP + 表/列/行义务 |
| 操作审计 | 审计/拦截/告警/（商）录屏等 | SQL·过程·结果元数据分级审计；录屏非目标 |

不是：又一个 BI、又一个纯 SQL IDE、又一个主机堡垒/录屏产品、又一个全量 SQL 翻译引擎。  
是：**在协议路径上以最低额外成本完成「谁在什么条件下对什么对象做什么，结果如何可见，并留下可证明痕迹」**。

### 0.1 对标交付优先级（技术验收顺序）

与 SQLDEV/防水坝销售验收对齐的工程顺序（**门户后置**）：

```text
1. 操作审计（SQL + 决策 + 过程元数据 + 可选结果统计）
2. 语句类 / 表级访问控制（DQL·DML·TCL·DDL）
3. 列级权限 + 动态脱敏（结果流）
4. 行级管控 + 敏感识别
5. 高级策略（时间维、动态赋权、审批/导出门闩）
6. Web SQL 门户 / 项目环境（必须仍走 PEP）
```

### 0.2 术语表（白话）

> 阅读本文时若遇生词，先查本表。英文缩写保留业界习惯，释义用中文。

#### 角色与分层

| 术语 | 白话 |
|------|------|
| **协议网关 / 代理** | 夹在「客户端」和「数据库」中间的程序；客户端连它，它再连真实库。 |
| **L0** | 协议与连接底座：握手、路由、连接池、跨协议、观测。**已基本完成。** |
| **L1** | 数据访问安全平面：身份、策略、脱敏、审计、审批等。**建设中。** |
| **L2** | 数据库自己的账号权限。网关管不到的最后一道，**不替代**。 |
| **管理面** | 运维谁能改网关配置、看监控（Admin / data-ui）。 |
| **数据面** | 真正跑 SQL、读业务数据的那条路径（应用 / DBA 连库）。 |
| **管理面 ≠ 数据面** | Admin 登录身份 **不能** 直接当「查业务表的人」。两套身份。 |

#### 身份与策略（谁、允不允许、还要做什么）

| 术语 | 白话 |
|------|------|
| **Subject（主体）** | 数据面「是谁」：某个人、某个应用、某个服务账号。带租户、部门、角色等属性。 |
| **PDP（Policy Decision Point）** | **策略大脑**：根据「谁 + 想干什么 + 对什么对象」算出 **允许 / 拒绝**，以及附带条件。自己不连库、不改数据包。 |
| **PEP（Policy Enforcement Point）** | **执行手脚**：网关里真正拦请求、改 SQL、改结果、记审计的地方。Data Nexus 的核心定位就是协议路径上的 PEP。 |
| **策略 / Policy** | 事先配好的规则，例如「分析师不能看 salary 明文」。 |
| **Decision（决策）** | PDP 的输出：`Allow`（放行）、`Deny`（拒绝）、`RequireApproval`（先审批）等。 |
| **义务（Obligation）** | **不是法律用语**。指：已经 **允许** 访问，但仍 **必须做完** 的处理。例如：打码、丢掉某列、只留本租户行、最多 1 万行、记更细审计。 **无义务** ≈ 原样转发；**有义务** ≈ 不能原样转发，要加工后再给客户端。 |
| **ACL** | 访问控制列表：谁能对哪张表/哪个操作说 yes/no。 |
| **细粒度权限** | 不只到「库」，还到 **表 / 列 / 行 / 时间段 / 语句类型**。 |
| **fail-closed** | 搞不清能不能放时，**默认拒绝**（更安全）。 |
| **fail-open** | 搞不清时 **默认放行**（更怕误伤业务；需显式配置）。 |

#### 路径与性能

| 术语 | 白话 |
|------|------|
| **透传（Passthrough）** | 同协议且无义务时，网关尽量 **不拆、不改** 数据包，原样转给客户端。最快。 |
| **包级 / 帧级** | 数据库协议里的一小段二进制消息（一帧/一包）。透传常在这个粒度转发。 |
| **流式（Streaming）** | 结果很大时，**边从库读边处理边写给客户端**，不要等全部读完。 |
| **窗口（Window）** | 流式时一次只处理的一批行，例如 256 行。控制内存，避免整表进内存。 |
| **全量物化** | 把查询结果 **整表装进内存** 再处理。现状问题；大数据时内存爆、延迟高。 |
| **Fast 路径** | 无义务、可透传的快速路径。 |
| **Secure 路径 / SecureStream** | 有脱敏、滤行等义务时的安全流式路径。 |
| **背压** | 客户端消费慢时，上游放慢生产，避免网关缓冲区撑爆。 |
| **热路径 / 冷路径** | 热：每条查询都走的关键路径（要极快）。冷：审计归档、报表分析等事后路径。 |

#### SQL 与结果处理

| 术语 | 白话 |
|------|------|
| **DQL** | 查询：主要是 `SELECT`。 |
| **DML** | 改数据：`INSERT` / `UPDATE` / `DELETE`。 |
| **DDL** | 改结构：`CREATE` / `ALTER` / `DROP` 等。 |
| **TCL** | 事务：`BEGIN` / `COMMIT` / `ROLLBACK`。 |
| **AST** | 把 SQL 解析成的语法树，便于找出涉及哪些表、列、操作。 |
| **ObjectSet / 对象集** | 这次 SQL 碰到的库表列等对象清单，供策略判断。 |
| **SQL 改写（Rewrite）** | 在发往数据库前改 SQL，例如自动加 `AND tenant_id = ?`、去掉无权限列。 |
| **动态脱敏 / Mask** | 查询时实时打码，如手机号 `138****0000`；一般不改库内真值。 |
| **列权限** | 某列能不能看；不能看则剔除或打码。 |
| **行级管控** | 同一张表，不同人看到不同行（常按租户/组织过滤）。 |
| **敏感数据识别** | 标出哪些列是手机号、证件号等，驱动默认脱敏策略。 |
| **水印** | 在结果中埋可追溯痕迹（谁导出的），用于泄密追责。 |
| **IR（中间表示）** | 网关内部统一的命令/结果结构（如 `GatewayCommand`），与具体 MySQL/PG 包格式解耦。 |

#### 审计与可观测

| 术语 | 白话 |
|------|------|
| **操作审计** | 记「谁、何时、对什么、做了什么、允许还是拒绝、结果大概怎样」。 |
| **AuditEvent** | 一条结构化审计记录。 |
| **审计分级 L0/L1/L2** | L0 只记元数据；L1 可含脱敏后 SQL/对象；L2 才可能带样本引用。**默认不存全结果。** |
| **异步审计** | 主路径只把事件丢进队列就返回；后台再落盘/外发，**不拖慢查询**。 |
| **有界队列** | 队列有最大长度；太忙时按策略丢弃或降采样，并打指标告警。 |
| **SQL 指纹** | 把 SQL 归一化后的摘要，用于归类与检索（不必存全文）。 |
| **trace_id / span** | 分布式追踪 ID；把一次请求的日志、指标、审计串起来。 |
| **OTel（OpenTelemetry）** | 业界通用的指标/链路/日志规范与导出方式。 |

#### 产品与阶段（文档里常出现）

| 术语 | 白话 |
|------|------|
| **S0–S6** | 数据安全产品分期：从审计壳子 → 表权限 → 列/脱敏 → 持久审计 → 审批 → 门户。见路线图。 |
| **树安 SQLDEV** | 竞品：偏 Web 数据库堡垒/安全访问门户（[sqldev.info](https://sqldev.info/zh)）。 |
| **美创数据防水坝** | 竞品：偏数据防泄漏与合规管控。 |
| **门户 / Web Terminal** | 浏览器里写 SQL 的界面；本项目放在后期，且 **必须仍走网关 PEP**。 |
| **金库 / 审批工单** | 高危操作先申请、双人批准、限时限次后再执行。 |
| **通道** | 流量从哪进来：协议代理、门户导出、批量作业等；可按通道加更严策略。 |

#### 一图串起来

```text
客户端 ──SQL──► 网关(PEP)
                  │
                  ├─ 认出是谁(Subject)
                  ├─ 问策略大脑(PDP)：允许？拒绝？附带义务？
                  │
                  ├─ 拒绝 ──► 直接报错 + 记审计
                  │
                  └─ 允许
                        ├─ 无义务 ──► 透传（原样转发，最快）
                        └─ 有义务 ──► 流式窗口：读一批→打码/过滤→写出
                                        └─ 审计事件异步落盘
```

---

## 1. 现状底座（必须认清，才能无负担重构）

### 1.1 已具备（L0，可继续用）

| 能力 | 位置 | 评价 |
|------|------|------|
| 双协议前端/后端 | `runtime/gateway` + `frontend/*` + `backend/*` | 生产可用 |
| 统一 IR | `GatewayCommand` / `GatewayResponse` / `GatewayValue` | 正确但 **全量物化** |
| 路由/池/插件 | `core_engine` + plugin policies | 治理齐 |
| 受控跨协议 | `translation_policy` + dialect | 默认关，正确 |
| 管理面 JWT | `admin_auth` + data-ui | 与数据面隔离 |
| 观测 | Prometheus + 可选 OTel | 可升级到日志信号 |

### 1.2 必须改掉的核心瓶颈

```text
今天：
  Backend 全读 → Vec<Vec<GatewayValue>> → encode 全包 → 客户端
  拷贝次数 ~2–3；峰值内存 O(结果集)

目标：
  无义务 → 同协议包级/帧级透传（零解析或最小解析）
  有义务 → 流式窗口：读一批 → 义务 → 编码一批 → 写出
  审计   → 有界队列异步落盘/外发，绝不阻塞主路径
```

`GatewayResponse::ResultSet { rows: Vec<...> }` **不能**再作为安全与大数据路径的唯一形态；它降级为：

- 小结果兼容路径
- 测试与跨协议翻译路径
- 管理/诊断路径

---

## 2. 业界技术选型（2026 结论）

以下选型基于当前生态成熟度（Rust crates / 规范），**热路径优先确定性与延迟，冷路径优先生态与可运维**。

### 2.1 选型总表

| 域 | 选择 | 版本/形态（约） | 不用 / 慎用 | 理由 |
|----|------|-----------------|-------------|------|
| 语言运行时 | **Rust + Tokio** | 现有 workspace | Go 重写 | 已有协议栈与零成本抽象 |
| 协议 | MySQL / PostgreSQL wire | 现有 `protocol`/`pg-srv` | 自研全协议 | 兼容是产品 |
| SQL 解析 | **sqlparser**（+ 方言扩展） | ≥0.62 | 手写正则当策略 | AST 对象抽取刚需 |
| 策略语言 | **Cedar**（主）+ 本地 DSL（辅） | cedar-policy ≥4.x | 热路径远程 OPA | 可分析、低延迟、Rust 原生；复杂企业可后接 OPA 旁路 |
| 结果热路径 IR | **行窗口 + `bytes::Bytes`** | bytes 1.x | Arrow 作代理 IR | 协议是行式；Arrow 列式转换贵 |
| 列式 / 分析 | **Arrow / DataFusion** | 仅冷路径 | 查询主路径 | 审计检索、导出、未来 Flight |
| 对象存储抽象 | **Apache OpenDAL** | ≥0.58 | 绑死单一 SDK | S3/OSS/本地/多云统一 |
| 序列化（策略缓存/审计事件） | **serde_json**（互通）+ **rkyv**（热缓存可选） | rkyv 0.8 | protobuf 强绑定前期 | 运维可读优先；热路径可换 |
| 可观测 | **OTel Traces + Metrics + Logs** | 现有 + Logs 补齐 | 自建日志协议 | trace_id 贯穿审计 |
| 消息/队列（审计） | 进程内 `mpsc` → 可选 Kafka/NATS | 有界 | 同步写 SIEM | 背压 + 丢弃策略可配 |
| 身份（数据面） | 连接属性 + Proxy Protocol + 可选 mTLS/JWT claim | 自建 Subject | Admin JWT 当数据身份 | 两层真相源 |
| 配置 | TOML v2 listeners/services | 现有 | 热路径读 YAML 反复解析 | 启动/热更编译成 Arc 快照 |

### 2.2 关键决策说明

#### A. 为什么策略主选 Cedar，而不是一上来 OPA？

| | Cedar | OPA/Rego | 纯自研 JSON 规则 |
|--|-------|----------|------------------|
| 嵌入 Rust | 一等公民 | 常 HTTP/sidecar | 自控 |
| 延迟 | 微秒～亚毫秒级本地评估 | 远程则毫秒+ | 视实现 |
| 可分析 | 设计目标（验证/差分） | 有限 | 弱 |
| 运维心智 | 学习曲线中等 | 企业已有则好 | 最低 |
| Data Nexus 用法 | **默认 PDP** | 可选 **RemotePDP** 适配器 | **S0–S1 引导 DSL**，编译到内部 Decision |

**落地策略**：

1. S0–S1：内部 `Decision + Obligations` 结构 + 简单 TOML/YAML 规则（快速交付）。  
2. S2+：规则编译/映射到 **Cedar schema + policies**（或双写）。  
3. 企业已有 OPA：实现 **F31 Remote PDP**（`security.pdp.backend=remote`），**不**把 OPA 放进每行 mask 循环。

#### A.1 F31 Remote PDP（已实现切片）

命令级 **表/动作** HTTP 旁路，与 Local/Cedar 共用 PEP 义务路径：

| 项 | 约定 |
|----|------|
| 配置 | `backend=remote`；必填 `remote_url`（http/https）；`remote_timeout_ms` 默认 50（1..=30000）；可选 `remote_token`；`remote_fail_closed` 默认 true |
| 调用时机 | 本地表规则 Allow 之后、时间窗/高危票/列 ACL/mask 之前；**仅命令路径** |
| 请求 JSON | `{ subject_id, service, action, tables[], sql_fingerprint? }` |
| 响应 JSON | `{ allow: bool, rule?, message? }` |
| 失败语义 | 超时/传输/非 2xx/坏 JSON → `remote_fail_closed=true` 时 **Deny**（默认） |
| 非目标 | 远程返回 mask 算法、行过滤、per-row 决策、OPA 包路径自动发现 |

```text
Local rules (table) → [Cedar?] → [Remote HTTP?] → time/ticket → column ACL → mask obligations
```

运维：生产模板见 `data-proxy/examples/prod/gateway.example.toml` 注释；单元测 `gateway_core` 的 `f31_*`。

#### B. 为什么热路径不用 Arrow / DataFusion？

- 线协议是 **行帧**（MySQL text/binary row、PG DataRow）。  
- 全量 `RecordBatch` 化 = 额外分配 + 类型擦除 + 再编码。  
- DataFusion 适合 **审计湖查询、策略仿真、导出作业**，不适合代理每秒数万短查询。

Arrow 的正确位置：

```text
冷路径：审计样本 / 导出 / 未来 ADBC·Flight SQL 旁路
热路径：Bytes 窗口 + 列投影 mask 表（小结构）
```

#### C. 为什么审计存储用 OpenDAL？

审计要同时支持：本地盘（开发）、对象存储（生产）、后续换云。  
OpenDAL 0.58 提供统一 `Operator`、分层 retry/metrics/otel，避免 `s3/oss/fs` 三套代码。

#### D. OTel Logs 的位置

访问审计事件应能：

- 与请求 **trace_id / span_id** 关联  
- 作为 **结构化 LogRecord** 导出（OTLP），而不仅是 `tracing` 文本  
- 与 Metrics（QPS、deny、mask 行数）同 Resource

实现：主路径 `tracing` 事件 → appender → OTLP Logs；完整 AuditEvent 仍走异步管道落库。

---

## 3. 目标架构

### 3.1 逻辑全景

```text
┌──────────────────────────────────────────────────────────────────────────┐
│                         Management Plane (已有)                          │
│  data-ui / Admin API / JWT·OIDC / reload / metrics                       │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │ 配置快照 Arc<RuntimeSnapshot>
┌────────────────────────────────▼─────────────────────────────────────────┐
│                         Control Plane (新建)                             │
│  PolicyRepo · SubjectStore · ApprovalService · AuditQuery · SchemaCache  │
│  PDP (Local/Cedar/Remote F31) · 编译缓存 · 热更新（epoch）                 │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │ Decision / Obligations / Risk
┌────────────────────────────────▼─────────────────────────────────────────┐
│                      Data Plane PEP (强化 core_engine)                   │
│                                                                          │
│  Listener ─► FrontendAdapter ─► Session+Subject ─► Analyze ─► PDP        │
│       │                                              │                   │
│       │                     ┌────────────────────────┴──────────────┐    │
│       │                     │ PathSelector                          │    │
│       │                     │  FastPath | SecureStream | Translate  │    │
│       │                     └────────────────────────┬──────────────┘    │
│       │                                              │                   │
│       │         BackendConnector ◄── SQL rewrite ◄───┘                   │
│       │              │                                                   │
│       │              ▼                                                   │
│       │         Frame/Row Stream ──► ObligationPipeline ──► Encode       │
│       ▼                                              │                   │
│  Client ◄────────────────────────────────────────────┘                   │
│                              │                                           │
│                              ▼ try_send (有界)                           │
│                       AuditPipeline ──► Sink (file/OpenDAL/OTLP/SIEM)    │
└──────────────────────────────────────────────────────────────────────────┘
```

### 3.2 四条执行路径（必须显式）

| 路径 | 条件 | 行为 | 延迟目标 |
|------|------|------|----------|
| **P0 Fast** | 同协议 + 无义务 + 解析成功且策略 Allow | 包/帧透传或「解析一次 SQL + 结果透传」 | ≈ 直连 + 微开销 |
| **P1 SecureStream** | 有 mask/投影/行过滤/水印/限流 | 流式读 → 义务 → 流式写 | P99 可控，内存 O(窗口) |
| **P2 Translate** | 跨协议且 translation 开启 | 现有翻译 + **尽量流式**（分阶段） | 允许更高 |
| **P3 Gate** | Deny / 需审批 / 解析失败且 fail-closed | 不访问后端或只记审计 | 最快失败 |

路径选择在 **PDP 之后、后端执行之前** 一次完成；结果阶段不再二次「猜策略」。

### 3.3 模块边界（crate 级建议）

在现有 `data-proxy` workspace 上演进，避免大爆炸拆仓：

```text
data-proxy/
  gateway/core          # IR、配置、Session、错误（扩展 Security 类型）
  runtime/gateway       # core_engine、前后端、路径实现
  security/             # 新建：subject / pdp / obligations / rewrite
  audit/                # 强化：event schema / pipeline / sinks
  policy/               # 新建：Cedar 适配、规则编译、缓存
  parser/               # 既有 + 对象抽取 ObjectSet
  http/                 # Admin + 未来 policy/audit API
  data-ui               # 控制台
```

原则：**security 与 audit 不依赖具体 MySQL/PG 包结构**；只依赖 IR + Stream trait。

---

## 4. 核心数据模型

### 4.1 Subject（数据面身份）

```text
Subject {
  subject_id: String,          // 稳定主键
  display_name: Option<String>,
  attrs: Map<String, Value>,   // tenant, dept, roles, clearances...
  authn: AuthnMethod,          # password|cert|proxy|token|unknown
  network: { client_ip, tls_sni, proxy_protocol },
  db_user: String,             # 协议登录用户（不等于 subject_id）
  service: String,             # 命中的 gateway service
  session_id: Uuid,
}
```

绑定顺序（可配置，默认严格）：

1. 显式网关认证插件（未来 mTLS / 连接 token）  
2. Proxy Protocol / 可信头（仅可信网络）  
3. 协议用户名 → Subject 映射表  
4. 否则 `anonymous` + 高风险默认策略  

**禁止**：Admin JWT `sub` 直接当数据面 Subject。

### 4.2 Decision 与 Obligations

```text
Decision = Allow | Deny | RequireApproval

Obligations {
  sql_rewrite: Option<RewritePlan>,   // 列剔除、行谓词注入、limit
  column_mask: Vec<MaskSpec>,         // 结果阶段
  row_filter: Option<RowFilter>,      // 仅当无法改写时的结果过滤
  watermark: Option<WatermarkSpec>,
  max_rows: Option<u64>,
  max_bytes: Option<u64>,
  audit_level: L0|L1|L2,              // 见审计分级
  sample: Option<SampleSpec>,
}
```

PDP **只产出决策与义务**；PEP **只执行**。禁止在 PDP 内做 IO。

### 4.3 流式结果抽象（取代全量 ResultSet）

```rust
// 概念 API（实现可落在 gateway/core + runtime）

pub struct ResultMeta {
    pub columns: Arc<[Column]>,
    pub frontend: ProtocolKind,
    pub backend: ProtocolKind,
}

pub enum RowBatch {
    /// 已解码为 Gateway 值（Secure 路径、跨协议）
    Values { rows: Vec<Vec<GatewayValue>> }, // 窗口，非全表
    /// 后端原始帧（同协议 Fast/部分 Secure）
    Wire { frames: Vec<Bytes> },
}

pub trait ResultStream: Send {
    fn meta(&self) -> &ResultMeta;
    fn poll_batch(self: Pin<&mut Self>, cx: &mut Context<'_>)
        -> Poll<Option<GatewayResult<RowBatch>>>;
}

pub enum ExecuteMode {
    Materialized,           // 兼容旧路径
    Streaming { window: usize },
    Passthrough,            // 同协议帧转发
}
```

`GatewayResponse` 演进建议：

```text
GatewayResponse::ResultSet { ... }           // 保留，小结果/测试
GatewayResponse::ResultStream(BoxStream)     // 新主路径（或连接内回调式写出）
```

工程上更务实的第一刀：**连接内 streaming write**（backend 回调 → obligation → frontend encode），不一定先把 Stream 枚举进 `GatewayResponse`（避免生命周期痛苦）。两种可并存：

1. **Callback/push 模型**（推荐 S0–S2）：`execute_streaming(cmd, sink)`  
2. **Pull Stream 模型**（S3+ 统一）：便于测试与组合

### 4.4 AuditEvent（统一 schema）

```text
AuditEvent {
  event_id, ts, trace_id, span_id,
  subject_id, db_user, client_ip, service, listener,
  action,                  // query|admin_write|login|export|approve
  decision, reasons[],
  objects: [{ kind, catalog?, schema?, name, columns? }],
  sql_fingerprint, sql_redacted?,
  obligations_summary,
  rows_in, rows_out, bytes_out, duration_ms,
  audit_level, sample_ref?,
  error_code?,
}
```

级别：

| 级别 | 内容 | 默认 |
|------|------|------|
| **L0** | 元数据 + fingerprint + 决策 | 全开 |
| **L1** | + 脱敏 SQL / 对象集 | 写操作、Deny、敏感表 |
| **L2** | + 样本行引用（对象存储 key） | 显式开启；禁止默认同步存全结果 |

---

## 5. 请求生命周期（Secure 路径）

```text
1. Accept + 协议握手
2. 建立/刷新 SessionState + Subject
3. Decode → GatewayCommand
4. Analyze:
     - sqlparser AST
     - ObjectSet（表/列/函数/写类型）
     - RiskHints（全表扫、无 where、多表 join…）
5. PDP.evaluate(Subject, Action, ObjectSet, Context) → Decision + Obligations
6. if Deny / RequireApproval → 响应客户端 + Audit L0/L1 → end
7. Apply RewritePlan → effective SQL
8. Backend execute streaming
9. For each window:
     apply column_mask / row_filter / watermark / max_rows
     encode to client (backpressure)
10. Finalize metrics + AuditEvent try_send
```

Fast 路径在步骤 5 后若 `obligations.is_empty() && same_protocol`，跳到 **帧透传**（仍可做 SQL 级审计 L0）。

---

## 6. 策略平面设计

### 6.1 分层策略

```text
L1-Global default (fail-closed | fail-open 可配，默认 closed 对写)
L2-Service / Endpoint
L3-Subject / Role / Attr
L4-Object (db.schema.table.column)
L5-Action (select|insert|update|delete|ddl|copy|export)
L6-Context (time, ip cidr, tool, risk)
```

冲突：显式 Deny > 审批门闩 > Allow+义务 > 默认。

### 6.2 Cedar 映射（目标态）

```text
entity User, Role, Table, Column, Database;
action select, insert, update, delete, ddl, export;

// 示例语义（非最终语法）
permit(principal in Role::"analyst", action == Action::"select",
       resource in Table::"orders")
when { principal.tenant == resource.tenant };

forbid(principal, action == Action::"select", resource)
when { resource.classification == "secret"
       && !principal.clearance.contains("secret") };
```

义务（mask 等）若 Cedar 不便表达：用 **permit + 注解/独立 MaskPolicy 表**，PDP 聚合为 `Obligations`。

### 6.3 编译与缓存

```text
PolicySource (git/API/文件)
    → Validate
    → Compile to PolicySet + Index (by action/service)
    → ArcSwap<CompiledPolicy>  // 无锁读
    → epoch++
```

热更新：与现有 admin reload 同一事务语义——**校验失败保留旧快照**。

评估延迟预算：**P99 < 100µs**（本地缓存命中，不含解析）。

---

## 7. 义务执行（PEP）

### 7.1 优先 SQL 改写，其次结果处理

| 义务 | 首选 | 回退 |
|------|------|------|
| 表禁止 | Deny | — |
| 列禁止 | 改写 SELECT 列表 / 拒绝 SELECT * 无元数据 | 结果丢列 |
| 行租户 | 注入 `AND tenant_id = $subj` | 结果过滤（贵） |
| 脱敏 | 结果 mask（或改写为表达式，慎） | — |
| 行数上限 | 注入 LIMIT | 流式截断 |
| 水印 | 结果列/行嵌入 | 导出通道 |

改写必须 **可审计**（original fingerprint + rewritten fingerprint）。

### 7.2 Mask 实现要点

- 按 **列下标** 预编译 `MaskFn` 数组，行循环无哈希查找。  
- 支持：`nullify` / `partial` / `hash` / `replace` / `truncate` / `keep_prefix`。  
- 二进制协议路径：解码单元格 → mask → 再编码；**禁止**对整包字符串 replace。  
- 对 `SELECT *`：依赖后端列元数据或预置 schema cache。

### 7.3 同协议透传

```text
条件：frontend.protocol == backend.protocol
      && obligations 空（或仅 L0 审计）
      && 非事务中间态特殊处理可接受

实现分期：
  T1: 结果阶段透传（SQL 仍解析一次）——收益大、风险小
  T2: 无状态简单查询全链路透传
  T3: 事务/预处理语句透传矩阵
```

---

## 8. 审计管道

### 8.1 架构

```text
PEP ──try_send──► bounded channel (N)
                    │
                    ▼
              AuditWorker(s)
                ├─ enrich (geo, service labels)  // 可选
                ├─ sample upload (OpenDAL) if L2
                └─ fanout:
                     ├─ local append-only log / SQLite|PG
                     ├─ OTLP Logs
                     └─ webhook / Kafka (可选)
```

### 8.2 背压策略（必须可配）

| 策略 | 行为 |
|------|------|
| `block` | 极少用；仅合规强制 |
| `drop_new` | 默认；指标 `audit_dropped_total` |
| `drop_old` | 保留最新 |
| `sample` | 高 QPS 降采样，Deny 永不采样丢弃 |

**Deny / 审批 / 管理写** 可走 **独立高优先级队列**。

### 8.3 存储

| 阶段 | 存储 |
|------|------|
| S0 | `tracing` + 结构化 JSON 行文件 |
| S4 | PostgreSQL/SQLite 索引表 + OpenDAL 对象（样本/大 payload） |
| 以后 | Parquet 分区冷归档（按日/租户），DataFusion 或外部引擎检索 |

---

## 9. 可观测性架构

```text
Traces:  session → command → pdp → backend → encode
Metrics: qps, path{fast|secure|translate|deny}, pdp_us, mask_rows,
         mem_window_bytes, audit_queue_depth, audit_dropped
Logs:    AuditEvent 子集 + 错误
```

统一 Resource：`service.name=data-nexus`, `service.version`, `deployment.environment`。  
每个命令 span 属性：`db.system`, `enduser.id`(subject), `data_nexus.path`, `data_nexus.decision`。

---

## 10. 配置模型（扩展 v2，默认关闭安全）

```toml
[security]
enabled = false
fail_closed = true
default_audit_level = "L0"

[security.subject]
# map protocol user -> subject id / attrs file or admin API
sources = ["protocol_user", "proxy_protocol"]

[security.pdp]
backend = "local"          # local | cedar | remote
policy_dir = "./policies"
cache_epoch_reload = true
# F31 remote (when backend = "remote"):
# remote_url = "https://pdp.example/v1/data_nexus"
# remote_timeout_ms = 50
# remote_token = ""          # optional Bearer
# remote_fail_closed = true
# F29 cedar attrs (when backend = "cedar"):
# [[security.pdp.subject_attrs]]
# subject_id = "alice"
# tenant = "acme"
# clearance = "secret"

[security.streaming]
window_rows = 256
max_rows = 1_000_000
max_bytes = 268435456
passthrough = true

[security.audit]
queue_capacity = 65536
overflow = "drop_new"
sinks = ["file", "otlp_logs"]
file_path = "./var/audit/events.jsonl"

[[security.rules]]
# S0–S1 引导 DSL；后续可导出为 Cedar
name = "deny-secret-tables"
effect = "deny"
actions = ["select", "export"]
tables = ["*.*.secret_*"]
```

热更新：进入现有 `GatewayConfig` 校验管线；无效则 keep-old。

---

## 11. 实现路线（工程切片，可并行）

> 产品分期仍见 `data-security-roadmap.md` S0–S6。  
> 此处是 **技术切片**，强调可合并 PR 的垂直交付。

### Track A — 性能底座（可与 S0 并行）

| 切片 | 交付 | 验收 |
|------|------|------|
| A1 | `ExecuteMode` + backend **窗口化读取**（先 PG 或 MySQL 一个） | 大结果 RSS 不随行数线性爆 |
| A2 | frontend **边编码边写** | 首包延迟下降 |
| A3 | 同协议 **结果透传**（无义务） | 基准接近直连 |
| A4 | 跨协议流式（后置） | 不回归现有 smoke |

### Track B — 安全控制面（对标 SQLDEV：访问 + 权限 + 脱敏）

| 切片 | 交付 | 对标能力 | 验收 |
|------|------|----------|------|
| B0 | `SecurityPolicyConfig` 默认 off + 类型壳 | 配置面 | 旧 smoke 全绿 |
| B1 | `Subject` 绑定 + 审计字段 `sub` | 数据面身份 | Admin/数据审计带 subject |
| B2 | Local PDP：语句类 + 表级 Deny | DQL/DML/TCL/DDL·表 ACL | smoke-security-deny |
| B3 | ObjectSet 抽取（sqlparser） | 细粒度前置 | 多表/别名单测 |
| B4 | 列 ACL + Rewrite/投影 | 字段级权限 | 无权限列不可见 |
| B5 | Mask 义务 + SecureStream | **动态脱敏** | 手机号/证件打码 E2E |
| B5b | 行谓词注入 / 结果行过滤 | **行级管控** | 租户隔离 E2E |
| B5c | 敏感列标签 + 规则/词典识别（MVP） | **敏感数据识别** | 标签驱动默认 mask |
| B6 | Cedar backend 可选 feature | 高级可分析策略 | 与 Local 一致集 |
| B6b | **F31 Remote PDP** HTTP 旁路 | 企业 OPA/外部决策 | 超时 fail_closed；表/动作 gate |
| B7 | 时间维 / 审批门闩 / 导出通道 | 高级策略·工单 | 高危 SQL 阻断 |

### Track C — 审计与运营

| 切片 | 交付 | 验收 |
|------|------|------|
| C0 | `AuditEvent` schema + 有界队列 | 压测不堵查询 |
| C1 | 文件/OTLP sink | 事件可检索 |
| C2 | OpenDAL 样本 | L2 开关 |
| C3 | Admin 查询 API + data-ui 页 | 按 subject/表/决策过滤 |
| C4 | 冷归档 Parquet（可选） | 生命周期任务 |

### 推荐并行节奏

```text
Week 1–2:  B0 + C0 + A1 设计评审与骨架
Week 3–4:  B1–B2 + A1 单协议 streaming MVP
Week 5–6:  B3–B4 + A3 passthrough
Week 7–8:  B5 mask + C1
之后:      B6 Cedar, B7 审批, C2–C4, A4
```

---

## 12. 关键 API / 代码落点（实现指引）

### 12.1 `core_engine` 伪代码

```text
async fn handle_command(conn, cmd) {
  let subject = conn.subject();
  let analysis = analyzer.analyze(&cmd)?;
  let decision = pdp.evaluate(subject, &analysis, &ctx)?;

  audit_builder.record_decision(&decision);

  match decision.effect {
    Deny => return encode_error(deny_msg),
    RequireApproval => return encode_error(pending_msg),
    Allow => {}
  }

  let cmd = rewriter.apply(cmd, &decision.obligations)?;

  if path_is_fast(&conn, &decision) {
    return backend.execute_passthrough(cmd, frontend_sink).await;
  }

  backend.execute_streaming(cmd, |batch| {
    let batch = obligations.apply(batch)?;
    frontend.write_batch(batch)
  }).await?;

  audit_pipeline.try_send(audit_builder.finish());
}
```

### 12.2 特性开关（Cargo features）

```toml
# 建议
security-cedar = ["cedar-policy"]
audit-opendal = ["opendal"]
audit-otlp = ["opentelemetry", "opentelemetry-otlp"]
# arrow/datafusion 仅 audit-analytics 可选
audit-analytics = ["datafusion", "arrow"]
```

默认 **不** 打开 Cedar/OpenDAL/DataFusion，保证基础二进制精简。

### 12.3 测试金字塔

| 层 | 内容 |
|----|------|
| 单元 | ObjectSet、Rewrite、MaskFn、PDP 表策略 |
| 组件 | streaming window 内存上界 property test |
| 契约 | Cedar fixture ↔ Local PDP |
| Smoke | deny / mask / passthrough / admin audit sub |
| 基准 | criterion：fast vs secure vs 旧 materialize |

---

## 13. 风险与非目标

### 13.1 风险

| 风险 | 缓解 |
|------|------|
| 解析失败导致误放行 | 默认 fail-closed（可配）+ 指标 + 采样 SQL |
| 改写破坏语义 | 仅白名单改写模板；复杂 SQL Deny 或仅结果义务 |
| 透传漏策略 | PathSelector 单点；义务非空强制 Secure |
| 审计丢事件 | Deny 高优队列；overflow 指标告警 |
| Cedar 学习成本 | S0–S1 Local DSL；文档与导出工具 |
| 全量物化回归 | CI 基准 + 大结果 smoke 看 RSS |

### 13.2 明确非目标（本架构不承诺）

- 用 Data Nexus 替换数据库原生权限（L2 仍保留）  
- 任意方言完美互转  
- 热路径 Arrow 计算  
- 默认同步存储完整结果集  
- 管理面与数据面身份混用  
- **对标 SQLDEV 商业版也不做的（或后置集成）**：主机堡垒机、操作录屏、一次性 30+ 数据源  
- 用门户替代协议 PEP（S6 门户必须经同一 PEP）

---

## 14. 成功度量

| 指标 | 目标（初值，可调） |
|------|-------------------|
| 无义务 P99 额外延迟 | < 0.5ms（同机） |
| 有 mask 时峰值内存 | O(window_rows × row_width)，窗口默认 256 |
| PDP P99 | < 100µs（本地） |
| 审计丢弃率 | 常态 0；过载可见且 Deny 不丢 |
| 策略热更 | 校验失败零中断 |
| 安全默认 | `security.enabled=false` 时与 L0 行为一致 |

---

## 15. 文档与代码演进约定

1. **本文件**为 2026 技术主路线；实现偏离时先改文档再改代码，或同 PR 更新。  
2. `data-audit-architecture.md` 中与本文冲突时，**以本文为准**（流式/双路径/技术选型）。  
3. `data-security-roadmap.md` 管产品阶段与对标；本文管 **怎么做**。  
4. `todo.md` 只跟踪切片完成态（B0/A1/…），不复制长文。  

---

## 16. 附录：技术雷达（Watch）

| 技术 | 态度 | 触发引入条件 |
|------|------|----------------|
| Apache Arrow Flight SQL | Watch | 需要分析型旁路接入 |
| ADBC | Watch | 标准数据库连接生态 |
| DataFusion | Adopt-冷 | 审计分析 / 策略仿真 |
| Cedar SymCC | Watch | 策略形式化验证需求 |
| eBPF 流量旁路 | Hold | 与协议 PEP 重叠且难义务 |
| WASM 策略插件 | Watch | 多租户自定义义务隔离 |
| io_uring | Watch | Linux 部署且连接海量 |

---

## 17. 结语

Data Nexus 下一阶段的技术本质不是「堆安全功能清单」，而是：

> **把协议网关做成可证明的 PEP：快路径足够快，安全路径足够流，策略足够可分析，审计足够异步且可关联 trace。**

实现上坚持：

1. **双路径**（透传 / 流式义务）  
2. **决策与执行分离**（PDP / PEP）  
3. **热路径行式 Bytes，冷路径列式 Arrow**  
4. **Cedar（或可编译规则）+ 有界审计 + OpenDAL 归档**  
5. **安全默认关闭，开启后 fail-closed 可证**

从 **Track A1 + B0 + C0** 开工，即可在不破坏 L0 的前提下，把架构从「全量物化中转站」推进到「现代数据访问安全平面」。
```
