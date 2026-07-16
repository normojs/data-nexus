# Data Nexus 数据安全能力升级路线图

**状态**：产品规划（对标美创数据防水坝、数安 SQLDev 的升级版 Data Nexus）  
**日期**：2026-07  
**底座**：现有协议网关（M0–M10）  
**原则**：网关作 **PEP（执行点）**，策略作 **PDP（决策点）**；管理面鉴权与数据面授权分离

---

## 1. 背景与产品边界

### 1.1 从「协议中转站」到「协议网关 + 数据访问安全」

当前 Data Nexus（见 `todo.md`、`docs/data-nexus-protocol-gateway-plan.md`）已完成：

- 多协议中转（MySQL / PostgreSQL）与受控跨协议（`translation_policy`）
- 路由 / 连接池 / 治理插件 / 可观测（Prometheus + 可选 OTel）
- 管理面鉴权（Admin JWT HMAC/JWKS、break-glass、data-ui OIDC）

**下一阶段产品目标**（业务已确认）：在协议网关之上建设数据安全能力，包括但不限于：

| 能力域 | 典型能力 |
|--------|----------|
| 数据授权 | 表 / 列 / 行级授权 |
| 隐私保护 | 动态脱敏、水印 |
| 高危管控 | 审批工单、金库 |
| 通道管控 | 终端识别、外发 / 导出 / 通道策略 |
| 合规 | 持久化审计、检索与报表 |
| 体验扩展 | 开发者 SQL 门户、项目 / 环境（SQLDev 向） |

这使 Data Nexus 与 **美创数据防水坝**、**数安 SQLDev** 从「相邻互补」变为 **同场竞技 + 可集成**，但仍应用 **协议原生 PEP** 作为差异化，而不是用门户替代协议。

### 1.2 与现有文档的关系

| 文档 | 关系 |
|------|------|
| `docs/data-nexus-protocol-gateway-plan.md` | L0 协议与拓扑底座；本路线图不推翻其架构 |
| `docs/admin-rbac-design.md` | **管理面** RBAC（谁管网关）；与数据面 Subject/ACL **两套模型** |
| `docs/admin-auth-password.md` | Admin 密码 / OIDC 运维配置 |
| `todo.md` | 执行看板；原「明确不做数据面 RBAC」改为 **延后至本路线图 Sx** |

### 1.3 两层真相源（必须坚持）

| 层 | 职责 | 现状 | 本路线图 |
|----|------|------|----------|
| **L0 协议与连接** | 握手、会话、池、路由、跨协议、观测 | 已完成 | 持续加固 |
| **L1 访问控制平面** | 身份、策略、审批、脱敏、审计、外发 | 仅管理面鉴权 | **主建设** |
| **L2 数据源** | 库原生权限 | 后端账号 | 仍为最后一道，不轻易替代 |

```text
客户端 / 终端 / 门户
        │
        ▼
┌────────────────────────────┐
│ Data Nexus Gateway (PEP)   │  协议 + 策略执行（拦截/改写/脱敏/水印）
│  runtime/gateway           │
└─────────────┬──────────────┘
              │ PolicyRequest / Decision + Obligations
              ▼
┌────────────────────────────┐
│ Policy / Approval (PDP)    │  新建：规则、资产、工单、金库
└─────────────┬──────────────┘
              ▼
         后端数据库
```

- **PEP** = Policy Enforcement Point（网关）  
- **PDP** = Policy Decision Point（策略服务，S0–S1 可进程内）

---

## 2. 现状能力盘点（代码对齐）

### 2.1 模块布局（`data-proxy/`）

| 路径 | 职责 |
|------|------|
| `gateway/core` | `GatewayCommand/Response`、`SessionState`、`PluginContext`、`RoutePlan`、`TranslationPolicy`、`AdminAuth*`、v2 config |
| `runtime/gateway` | `core_engine` 编排、frontend/backend、dialect、OTel 业务 metrics |
| `protocol/mysql`、`protocol/postgresql` | 线协议 |
| `parser/mysql` | MySQL AST |
| `plugin` | 熔断 / 并发（regex 级） |
| `http` | Admin API + JWT + 嵌入式 `/admin` |
| `cmd/pisa` | 进程入口；`--features otel` |
| `data-ui/` | 运维控制台（非 SQL IDE） |

**命令主路径**（`runtime/gateway/src/core_engine.rs`）：

```text
decode → route → plugins.evaluate → translation → backend.execute
      → map_response_types → encode
```

### 2.2 已具备（对安全升级有价值）

| 能力 | 说明 | 代表路径 |
|------|------|----------|
| 多协议 PEP 骨架 | 所有客户端流量可强制过网关 | `frontend/*`、`backend/*`、`core_engine` |
| 策略型配置先例 | `translation_policy`：开关 + 子集 + 明确拒绝 | `gateway/core/src/translation.rs` |
| 插件决策模型 | `Continue` / `Reject` / `Rewrite` | `gateway/core/src/plugin.rs` |
| 方言与 AST | MySQL `mysql_parser`；PG `sqlparser` | `runtime/gateway/src/dialect.rs` |
| 管理面鉴权 | viewer/operator/admin、HMAC/JWKS、break-glass | `gateway/core/src/admin_auth.rs`、`http/` |
| 审计日志（弱） | `data_nexus::audit` tracing | `core_engine` |
| 可观测 | Prometheus + 可选 OTel | `examples/OBSERVABILITY.md` |

### 2.3 关键缺口（相对防水坝 / SQLDev）

| 缺口 | 现状 |
|------|------|
| 数据面 Subject | 仅 static 用户名写入 `SessionState.user` |
| 表/列/行 ACL | 无；dialect 只做读写分类 / leading keyword |
| 结果集改写钩子 | **无** post-response 路径（脱敏/水印前置条件） |
| 持久化审计 / 查询 UI | 仅日志，无检索 API |
| 审批 / 金库 | 无 |
| 账号保险箱 | endpoint 静态明文凭据 |
| 终端 / 外发通道 | 无 |
| 开发者 SQL 门户 | 无（data-ui 是运维台） |
| 资产分类分级 | 无 |

### 2.4 扩展点（实现时挂载位置）

| 阶段 | 挂载点 | 用途 |
|------|--------|------|
| 握手后 | `gateway.rs` + `SessionState` / `SecurityContext` | 绑定 Subject、client_addr |
| Pre-execute | `core_engine`（plugin 前/后可配） | 对象级 ACL、审批门闩 |
| SQL 改写 | `PluginDecision::Rewrite` 或独立义务 | 行过滤谓词（慎用） |
| Post-execute | **新建**（`map_response_types` 后、`encode` 前） | 脱敏、水印 |
| 始终 | 结构化 audit | 合规 |

**最大技术债**：统一的 **SQL 对象抽取**（schema/table/column + 操作类型），见 S1/S2。

---

## 3. 竞品能力矩阵与差距

### 3.1 产品形态对照

| 维度 | Data Nexus（升级后目标） | 美创数据防水坝 | 数安 SQLDev 类 |
|------|--------------------------|----------------|----------------|
| 本质 | 协议 PEP + 统一策略平台 | 数据访问防泄漏 / 合规 | 安全 SQL 开发门户 |
| 主路径 | 原生 MySQL/PG 协议 | 多通道代理/旁路 | 浏览器 / IDE |
| 主用户 | 应用 + 运维 + 安全 +（后期）开发 | 安全 / 合规 / 业务 | 开发 / 分析 + 安全 |
| 差异化 | 协议中立、跨协议子集、云原生观测 | 脱敏/水印/外发/等保话术 | 项目环境 / 写 SQL 体验 |

### 3.2 功能矩阵

| 能力域 | 防水坝 | SQLDev | Data Nexus 现状 | 升级后目标阶段 |
|--------|:------:|:------:|:---------------:|:--------------:|
| 协议代理 / 流量入口 | ● | ○ | **● 强** | L0 持续 |
| 跨协议受控 | ○ | ○ | **●** | L0 差异化 |
| 管理面 SSO / RBAC | ● | ● | **●** | 已完成 |
| 数据面身份（人/应用） | ● | ● | ○ | S1 |
| 库/表 ACL | ● | ● | — | S1–S2 |
| 列级授权 | ● | ○ | — | S2 |
| 行级控制 | ● | ○ | — | S3 |
| 动态脱敏 | ● | ○ | — | S3 |
| 水印 | ● | ○ | — | S3–S4 |
| 审批工单 | ● | ● | — | S5 |
| 金库 | ● | ○ | — | S5 |
| 账号保险箱 | ● | ● | — | S6 |
| 终端 / 导出通道 | ● | ○ | — | S5–S6 |
| 审计与合规报表 | ● | ● | ○ 日志 | S4 |
| 开发者 SQL 门户 | ○ | ● | — | S6 |
| 项目 / 环境权限 | ○ | ● | — | S6 |
| 可观测 / 多协议 metrics | ○ | ○ | **●** | 优势保持 |
| 插件化治理 | ○ | ○ | ● regex | S1+ 语义化 |

图例：● 强 / ○ 弱或部分 / — 无

### 3.3 差距与竞争策略

1. **不要一次性对等防水坝全家桶**；用 S0–S6 渐进，否则毁掉网关交付节奏。  
2. **护城河**：协议原生强制管控（应用可不改门户）+ 多协议统一策略 + 可选跨协议。  
3. **SQLDev 能力**是门户层：可建在同一 PEP 之上，**禁止**门户直连生产库绕过网关。  
4. **与竞品关系**：可替代、可并行、可被上层安全平台调用 PDP；销售话术需从「纯中转」升级为「协议执行点 + 策略中心」，并备齐审计/脱敏验收项后再对标合规。

---

## 4. 目标架构

### 4.1 原则

| 原则 | 说明 |
|------|------|
| 网关 = PEP | 数据面流量必经；decode/encode 主路径不推倒 |
| PDP 可本地可远程 | S0–S2 进程内；S5+ 可外置，契约稳定 |
| 决策与义务分离 | Deny 立即拒绝；Allow + mask/watermark/row_filter 由 PEP 执行 |
| 不破坏现有插件 | circuit_break / concurrency 保留；安全策略并列、顺序可配 |
| 管理面 ≠ 数据面 | Admin JWT 不直接当数据面 Subject |
| 配置哲学对齐 | 复用 `translation_policy` 模式：命名策略 + service 引用 + default off |

### 4.2 核心类型（概念）

```text
Subject {
  subject_id, subject_type,   // human | app | service
  auth_method, client_addr, client_app,
  roles / attributes,         // groups, dept, env
  effective_db_user           // 后端实际账号，可与前端不同
}

ObjectAccess {
  catalog?, schema?, table, columns[],
  op: select|insert|update|delete|ddl|other
}

PolicyRequest {
  subject, service, listener, channel,
  sql_fingerprint, objects[], risk_hints
}

PolicyResponse {
  Allow
  | Deny { code, message }
  | RequireTicket { ticket_types[] }
  | AllowWithObligations {
      rewrite_sql?,
      mask_columns[],
      watermark?,
      max_rows?
    }
}
```

### 4.3 配置草案（目标形态）

```toml
[[security_policies]]
name = "orders-secure"
enabled = true
default_effect = "deny"   # 生产推荐；开发可 allow

# 规则 / 脱敏 / 高危门闩等随阶段扩展……

[[services]]
name = "orders"
security_policy = "orders-secure"
# 与 translation_policy、plugin_policies 并列
```

### 4.4 与现有组件关系

| 现有 | 关系 |
|------|------|
| `PluginContext` / `PluginDecision` | 可桥接安全决策，但 **PDP 逻辑独立**，避免全塞 regex plugin |
| `translation_policy` | 跨方言子集；在 security 之后或之前顺序 **可配**（建议：security → translation → execute） |
| `DialectParser` | 扩展为对象抽取，而非仅 `is_read_only` |
| Admin auth | 管「谁配置策略 / 谁审批」；数据访问 Subject 另建映射 |

---

## 5. 功能详细分析与阶段映射

### 5.1 表 / 列 / 行级授权

| 粒度 | 依赖 | 网关动作 | 阶段 |
|------|------|----------|------|
| 表 + 操作类型 | 表名抽取、Subject | Reject 或 Allow | **S1**（表 best-effort）→ **S2**（AST） |
| 列 | SELECT 列表 / 写列 | Reject 或列裁剪 | **S2** |
| 行 | 谓词注入或结果过滤 | Rewrite SQL 或过滤行 | **S3**（注入优先于结果过滤，需严格测试） |

**风险**：解析失败策略必须可配（`fail_closed` / `fail_open`）；生产默认 fail_closed + 强可观测。

### 5.2 动态脱敏 / 水印

| 能力 | 依赖 | 网关动作 | 阶段 |
|------|------|----------|------|
| 动态脱敏 | 列标签、算法、ResultSet 钩子 | 改写 `GatewayValue` | **S3** |
| 水印 | 会话/工单 ID、导出通道 | 结果集隐写或可见标记 | **S3–S4** |

算法示例：mask / partial / hash / nullify（可插拔）。  
**跨协议**：脱敏在逻辑列上执行，encode 前完成，MySQL/PG 前端共用。

### 5.3 审批工单 / 金库

| 能力 | 依赖 | 网关动作 | 阶段 |
|------|------|----------|------|
| 高危识别 | 规则（DDL、无 WHERE 更新、大导出） | `RequireTicket` | **S5** |
| 工单 | 流程、通知、审批人 | 校验 ticket 绑定 subject+SQL 指纹+时间窗 | **S5** |
| 金库 | 双人、限时、限次 | 票据未生效则阻断 | **S5** |

网关 **不实现完整 BPM**；认票据接口即可，工单可外置。

### 5.4 终端 / 外发 / 通道管控

| 能力 | 依赖 | 阶段 |
|------|------|------|
| 通道分类（协议代理 / 门户导出 / 批量作业） | channel 标签 | **S5** |
| 网络属性（IP、时段） | `client_addr` | **S1 起可做** |
| 禁止 COPY / OUTFILE / 大结果导出 | 语句识别 + max_rows | **S5–S6** |
| 深终端 Agent | 独立产品能力 | **后置**，非 S0–S4 必做 |

### 5.5 其它必备闭环能力

| 能力 | 阶段 | 说明 |
|------|------|------|
| 统一数据面身份 | S1 | 人/应用；与 IdP 映射可渐进 |
| 数据资产 / 分类分级 | S2–S3 | 驱动列脱敏；可先配置静态标签 |
| 持久化审计 + 检索 | S4 | 无此则合规话术不成立 |
| 账号保险箱 | S6 | endpoint 凭据不落客户端 |
| 开发者门户 / 环境 | S6 | SQLDev 向；流量仍过 PEP |

---

## 6. 分阶段路线 S0–S6

```text
已完成  M0–M10   协议网关 + 管理面鉴权 + UI + 观测

S0  边界修订 + 审计模型 + security 配置空壳
S1  Subject + 语句/表级 Deny（MVP PEP）
S2  AST 对象抽取 + 表/列 ACL
S3  ResultSet 钩子 + 动态脱敏（+ 行级/水印雏形）
S4  持久化审计 + 查询 API/UI
S5  审批 / 金库 + 通道高危门闩
S6  门户 / 环境 / Vault / 导出与水印运营化
```

### S0 — 边界与可观测加固

| 项 | 内容 |
|----|------|
| **目标** | 为数据安全立项立规矩；行为默认与现网一致 |
| **交付** | 本文档；`todo.md` 边界修订；`SecurityPolicyConfig` 空壳（`enabled=false`）；统一 `data_nexus::audit` 字段；Admin 写操作 audit 带 `sub` |
| **退出** | default off 全量 smoke 绿；审计字段可检索；配置可解析校验 |

### S1 — Subject + 语句/表级策略 MVP

| 项 | 内容 |
|----|------|
| **目标** | 回答「谁在哪个 service 上对哪些表做了什么操作，是否允许」 |
| **交付** | `SecurityContext`；best-effort 表名抽取；规则 user/role × service × op × table_glob；`core_engine` 挂载；拒绝错误协议化；`GET /admin/security-policies`；smoke |
| **退出** | 指定表/语句可拒绝；fail-closed/open 可配；无基线性能回归 |
| **不做** | 列/行、脱敏、审批、水印、SQL IDE |

### S2 — 对象级 ACL（表/列）

| 项 | 内容 |
|----|------|
| **目标** | 对齐防水坝「库表列权限」最小集 |
| **交付** | MySQL/PG AST visitor → `ObjectAccess[]`；列 deny；策略热更可接 reload；测试矩阵 |
| **退出** | 列级拒绝 E2E；复杂 SQL 有单测；解析失败可观测 |

### S3 — 动态脱敏 + 行级/水印雏形

| 项 | 内容 |
|----|------|
| **目标** | 防水坝核心体验：同查询不同可见性 |
| **交付** | Post-response ResultSet 钩子；mask 算法；列标签绑定；可选行谓词注入；可选水印 ID |
| **退出** | 角色 A 脱敏 / 角色 B 明文；跨协议路径一致 |

### S4 — 持久化审计与合规查询

| 项 | 内容 |
|----|------|
| **目标** | 可追溯、可出报告 |
| **交付** | sink（文件/OTLP/DB）；查询 API；data-ui Audit 页；保留周期 |
| **退出** | 放行/拒绝均可按 subject/table/decision 查询 |

### S5 — 审批 / 金库 + 通道门闩

| 项 | 内容 |
|----|------|
| **目标** | 高危操作可控 |
| **交付** | `RequireTicket`；ticket 校验（subject + 指纹 + 窗口）；高危规则；通道标签；金库双人/限时 |
| **退出** | 无票拒绝、有票放行并记审计 |

### S6 — SQLDev 向门户 + 保险箱 + 外发运营

| 项 | 内容 |
|----|------|
| **目标** | 开发者安全访问 + 生产加固 |
| **交付** | 项目/环境；门户发连接；Vault 凭据；导出限制；水印运营；与 Admin 控制台整合 |
| **退出** | 开发/生产环境策略分离；客户端无生产明文密码 |

---

## 7. S0 / S1 代码触点（开工用）

### 7.1 S0

| 动作 | 路径 |
|------|------|
| 路线图 | `docs/data-security-roadmap.md`（本文） |
| 看板 | `todo.md` |
| 配置空壳 | `gateway/core/src/config.rs`、`security` 模块占位 |
| 审计字段 | `runtime/gateway/src/core_engine.rs` |
| Admin 写 audit | `http/src/http/mod.rs` |
| 观测文档 | `examples/OBSERVABILITY.md` |

### 7.2 S1

| 动作 | 路径 |
|------|------|
| Subject 绑定 | `runtime/gateway/src/gateway.rs` |
| 会话模型 | `gateway/core/src/model.rs` |
| 抽取 / PDP | `runtime/gateway/src/dialect.rs`、新建 `security/` 或 `gateway/core` 类型 |
| PEP 挂载 | `runtime/gateway/src/core_engine.rs` |
| 配置校验 | `gateway/core/src/config.rs::validate` |
| Admin API | `http/src/http/mod.rs` |
| 示例 + smoke | `examples/security-*-gateway-config.toml`、`smoke-security-*.sh` |

**建议实现顺序**：core 类型与配置 → extractor → 进程内 PDP → core_engine 挂载 + audit → smoke → Admin 只读 API。

---

## 8. 早期非目标（S0–S2）

| 非目标 | 原因 |
|--------|------|
| 一次做齐防水坝全功能 | 范围爆炸 |
| 任意方言全量互转 | 协议规划已否决 |
| Admin JWT 直接当数据面身份 | 威胁模型不同 |
| S2 前默认行级自动注入 | 语义风险高 |
| 仅靠门户管控、无协议 PEP | 可被客户端绕过 |
| 全部 ACL 写在 plugin regex | 不可维护 |
| 重写 frontend/backend 协议栈 | 扩展点已足够 |
| 默认 fail-open 且无指标 | 虚假安全感 |

---

## 9. 风险与治理

| 风险 | 缓解 |
|------|------|
| 误拦生产流量 | 灰度、按 service 开关、紧急 bypass（金库级）、演练 |
| 解析不全 | 阶段化抽取 + 失败策略可配 + 持续补测试矩阵 |
| 脱敏性能 | 流式改写、大结果限制、采样审计 |
| 与库权限冲突 | 文档明确「叠加模型」；后端最小权限账号 |
| 合规超卖 | 脱敏+审计+审批未齐前不对外承诺等保话术 |
| 组织投入 | S0–S6 是产品线级；需单独里程碑与人力 |

---

## 10. 决策记录（建议默认）

| 议题 | 建议默认 |
|------|----------|
| 第一期最小闭环 | **S1 表级 + 审计**；列脱敏进 S3，不与 S1 强绑 |
| 身份主路径 | S1 static/map；S2+ 扩展应用身份与 IdP 属性 |
| PDP | S1–S2 **进程内**；S5 视规模外置 |
| 与内部安全产品 | 默认 **可并行**；预留 PDP API 以便对接 |
| 解析失败 | 生产 **fail_closed**；开发可 fail_open |
| 策略默认效果 | 生产 **default deny**（显式 allow） |

---

## 11. 术语表

| 术语 | 含义 |
|------|------|
| PEP | 策略执行点（本网关数据面） |
| PDP | 策略决策点 |
| Obligation | 允许时附带义务（脱敏、水印、改写） |
| Subject | 数据访问主体（人/应用） |
| 管理面 RBAC | 谁能操作 Admin API |
| 数据面授权 | 谁能对哪些数据对象执行哪些操作 |

---

## 12. 参考路径索引

| 主题 | 路径 |
|------|------|
| 产品 todo | `todo.md` |
| 协议规划 | `docs/data-nexus-protocol-gateway-plan.md` |
| Admin RBAC | `docs/admin-rbac-design.md` |
| Admin 密码 | `docs/admin-auth-password.md` |
| Core 契约 | `data-proxy/gateway/core/src/` |
| 命令引擎 | `data-proxy/runtime/gateway/src/core_engine.rs` |
| 方言/AST | `data-proxy/runtime/gateway/src/dialect.rs` |
| 插件 | `data-proxy/plugin/` |
| Admin HTTP | `data-proxy/http/src/http/` |
| UI | `data-ui/` |
| Smoke | `data-proxy/examples/smoke-*.sh` |

---

## 13. 修订记录

| 日期 | 说明 |
|------|------|
| 2026-07 | 初稿：对标防水坝/SQLDev，基于代码现状与 M0–M10 完成态，定义 S0–S6 与 PEP/PDP 架构 |

---

## 14. 小结

1. **升级方向已确认**：表/列/行、脱敏、水印、审批/金库、通道管控等进入产品范围，需用 **分阶段路线** 消化。  
2. **现有 Data Nexus 是合格 PEP 底座**；数据安全挂在 `core_engine` 与 ResultSet 钩子上，而不是另起代理。  
3. **管理面鉴权已完成，数据面授权是新体系**；二者 Subject/权限/审计字段分离。  
4. **对标防水坝/SQLDev** 时主打：协议原生强制、多协议统一策略、跨协议 + 安全组合；工单/脱敏等按 S3–S6 交付后再做强合规叙事。  
5. **下一步工程落地**：按 **S0（审计模型 + security 配置空壳 + todo 边界修订）** 开工，再进入 **S1（Subject + 表级 Deny MVP）**。
