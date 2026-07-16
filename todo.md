# Data Nexus 开发看板

**架构文档**（细节以文档为准，本文件只排期与勾选）：

| 文档 | 用途 |
|------|------|
| `docs/data-nexus-protocol-gateway-plan.md` | L0 / v1 协议网关底座 |
| `docs/data-security-roadmap.md` | 产品对标（防水坝 / 树安 SQLDEV）+ S0–S6 定义 |
| `docs/data-nexus-tech-architecture-2026.md` | **v2 技术主文档**（术语、选型、双路径、实现切片） |
| `docs/data-audit-architecture.md` | 审计/流式专项 |

---

## 0. 版本划分

```text
v1 = L0   数据库协议中转站 + 管理面鉴权 + 运维 UI + 观测     ✅ 已完成（M0–M10）
v2 = L1   数据访问安全（对标 SQLDEV：访问+脱敏+权限+审计）   ⏳ 待开发（S0–S6）
```

| 版本 | 一句话 | 状态 |
|------|--------|:----:|
| **v1** | 客户端 ↔ 网关 ↔ MySQL/PG；路由/池/跨协议/Admin | **完成** |
| **v2** | 谁在何种条件下对何对象做什么；结果如何可见；可证明审计 | **进行中（S0–S5 完成）** |

**原则**

- v2 默认 `security.enabled=false`，不破坏 v1 行为
- 管理面鉴权 ≠ 数据面 Subject
- 验收顺序对齐竞品话术：`审计 → 表权 → 列/脱敏 → 行 → 敏感识别 → 工单 → 门户`
- 非目标：主机堡垒、操作录屏、一次 30+ 库、热路径 Arrow、Admin JWT 当数据身份

**术语**：见 `docs/data-nexus-tech-architecture-2026.md` §0.2

---

## 1. 现状快照

### 1.1 v1 已完成

- [x] 同/跨协议 E2E（MySQL / PostgreSQL）
- [x] 方言 AST、路由/连接池、治理插件
- [x] Admin JWT（HMAC/JWKS）、break-glass、data-ui
- [x] Prometheus + 可选 OTel
- [x] smoke：`smoke-dual-listener` / `smoke-cross-protocol` / `smoke-cross-protocol-pg-to-mysql` / `smoke-admin-auth`

### 1.2 v2 总状态

- [x] **S0** — 边界 + 审计模型 + security 配置空壳
- [x] **S1** — Subject + 语句/表级 Deny MVP
- [x] **S2** — AST 对象抽取 + 表/列 ACL
- [x] **S3** — 动态脱敏 + 行级雏形（物化路径 MVP）
- [x] **S4** — 持久化审计 + 查询 API（Admin；UI 后置）
- [x] **S5** — 审批票据门闩（高危 DDL / 无 WHERE 写）
- [ ] **S6** — Web SQL 门户 + Vault + 导出运营
- [x] **A 轨** — 性能：流式窗口 + 同协议透传 + 跨协议流式（A1–A4 完成）

### 1.3 v1 可选增强（不挡 v2）

- [ ] OTel span 自定义 attributes / 按 service 采样
- [ ] data-ui 403 友好页

---

## 2. v2 开发总顺序（强制依赖）

```text
        ┌──────────── A 轨：性能底座（可并行）────────────┐
        │  A1 窗口流式  →  A2 边写  →  A3 透传  →  A4…   │
        └───────────────────┬────────────────────────────┘
                            │ 建议 A1 不晚于 S3
S0 壳子+审计字段
 │
 ▼
S1 Subject + 表/语句 Deny          ◄── 第一个「能卖」的安全能力
 │
 ▼
S2 列 ACL + 对象抽取
 │
 ├──────────────────────────────┐
 ▼                              ▼
S3 脱敏+行级（依赖流式更佳）    S4 持久审计（可与 S3 后半并行）
 │                              │
 └──────────┬───────────────────┘
            ▼
         S5 审批/通道
            ▼
         S6 门户/Vault
```

**推荐串行主线**（产品验收）：

```text
S0 → S1 → S2 → S3 → S4 → S5 → S6
```

**推荐并行**

- [ ] S0 ∥ A1 设计（配置壳 + 流式 API 设计）
- [ ] S2 ∥ A1 落地（列权限设计时后端已能窗口读）
- [ ] S3 ∥ 审计 sink 增强（脱敏与文件/OTLP 可并行）
- [ ] S4 ∥ S5 前期（审计 UI 与工单模型可错开人力）

**不要并行**：S1 未完成就做 S3 脱敏（没有 Subject/决策语义）。

---

## 3. v2 功能清单（按能力域）

> 完成后改为 `- [x]`；细节勾选以第 4 节阶段任务为准。

- [x] **F04** 数据面 Subject 绑定 — 身份 — S1 — P0
- [x] **F05** 语句类管控 DQL/DML/TCL/DDL — 数据访问 — S1 — P0
- [x] **F06** 表级 Allow/Deny — 权限 — S1 — P0
- [x] **F07** Local PDP + Decision — 策略引擎 — S1 — P0
- [x] **F28** 策略热更（失败 keep-old） — 运维 — S1（security 变更重建 listener）
- [x] **F08** AST → ObjectSet（表/列/操作） — 细粒度前置 — S2 — P0
- [x] **F09** 列级 ACL（投影剔除/拒绝） — 字段权限 — S2 — P0
- [x] **F10** SQL 改写义务（列剔除 + 行谓词注入） — 权限执行 — S2–S3 — P0
- [x] **F11** 结果侧动态脱敏 Mask（物化路径） — 数据脱敏 — S3 — P0
- [x] **F12** 行级过滤（SQL 谓词注入优先） — 行级管控 — S3 — P0
- [x] **F13** 敏感列标签 / 规则绑定 MVP — 敏感识别 — S3 — P1
- [ ] **F14** 水印雏形 — 防泄漏 — S3–S4 — P2
- [x] **F15** 审计持久化 + 查询 API（Admin）— 合规审计 — S4 — P0（data-ui 页后置）
- [x] **F16** 审计分级 L0 默认 + 有界队列背压 — 高性能审计 — S4 — P0
- [x] **F17** 高危规则 + 审批票据 — 工单 — S5 — P1
- [ ] **F18** 金库（双人/限时/限次增强） — 金库 — S5 — P2（MVP 已有 ttl/max_uses）
- [x] **F19** 通道标签雏形（protocol 默认；export 规则 kind） — 通道管控 — S5 — P1
- [x] **F20** 导出/OUTFILE/COPY 门闩 kind=export — 外发 — S5 — P1
- [ ] **F21** Web SQL 门户（经 PEP） — SQLDEV 体验 — S6 — P2
- [ ] **F22** 项目/环境权限 — 多租户运营 — S6 — P2
- [ ] **F23** 账号保险箱 / Vault — 凭据 — S6 — P2
- [x] **F24** 同协议结果透传（MySQL Wire）— 性能 — A3 — P0
- [x] **F25** Backend 窗口读 + Frontend 分阶段窗口 encode（A1/A2）— 性能 — P0
- [ ] **F26** Cedar PDP（可选 feature） — 高级策略 — S2+ — P2
- [ ] **F27** 时间维策略 — 高级策略 — S5 — P2

---

## 4. 分阶段开发计划（详细勾选）

### 4.0 进入 v2 的门槛（开工前）

- [ ] 四条 v1 smoke 本地/CI 再确认全绿
- [ ] 团队确认：v2 default off、fail-closed 默认、非目标列表
- [ ] 读过术语表 §0.2 与 roadmap §3

**L0 验收命令**

| 场景 | 命令 |
|------|------|
| 同协议双 listener | `./data-proxy/examples/smoke-dual-listener.sh` |
| MySQL → PG | `./data-proxy/examples/smoke-cross-protocol.sh` |
| PG → MySQL | `./data-proxy/examples/smoke-cross-protocol-pg-to-mysql.sh` |
| Admin 鉴权 | `./data-proxy/examples/smoke-admin-auth.sh` |

---

### S1 — Subject + 语句/表级 Deny（MVP PEP） ✅

| 项 | 内容 |
|----|------|
| **目标** | 「谁在哪个 service 对哪些表做哪类操作，是否允许」 |
| **退出** | 指定用户/表/语句可拒绝；协议错误可理解；有 smoke |

**功能 / 任务**

- [x] `Subject` 绑定（`protocol_user` → `subject_id`）
- [x] 语句分类：select/insert/update/delete/ddl/tcl/other
- [x] best-effort 表名抽取 + glob
- [x] Local PDP：`LocalPdp` + `SecurityDecision`
- [x] `core_engine` pre-execute Deny（`security_deny`，不访问后端）
- [x] `fail_closed` 用于空 SQL / EXECUTE 未分类
- [x] `GET /admin/security-policies`
- [x] `smoke-security-deny.sh` + `security-deny-gateway-config.toml`
- [x] reload：`security_changed` 时重建 listener（校验失败 keep-old 沿用既有）

**代码**：`gateway/core/src/pdp.rs`、`runtime/gateway/src/core_engine.rs`、`http` Admin API、`examples/smoke-security-deny.sh`

**不做**：列/行、脱敏、审批、门户、完整 AST ObjectSet（S2）

---

### S2 — 对象抽取 + 表/列 ACL ✅

| 项 | 内容 |
|----|------|
| **目标** | 库表列权限最小集（对齐 SQLDEV 细粒度前置） |
| **退出** | 列级拒绝 E2E；复杂 SQL 有单测；解析失败可观测 |

**功能 / 任务**

- [x] MySQL/PG AST visitor → `ObjectAccess[]` / `ObjectSet`（`runtime/gateway/src/object_extract.rs`）
- [x] 列级 allow/deny；`SELECT *` 策略 `star_policy=deny|allow`（默认 deny，无 schema 展开）
- [x] SQL 改写：SELECT 投影剔除无权限列（启发式）；无法改写则 Deny
- [x] 多表 JOIN / 别名 / schema 限定单测矩阵（object_extract + pdp）
- [x] 解析失败路径：warn 日志 + `fail_closed` Deny
- [x] Admin：文件加载策略 + `GET /admin/security-policies` 暴露 columns/star_policy
- [ ] （可选 P2）Cedar feature 开关，与 Local 决策对照测试 — **延后**

**代码**：`gateway/core/src/object_set.rs`、`pdp.rs`、`security.rs`；`runtime/gateway/src/object_extract.rs`、`core_engine.rs`；`examples/smoke-security-column.sh`、`security-column-gateway-config.toml`

**不做**：schema 展开 `SELECT *`、行谓词、脱敏、Cedar、Admin 策略 CRUD

---

### A 轨 — 性能底座（与 S 并行）

**验收**：大结果 RSS 不随全表线性爆炸；无义务路径延迟接近 v1 或不显著回退。

- [x] **A1** Backend 窗口化读取 + `ExecuteMode` + `max_rows` 早截断（MySQL 窗口解码；PG max_rows）
- [x] **A2** Frontend 分阶段 encode + 窗口写出（header/rows/footer；窗口间可 await write）
- [x] **A3** 同协议结果透传（无义务；MySQL wire；PG 降级物化）
- [x] **A4** 跨协议流式（强制 Streaming + 类型映射后窗口 encode）

**A1–A4 代码**：`ExecuteMode`、`Wire`、窗口 encode、跨协议 `xproto_stream`；smoke-stream / passthrough / cross-protocol-stream

---

### S3 — 动态脱敏 + 行级 + 敏感识别 MVP ✅

| 项 | 内容 |
|----|------|
| **目标** | 同查询不同可见性；结果侧 mask（SQLDEV 动态脱敏） |
| **退出** | 脱敏 + 行级隔离可证；物化路径 MVP（流式 → A1/A2） |

**功能 / 任务**

- [x] Decision → `Obligations`（mask / row_filter / max_rows）
- [x] 结果钩子：物化 `GatewayResponse::ResultSet` 路径（SecureStream 依赖 A1/A2，后置）
- [x] Mask 算法：`nullify` / `partial` / `hash` / `replace` / `keep_prefix`
- [x] 列标签 `column_tags` 绑定 `mask_rules`
- [x] 行级：规则 `row_filter` SQL 谓词注入（失败 fail_closed 可拒）
- [x] 敏感识别 MVP：静态 column_tags（非 ML）
- [ ] （P2）水印 ID 雏形 — **延后**
- [x] `smoke-security-mask.sh` + `security-mask-gateway-config.toml`
- [x] 跨协议：义务在 IR 层执行（mask 在 map_response_types 后），同路径

**代码**：`gateway/core/src/obligations.rs`、`pdp.rs`、`security.rs`；`runtime/gateway/src/core_engine.rs` 结果义务执行

**不做**：SecureStream 窗口流式（A1）、结果侧行回退过滤、水印、按 subject 差异化角色 smoke（配置已支持 subjects glob）

---

### S4 — 持久化审计 + 查询 ✅

| 项 | 内容 |
|----|------|
| **目标** | 可追溯、可检索、可出简单合规报告 |
| **退出** | 放行/拒绝均可按 subject/decision 查 |

**功能 / 任务**

- [x] 有界队列 `AuditPipeline` + 后台 worker（`gateway/core/src/audit_pipeline.rs`）
- [x] overflow：`drop_new`（默认）/ `drop_old` / `sample`；热路径永不 block
- [x] Sink：`tracing` + JSONL `file`（OTLP/DB 后置）
- [ ] （P2）OpenDAL 样本（L2）— **延后**
- [x] Admin `GET /admin/audit/events`（decision/subject/service/limit）+ `/admin/audit/stats`
- [ ] data-ui Audit 页 — **后置**（API 已就绪）
- [ ] 保留周期 / 清理任务 — **后置**
- [x] 主路径 `try_send` 非阻塞；`dropped` 计数可观测（smoke + 单测）

**代码**：`audit_pipeline.rs`、`core_engine` try_audit、`http` Admin audit 路由；`smoke-security-audit.sh`

**不做**：OTLP Logs sink、DB 持久化、data-ui 页、Deny 独立高优队列（当前与普通事件同队列 + recent ring）

---

### S5 — 审批 / 金库 + 通道门闩 ✅

| 项 | 内容 |
|----|------|
| **目标** | 高危操作可控；网关不自建完整 BPM |
| **退出** | 无票拒绝、有票放行并记审计 |

**功能 / 任务**

- [x] 高危规则：`ddl` / `write_no_where` / `action` / `table_write` / `export`
- [x] `RequireTicket` 决策（客户端错误码 `security_require_ticket`）
- [x] Ticket：subject + SQL 指纹 + TTL + max_uses；`/*dn_ticket:<id>*/` 前缀
- [x] Admin `POST/GET /admin/tickets` 签发/列表
- [ ] （P2）双人金库、外置 BPM 回调 — **延后**
- [x] export 语句启发式门闩（OUTFILE/COPY）
- [ ] （P2）时间维策略 — **延后**
- [x] `smoke-security-ticket.sh`

**代码**：`gateway/core/src/ticket.rs`、`pdp` high_risk、`core_engine` RequireTicket 臂、`http` tickets API

**不做**：完整工单 UI、外置审批流、双人授权

---

### S6 — SQLDEV 向门户 + Vault + 导出运营

| 项 | 内容 |
|----|------|
| **目标** | 浏览器安全访问体验；**流量仍过 PEP** |
| **退出** | 环境隔离；客户端无生产明文库密 |

**功能 / 任务**

- [ ] 项目 / 环境模型
- [ ] Web SQL 门户（查询走网关或门户专用 listener，禁止直连库）
- [ ] 账号保险箱 / Vault 发短时凭据
- [ ] 导出限制与审计联动
- [ ] 水印运营化
- [ ] 与 data-ui / Admin 整合导航

**明确不做**：主机堡垒、操作录屏（可集成第三方）

---

## 5. 建议排期（可按人力压缩/拉长）

| 波次 | 阶段 | 建议产出（可对外演示） |
|------|------|------------------------|
| **W1** | S0 + A1 设计 | 配置壳、审计字段、文档一致 |
| **W2** | S1 | **表/语句级拦截** 演示 |
| **W3** | S2 + A1 落地 | 列权限 + 大结果不爆内存雏形 |
| **W4** | S3 + A2/A3 | **动态脱敏** + 透传对比 |
| **W5** | S4 | 审计可查 UI |
| **W6** | S5 | 高危工单门闩 |
| **W7+** | S6 | 门户与保险箱 |

「周」为相对单位，非日历承诺。

---

## 6. 模块边界（v2 落点）

```text
gateway/core      IR、配置、AdminAuth、Security 类型、Decision/Obligations
runtime/gateway   PEP：core_engine、Subject 绑定、路径选择、流式/透传、义务执行
security/ / policy/（可新建）  Local/Cedar PDP、规则编译缓存
parser / dialect  ObjectSet 抽取
audit/            AuditEvent、Pipeline、Sinks
http/             Admin：策略只读/CRUD、审计查询、ticket 校验回调
data-ui           运维 → 策略 / 审计 / 工单 /（S6）门户入口
```

---

## 7. 每阶段完成定义（DoD）

每个 Sx / Ax 合并前必须满足：

- [ ] 有示例 config 或 `examples/smoke-*.sh`（安全类 default 可单独脚本）
- [ ] `cargo test` / `cargo check` 相关包通过
- [ ] **v1 smoke 在 security default off 下仍全绿**
- [ ] 无新的主路径 panic；Deny/解析失败路径有指标或日志
- [ ] 更新本文件勾选 + 必要时改 roadmap/tech-architecture

---

## 8. 风险与纪律

| 纪律 | 说明 |
|------|------|
| 先壳后肉 | S0 不做真拦截也要有配置与审计字段 |
| 先表后列再脱敏 | 禁止一上来只做 mask 无 Subject |
| 流式先于大数据脱敏 | 全量物化上做 mask 仅作过渡 |
| 审计不堵查询 | 有界队列 + 可观测丢弃 |
| 门户不直连 | S6 铁律 |
| 文档同步 | 行为变更同 PR 改文档 |

---

## 9. 当前下一动作（唯一焦点）

**>>> S6 门户 / Vault（可选） <<<**

- [ ] 项目/环境模型
- [ ] Web SQL 经 PEP（禁止直连）
- [ ] 账号保险箱 / 短时凭据
- [ ] data-ui Audit 页（S4 API 已就绪）

S0–S5 + **A1–A4** 性能轨完成。  
smoke：deny / column / mask / audit / ticket / stream / passthrough / cross-protocol-stream。
