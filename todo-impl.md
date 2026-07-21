# Data Nexus 已交付归档

**未完成债** → [`todo.md`](todo.md)  
本文件只记**已完成**切片与历史提交近端，避免主看板膨胀。新完成项从 `todo.md` 迁入此处并勾选。

---

## 0. 版本主线（已完成）

| 版本 | 一句话 | 状态 |
|------|--------|:----:|
| **v1 / L0** | 客户端 ↔ 网关 ↔ MySQL/PG；路由/池/跨协议/Admin | **完成** |
| **v2 MVP** | 谁在何种条件下对何对象做什么；结果如何可见；可证明审计 | **完成** |
| **v2.1** | 可上线：CI、密钥、冷归档、审计检索、策略运维、UI | **主线完成** |
| **v2.2** | 真流式封顶 + ABAC/样本/Remote PDP | **进行中** → 见 `todo.md` |

### 主线清单

- [x] **v1 / L0**：双协议、跨协议、Admin JWT/OIDC 雏形、data-ui、观测、smoke  
- [x] **S0–S6**：配置壳、表/语句/列 ACL、脱敏与行级、审计管道、票据、门户+Vault  
- [x] **A1–A4**：窗口读、窗口 encode、同协议透传（MySQL wire）、跨协议流式 encode  
- [x] **P1**：水印 F14、L0 回归 B01、403 页 B02  
- [x] **P2**：双人金库 F18、时间窗 F27、Cedar F26/F26b、OTel B03、审计轮转+OpenDAL B04、portal 导出 B05  
- [x] **P3 主线**：H01–H04、B04c/B05b/B06/B07、F28、A05、UI01/UI02、smoke 硬化  

### 关键 smoke（矩阵规模；发版前 `all`+`cedar`）

| 组 | 脚本数 | 内容 |
|----|:------:|------|
| `l0` | 4 | admin-auth / dual-listener / cross-protocol ×2 |
| `security-core` | 9 | deny / column / mask / audit / **audit-sample** / ticket / portal / vault / **state-file** |
| `security-extended` | 8 | stream / passthrough / watermark / dual-control / time / xproto-stream / **portal-xproto×2** |
| `cedar` | 2 | cedar + cedar-reload（需 `--features security-cedar`） |
| **default** | **13** | l0 + security-core |
| **all** | **21** | default + security-extended（不含 cedar） |

### 可选 Cargo features

| Feature | 用途 |
|---------|------|
| `otel` | OTLP 导出 + 业务 metrics |
| `security-cedar` | Cedar 表/动作 PDP + 热更新 |
| `audit-opendal` | 轮转 JSONL 的 OpenDAL 归档（`fs` / `memory` / `s3` / `oss`） |

### 代码落点（稳定）

```text
gateway/core     security / pdp / cedar_pdp / obligations / audit_* / ticket / vault / transport
runtime/gateway  core_engine PEP、流式/透传、object_extract
http             Admin API（策略/审计/票据/门户/Cedar reload）
data-ui          运维台 + SQL Portal + Audit + Tickets + Vault + Cedar
examples/        smoke + gateway config 样例
.claude/         rules + skills + commands
```

---

## 1. 切片完成表（按交付）

| ID | 项 | 提交（近端） |
|----|----|--------------|
| S0–S6 | 安全主线 MVP | … → portal 等 |
| A1–A4 | 性能双路径骨架 | `332573e`…`4a3094f` |
| F14 | 结果水印 | `4a9d995` |
| B01 | L0 smoke 回归 | `ae04aa0` |
| B02 | data-ui 403 | `66a9761` |
| F18 | 双人金库 | `cbc196e` |
| F27 | 时间维策略 | `bd6588e` |
| B05 | portal CSV/NDJSON | `507890e` |
| F26 | Cedar PDP | `bd15913` |
| F26b | Cedar 热更新 | `82974f9` |
| B03 | OTel 安全属性 | `b6fe519` |
| B04 | JSONL 轮转/保留 | `120252f` |
| B04b | OpenDAL fs/memory | `0dda947` |
| B04c | OpenDAL S3/OSS | `4118e80` |
| B05b | portal HTTP 真流式 NDJSON | `b0343be` |
| B07 | Deny 高优审计队列 | `26ce55c` |
| B06 | 审计 SQLite 检索索引 | `bc88b36` |
| F28 | Local 规则热更新 | `b642c29` |
| A05 | 透传路径观测补齐 | `25bc948` |
| UI01 | 票据/金库管理页 | `e3d16ed` |
| UI02 | Cedar 状态页 | `e3d16ed` |
| H01–H04 | 生产配置 / CI 矩阵 / Vault 硬化 / OIDC 文档 | `16abb2b`…`9325215` |
| chore | rustc 1.94.1 + smoke 硬化 | `ff88c73` |
| chore | 开发规则 + 审计债小修 | `6ff8cef` |
| chore | Claude skills/rules/commands | `91abab3` |
| A09 | portal NDJSON backend 窗口流（部分进展，整项仍开） | feat(a09) |
| A06 | PG 非事务 Streaming yield（部分进展） | feat(a06) |
| A10 | prepared 注册表 + encode（部分进展） | feat(a10) |
| A10 | 参数绑定 + PG 扩展协议解码（部分进展） | feat(a10) |
| A06 | 事务内 Streaming 还 lease（部分进展） | feat(a06) |
| H06 | origin 同步完成 | `223f2c0` |
| A10 | prepare param defs + PG ParameterDescription（部分进展） | feat(a10) |
| A08 | PG 非事务 TCP 帧中继 + WireRelay | feat(a08) |
| A08 | PG 事务内 TCP 帧中继（tcp_txn 复用） | feat(a08) |
| A08 | 非事务 TCP idle pool（按 address\|db\|user） | feat(a08) |
| A08 | idle pool TTL（默认 30s） | feat(a08) |
| A08 | idle 主动健康探测 SELECT 1 | feat(a08) |
| A08 | backend SSL（ssl_mode disable/prefer/require） | feat(a08) |
| F32 | 审计 L0/L1 SQL 载荷裁剪 | feat(f32) |
| A10 | MySQL binary resultset after Execute（部分进展） | feat(a10) |
| H05 | ticket/vault file state backend（部分进展） | feat(h05) |
| A10 | MySQL DATE/TIME/DATETIME binary encode（部分进展） | feat(a10) |
| A10 | PG Bind result_format binary portal 结果（部分进展） | feat(a10) |
| A10 | PG date/timestamp/time binary encode（部分进展） | feat(a10) |
| A10 | QueryParams + prepare/bind Execute（部分进展） | feat(a10) |
| A10 | 连接级 Statement 缓存（QueryParams） | feat(a10) |
| A10 | QueryParams Streaming 窗口 yield | feat(a10) |
| H05 | ticket/vault file advisory locks（部分进展） | feat(h05) |
| H05 | audit SQLite multi-writer + LocalPdp policy_path（部分进展） | feat(h05) |
| H05 | LocalPdp policy_path mtime 轮询热更（部分进展） | feat(h05) |
| H05 | vault 文件 AES-GCM 加密 + 密钥恢复 secret（部分 / H08） | feat(h05) |
| H05 | ticket 文件 AES-GCM 加密（`ticket_encrypt_key`） | feat(h05) |
| A08 | backend SSL `ssl_mode` disable/prefer/require | feat(a08) |
| A06 | smoke 双协议 max_rows + streaming metrics（部分进展） | feat(a06) |
| A09 | portal multi-row NDJSON 强制 backend_window（部分进展） | feat(a09) |
| H07 | CI extended/cedar jobs + nightly schedule + rustc 1.94.1 | feat(h07) |
| A08 | backend TLS `ssl_ca_file` + `ssl_accept_invalid_certs`（部分进展） | feat(a08) |
| A10 | MySQL QueryParams COM_STMT prepare/bind（部分进展） | feat(a10) |
| A10 | MySQL QueryParams Streaming 窗口 yield（部分进展） | feat(a10) |
| O01 | Secure 路径 mask/window/audit 指标 | feat(o01) |
| A06 | 事务内 Streaming max_rows 双协议 smoke（部分进展） | feat(a06) |
| A09 | portal json/csv 物化边界 smoke（部分进展） | feat(a09) |
| A09 | portal CSV backend_window 流式 + json 仍物化（部分进展） | feat(a09) |
| A10 | PG prepared Execute Streaming 与 QueryParams 对齐（部分进展） | feat(a10) |
| A10 | 协议路径 prepared max_rows smoke + Bind/row 兼容（部分进展） | feat(a10) |
| T01 | 列 ACL / 复杂 SQL 矩阵（部分进展） | feat(t01) |
| T01 | WHERE/HAVING/JOIN 子查询表提取 | feat(t01) |
| H05 | multi-instance file bundle + prod state template（部分进展） | feat(h05) |
| A08 | MySQL backend TLS via ssl_mode/ssl_ca_file（部分进展） | feat(a08) |
| A08 | MySQL prefer 明文回落（服务端无 CLIENT_SSL） | feat(a08) |
| A10 | MySQL binary DATE/TIME/DATETIME ISO 解码 | feat(a10) |
| A08 | 生产 TLS pin require+CA（validate） | feat(a08) |
| A10 | MySQL ISO string 参数绑 DATE/TIME/DATETIME | feat(a10) |
| A10 | PG ISO string 参数绑 DATE/TIME/TIMESTAMP | feat(a10) |
| B08 | Streaming 首窗样本（脱敏后） | feat(b08) |
| F31 | Remote PDP HTTP 旁路（表/动作） | feat(f31) |
| F31 | 架构文档 Remote PDP 收口 | docs(f31) |
| H06 | post-F31 full smoke all+cedar（已 push 前验证） | chore(h06) |
| UI04 | 策略只读页 + security-policies 扩展字段 | feat(ui04) |
| T02 | Ticket/Vault 运维 runbook | feat(t02) |
| UI03 | Audit stats 卡片 + source 角标 + 导出 | feat(ui03) |
| B08 | L2 结果样本 attach + 可选 OpenDAL | feat(b08) |
| F29 | Cedar 实体属性 tenant/clearance | feat(f29) |
| H06 | 本地 full smoke all+cedar 发版验证（未 push） | chore(h06) |
| H06 | push origin/main 至 `47faec5` | chore(h06) |
| A09 | portal CSV backend_window（`dae6294`） | feat(a09) |
| A10 | PG Execute Streaming（`564b231`） | feat(a10) |
| A10 | 协议 smoke prepared Streaming max_rows（`a3140b9`） | feat(a10) |
| A09 | portal JSON backend_window 分片文档 + multi-row smoke | feat(a09) |
| A10 | PG Describe 显式 SELECT → RowDescription + psycopg smoke | feat(a10) |
| A06 | Materialized Query* 升 Streaming + peak-window 单测 | feat(a06) |
| A10 | SELECT * catalog DescribeSql + RowDescription | feat(a10) |
| A09 | Complete 回退 CSV/JSON/NDJSON 窗口 chunked | feat(a09) |
| A10 | same-conn re-Bind/Execute RowDescription fix | feat(a10) |
| A06 | peak_window_rows metric + smoke ≤ window_rows | feat(a06) |
| A10 | MySQL COM_STMT_PREPARE result column defs | feat(a10) |
| A10 | extended Execute omits ReadyForQuery (same-conn rebind) | fix(a10) |
| A10 | client Execute max_rows → PortalSuspended footer | feat(a10) |
| A09 | portal cross-protocol MySQL→PG backend_window smoke | feat(a09) |
| A08 | default ssl_accept_invalid=false + PG passthrough smoke | feat(a08) |
| A09 | portal reverse cross-protocol PG→MySQL backend_window smoke | feat(a09) |
| H05 | vault backend_password ZeroizeOnDrop + runbook honesty | feat(h05) |
| A10 | PortalSuspended multi-Execute logical skip resume | feat(a10) |
| A08 | passthrough demotes extended QueryParams to Streaming + smoke | feat(a08) |
| B08 | sample_enabled requires L2 + audit sample smoke + docs | feat(b08) |
| T01 | nested SELECT list column strip rewrite | feat(t01) |
| T01 | multi-level nested SELECT column strip E2E smoke | feat(t01) |
| A09 | portal same-protocol smoke pins window_rows=2 | feat(a09) |
| A09 | portal Complete INSERT forces stream=chunked smoke | feat(a09) |
| A09 | portal Complete INSERT CSV stream=chunked smoke | feat(a09) |
| UI06 | Vault/Tickets pages show H05 state summary | feat(ui06) |
| UI07 | Portal Context shows gateway streaming window_rows | feat(ui07) |
| UI08 | Portal result meta shows stream badge + window_rows | feat(ui08) |
| UI09 | Tickets dual-control self-approve guard + admin subject | feat(ui09) |
| UI10 | Audit Sample detail expand for B08 sample_body | feat(ui10) |
| UI11 | Tickets disable self-approve; Portal stream path hint | feat(ui11) |
| UI12 | Audit CSV export includes B08 sample_* columns | feat(ui12) |
| UI13 | Portal truncated explains client vs policy max_rows | feat(ui13) |
| UI14 | Audit table Level column (audit_level) | feat(ui14) |
| chore | streaming rule INSERT chunked honesty; tickets dual-control hint | chore |
| UI03 | Audit table Sample column for B08 sample_* | feat(ui03) |
| UI05 | Portal query status shows stream + window_rows | feat(ui05) |
| UI04 | security-policies exposes B08 audit_sample knobs | feat(ui04) |
| chore | smoke matrix inventory + portal export stream header UI | chore(smoke/ui) |
| A06 | OBSERVABILITY O01/A06 metrics + stream smoke hard-fail peak | docs(a06)/test |
| H05 | backend_identity returns Zeroizing password | feat(h05) |
| A09 | xproto portal smokes hard-assert window_rows==2 | test(a09) |
| A08 | MySQL prepared under passthrough demotes Streaming smoke | test(a08) |
| H05 | security-policies exposes state summary (no keys) | feat(h05/ui04) |
| H05 | file state + AES-GCM restart smoke (state-file) | feat(h05) |
| H05 | policy_path mtime poll E2E in state-file smoke | feat(h05) |

---

## 2. 整项已关闭（不再出现在 todo.md  backlog 主表）

下列 ID 在主看板上视为**整项完成**（子债若有则已并入其他未关项的诚实账）：

- [x] **A07** 编码直写 socket — `handle_frame_to_writer` + socket `ResponseWriter`  
- [x] **F29** Cedar 实体属性 tenant/clearance  
- [x] **F31** Remote PDP HTTP 旁路（表/动作；默认 fail_closed）  
- [x] **F32** 审计 L0/L1 SQL 载荷裁剪  
- [x] **H06** 发布与 origin 同步  
- [x] **H07** CI 矩阵加深（default PR；nightly extended+cedar）  
- [x] **UI03** Audit 页增强  
- [x] **UI04** 策略只读页  
- [x] **T02** Ticket/Vault runbook  
- [x] **O01** Secure 路径观测（Prometheus always-on）  
- [x] **B01 / B02 / B03 / B04 / B04b / B04c / B05 / B05b / B06 / B07**  
- [x] **F14 / F18 / F26 / F26b / F27 / F28**  
- [x] **H01–H04**（H04b 部署侧除外，仍在 `todo.md`）  
- [x] **UI01 / UI02**  
- [x] **A05** 透传路径观测  
- [x] **S0–S6 / A1–A4 / v1 L0**  

**仍开整项（详见 todo.md）**：A06、A08、A09、A10、B08、H05（含 H08 内存明文边界）、H04b、T01、F30（延后）、P01–P04（延后）。

---

## 3. 维护约定

1. 子切片交付：在本表追加一行（ID + 说明 + 提交），并在 `todo.md` 对应条的「已有」里更新。  
2. **整项** DoD 满足且无「仍欠」：从 `todo.md` 删除该 `- [ ]`，在本文件 §2 勾选。  
3. 禁止把延后项（F30、P0x）标完成而不改 `todo.md` 诚实账。  
4. 发版 / 同步：`todo.md` §5 下一动作 + 本文件 tip 提交即可，不必复制长架构文。

---

修订：从原 `todo.md` §1–§2 拆出；主看板仅保留未完成。
| UI15 | Audit event detail shows F32 sql_text + sample | feat(ui15) |
| F32 | smoke L0 strips sql_text on deny audit events | test(f32) |
| F32 | smoke L2 keeps truncated sql_text on sample events | test(f32) |
| F32 | OBSERVABILITY audit level payload table + UI tables | docs(f32)/feat(ui) |
| F32 | expose sql_text_max_chars on security-policies API/UI | feat(f32/ui) |
| UI16 | Audit filter by audit_level; O01 mask smoke hard-fail | feat(ui16)/test |
| B07 | smoke priority_accepted after deny + OBSERVABILITY | test(b07)/docs |
| B07 | expose audit_queue on security-policies API/UI + smoke | feat(b07/ui) |
| UI17 | Audit filter by outcome (index col + recent + UI) | feat(ui17) |
| UI18 | security-policies exposes F31 PDP remote knobs (no secrets) | feat(ui18) |
