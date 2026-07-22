# Data Nexus 开发看板（未完成）

**已交付归档** → [`todo-impl.md`](todo-impl.md)  
**架构与规则**（细节以文档为准，本文件只排未完成债）：

| 文档 | 用途 |
|------|------|
| `docs/data-nexus-protocol-gateway-plan.md` | L0 / v1 协议网关底座 |
| `docs/data-security-roadmap.md` | 产品对标 + S0–S6 |
| `docs/data-nexus-tech-architecture-2026.md` | **v2 技术主文档** |
| `docs/data-audit-architecture.md` | 审计 / 流式专项 |
| `docs/ticket-vault-runbook.md` | Ticket/Vault 运维 |
| `data-proxy/docs/build-cache.md` | Cargo target 外置缓存 |
| `.claude/rules/data-nexus-development.md` | 开发强制规则 |
| `CLAUDE.md` | 规则与技能入口 |

---

## 0. 版本与原则

```text
v1 / L0     协议中转 + 管理面 + 观测          ✅ 见 todo-impl.md
v2 MVP      访问 + 脱敏 + 权限 + 审计         ✅ 见 todo-impl.md
v2.1        生产化 / 运维硬化                 ✅ 见 todo-impl.md
v2.2        真流式封顶 + 企业策略/合规         ⏳ 本文件唯一焦点
```

| 原则 | 说明 |
|------|------|
| 默认关安全 | `security.enabled=false` 不破坏 v1 |
| 身份分离 | 管理面鉴权 ≠ 数据面 Subject |
| 门户经 PEP | 禁止 UI/API 直连生产库 |
| 审计不堵查询 | 有界队列；worker 落盘/索引 |
| 配置勿静默 no-op | 未实现能力必须校验失败 |
| 诚实边界 | 部分完成标「部分」，见 §3 |

**工具链**：`CARGO_TARGET_DIR` 外置；rustc **1.94.1**。

**Smoke（本机门禁）**

```bash
cd data-proxy
./examples/run-smoke-matrix.sh default   # CI 默认
./examples/run-smoke-matrix.sh all       # + extended
./examples/run-smoke-matrix.sh cedar     # 需 --features security-cedar
```

---

## 1. P0 — 真流式 / 热路径封顶

> 目标：backend 行流 → 义务 → 编码 → 客户端；峰值内存 ≈ 1～2 个窗口。  
> A1–A4 / A07 骨架与 socket writer 已交付（见归档）。

- [ ] **A06** Backend→PEP 真行流  
  - 已有：MySQL/PG `RowStream` + channel（含事务 producer 还 lease）；smoke 双协议 max_rows（含 txn）；**Materialized Query* 升 Streaming**；encode 峰值单测；**`peak_window_rows` + Prometheus `gateway_encode_peak_window_rows`**；**`peak_window_bytes` + `gateway_encode_peak_window_bytes`**（单窗 encode 载荷高水位；smoke 多窗 peak_bytes≪total）；smoke **强制** `execute_path=streaming` + `encode_windows>0` + **peak≤window_rows**；**粗粒度进程内存 smoke**（双协议 50k；cgroup/proc/ps；绝对 cap）；**逻辑 peak 仍权威**  
  - 仍欠：控制语句/空结果 Complete 仍可小物化；**无进程/cgroup 精确 1–2 窗字节 CI**（逻辑 window-byte peak 已有；OS RSS 仍噪声大）；portal Complete 见 A09  
  - 路径：`transport`、`server/metrics`、`core_engine`、`smoke-security-stream.sh`、`smoke-security-stream-rss.sh`、`OBSERVABILITY.md`

- [ ] **A08** PostgreSQL wire 透传 + backend TLS  
  - 已有：idle pool（cap/TTL/SELECT 1）；事务 `tcp_txn`；双协议 TLS；**PG simple Query 透传**；**passthrough 下 extended：优先客户端原包 P/B/E TCP**（`passthrough_client`）；**multi-Execute 连续 client-frame**（首页 hold 无 Sync；续页只中继 Execute；Sync→`PgBackendSync` 刷 Z）；回落 **backend 重编码**（`passthrough_extended`）；否则 **`streaming_demote`**（MySQL COM_STMT）  
  - 仍欠：Streaming 仍用 pool；非自由代理（义务路径强制 Streaming 已有 smoke-security-mask 钉）  
  - 路径：`pg_client_extended_frames` + `pg_ext_tcp_hold`、`client_frames_relay_hold_into`、`PgBackendSync`、`smoke-security-passthrough.sh`

- [ ] **A09** Portal 端到端流式  
  - 已有：NDJSON + CSV + **JSON** Streaming → `backend_window`；**Complete 回退** 三格式 `chunked`（smoke：INSERT NDJSON/JSON/CSV **强制** `x-data-nexus-stream: chunked`）；JSON 分片文档 UI 可 parse；**同协议 portal smoke 钉 `window_rows=2`**；**跨协议 portal 双向** smoke 同窗；**响应头 `x-data-nexus-window-rows`**；**portal HTTP 记 Prometheus `type=PORTAL_STREAM|PORTAL_CHUNKED`**（同协议 streaming / 跨协议 **xproto_stream** + 逻辑 peak；smoke 强制 PORTAL_STREAM peak≤window，含 xproto 双向）；**OBSERVABILITY** 标明 chunked ≠ backend_window  
  - 仍欠：Complete 路径 ResultSet 在 backend 侧仍可能先物化（无 RowStream 时不可避免）；无进程 RSS 峰值 CI（逻辑 window 已钉）  
  - 路径：`http` portal_execute_*_streaming；`security-portal-gateway-config.toml`；`security-portal-xproto{,-pg-mysql}-gateway-config.toml`；`smoke-security-portal{,-xproto,-xproto-pg-mysql}.sh`

- [ ] **A10** 预处理 / 事务透传矩阵  
  - 已有：MySQL COM_STMT + Streaming + PREPARE 列定义；PG Parse/Bind/Execute + Streaming；Describe 显式 SELECT + `SELECT *` catalog；扩展协议 Execute 不发 Z；**客户端 Execute max_rows → PortalSuspended（s）**；**同 portal multi-Execute 续读**：**优先 backend `RowStream` hold**（`hold_remainder`，不重跑 SQL）；hold 不可用时 **logical skip** 回落；策略 max_rows 仍 C；Bind/Close/Sync 丢弃 hold；unit `a10_hold_remainder_keeps_stream_for_resume` + stream smoke multi-Execute；**Prometheus `gateway_portal_resume_total{mode=hold\|resume_hold\|logical_skip}`**（smoke 强制 hold+resume_hold 或 skip）；**PDP prepared Execute 继承 `streaming.max_rows`**（防 passthrough demote 绕过 cap）；**简单查询 `DECLARE/FETCH/CLOSE` 进程内命名游标**（`named_cursors`；DECLARE 不套 policy max_rows；**进程内** WITH HOLD 跨 COMMIT / 无 WITH HOLD 在 COMMIT 丢弃；**会话结束清空**；**双游标并发**；**同名 DECLARE 拒绝**；**FETCH ALL 耗尽**；**MOVE/FETCH ABSOLUTE 等 fail-closed**；metrics `sql_cursor_*`；**仍非** backend 服务端游标）  
  - 仍欠：**非** backend SQL `DECLARE … WITH HOLD` 服务端命名游标（进程内游标随 session 消亡；仅 forward FETCH）；复杂 JOIN `*` 依赖 backend prepare  
  - 路径：`transport` hold/`PrefixedRowStream`、`CoreGatewayConnection.held_portal_stream` + `named_cursors` + `Drop`、`pdp` Execute obligations、`server/metrics` portal_resume、frontend Bind/Close/Sync + `COMMIT;` 分号、`smoke-security-stream.sh`

---

## 2. P1 — 策略 / 合规 / 运维

- [ ] **B08** L2 样本 / 大 payload  
  - 已有：物化 ResultSet + Streaming 首窗（脱敏后）；`sample_enabled` 默认关；OpenDAL 可选；**validate：`sample_enabled` 必须 `default_audit_level=L2`**（防静默 no-op）；`OBSERVABILITY.md` + prod 模板诚实说明；smoke `smoke-security-audit-sample.sh` 断言 `sample_body` 有界且 **truncated 当 seed>max_rows**；UI 标明 **非 L3**；**`smoke-security-config-validate` 拒绝 L0+sample_enabled**；API/UI 暴露 **`requires_audit_level=L2` / `full_result_l3=false`**  
  - 仍欠：勿宣传「全量 L2 / L3 合规样本」；OpenDAL 上传仍需 feature；高 QPS 默认仍应关  
  - 路径：`security.rs` validate、`audit` sample attach、`OBSERVABILITY.md`、`smoke-security-audit-sample.sh`、`smoke-security-config-validate.sh`

- [ ] **H05** 多实例状态外置（含 H08 vault 文件加密）  
  - 已有：ticket/vault JSON+lock+**AES-GCM**；审计 SQLite multi-writer；LocalPdp `policy_path` mtime 轮询；prod `security.state` 模板；**vault `backend_password` ZeroizeOnDrop + revoke zeroize**；**`backend_identity` → `Zeroizing<String>`**；**Admin `security-policies.state` 只读摘要**含 **`last_writer_wins=true` / `merge_strategy=last_writer_wins` / `crdt=false` / `mlock=false` / `vault_password_zeroize=true`**；**smoke `smoke-security-state-file`** 断言 encrypt flags + 密文 + 重启 + mtime 热更 + **LWW/crdt/mlock 诚实字段** + **磁盘 last-writer 全文件替换 reload**；unit last-writer 全文件替换；UI Overview/Settings/Vault/Tickets/Policies 标明 **非 CRDT / 非 mlock**  
  - 仍欠：**无 CRDT merge**（全文件替换 last-writer-wins）；活跃 lease 密码仍在进程 RAM（**非 mlock**）；轮询默认 1s（smoke 用 200ms）  
  - 路径：ticket/vault file backend、`vault.rs` zeroize、`http` state summary、`smoke-security-state-file.sh`、prod 模板、runbook

- [ ] **H04b** 真 IdP OIDC 联调  
  - 已有：文档 + 模板  
  - 仍欠：部署侧真实回调与角色映射验收（**本仓不强制**）  
  - 路径：部署 runbook / 运维侧

- [ ] **T01** 列 ACL / 复杂 SQL 用例矩阵  
  - 已有：extract/PDP 单测；WHERE/HAVING/EXISTS/IN/标量子查询表提取；column smoke WHERE IN deny；**嵌套 SELECT 列表列 strip**（多层 derived table 单测 + `smoke-security-column` multi-level E2E）；**`*` / `t.*` / alias `e.*` 在 star_policy=deny 下拒绝**（smoke + unit；**不展开**为列再 strip）  
  - 仍欠：**`*` / `t.*` 仍不展开**（allow 时也不自动 strip 隐式列）；相关子查询表达式/极端方言仍 heuristic  
  - 路径：`object_extract`、`pdp::rewrite_select_strip_columns`、`smoke-security-column.sh`

- [ ] **F30** 敏感识别增强 — **延后**  
  - 现状：仅 `column_tags` + mask 规则  
  - 非目标：全量 DLP  
  - 未点名勿静默当完成

---

## 3. P3 — 边界扩展（明确后置）

- [ ] **P01** 新协议（Redis/…）— **延后**
- [ ] **P02** 深终端 Agent — **不做/后置**
- [ ] **P03** 审计 Parquet/分析（DataFusion 可选）— **延后**
- [ ] **P04** Sharding rewrite（`gateway_core` stub）— **延后**

---

## 4. 已知限制（诚实账，勿当已交付宣传）

| 主题 | 限制 |
|------|------|
| Portal「流式」 | A09 NDJSON+CSV+JSON：Streaming → `backend_window`（**双向跨协议 portal** MySQL↔PG）；**Complete → `chunked`**；**`x-data-nexus-window-rows` 头**（CSV 可钉窗）；backend 无 RowStream 时仍可能先物化；无进程峰值 CI |
| 脱敏大数据 | A06 Streaming 真窗口（含 txn）；Query* Materialized 已升 Streaming；**逻辑 peak_window_rows + peak_window_bytes**（多窗 smoke peak_bytes≪total）；**粗粒度内存 smoke**（双协议；cgroup/proc/ps；多窗 encode 下限）；非进程精确 1–2 窗字节；控制语句/Complete 小结果仍可物化 |
| PG/MySQL backend TLS | A08：simple Query `passthrough`；**extended 优先 `passthrough_client`（客户端原包单元 TCP）**；回落 `passthrough_extended`；MySQL COM_STMT `streaming_demote`；multi-Execute hold 仍 Streaming |
| 预处理语句 | A10：协议 smoke + mysql description + **psycopg 同连接 rebind** + **PortalSuspended + multi-Execute 续读（优先 RowStream hold；logical skip 回落；`gateway_portal_resume_total`）**；**简单查询 DECLARE/FETCH/CLOSE 进程内游标**（`sql_cursor_*`；无 WITH HOLD 在 COMMIT 丢弃；WITH HOLD 跨 COMMIT 但**断连即死**；**非** backend 服务端游标）；策略截断仍 C |
| 多副本 | H05：file+lock+可选 AES-GCM；全文件替换 last-writer-wins（`merge_strategy`/`crdt=false` API）；活跃 vault 密码在 RAM；revoke/prune/Drop **Zeroize**（`vault_password_zeroize=true`，**非 mlock**）；`backend_identity` 返回 Zeroizing |
| L2 样本 | B08：默认关；有界 rows/bytes；**sample_enabled 强制 L2**；OpenDAL 需 feature；**非全量 L3** |
| Remote PDP | F31 已交付：表/动作 gate；超时 fail_closed；**非**热路径逐行 mask |
| Cedar ABAC | F29 已交付：静态 `subject_attrs`/`table_attrs`；非动态 IdP 同步 |
| 复杂 SQL / 列 ACL | T01：表可抽；**嵌套 SELECT 列表可 strip 列**；`*` / `t.*` **不展开**（deny 时整句拒绝；allow 时不隐式 strip） |

---

## 5. 当前下一动作（唯一焦点）

**>>> A 轨剩余诚实债 或 体验小刀 或 下一产品切片 <<<**

建议优先级：

1. **A10** backend SQL `DECLARE … WITH HOLD` 服务端游标（可选；进程内 `named_cursors` + `sql_cursor_*` + UI 诚实提示已有）  
2. **H05** CRDT merge / mlock（可选；LWW + Zeroize + `vault_password_zeroize` 诚实字段已有）  
3. **A06** 进程/cgroup 精确 1–2 窗字节 CI（可选；逻辑 peak_window_bytes 已有）  
4. 体验小刀；**F30/P0x 延后项未点名勿做**

```bash
# A 轨相关回归入口
./examples/smoke-security-stream.sh
./examples/smoke-security-portal.sh
./examples/smoke-security-portal-xproto.sh
./examples/smoke-security-portal-xproto-pg-mysql.sh
./examples/smoke-security-passthrough.sh
cargo test -p postgresql_protocol a10_decodes_bind
cargo test -p runtime_gateway --lib a10_prepared_execute_streaming
cargo test -p http@0.1.0 --lib a09_portal_prepare
```

---

## 6. 完成定义（DoD）

每个任务合并前：

- [ ] 有 smoke 或单测  
- [ ] 相关 `cargo test` / `cargo check` 通过（feature 任务在对应 feature 下测）  
- [ ] `security.enabled=false` 不破坏 v1 行为  
- [ ] 更新本文件勾选；**整项完成后**迁入 [`todo-impl.md`](todo-impl.md) 并删本文件对应条  
- [ ] 行为变更同步规则 / 必要架构文 / §4 诚实账  
- [ ] `git commit`（scope 清晰，带看板 ID）  

部分完成：保持 `- [ ]`，更新「已有 / 仍欠」，**不要**假装勾完。

---

## 7. 纪律

| 纪律 | 说明 |
|------|------|
| 门户不直连 | S6 铁律 |
| 审计不堵查询 | 有界队列；归档/索引在 worker |
| 流式先于大数据脱敏 | 禁止把 HTTP chunk 说成端到端流式 |
| 默认二进制精简 | Cedar/OpenDAL/OTel 继续 optional feature |
| 配置勿静默 no-op | 未实现能力必须校验失败 |
| 文档同步 | 行为变更同 PR 改看板 / 规则 |
| 构建缓存外置 | 禁止仓库内多 GB `.cargo-target*` |
| 规则优先 | 铁律 > `.claude/rules` > 架构文 > 本看板 |

---

修订：未完成债在本文件；已交付历史见 [`todo-impl.md`](todo-impl.md)。
