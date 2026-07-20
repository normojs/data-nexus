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
  - 已有：MySQL/PG `RowStream` + channel（含事务 producer 还 lease）；smoke 双协议 max_rows（含 txn）；**Materialized Query* 升 Streaming**；encode 峰值单测；**`StreamingEncodeStats.peak_window_rows` + Prometheus `gateway_encode_peak_window_rows`**（逻辑峰值高水位，非 RSS）；smoke **强制** `execute_path=streaming` + `encode_windows>0` + **peak≤window_rows**  
  - 仍欠：控制语句/空结果 Complete 仍可小物化；**无进程 RSS 峰值 CI**（仅逻辑窗口峰值）；portal Complete 见 A09  
  - 路径：`transport`、`server/metrics`、`core_engine`、`model::ExecuteMode`、`smoke-security-stream.sh`

- [ ] **A08** PostgreSQL wire 透传 + backend TLS  
  - 已有：idle pool（cap/TTL/SELECT 1）；事务 `tcp_txn`；双协议 `ssl_mode` + `ssl_ca_file` / `ssl_accept_invalid_certs`；**默认 `ssl_accept_invalid_certs=false`（verify）**；prod 模板 require+CA+verify；validate 拒绝 require+verify 无 CA；MySQL prefer 可明文回落；**PG simple Query 透传 smoke**（WireRelay + txn `tcp_txn`，与 MySQL 同脚本）  
  - 仍欠：**extended 协议不透传**（QueryParams/prepared 走 Streaming/re-encode）；Streaming 仍用 pool  
  - 路径：`backend/postgresql` + `pg_tcp_relay`、endpoint 配置与 validate、`smoke-security-passthrough.sh`

- [ ] **A09** Portal 端到端流式  
  - 已有：NDJSON + CSV + **JSON** Streaming → `backend_window`；**Complete 回退** 三格式 `chunked`；JSON 分片文档 UI 可 parse；**跨协议 portal**（MySQL SQL surface → PG backend）：translation + 列类型映射 + multi-row 三格式 `backend_window` smoke（`smoke-security-portal-xproto.sh`，`window_rows=2`）  
  - 仍欠：Complete 路径 ResultSet 在 backend 侧仍可能先物化（无 RowStream 时不可避免）；无进程峰值 CI；反向 PG→MySQL portal 未单独 smoke  
  - 路径：`http` portal_execute_*_streaming + `portal_prepare` translation；`security-portal-xproto-gateway-config.toml`；`smoke-security-portal{,-xproto}.sh`

- [ ] **A10** 预处理 / 事务透传矩阵  
  - 已有：MySQL COM_STMT + Streaming + PREPARE 列定义；PG Parse/Bind/Execute + Streaming；Describe 显式 SELECT + `SELECT *` catalog；扩展协议 Execute 不发 Z；**客户端 Execute max_rows 截断 → PortalSuspended（s）**（策略 max_rows 仍 C）；`StreamingEncodeStats.truncated` + core_engine 折叠 page 进 encode max_rows；协议 smoke（policy C + page 独立网关 max_rows=100 强制 `s`）+ mysql description + psycopg 同连接 rebind  
  - 仍欠：非 TCP passthrough；PortalSuspended 后 **真游标续读**（当前 re-Execute 会重跑 SQL / drain 剩余）；复杂 JOIN `*` 依赖 backend prepare  
  - 路径：frontend/backend mysql+pg、`SessionState.pg_execute_max_rows`、`encode_portal_suspended`、`security-stream-page-gateway-config.toml`、`smoke-security-stream.sh`

---

## 2. P1 — 策略 / 合规 / 运维

- [ ] **B08** L2 样本 / 大 payload  
  - 已有：物化 ResultSet + Streaming 首窗（脱敏后）；`sample_enabled` 默认关；OpenDAL 可选  
  - 仍欠：默认关与有界语义文档化到位；勿宣传「全量 L2 合规样本」  
  - 路径：audit sample attach、`audit-opendal` feature

- [ ] **H05** 多实例状态外置（含 H08 vault 文件加密）  
  - 已有：ticket/vault JSON+lock+**AES-GCM**；审计 SQLite multi-writer；LocalPdp `policy_path` mtime 轮询；prod `security.state` 模板  
  - 仍欠：**全文件替换非 CRDT**；**进程内存 vault 密码仍明文**；轮询默认 1s  
  - 路径：ticket/vault file backend、prod 模板

- [ ] **H04b** 真 IdP OIDC 联调  
  - 已有：文档 + 模板  
  - 仍欠：部署侧真实回调与角色映射验收（**本仓不强制**）  
  - 路径：部署 runbook / 运维侧

- [ ] **T01** 列 ACL / 复杂 SQL 用例矩阵  
  - 已有：extract/PDP 单测；WHERE/HAVING/EXISTS/IN/标量子查询表提取；column smoke WHERE IN deny  
  - 仍欠：**列 rewrite 不深改嵌套 SELECT 列表**；极端方言/解析失败仍 heuristic  
  - 路径：`object_extract`、PDP column rewrite、smoke

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
| Portal「流式」 | A09 NDJSON+CSV+JSON：Streaming → `backend_window`（**含跨协议 MySQL→PG portal**）；**Complete → `chunked`**；backend 无 RowStream 时仍可能先物化；无进程峰值 CI |
| 脱敏大数据 | A06 Streaming 真窗口（含 txn）；Query* Materialized 已升 Streaming；**逻辑 peak_window_rows 指标+smoke≤window**；控制语句/Complete 小结果仍可物化；**非进程 RSS CI** |
| PG/MySQL backend TLS | A08：默认 accept_invalid=**false**（verify）；dev 可显式 true；prod 模板 require+CA；simple Query 透传有 smoke；**非 extended 透传** |
| 预处理语句 | A10：协议 smoke + mysql description + **psycopg 同连接 rebind** + **PortalSuspended（客户端 page）**；策略截断仍 C；真游标续读未做；非 TCP passthrough |
| 多副本 | H05：file+lock+可选 AES-GCM；全文件替换非 CRDT；进程内存 vault 密码仍明文 |
| L2 样本 | B08：默认关；有界 rows/bytes；OpenDAL 需 feature |
| Remote PDP | F31 已交付：表/动作 gate；超时 fail_closed；**非**热路径逐行 mask |
| Cedar ABAC | F29 已交付：静态 `subject_attrs`/`table_attrs`；非动态 IdP 同步 |
| 复杂 SQL / 列 ACL | T01：表可抽；**列 rewrite 不深改嵌套 SELECT** |

---

## 5. 当前下一动作（唯一焦点）

**>>> A 轨剩余诚实债 或 体验小刀 或 下一产品切片 <<<**

建议优先级：

1. **A08** extended 透传（可选；当前 simple Query 已透传）  
2. **A06/A09** 进程峰值 CI（可选）或 A09 反向 PG→MySQL portal smoke  
3. **A10** PortalSuspended 真游标续读（可选）  
4. **H05** 多副本语义 / 进程内 vault 明文边界  
5. 体验小刀；**F30/P0x 延后项未点名勿做**

```bash
# A 轨相关回归入口
./examples/smoke-security-stream.sh
./examples/smoke-security-portal.sh
./examples/smoke-security-portal-xproto.sh
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
