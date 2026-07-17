# Data Nexus 开发看板

**架构文档**（细节以文档为准，本文件只排期与勾选）：

| 文档 | 用途 |
|------|------|
| `docs/data-nexus-protocol-gateway-plan.md` | L0 / v1 协议网关底座 |
| `docs/data-security-roadmap.md` | 产品对标（防水坝 / 树安 SQLDEV）+ S0–S6 定义 |
| `docs/data-nexus-tech-architecture-2026.md` | **v2 技术主文档**（术语、选型、双路径、实现切片） |
| `docs/data-audit-architecture.md` | 审计/流式专项 |
| `data-proxy/docs/build-cache.md` | Cargo target 外置缓存 |
| `.claude/rules/data-nexus-development.md` | **开发强制规则**（DoD / 铁律 / 双路径） |
| `CLAUDE.md` | 规则入口 |

---

## 0. 版本划分

```text
v1 = L0   数据库协议中转站 + 管理面鉴权 + 运维 UI + 观测     ✅ 已完成（M0–M10）
v2 = L1   数据访问安全（对标 SQLDEV：访问+脱敏+权限+审计）   ✅ MVP + P1/P2 增强已完成
v2.1      生产化 / 运维硬化 / 审计与策略深化                 ✅ P3 主线完成
v2.2      真流式封顶 + 企业策略/合规深化                     ⏳ 下一阶段（见 §3 未完成）
```

| 版本 | 一句话 | 状态 |
|------|--------|:----:|
| **v1** | 客户端 ↔ 网关 ↔ MySQL/PG；路由/池/跨协议/Admin | **完成** |
| **v2 MVP** | 谁在何种条件下对何对象做什么；结果如何可见；可证明审计 | **完成** |
| **v2.1** | 可上线：CI、密钥、冷归档、审计检索、策略运维、UI | **主线完成** |
| **v2.2** | 大数据热路径封顶 + ABAC/样本/Remote PDP | **规划中** |

**原则（不变）**

- v2 默认 `security.enabled=false`，不破坏 v1 行为
- 管理面鉴权 ≠ 数据面 Subject
- 门户 SQL 必须经 PEP，禁止直连生产库
- 非目标：主机堡垒、操作录屏、一次 30+ 库、热路径 Arrow、Admin JWT 当数据身份

**工具链**

- 日常构建：`/Volumes/fushilu/.caches/data-nexus/cargo-target`（见 `data-proxy/docs/build-cache.md`）
- **rustc 钉 1.94.1**（`data-proxy/rust-toolchain.toml`；`time`/Cedar 要求 ≥1.88）

---

## 1. 现状快照（已交付）

### 1.1 主线

- [x] **v1 / L0**：双协议、跨协议、Admin JWT/OIDC 雏形、data-ui、观测、smoke
- [x] **S0–S6**：配置壳、表/语句/列 ACL、脱敏与行级、审计管道、票据、门户+Vault
- [x] **A1–A4**：窗口读、窗口 encode、同协议透传（MySQL wire）、跨协议流式 encode
- [x] **P1**：水印 F14、L0 回归 B01、403 页 B02
- [x] **P2**：双人金库 F18、时间窗 F27、Cedar F26/F26b、OTel B03、审计轮转+OpenDAL B04、portal 导出 B05
- [x] **P3 主线**：H01–H04、B04c/B05b/B06/B07、F28、A05、UI01/UI02、smoke 硬化

### 1.2 关键 smoke（本机 19/19 绿）

| 组 | 脚本数 | 内容 |
|----|:------:|------|
| `l0` | 4 | admin-auth / dual-listener / cross-protocol ×2 |
| `security-core` | 7 | deny / column / mask / audit / ticket / portal / vault |
| `security-extended` | 6 | stream / passthrough / watermark / dual-control / time / xproto-stream |
| `cedar` | 2 | cedar + cedar-reload（需 `--features security-cedar`） |

```bash
cd data-proxy
./examples/run-smoke-matrix.sh default   # l0 + security-core（CI 默认）
./examples/run-smoke-matrix.sh all       # + extended
./examples/run-smoke-matrix.sh cedar     # 需预编译 feature
```

### 1.3 可选 Cargo features

| Feature | 用途 |
|---------|------|
| `otel` | OTLP 导出 + 业务 metrics |
| `security-cedar` | Cedar 表/动作 PDP + 热更新 |
| `audit-opendal` | 轮转 JSONL 的 OpenDAL 归档（`fs` / `memory` / `s3` / `oss`） |

### 1.4 代码落点

```text
gateway/core     security / pdp / cedar_pdp / obligations / audit_* / ticket / vault
runtime/gateway  core_engine PEP、流式/透传、object_extract
http             Admin API（策略/审计/票据/门户/Cedar reload）
data-ui          运维台 + SQL Portal + Audit + Tickets + Vault + Cedar
examples/        smoke + gateway config 样例
.claude/rules/   开发强制规则
```

---

## 2. 已完成归档（不重复开发）

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

---

## 3. 未完成 backlog（v2.2）

按 **性能封顶 → 合规/策略 → 体验 → 边界** 排序。  
每项仍遵守：规划 → 实现 → smoke/单测 → 勾选本文件 → `git commit`（见开发规则 DoD）。

### 3.1 P0 — 真流式 / 热路径封顶（大数据场景必做）

> 架构目标：backend 行流 → 义务 → 编码 → 客户端。当前 A1–A4 是骨架，**端到端「只持有一个窗口」未封顶**。

| ID | 项 | 说明 | 现状 / 债务 | 状态 |
|----|----|------|-------------|:----:|
| **A06** | Backend→PEP 真行流 | `RowStream` / 窗口迭代 API；Secure 路径禁止「先全量 `ResultSet` 再 `apply_obligations`」 | 有义务时仍整包物化后改 | **待做** |
| **A07** | 编码直写 socket | 减少 `handle_frame → Vec<Vec<u8>>` 二次缓冲；与 A06 对齐 | 编码结果先攒包再写 | **待做** |
| **A08** | PostgreSQL 真 wire 透传 | 同协议无义务时对齐 MySQL wire 路径 | 现将 Passthrough **降级 Materialized**（tokio-postgres 无 raw frame） | **待做** |
| **A09** | Portal 端到端流式 | B05b 仅 HTTP chunk；`portal_execute_logical` 仍先物化逻辑结果 | 注释已标明边界 | **待做**（依赖 A06） |
| **A10** | 预处理 / 事务透传矩阵 | MySQL prepared encode 仍偏 legacy；**PG prepared encode not implemented** | 易把流量打进慢路径或直接报错 | **待做** |

### 3.2 P1 — 策略 / 合规深化

| ID | 项 | 说明 | 现状 / 债务 | 状态 |
|----|----|------|-------------|:----:|
| **F29** | Cedar 实体属性 | Subject/Table 属性（tenant/clearance）进 Entities；与 Local 对照用例 | 现仅 User/Action/Table 字符串 id | **延后** |
| **B08** | L2 样本 / 大 payload | 可选结果样本上传 OpenDAL；体积/采样可配 | 有 `AuditLevel::L2` 枚举，**无**样本上传实现 | **延后** |
| **F31** | Remote PDP 适配器 | HTTP 旁路 OPA/外部 PDP；超时 fail_closed | 配置已 **拒绝** `backend=remote`（防静默 no-op）；实现后放开 | **延后** |
| **F30** | 敏感识别增强 | 静态列标签之外的规则/词典 MVP（仍不做全量 DLP） | 仅 `column_tags` + mask 规则 | **延后** |
| **F32** | 审计 L0/L1 载荷裁剪 | 按 audit level 控制 SQL 全文是否进管道/索引 | 级别可配，管道未严格按级裁剪 | **待做** |

### 3.3 P1 — 运维 / 多实例 / 发布

| ID | 项 | 说明 | 现状 / 债务 | 状态 |
|----|----|------|-------------|:----:|
| **H04b** | 真 IdP OIDC 联调 | 部署侧真实回调、角色映射验收 | 文档+模板完成；真 IdP 未在本仓库验收 | **部署侧** |
| **H05** | 多实例状态外置 | ticket / vault / LocalPdp / SQLite 索引现为**进程内** | 水平扩展需粘性或外置 store | **待做** |
| **H06** | 发布与 origin 同步 | `main` 长期领先 origin；发布 checklist + 默认 smoke | 本机 default/all/cedar 已绿 | **待做** |
| **H07** | CI 矩阵加深 | PR 已 default；extended / cedar job 可选或 nightly | workflow_dispatch 可选手动 | **可选** |
| **H08** | Vault 文件加密后端 | 进程内存明文密码后置方案 | H03 已声明后置 | **延后** |

### 3.4 P2 — 体验与正确性打磨

| ID | 项 | 说明 | 现状 / 债务 | 状态 |
|----|----|------|-------------|:----:|
| **UI03** | Audit 页增强 | 已接 B06 过滤；可补 stats 卡片、source 角标、导出 | `event_id`/时间窗/`source` 已做（`6ff8cef`） | **可选** |
| **UI04** | 策略只读页 | data-ui 展示 security rules / mask / high-risk（现多靠 API/配置） | 无专用页 | **可选** |
| **T01** | 列 ACL / 复杂 SQL 用例矩阵 | 子查询、多表、方言边界；启发式 `parse_failed` 行为 | smoke 覆盖主路径，复杂 SQL 仍靠补测 | **待做** |
| **T02** | Ticket/Vault runbook | 注释注入约定、双人审批、吊销运维说明进 docs | API+UI 有，运维叙事可再收紧 | **可选** |
| **O01** | Secure 路径观测 | mask 行数、窗口字节、审计 insert 延迟、队列直方图 | A05 已有 path/bytes | **可选** |

### 3.5 P3 — 边界扩展（明确后置）

| ID | 项 | 说明 | 状态 |
|----|----|------|:----:|
| **P01** | 新协议（Redis/…） | 路线图「扩库型后置」 | **延后** |
| **P02** | 深终端 Agent | 非协议 PEP 主线 | **不做/后置** |
| **P03** | 审计 Parquet/分析 | DataFusion 可选 feature | **延后** |
| **P04** | Sharding rewrite | `gateway_core` 仍为 stub | **延后**（非主线） |

### 3.6 已知限制（诚实账，勿当已交付宣传）

| 主题 | 限制 |
|------|------|
| Portal「流式」 | B05b = **HTTP** 边写；backend 逻辑结果仍可能全量进内存 |
| 脱敏大数据 | 有义务时峰值仍可能 ≈ 结果集大小 |
| PG passthrough | 配置可开，实现降级为 Materialized（有 debug 日志） |
| 预处理语句 | PG prepared encode 未实现；MySQL 部分仍偏 legacy |
| 多副本 | 票据/金库/SQLite 索引/LocalPdp **非**共享状态 |
| L2 样本合规 | **未实现**（B08） |
| Remote PDP | **未实现**（F31）；误配会被配置校验拒绝 |

---

## 4. 当前下一动作（唯一焦点）

**>>> A06 Backend→PEP 真行流（或发布 H06 / 部署 H04b）<<<**

开发规则：`.claude/rules/data-nexus-development.md`。

建议下一刀（三选一，按目标）：

| 目标 | 下一任务 |
|------|----------|
| **大数据脱敏代理** | **A06** → A07 → A08 → A09 |
| **可上线发布** | **H06** origin 同步 + 发布 checklist；部署 **H04b** |
| **企业 ABAC/合规** | **F29** → B08 → F31 |

```bash
# 回归基线
cd data-proxy && ./examples/run-smoke-matrix.sh default
cargo test -p gateway_core --lib
```

---

## 5. 完成定义（DoD）

每个任务合并前：

- [ ] 有 smoke 或单测
- [ ] 相关 `cargo test` / `cargo check` 通过（feature 任务在对应 feature 下测）
- [ ] `security.enabled=false` 不破坏 v1 行为
- [ ] 更新本文件勾选与「下一动作」
- [ ] 行为变更同步规则/必要架构文
- [ ] `git commit`（scope 清晰，带看板 ID）

---

## 6. 纪律

| 纪律 | 说明 |
|------|------|
| 门户不直连 | S6 铁律 |
| 审计不堵查询 | 有界队列；归档/索引在 worker 侧 |
| 流式先于大数据脱敏 | A 轨目标；禁止把 HTTP chunk 说成端到端流式 |
| 默认二进制精简 | Cedar/OpenDAL/OTel 继续 optional feature |
| 配置勿静默 no-op | 未实现能力必须校验失败（如 remote PDP） |
| 文档同步 | 行为变更同 PR 改看板/必要架构文 |
| 构建缓存外置 | 禁止再在仓库写多 GB `.cargo-target*` |
| 规则优先 | 冲突时：铁律 > `.claude/rules` > 架构文 > 本看板排期 |
