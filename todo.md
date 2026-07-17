# Data Nexus 开发看板

**架构文档**（细节以文档为准，本文件只排期与勾选）：

| 文档 | 用途 |
|------|------|
| `docs/data-nexus-protocol-gateway-plan.md` | L0 / v1 协议网关底座 |
| `docs/data-security-roadmap.md` | 产品对标（防水坝 / 树安 SQLDEV）+ S0–S6 定义 |
| `docs/data-nexus-tech-architecture-2026.md` | **v2 技术主文档**（术语、选型、双路径、实现切片） |
| `docs/data-audit-architecture.md` | 审计/流式专项 |
| `data-proxy/docs/build-cache.md` | Cargo target 外置缓存 |

---

## 0. 版本划分

```text
v1 = L0   数据库协议中转站 + 管理面鉴权 + 运维 UI + 观测     ✅ 已完成（M0–M10）
v2 = L1   数据访问安全（对标 SQLDEV：访问+脱敏+权限+审计）   ✅ MVP + P1/P2 增强已完成
v2.1      生产化 / 运维硬化 / 审计与策略深化                 ⏳ 下一阶段（P3）
```

| 版本 | 一句话 | 状态 |
|------|--------|:----:|
| **v1** | 客户端 ↔ 网关 ↔ MySQL/PG；路由/池/跨协议/Admin | **完成** |
| **v2 MVP** | 谁在何种条件下对何对象做什么；结果如何可见；可证明审计 | **完成** |
| **v2.1** | 可上线：CI、密钥、对象冷归档、审计检索、策略运维 | **规划中** |

**原则（不变）**

- v2 默认 `security.enabled=false`，不破坏 v1 行为
- 管理面鉴权 ≠ 数据面 Subject
- 门户 SQL 必须经 PEP，禁止直连生产库
- 非目标：主机堡垒、操作录屏、一次 30+ 库、热路径 Arrow、Admin JWT 当数据身份

**工具链**

- 日常构建：`/Volumes/fushilu/.caches/data-nexus/cargo-target`（见 `data-proxy/docs/build-cache.md`）
- Cedar / 新依赖：推荐 **rustc ≥ 1.88**（本机 smoke 常用 1.94.1）

---

## 1. 现状快照（已交付）

### 1.1 主线

- [x] **v1 / L0**：双协议、跨协议、Admin JWT/OIDC 雏形、data-ui、观测、smoke
- [x] **S0–S6**：配置壳、表/语句/列 ACL、脱敏与行级、审计管道、票据、门户+Vault
- [x] **A1–A4**：窗口读、窗口 encode、同协议透传、跨协议流式 encode
- [x] **P1**：水印 F14、L0 回归 B01、403 页 B02
- [x] **P2**：双人金库 F18、时间窗 F27、Cedar F26/F26b、OTel B03、审计轮转+OpenDAL fs/memory B04、portal 导出 B05

### 1.2 关键 smoke

`smoke-admin-auth` / `dual-listener` / `cross-protocol` / `cross-protocol-pg-to-mysql` / `cross-protocol-stream`  
`smoke-security-deny` / `column` / `mask` / `audit` / `ticket` / `dual-control` / `time` / `watermark`  
`smoke-security-stream` / `passthrough` / `portal` / `vault` / `cedar` / `cedar-reload`

### 1.3 可选 Cargo features

| Feature | 用途 |
|---------|------|
| `otel` | OTLP 导出 + 业务 metrics |
| `security-cedar` | Cedar 表/动作 PDP + 热更新 |
| `audit-opendal` | 轮转 JSONL 的 OpenDAL 归档（当前 `fs` / `memory`） |

### 1.4 代码落点

```text
gateway/core     security / pdp / cedar_pdp / obligations / audit_* / ticket / vault
runtime/gateway  core_engine PEP、流式/透传、object_extract
http             Admin API（策略/审计/票据/门户/Cedar reload）
data-ui          运维台 + SQL Portal + Audit
examples/        smoke + gateway config 样例
```

---

## 2. 已完成归档（不重复开发）

| ID | 项 | 提交提示（近端） |
|----|----|------------------|
| S0–S6 | 安全主线 MVP | … → `16c569b` portal 等 |
| A1–A4 | 性能双路径 | `332573e`…`4a3094f` |
| F14 | 结果水印 | `4a9d995` |
| B01 | L0 smoke 回归 | `ae04aa0` |
| B02 | data-ui 403 | `66a9761` |
| F18 | 双人金库 | `cbc196e` |
| F27 | 时间维策略 | `bd6588e` |
| B05 | portal CSV/NDJSON | `507890e` |
| F26 | Cedar PDP | `bd15913` |
| B03 | OTel 安全属性 | `b6fe519` |
| B04 | JSONL 轮转/保留 | `120252f` |
| B04b | OpenDAL fs/memory | `0dda947` |
| F26b | Cedar 热更新 | `82974f9` |
| chore | target 外置缓存 | `2700698` |

---

## 3. 后续 backlog（v2.1 / P3）

按 **可上线 → 审计深化 → 策略/体验 → 边界扩展** 排序。每项仍遵守：规划 → 实现 → smoke/单测 → 勾选本文件 → `git commit`。

### P3-A — 生产化（优先）

| ID | 项 | 说明 | 依赖/备注 | 状态 |
|----|----|------|-----------|:----:|
| **H01** | 生产配置样例包 | `examples/prod-*.toml`：fail_closed、admin_auth 开、audit file+retain、streaming 合理默认；禁止明文口令示例进文档正文 | 无 | **完成** |
| **H02** | CI smoke 矩阵 | GitHub/本地脚本：security off 四条 L0 + 核心 security smoke；文档 rustc/缓存路径；可选 `security-cedar` job | 外置 target、Docker | **完成** |
| **H03** | 密钥与 Vault 硬化 | lease/ticket 吊销·续期·prune；后端密码永不回传且 revoke 时擦除；进程内存（文件加密后端后置） | S6 vault | **完成** |
| **H04** | data-ui OIDC 生产联调 | 真实 IdP、回调、角色映射；与 break-glass 并存说明 | data-ui、admin_auth | **完成**（接线文档+模板；真 IdP 由部署侧完成） |

### P3-B — 审计与合规

| ID | 项 | 说明 | 依赖/备注 | 状态 |
|----|----|------|-----------|:----:|
| **B04c** | OpenDAL S3/OSS scheme | `opendal_scheme=s3|oss` + endpoint/region/凭据 env；失败重试不堵查询 | `audit-opendal` | 待做 |
| **B06** | 审计检索索引 | SQLite/PG 旁路索引（event_id/subject/decision/time）；Admin 查询不扫全量 JSONL | 架构 S4 | 待做 |
| **B07** | Deny 高优审计队列 | deny/require_ticket 独立有界队列或优先入队，防 drop_new 丢关键事件 | audit_pipeline | 待做 |
| **B08** | L2 样本/大 payload | 可选结果样本上传 OpenDAL；体积/采样策略可配 | B04c、流式 | 延后 |

### P3-C — 策略与数据面

| ID | 项 | 说明 | 依赖/备注 | 状态 |
|----|----|------|-----------|:----:|
| **F28** | Local 规则热更新 | 仅 `security.rules`/mask 变更时刷新 PDP，避免无谓 listener 重建 | reload diff | 待做 |
| **F29** | Cedar 实体属性 | Subject/Table 属性（tenant/clearance）进 Entities；与 Local 对照用例 | F26 | 延后 |
| **F30** | 敏感识别增强 | 静态列标签之外的规则/词典 MVP（仍不做全量 DLP） | S2/S3 tags | 延后 |
| **F31** | Remote PDP 适配器 | HTTP 旁路 OPA/外部 PDP；超时 fail_closed | 架构 RemotePDP | 延后 |

### P3-D — 体验与性能

| ID | 项 | 说明 | 依赖/备注 | 状态 |
|----|----|------|-----------|:----:|
| **B05b** | portal 真流式 NDJSON | 边读边写 HTTP chunk，避免大结果全量进内存 | portal_execute | 待做 |
| **A05** | 透传路径观测补齐 | passthrough 命中率/字节 metrics；与 B03 属性对齐 | otel/prometheus | 待做 |
| **UI01** | 票据/金库管理页 | data-ui 发票、双人审批、列表（现多靠 API） | F18、tickets API | 待做 |
| **UI02** | Cedar 状态页 | 展示 epoch/files/reload 按钮 | F26b API | 延后 |

### P3-E — 边界扩展（明确后置）

| ID | 项 | 说明 | 状态 |
|----|----|------|:----:|
| **P01** | 新协议（Redis/…） | 路线图「扩库型后置」；不阻塞 v2.1 | 延后 |
| **P02** | 深终端 Agent | 非协议 PEP 主线 | 不做/后置 |
| **P03** | 审计 Parquet/分析 | DataFusion 可选 feature | 延后 |

---

## 4. 当前下一动作（唯一焦点）

**>>> B04c OpenDAL S3/OSS / 或 B05b portal 真流式 / B07 Deny 高优队列 <<<**

P3-A 生产化四项均已交付：

| ID | 交付物 |
|----|--------|
| H01 | `examples/prod/` 模板 + render |
| H02 | `run-smoke-matrix.sh` + GHA |
| H03 | vault/ticket revoke·renew·prune |
| H04 | `data-ui/docs/oidc-production.md` + JWKS/UI env 模板 |

```bash
# OIDC（部署侧填真实 IdP）
# 见 data-ui/docs/oidc-production.md
```

建议下一任务（P3-B/D）：

1. **B04c** — OpenDAL S3/OSS scheme  
2. **B05b** — portal 真流式 NDJSON  
3. **B07** — Deny 高优审计队列

---

## 5. 完成定义（DoD）

每个任务合并前：

- [ ] 有 smoke 或单测
- [ ] 相关 `cargo test` / `cargo check` 通过（feature 任务在对应 feature 下测）
- [ ] `security.enabled=false` 不破坏 v1 行为
- [ ] 更新本文件勾选与「下一动作」
- [ ] `git commit`（中文/英文 scope 清晰）

---

## 6. 纪律

| 纪律 | 说明 |
|------|------|
| 门户不直连 | S6 铁律 |
| 审计不堵查询 | 有界队列；归档/索引在 worker 侧 |
| 流式先于大数据脱敏 | A 轨已铺垫；portal 大结果优先 B05b |
| 默认二进制精简 | Cedar/OpenDAL/OTel 继续 optional feature |
| 文档同步 | 行为变更同 PR 改看板/必要架构文 |
| 构建缓存外置 | 禁止再在仓库写多 GB `.cargo-target*` |
