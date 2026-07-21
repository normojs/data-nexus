---
paths: **/*
---

# Data Nexus 开发规则（强制）

本仓库所有实现、评审、提交必须遵守。细节冲突时：**安全铁律 > 本文件 > 架构文档 > 看板排期**。

配套：

- 流式热路径：[`streaming-performance.md`](streaming-performance.md)（结果路径文件触发）
- 测试 Smoke：[`testing-smoke.md`](testing-smoke.md)（测试/smoke 文件触发）
- 能力地图 / Superpowers：[`../README.md`](../README.md)
- Skills：`../skills/dn-*/SKILL.md`；快捷入口：`../commands/dn-*.md`

## 1. 产品与范围

| 版本 | 含义 |
|------|------|
| v1 / L0 | 协议中转、路由池、Admin、观测 |
| v2 MVP | 数据面：谁在何种条件下对何对象做什么；结果如何可见；可证明审计 |
| v2.1 / P3 | 可上线：CI、密钥、冷归档、审计检索、策略运维、UI（主线已完成） |
| v2.2 | 真流式封顶 + 企业策略/合规（见 `todo.md`） |

**非目标（禁止当主线做）**：主机堡垒、操作录屏、一次 30+ 库、热路径 Arrow、Admin JWT 当数据面身份、默认二进制塞满可选 feature。

**铁律**

1. 门户 SQL **必须经 PEP**，禁止 UI/API 直连生产库拿结果。
2. **管理面鉴权 ≠ 数据面 Subject**（Admin JWT/OIDC 不能冒充业务库用户，除非显式 vault/portal 绑定）。
3. **审计不得堵查询**：热路径仅 `try_send`；落盘/索引/归档在 worker。
4. **`security.enabled=false` 必须保持 v1 行为**（默认关安全）。
5. **默认二进制精简**：Cedar / OpenDAL / OTel 继续 optional feature；开 feature 要写进文档与 smoke。
6. **Fail-closed 可配且生产默认偏安全**：解析失败、策略失败行为必须显式。
7. **配置不得静默 no-op**：未实现能力必须在校验阶段拒绝；已实现能力（如 F31 remote PDP）须有真实行为与 fail-closed 语义。

## 2. 开发流程（DoD）

每个任务合并前（skill **dn-dod** 或 `/dn-dod`）：

1. **规划**：对照 `todo.md` ID 与架构文档术语，写清非目标。
2. **实现**：落在既有分层（见 §3），不发明平行体系。
3. **测试**：单测和/或 smoke；feature 任务在对应 feature 下测。
4. **回归**：至少不破坏 `security.enabled=false`；相关 `cargo test` / smoke 通过。
5. **文档**：更新 `todo.md`（未完成 `- [ ]` +「已有/仍欠」+ §5 下一动作）；整项完成迁入 `todo-impl.md`；行为变更同步架构/runbook/OBSERVABILITY。
6. **提交**：scope 清晰（`feat(b06):` / `fix:` / `chore:`）；中英文均可，但 ID 与意图清楚。
7. **诚实**：部分完成保持 `- [ ]`，更新 `todo.md` §4 已知限制；禁止把部分当交付。

**禁止**

- 无测试的“感觉能跑”合入主路径。
- 配置能写、运行时静默 no-op 的能力。
- 在仓库内再写多 GB `.cargo-target*`（用外置 `CARGO_TARGET_DIR`）。
- 热路径同步写盘、同步远程 PDP、默认同步 fsync 审计。
- 把 HTTP chunk / 窗口 encode 宣传成「端到端已流式」。

## 3. 分层与代码落点

```text
gateway/core     协议中立：security / pdp / cedar / obligations / audit_* / ticket / vault / transport
runtime/gateway  热路径：core_engine PEP、流式/透传、object_extract、backend/frontend
http             Admin API + portal（经 PEP）
data-ui          运维台；只调 Admin API
examples/        smoke + 配置样例（含 prod 模板）
docs/            架构与路线图（权威细节）
.claude/         rules + skills + commands
```

- **新策略语义** → `gateway_core` + 单测；再接线 `core_engine`。
- **新观测** → Prometheus 默认可开；OTel 放 `otel` feature + stub。
- **新 Admin 能力** → `http` API 先于 UI；UI 不得绕过 API。

## 4. 性能与双路径

详见 [`streaming-performance.md`](streaming-performance.md)。摘要：

| 路径 | 条件 | 要求 |
|------|------|------|
| Fast / 透传 | 同协议 + 无结果义务 | 尽量 wire；禁止无谓物化 |
| Secure / 流式 | 有 mask 等义务 | 窗口内处理；禁止「全量再改」唯一实现 |
| 跨协议 | 翻译开启 | Streaming 窗口 encode |

**已知债务（改动时优先还）**：Complete/控制语句小物化；Portal Complete 无 RowStream 时 backend 仍可能物化；PG/MySQL extended **非** TCP bind 帧中继（passthrough 下 demote Streaming）；A10 逻辑 skip 续读 **非** backend 真游标；进程 RSS 峰值 CI 未做（仅逻辑 peak_window_rows）。

## 5. 安全与审计

- 审计队列有界；**deny / require_approval** 高优队列（B07）。
- 索引（B06）在 worker 写；stats **禁止**热路径 `COUNT(*)`。
- L2 样本（B08）：默认关；`sample_enabled` 须 `default_audit_level=L2`；有界 rows/bytes；**勿宣传全量 L3**。
- Vault：永不回传后端密码；revoke 擦除内存。
- Ticket：双人审批 approver ≠ issuer。

## 6. 配置与兼容

- 新配置项：**默认安全/关闭**，向后兼容。
- `security.pdp.backend`：`local` | `cedar`（需 feature）| `remote`（F31 HTTP 旁路；需 `remote_url`，超时默认 fail_closed）。
- 生产模板禁止真实密钥；`__DN_*__` + env。
- rustc：**1.94.1**。

## 7. 测试与 Smoke

详见 [`testing-smoke.md`](testing-smoke.md)。默认门禁：`./examples/run-smoke-matrix.sh default`。

## 8. UI（data-ui）

- 只使用 `useAdminApi`。
- 401 → 登录；403 → 友好页。
- 后端已有过滤字段时 UI 必须吃到（审计 `event_id` / 时间窗 / `source` / `audit_level` / `outcome` / `listener` / `rule` / B08 `sample_*`；portal `stream` / `window_rows`）。

## 9. Git 与发布

- 小步提交，ID 与看板一致。
- 发版用 skill **dn-release** 或 `/dn-release`。
- 长期领先 origin 时，发布前跑 full smoke。

## 10. 任务选择启发式

| 目标 | 优先 |
|------|------|
| 中小流量可上线 | 文档、CI、误配修复、UI |
| 大数据脱敏 | **dn-stream**（A06 续 / A09 / A08） |
| 企业 ABAC/合规 | F29 / B08 / F31 已有切片；深化见 `todo.md` |

---

修订：与 Claude 能力地图同步；规则与代码冲突时 **改代码或改规则并提交说明，禁止静默违反**。
