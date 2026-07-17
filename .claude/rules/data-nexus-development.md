# Data Nexus 开发规则（强制）

本仓库所有实现、评审、提交必须遵守。细节冲突时：**安全铁律 > 本文件 > 架构文档 > 看板排期**。

## 1. 产品与范围

| 版本 | 含义 |
|------|------|
| v1 / L0 | 协议中转、路由池、Admin、观测 |
| v2 MVP | 数据面：谁在何种条件下对何对象做什么；结果如何可见；可证明审计 |
| v2.1 / P3 | 可上线：CI、密钥、冷归档、审计检索、策略运维、UI |

**非目标（禁止当主线做）**：主机堡垒、操作录屏、一次 30+ 库、热路径 Arrow、Admin JWT 当数据面身份、默认二进制塞满可选 feature。

**铁律**

1. 门户 SQL **必须经 PEP**，禁止 UI/API 直连生产库拿结果。  
2. **管理面鉴权 ≠ 数据面 Subject**（Admin JWT/OIDC 不能冒充业务库用户，除非显式 vault/portal 绑定）。  
3. **审计不得堵查询**：热路径仅 `try_send`；落盘/索引/归档在 worker。  
4. **`security.enabled=false` 必须保持 v1 行为**（默认关安全）。  
5. **默认二进制精简**：Cedar / OpenDAL / OTel 继续 optional feature；开 feature 要写进文档与 smoke。  
6. **Fail-closed 可配且生产默认偏安全**：解析失败、策略失败行为必须显式。

## 2. 开发流程（DoD）

每个任务合并前：

1. **规划**：对照 `todo.md` ID 与架构文档术语，写清非目标。  
2. **实现**：落在既有分层（见 §3），不发明平行体系。  
3. **测试**：单测和/或 smoke；feature 任务在对应 feature 下测。  
4. **回归**：至少不破坏 `security.enabled=false`；相关 `cargo test` / smoke 通过。  
5. **文档**：更新 `todo.md` 勾选与「下一动作」；行为变更同步架构/runbook/OBSERVABILITY。  
6. **提交**：scope 清晰（`feat(b06):` / `fix:` / `chore:`）；中英文均可，但 ID 与意图清楚。

**禁止**

- 无测试的“感觉能跑”合入主路径。  
- 配置能写、运行时静默 no-op 的能力（例如假 `remote` PDP）——校验阶段必须拒绝或明确实现。  
- 在仓库内再写多 GB `.cargo-target*`（用外置 `CARGO_TARGET_DIR`）。  
- 热路径同步写盘、同步远程 PDP、默认同步 fsync 审计。

## 3. 分层与代码落点

```text
gateway/core     协议中立：security / pdp / cedar / obligations / audit_* / ticket / vault
runtime/gateway  热路径：core_engine PEP、流式/透传、object_extract、backend/frontend
http             Admin API + portal（经 PEP）
data-ui          运维台；只调 Admin API
examples/        smoke + 配置样例（含 prod 模板）
docs/            架构与路线图（权威细节）
```

- **新策略语义** → `gateway_core` + 单测；再接线 `core_engine`。  
- **新观测** → Prometheus 默认可开；OTel 放 `otel` feature + stub。  
- **新 Admin 能力** → `http` API 先于 UI；UI 不得绕过 API。

## 4. 性能与双路径（不可违背的方向）

| 路径 | 条件 | 要求 |
|------|------|------|
| Fast / 透传 | 同协议 + 无结果义务 + 允许 | 尽量 wire/帧转发；**禁止**无谓 `ResultSet` 物化 |
| Secure / 流式 | 有 mask/列删/行滤/水印等 | **目标**是窗口内处理；禁止“先全量再改”成为唯一实现（过渡期必须在文档标明） |
| 跨协议 | 翻译开启 | 强制 Streaming 窗口 encode；禁止纯 Materialized 当生产默认 |

实现新功能时：

1. 先问：**会不会迫使全量 `Vec<Vec<…>>`？** 会 → 设计窗口/流或明确 cap。  
2. Portal 导出：HTTP 层可 chunk（B05b）；**不得**假装已解决 backend 物化。  
3. 指标：路径命中、透传字节、队列深度、审计 drop 必须可观测（A05/B03 方向）。  
4. PDP 读路径：snapshot + 廉价句柄；避免每次 `rules()` 全量 clone 到热路径。

**已知债务（改动时优先还）**

- 有义务时仍可能全量 `ResultSet` 再 `apply_obligations`。  
- PostgreSQL “Passthrough” 可能降级 Materialized。  
- Portal 逻辑结果仍先物化再窗口写 HTTP。  
- 预处理语句 / PG prepared encode 不完整。

## 5. 安全与审计

- 审计队列有界；**deny / require_approval** 高优队列（B07）不得被 allow 洪峰挤掉。  
- 索引（B06）在 worker 写；Admin 查询优先索引，失败才回落 recent。  
- 统计接口禁止对大表每次 `COUNT(*)` 热路径；用维护计数或近似。  
- L0 默认；L1/L2 不得默认全结果；L2 样本（B08）未实现前不要宣传“已有样本合规”。  
- Vault：**永不**把后端密码返回浏览器；revoke 擦除内存中的密码。  
- Ticket：双人审批时 approver ≠ issuer；消耗后用途计数正确。

## 6. 配置与兼容

- 新配置项：**默认安全/关闭**，向后兼容。  
- `security.pdp.backend`：`local` | `cedar`（需 feature）| **`remote` 在实现 F31 前必须校验失败**。  
- 生产模板（H01）禁止提交真实密钥；用 `__DN_*__` + env。  
- rustc：smoke / cedar / `time` 依赖要求 **≥1.88**，本仓库钉 **1.94.1**（`data-proxy/rust-toolchain.toml`）。

## 7. 测试与 Smoke

| 组 | 内容 |
|----|------|
| l0 | security off 路径 |
| security-core | deny/column/mask/audit/ticket/portal/vault |
| security-extended | stream/passthrough/watermark/dual-control/time/xproto-stream |
| cedar | 需 `--features security-cedar` |

- 合并安全相关改动：至少相关单测 + 对应 smoke 或说明为何不跑。  
- CI：PR 默认应覆盖 **l0 + security-core（default）**；extended/cedar 可 dispatch。  
- Smoke 启动前清理残留 proxy；DB seed 避免 schema 漂移（必要时 DROP+CREATE）。

## 8. UI（data-ui）

- 只使用 `useAdminApi` 封装的 Admin API。  
- 401 → 登录；403 → 友好页；写操作需权限提示。  
- 后端已有过滤/字段时，**UI 必须吃到**（例如审计 `event_id` / 时间窗 / `source=index`），禁止长期只暴露最小子集。  
- 新页面：导航入口 + 与现有 layout/样式一致。

## 9. Git 与发布

- 小步提交，ID 与看板一致。  
- 不把密钥、大体积 target、本机绝对路径密钥写进库。  
- 长期领先 origin 时，发布前跑 `./examples/run-smoke-matrix.sh default`（或 all）。  
- 文档状态与代码一致：主线交付后更新版本表，不把“已完成”留在“规划中”。

## 10. 任务选择启发式

| 目标 | 优先 |
|------|------|
| 中小流量可上线 | 文档、CI、误配修复、UI 用满已有 API |
| 大数据脱敏 | 真流式义务 + 禁全量物化 + PG 透传 |
| 企业 ABAC/合规 | F29 实体属性 → B08 样本 → F31 Remote PDP |

---

修订：与审计结论同步；实现时若发现本规则与代码冲突，**改代码或改规则并提交说明，禁止静默违反**。
