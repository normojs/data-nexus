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
v2 = L1   数据访问安全（对标 SQLDEV：访问+脱敏+权限+审计）   ✅ MVP（S0–S6 + A1–A4）
```

| 版本 | 一句话 | 状态 |
|------|--------|:----:|
| **v1** | 客户端 ↔ 网关 ↔ MySQL/PG；路由/池/跨协议/Admin | **完成** |
| **v2** | 谁在何种条件下对何对象做什么；结果如何可见；可证明审计 | **MVP 完成；P2 增强进行中** |

**原则**

- v2 默认 `security.enabled=false`，不破坏 v1 行为
- 管理面鉴权 ≠ 数据面 Subject
- 验收顺序：`审计 → 表权 → 列/脱敏 → 行 → 敏感识别 → 工单 → 门户`
- 非目标：主机堡垒、操作录屏、一次 30+ 库、热路径 Arrow、Admin JWT 当数据身份

---

## 1. 现状快照

### 1.1 主线已交付

- [x] **v1 / L0**：双协议、跨协议、Admin JWT/OIDC、data-ui、观测、smoke
- [x] **S0–S6**：配置壳、表/语句/列 ACL、脱敏与行级、审计管道、票据门闩、门户+Vault
- [x] **A1–A4**：窗口读、窗口 encode、同协议透传、跨协议流式 encode
- [x] data-ui：`/portal`、`/audit`、拓扑/会话/设置

### 1.2 关键 smoke

`smoke-security-deny` / `column` / `mask` / `audit` / `ticket` / `dual-control` / `stream` / `passthrough` / `portal` / `watermark` / `cross-protocol` / `cross-protocol-stream` / `smoke-dual-listener` / `smoke-admin-auth`

### 1.3 代码落点（摘要）

```text
gateway/core   security / pdp / obligations / audit_pipeline / ticket / vault / object_set
runtime/gateway  core_engine PEP、object_extract、backend/frontend 流式与透传
http           Admin API：策略/审计/票据/门户/Vault
data-ui        运维台 + SQL Portal + Audit
```

---

## 2. 剩余 backlog（按优先级）

### P1 — 建议继续

| ID | 项 | 说明 | 状态 |
|----|----|------|:----:|
| **F14** | 结果水印雏形 | Allow 结果嵌入可追溯 token（列/后缀） | **完成** |
| **B01** | v1 smoke 回归确认 | security default off 下四条 L0 smoke 全绿 | **完成** |
| **B02** | data-ui 403 友好页 | Admin API 鉴权失败可理解 | 待做 |

### P2 — 可选增强

| ID | 项 | 说明 | 状态 |
|----|----|------|:----:|
| **F18** | 双人金库 | 票据需第二审批人确认后再生效 | **完成** |
| **F27** | 时间维策略 | 仅工作时间可写等高危规则 | 待做 |
| **F26** | Cedar PDP feature | 可选 feature，与 Local 对照 | 延后 |
| **B03** | OTel 自定义 attributes / 采样 | 可观测加深 | 延后 |
| **B04** | 审计保留清理 / OpenDAL L2 | 冷归档 | 延后 |
| **B05** | portal 导出按钮 / 流式 JSON | 门户体验 | 延后 |

---

## 3. 当前下一动作（唯一焦点）

**>>> B02 data-ui 403 友好页 / 或 F27 时间维策略 <<<**

F18 已完成：`dual_control` 票据 `pending → active/rejected`；`POST /admin/tickets/:id/approve|reject`；审批人 ≠ 签发人；`smoke-security-dual-control` + S5 ticket 回归。

建议下一任务：

1. **B02** — data-ui 403 友好页  
2. **F27** — 时间维策略  

---

## 4. 完成定义（DoD）

每个任务合并前：

- [ ] 有 smoke 或单测
- [ ] 相关 `cargo test` / `cargo check` 通过
- [ ] security default off 不破坏 v1 行为
- [ ] 更新本文件勾选

---

## 5. 纪律

| 纪律 | 说明 |
|------|------|
| 门户不直连 | S6 铁律 |
| 审计不堵查询 | 有界队列 |
| 流式先于大数据脱敏 | A 轨已铺垫 |
| 文档同步 | 行为变更同 PR 改看板/必要架构文 |
