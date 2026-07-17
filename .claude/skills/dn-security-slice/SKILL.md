---
name: dn-security-slice
description: End-to-end delivery workflow for Data Nexus security, audit, policy, portal, ticket, vault, or admin API tasks (todo IDs S*, F*, B*, H*, UI*). Use when implementing or fixing ACL, mask, PDP, Cedar, audit pipeline, tickets, vault, portal PEP, or admin/data-ui features. Enforces layering, fail-closed config, and DoD.
---

# dn-security-slice — 安全/策略切片交付

## 前置

- 已有焦点 ID（来自用户或 **dn-board**）。
- 已读 rules：`data-nexus-development.md`。

## 流程

### 1. 规划（短）

- 对照架构术语（Subject ≠ Admin、PEP、义务、审计 L0…）。
- 写清：**配置默认关/安全**、**热路径是否可能全量物化**。
- 若涉及结果路径 → 切换/并读 **dn-stream**。

### 2. 落点（强制分层）

| 改什么 | 写哪里 |
|--------|--------|
| 策略语义 / schema / 义务 | `gateway/core` + 单测 |
| 热路径 PEP / 透传 / 流式 | `runtime/gateway` |
| Admin API | `http` 先于 UI |
| 运维 UI | `data-ui` 只调 Admin API |
| 配置样例 / smoke | `examples/` |

禁止：UI 直连生产库；热路径同步写审计盘；配置能写运行时 no-op。

### 3. 实现检查

- [ ] `security.enabled=false` 行为不变  
- [ ] 新配置有默认值且校验失败要明确（参考 remote PDP 拒绝）  
- [ ] 审计：热路径 `try_send`；deny 走高优队列  
- [ ] Vault：密码永不回传浏览器  
- [ ] Feature（cedar/opendal/otel）文档 + smoke 说明  

### 4. 验证

```bash
# 相关单测
cargo test -p gateway_core --lib <filter>
cargo test -p runtime_gateway --lib <filter>

# 相关 smoke（见 dn-smoke）
cd data-proxy && ./examples/run-smoke-matrix.sh security-core   # 或更小子集
```

### 5. 收尾

- 更新 `todo.md` 状态与「下一动作」。
- Commit：`feat(b06):` / `fix(f28):` 等，scope 清晰。
- 走 **dn-dod** 清单再提交。

## 反模式

- 在 `http` 里复制一套 PDP。
- Admin JWT 当数据面 Subject。
- 宣传 L2 样本 / Remote PDP 已可用（未实现）。
