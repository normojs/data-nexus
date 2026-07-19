---
name: dn-security-slice
description: >
  Use when implementing or fixing Data Nexus security, ACL, mask, PDP, Cedar, audit,
  ticket, vault, portal PEP, admin API, or data-ui work (todo IDs S*, F*, B*, H*, UI*).
  Also when user mentions 策略, 脱敏, 审计, 票据, 金库, portal, fail-closed, or remote PDP.
---

# dn-security-slice — 安全/策略切片交付

## Overview

端到端交付安全相关看板项：分层、fail-closed 配置、铁律、DoD。

## Prerequisites

- 焦点 ID（用户或 **dn-board**）
- 已读 rules：`data-nexus-development.md`

## Flow

### 1. 规划（短）

- 术语：Subject ≠ Admin、PEP、义务、审计 L0…
- 写清：配置默认关/安全；热路径是否可能全量物化
- 涉及结果路径 → 并读 **dn-stream**

### 2. 落点

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
- [ ] 新配置有默认值；未实现能力校验失败（参考 remote PDP）
- [ ] 审计：热路径 `try_send`；deny 走高优队列
- [ ] Vault：密码永不回传浏览器
- [ ] Feature（cedar/opendal/otel）文档 + smoke 说明

### 4. 验证

```bash
export RUSTUP_TOOLCHAIN=1.94.1
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"

cargo test -p gateway_core --lib <filter>
cargo test -p runtime_gateway --lib <filter>
cd data-proxy && ./examples/run-smoke-matrix.sh security-core
```

### 5. 收尾

- 更新 `todo.md`（`- [ ]` + 已有/仍欠 + §5 下一动作）；整项完成迁 `todo-impl.md`
- Commit：`feat(b06):` / `fix(f28):` 等
- 走 **dn-dod**

## Anti-patterns

- 在 `http` 里复制一套 PDP
- Admin JWT 当数据面 Subject
- 宣传 L2 样本 / Remote PDP 已可用
