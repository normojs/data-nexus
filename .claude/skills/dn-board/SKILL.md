---
name: dn-board
description: >
  Use when the user says continue, 继续, 下一任务, 下一刀, 看板, 继续开发, what next,
  pick a task, plan from todo, or asks which backlog item to implement next.
  Prefer before any multi-file feature so work stays on the single board focus.
---

# dn-board — 看板选刀

## Overview

从 `todo.md` 选出**唯一焦点**，输出可提交的实现切片。禁止跳过看板开平行主线。

## Steps

1. 读 [`todo.md`](../../../todo.md)（**仅未完成**；已交付见 [`todo-impl.md`](../../../todo-impl.md)）：
   - §0 版本状态
   - §1–§3 未完成 backlog（P0→P3，条目为 `- [ ]`）
   - §4 已知限制（诚实账）
   - **§5 当前下一动作（唯一焦点）**
2. 用户已点名 ID（如 A09、F29）→ 以用户为准；否则采用 §5。
3. 对照 [`.claude/rules/data-nexus-development.md`](../../rules/data-nexus-development.md) 确认非目标。
4. 输出切片：

```markdown
## 焦点
- ID:
- 一句话目标:
- 非目标（本次不做）:

## 落点
- gateway/core:
- runtime/gateway:
- http / data-ui / examples:

## 验证
- 单测:
- smoke 组:
- security.enabled=false:

## DoD
- [ ] 实现
- [ ] 测试
- [ ] todo 更新（部分：改「已有/仍欠」；整项完成：迁 todo-impl.md）+ 下一动作
- [ ] commit（feat(id): …）
```

5. 大任务拆成可提交小步；**禁止**一次吞下整个 P0 流式封顶。
6. 流式/性能 → **dn-stream**；安全/审计/策略/UI → **dn-security-slice**。

## Forbidden

- 忽略 §4 诚实账，把「部分」写成「已交付」。
- 私自开 P01/Agent/Arrow 等非目标主线。
