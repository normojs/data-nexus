---
name: dn-board
description: Read the Data Nexus todo board, pick the single next focus, and produce an implementation slice. Use whenever the user says continue, next task, 下一任务, 看板, 继续开发, what to do next, or asks to plan work from todo.md. Prefer this before starting any multi-file feature so work stays aligned with the board.
---

# dn-board — 看板选刀

## 步骤

1. 读 [`todo.md`](../../../todo.md)：
   - §0 版本状态
   - §3 未完成 backlog（P0→P3）
   - §3.6 已知限制（诚实账）
   - **§4 当前下一动作（唯一焦点）**
2. 若用户已点名 ID（如 A09、F29），以用户为准；否则采用 §4 焦点。
3. 对照 [`.claude/rules/data-nexus-development.md`](../../rules/data-nexus-development.md) 确认非目标。
4. 输出实现切片（给用户确认或直接开干，取决于用户是否说「继续」）：

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
- [ ] todo 勾选 + 下一动作
- [ ] commit（feat(id): …）
```

5. 大任务拆成可提交的小步；**禁止**一次吞下整个 P0 流式封顶。
6. 流式/性能类任务 → 接着用 **dn-stream**；普通安全切片 → **dn-security-slice**。

## 禁止

- 忽略 §3.6 诚实账，把「部分完成」写成「已交付」。
- 跳过看板私自开平行主线（新协议、Agent、Arrow 等）。
