# Data Nexus Claude 能力地图

本仓库的 Claude Code 配置：**规则强制约束** + **Skills 工作流** + **看板驱动**。  
目标：少重复踩坑、DoD 可执行、大任务可切片交付。

## 分层

| 层 | 路径 | 何时生效 | 作用 |
|----|------|----------|------|
| 入口 | [`CLAUDE.md`](../CLAUDE.md) | 每会话 | 索引规则 / 看板 / 工具链 |
| **Rules（强制）** | [`.claude/rules/`](rules/) | 始终 | 铁律、DoD、分层、禁止项 |
| **Skills（流程）** | [`.claude/skills/`](skills/) | 匹配任务时 / 用户点名 | 可重复工作流（smoke、流式、发版…） |
| **Agents（可选）** | [`.claude/agents/`](agents/) | 显式 spawn | 专用子代理（预留） |
| **Commands（可选）** | [`.claude/commands/`](commands/) | 用户 `/cmd` | 快捷入口（预留） |
| 看板 | [`todo.md`](../todo.md) | 排期 | 唯一焦点 + 未完成债 |
| 架构 | `docs/*` | 细节争议时 | 术语与目标态 |

冲突优先级：**安全铁律 > rules > 架构文档 > todo 排期**。

## Superpowers（推荐工作流）

把「规划 → 实现 → 验证 → 勾选 → 提交」收成一条链，类似 superpowers：

| 能力 | Skill | 触发场景 |
|------|-------|----------|
| **选刀** | `dn-board` | “继续 / 下一任务 / 看看板” |
| **切片交付** | `dn-security-slice` | 实现 todo 某 ID（F*/B*/A*/H*） |
| **流式/性能** | `dn-stream` | A06–A10、mask、透传、峰值内存 |
| **回归** | `dn-smoke` | 改完要测、发版前、修 CI |
| **合入门禁** | `dn-dod` | 准备 commit / PR |
| **发布** | `dn-release` | 推 origin、checklist、smoke 全矩阵 |

**默认链路（日常开发）**

```text
dn-board（定唯一焦点）
  → dn-security-slice 或 dn-stream（实现）
  → dn-smoke（相关组）
  → dn-dod（勾选+提交）
```

**发版链路**

```text
dn-smoke (default → all → cedar)
  → dn-dod
  → dn-release
```

## Rules 一览

| 文件 | 内容 |
|------|------|
| [`rules/data-nexus-development.md`](rules/data-nexus-development.md) | 主规则：范围、DoD、分层、双路径、审计、配置、测试、UI、Git |
| [`rules/streaming-performance.md`](rules/streaming-performance.md) | 热路径：何时必须流式、禁止全量物化、诚实边界 |
| [`rules/testing-smoke.md`](rules/testing-smoke.md) | 工具链、smoke 组、清理 proxy、schema seed |

## Skills 一览

```text
.claude/skills/
  dn-board/SKILL.md           # 读看板、选唯一焦点、写实现切片
  dn-security-slice/SKILL.md  # 安全/审计/策略类任务端到端
  dn-stream/SKILL.md          # 真流式 / 透传 / ResponseWriter
  dn-smoke/SKILL.md           # smoke 矩阵与工具链
  dn-dod/SKILL.md             # 合并前 DoD 清单
  dn-release/SKILL.md         # 发布与 origin 同步
```

用户也可说：「用 dn-smoke 跑 security-core」「按 dn-dod 检查再提交」。

## 与代码库的对应关系

| 主题 | 规则/Skill | 代码落点 |
|------|------------|----------|
| 策略/PDP | rules + dn-security-slice | `gateway/core` pdp/cedar/obligations |
| 热路径 | streaming-performance + dn-stream | `runtime/gateway` core_engine/backend |
| 审计 | rules §5 + dn-security-slice | audit_pipeline / audit_index |
| Admin/UI | rules §8 + dn-security-slice | `http` + `data-ui` |
| 验证 | testing-smoke + dn-smoke | `examples/smoke-*.sh` |
| 发版 | dn-release | git + smoke matrix |

## 刻意不做

- 不在 rules 里写长篇架构复述（指向 `docs/`）。
- 不默认打开 Cedar/OpenDAL/OTel（精简二进制）。
- 不把「HTTP chunk」说成端到端流式（诚实账在 todo §3.6）。
- Agents/Commands 先空置，等有稳定多代理场景再补。

## 维护

- 行为变更：同 PR 更新 **rules（若铁律变）** + **todo 勾选** + 必要 docs。
- 新重复流程：优先加 **Skill**，不要把步骤堆进 rules。
- 新禁止项：进 **rules**，不要只写在聊天里。
