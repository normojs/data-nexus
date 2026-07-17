# Commands

Slash 入口包装 project skills（`.claude/skills/dn-*/SKILL.md`）。命令文件是给 Claude 的指令；细节以 skill 为准。

| Command | Skill | 用途 |
|---------|-------|------|
| `/dn-board` | dn-board | 看板选唯一焦点 |
| `/dn-stream` | dn-stream | 真流式 / 透传 / 热路径 |
| `/dn-security-slice` | dn-security-slice | 安全/策略切片交付 |
| `/dn-smoke [group]` | dn-smoke | smoke 矩阵（默认 default） |
| `/dn-dod` | dn-dod | 合并前 DoD |
| `/dn-release` | dn-release | 发版 / origin 同步 |

自然语言同样可触发 skill（description 含中英文触发词）。日常链路：

```text
/dn-board → /dn-stream 或 /dn-security-slice → /dn-smoke → /dn-dod
发版：/dn-smoke all → cedar → /dn-dod → /dn-release
```
