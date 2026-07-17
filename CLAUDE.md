# Data Nexus

开发时请阅读并遵守：

## 必读

| 资源 | 用途 |
|------|------|
| [**开发规则（强制）**](.claude/rules/data-nexus-development.md) | 铁律、DoD、分层、禁止项 |
| [流式/热路径规则](.claude/rules/streaming-performance.md) | 改结果路径时 |
| [测试/Smoke 规则](.claude/rules/testing-smoke.md) | 回归与工具链 |
| [**Claude 能力地图**](.claude/README.md) | Skills / Superpowers 工作流 |
| [看板 `todo.md`](todo.md) | 唯一焦点与未完成债 |

## 架构

- `docs/data-nexus-tech-architecture-2026.md`
- `docs/data-audit-architecture.md`
- `docs/data-security-roadmap.md`

## 工具链

- rustc：**1.94.1**（`data-proxy/rust-toolchain.toml`）
- 构建缓存：`data-proxy/docs/build-cache.md`（外置 `CARGO_TARGET_DIR`）

## Superpowers（默认链路）

```text
dn-board → dn-security-slice | dn-stream → dn-smoke → dn-dod
发版：dn-smoke(all/cedar) → dn-dod → dn-release
```

用户可说：「继续」走看板；「跑 smoke」走 dn-smoke；「提交前检查」走 dn-dod。
