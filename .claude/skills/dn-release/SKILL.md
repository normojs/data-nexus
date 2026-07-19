---
name: dn-release
description: >
  Use when the user wants to push, publish, sync origin, cut a release, H06, 发版,
  推 origin, or run full pre-release smoke. Covers smoke matrix order, default binary
  restore after cedar builds, and board honesty.
---

# dn-release — 发布 / origin 同步

## Overview

发版与 origin 同步 checklist（todo H06）。**用户明确同意后再 push**。

## Prerequisites

- 工作区干净或仅含有意发布的提交
- 已知领先 `origin` 的 commit 范围

## Steps

### 1. 全量验证

```bash
export RUSTUP_TOOLCHAIN=1.94.1
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
pkill -f '/debug/proxy' 2>/dev/null || true

cd data-proxy
./examples/run-smoke-matrix.sh all

cargo build -p data-proxy --bin proxy --features security-cedar
./examples/run-smoke-matrix.sh cedar
cargo build -p data-proxy --bin proxy   # 恢复默认二进制
```

### 2. 文档与看板

- [ ] `todo.md` 版本表与 §5「下一动作」与代码一致
- [ ] 已知限制 §4 无夸大；已交付与 `todo-impl.md` 不矛盾
- [ ] 生产模板无真实密钥（`__DN_*__`）
- [ ] OBSERVABILITY / runbook 若行为变已更新

### 3. Git

```bash
git log origin/main..HEAD --oneline
git status
# 用户明确同意后再：
git push origin HEAD
```

### 4. 发布说明

几条 bullet：新能力、可选 feature、诚实边界、smoke 结果。

## Forbidden

- 未跑 smoke 就 push 主线
- 留下 `--features security-cedar` 的 proxy 当默认
- 提交 `.env` / 私钥 / 本机绝对路径密钥
