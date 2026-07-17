---
name: dn-release
description: Release and origin-sync checklist for Data Nexus (todo H06). Use when the user wants to push, publish, sync origin, cut a release, or run full pre-release smoke. Covers smoke matrix order, default binary restore after cedar builds, and board honesty.
---

# dn-release — 发布 / origin 同步

## 前置

- 工作区干净或仅含有意发布的提交。  
- 已知领先 `origin` 的 commit 范围。

## 步骤

### 1. 全量验证

```bash
export RUSTUP_TOOLCHAIN=1.94.1
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
pkill -f '/debug/proxy' 2>/dev/null || true

cd data-proxy
./examples/run-smoke-matrix.sh all

# Cedar（可选但发版建议）
cargo build -p data-proxy --bin proxy --features security-cedar
./examples/run-smoke-matrix.sh cedar
cargo build -p data-proxy --bin proxy   # 恢复默认二进制
```

### 2. 文档与看板

- [ ] `todo.md` 版本表与「下一动作」与代码一致  
- [ ] 已知限制 §3.6 无夸大  
- [ ] 生产模板无真实密钥（`__DN_*__`）  
- [ ] OBSERVABILITY / runbook 若行为变已更新  

### 3. Git

```bash
git log origin/main..HEAD --oneline   # 或 origin/master
git status
# 用户明确同意后再 push
git push origin HEAD
```

### 4. 发布说明（给用户）

用几条 bullet 总结：新能力、可选 feature、诚实边界、smoke 结果。

## 禁止

- 未跑 smoke 就 push 主线。  
- 留下 `--features security-cedar` 的 proxy 当默认。  
- 提交 `.env` / 私钥 / 本机绝对路径密钥。
