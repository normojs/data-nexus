---
name: dn-dod
description: >
  Use before every git commit or PR for this repo, or when the user says DoD, 提交前检查,
  ready to commit, 合并前, 可以提交了, or pre-merge checklist. Blocks incomplete commits
  that skip tests, todo updates, or honesty about limitations.
---

# dn-dod — 合并前 DoD

## Overview

对当前改动逐项确认；**全部通过再 `git commit`**。无新鲜验证证据不得声称完成。

## Checklist

- [ ] **焦点**：对应 `todo.md` ID 或明确 chore/docs
- [ ] **非目标**：未偷做 P01/Agent/Arrow 等
- [ ] **分层**：代码在正确 crate（core / runtime / http / data-ui）
- [ ] **铁律**：
  - [ ] 门户不直连库
  - [ ] 审计不堵查询
  - [ ] `security.enabled=false` 未破坏
  - [ ] 无「配置能写、运行时 no-op」
- [ ] **测试**：相关 `cargo test` 通过（本回合跑过，有输出）
- [ ] **Smoke**：相关组通过，或说明为何本 PR 不跑（仅 docs 可跳过）
- [ ] **todo.md**：未完成条仍为 `- [ ]`；「已有/仍欠」与 §5 下一动作已更新
- [ ] **todo-impl.md**：整项完成后迁入并勾选；子切片可追加交付行
- [ ] **诚实账**：部分完成不勾完；§4 已知限制若需更新已更新
- [ ] **Commit message**：`feat(a06):` / `fix:` / `docs(todo):` + 意图清晰
- [ ] **无密钥 / 无巨大 target 目录**

## Suggested commands

```bash
export RUSTUP_TOOLCHAIN=1.94.1
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
cargo test -p gateway_core --lib <relevant>
cargo test -p runtime_gateway --lib <relevant>
# 或
cd data-proxy && ./examples/run-smoke-matrix.sh default
```

## Commit trailer

```
Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

未勾选完 → **不要提交**；回去补测或缩 scope。
