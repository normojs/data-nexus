---
name: dn-dod
description: Pre-merge Definition of Done checklist for Data Nexus. Use before every git commit or PR for this repo, or when the user says DoD, 提交前检查, ready to commit, or 合并前. Blocks incomplete commits that skip tests, todo updates, or honesty about limitations.
---

# dn-dod — 合并前 DoD

对当前改动逐项确认（全部通过再 `git commit`）：

## 清单

- [ ] **焦点**：对应 `todo.md` ID 或明确 chore/docs  
- [ ] **非目标**：未偷做 P01/Agent/Arrow 等  
- [ ] **分层**：代码在正确 crate（core / runtime / http / data-ui）  
- [ ] **铁律**：  
  - [ ] 门户不直连库  
  - [ ] 审计不堵查询  
  - [ ] `security.enabled=false` 未破坏  
  - [ ] 无「配置能写、运行时 no-op」  
- [ ] **测试**：相关 `cargo test` 通过  
- [ ] **Smoke**：相关组通过，或说明为何本 PR 不跑（仅 docs 可跳过）  
- [ ] **todo.md**：勾选状态 +「下一动作」已更新  
- [ ] **诚实账**：部分完成标 **部分**，§3.6 若需更新已更新  
- [ ] **Commit message**：`feat(a06):` / `fix:` / `docs(todo):` + 意图清晰  
- [ ] **无密钥 / 无巨大 target 目录**  

## 建议命令

```bash
cargo test -p gateway_core --lib <relevant>
cargo test -p runtime_gateway --lib <relevant>
# 或
cd data-proxy && ./examples/run-smoke-matrix.sh default
```

## Commit 尾注

```
Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

（若环境要求。）

未勾选完 → **不要提交**；回去补测或缩 scope。
