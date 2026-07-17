---
description: Release / origin-sync checklist (H06) with full smoke
---

Follow the project skill **dn-release** (`.claude/skills/dn-release/SKILL.md`) exactly.

Run full verification (all + cedar) before any push. **Never push without explicit user approval.**
Restore the default proxy binary after cedar feature builds.

If `$ARGUMENTS` is `push` or `sync`, still require user confirmation before `git push`.
