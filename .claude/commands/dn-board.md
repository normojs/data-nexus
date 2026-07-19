---
description: Pick the single next Data Nexus board focus from todo.md and produce an implementation slice
---

Follow the project skill **dn-board** (`.claude/skills/dn-board/SKILL.md`) exactly.

1. Read `todo.md` §0 / §1–§3 (open `- [ ]`) / §4 honesty / §5 next focus. Delivered history is in `todo-impl.md`.
2. If `$ARGUMENTS` names a todo ID (e.g. A09), use that as focus; otherwise use §4.
3. Output the implementation slice template from the skill.
4. If the user already said to implement (e.g. 继续), hand off to **dn-stream** or **dn-security-slice** as the skill directs — do not stop at planning only.
