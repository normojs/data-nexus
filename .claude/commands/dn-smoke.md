---
description: Run Data Nexus smoke matrix (default group unless arguments override)
---

Follow the project skill **dn-smoke** (`.claude/skills/dn-smoke/SKILL.md`) exactly.

Environment:

```bash
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
export RUSTUP_TOOLCHAIN=1.94.1
export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:${PATH}"
pkill -f '/debug/proxy' 2>/dev/null || true
```

Smoke group: use `$ARGUMENTS` if provided (e.g. `security-core`, `all`, `cedar`); otherwise `default`.

```bash
cd data-proxy
./examples/run-smoke-matrix.sh <group>
```

For `cedar`: build with `--features security-cedar` first, run cedar group, then rebuild default binary without optional features.

Report pass/fail with actual command output. Do not claim green without running.
