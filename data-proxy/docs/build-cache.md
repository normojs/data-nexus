# Build cache location

Cargo `target/` for this workspace is **not** stored in the git tree.

| Item | Path |
|------|------|
| Default `target-dir` | `/Volumes/fushilu/.caches/data-nexus/cargo-target` |
| Config | [`data-proxy/.cargo/config.toml`](../.cargo/config.toml) and repo-root [`.cargo/config.toml`](../../.cargo/config.toml) |
| Compat symlink | `/Volumes/fushilu/.caches/data-nexus-target` → `…/data-nexus/cargo-target` |

## Why

Debug builds of `proxy` plus feature variants easily exceed **10–20 GB**. Keeping them on `/Volumes/fushilu/.caches` frees the project volume.

## Override

```bash
# one-off
CARGO_TARGET_DIR=/tmp/my-target cargo build -p data-proxy --bin proxy

# smoke scripts honor CARGO_TARGET_DIR if set; otherwise use the volume path
./examples/smoke-admin-auth.sh
```

## Feature builds (Cedar / OTel / OpenDAL)

Use the **same** `target-dir`. Do not create parallel `.cargo-target-*` directories under the repo.
