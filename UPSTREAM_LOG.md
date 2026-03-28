# Upstream Sync Log

This is a **permanent fork** of [OpenCode](https://github.com/sst/opencode) (MIT).
OpenCode is now archived upstream; no further syncing will occur.

**Fork base**: `ced8898` (v4.0.0, 2026-03-28)

## History

The `agent/` directory was forked from OpenCode v4.0.0 and heavily specialized
for penetration testing. The upstream sync workflow and merge script were removed
as of this update since the upstream project is archived and the codebases have
fully diverged.

<details>
<summary>Original sync strategy (archived)</summary>

| Zone | Directories | Strategy |
|------|-------------|----------|
| Safe | `provider/`, `auth/`, `effect/`, `id/`, `format/`, `bus/`, `env/`, `packages/ui/`, `packages/plugin/` | Auto cherry-pick via `script/upstream-merge-safe.sh` |
| Review | `session/`, `config/`, `storage/`, `mcp/`, `server/`, `permission/`, `plugin/`, `skill/` | Manual cherry-pick with `-x` flag |
| Diverged | `tool/`, `agent/`, `prompt/`, `command/`, `bridge/`, `lsp/`, `ide/`, `worktree/` | Never sync — read for architectural insights only |

</details>

## Decision Log

| Upstream Commit | Date | Zone | Applied? | Notes |
|----------------|------|------|----------|-------|
| — | 2026-03-28 | — | — | Fork created at v4.0.0 (`ced8898`) |
| — | — | — | — | Fork declared permanent; upstream sync removed |
