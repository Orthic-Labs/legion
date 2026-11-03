# Audit state and cache root

`legion audit` keeps its snapshots, source cache and PR cache under a per-user state root, outside the audited repository.

## Choosing the root

- `LEGION_STATE_ROOT` (absolute path, no `..`) overrides the default. Layout: `<root>/state/...`, with audit data under `audit-cache/<sha256 of the canonical repository path>/`.
- Unset or empty: the per-user default. Windows `%LOCALAPPDATA%\Orthic Labs\Legion`, macOS `~/Library/Application Support/Orthic Labs/Legion`, other `$XDG_STATE_HOME/legion` (else `~/.local/state/legion`).

Point `LEGION_STATE_ROOT` at a short real path (for example `C:\lg`) to keep snapshot paths well under 260 characters.

## Links

- The state root is host-chosen. If its own ancestors are junctions or symlinks (for example a per-profile Claude home on Windows where `Orthic Labs` is a junction), they are resolved once and the resolved path is used. A root that resolves inside the audited repository is rejected.
- Everything beneath the root, the audited repository, `--out`, and snapshot contents keep the symlink and reparse-point refusal.
- On Windows the resolved root uses the verbatim `\\?\` spelling, so paths over 260 characters work.
