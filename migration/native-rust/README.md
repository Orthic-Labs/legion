# Native Rust executable graph ledger

LEG-000 inventory is source-bound to Legion baseline `90678a130dc26937d544304b79a22f24d74383ac`.

`executable-ledger.json` has one row for every tracked `.mjs`, `.js`, `.cjs`, `.ts`, `.py`, `.sh`, `.bash`, `.zsh`, `.ps1`, `.bat`, and `.cmd` path. `invocation-graph.json` records normalized executable nodes, package-script launch sites, shebangs, process/dynamic-load sites, and observed edges. `public-contract-inventory.json` records shipped entrypoints, exports, package scripts, hook/MCP surfaces, manifests, and schema identifiers. `legacy-path-ownership.json` gives every legacy executable path exactly one future packet owner.

Disposition is deliberately closed: `port`, `data`, `external-tool`, `dev-only`, or `delete`. Port rows name one crate from the locked migration map. Dev-only rows carry six path-specific exclusion proofs covering package archive, installer, host command, runtime imports, generated config, and production entrypoint. Rows without a production target retain a concrete static evidence trail and a named cutover/deletion gate. Arrays are lexical by stable ID/path; JSON uses two-space indentation and terminal newlines.

Source scans used for this ledger: tracked executable extensions, shebangs, package scripts, manifests/workflows, imports/dynamic imports, child-process APIs, Python subprocess/importlib APIs, hooks, MCP registration, and generated command strings. No build, test, formatter, repository script, dependency, or network command is part of LEG-000.
