# M1 native core vertical slice — corrective execution request

Execute M1 only from `main` at `dfcf1447c2e21f6366de8d4da3cfee9e0cc09414`.

The authoritative semantic and product contracts remain:

- `migration/native-rust/m0/contract-freeze.json`
- `migration/native-rust/MIGRATION-PLAN-V2.md` § M1
- `migration/native-rust/PRODUCT-ARCHITECTURE-V2.md`
- `docs/LEGION-CANONICAL-SSOT.md`

Correct two execution-planning defects in the broad M1–M8 roadmap packet:

1. The 524 legacy Node/Python/shell paths classified to M1 are read-only port inputs, not M1 edit targets. Preserve them unchanged during the vertical slice.
2. `legion serve --stdio` requires a reusable `legion-mcp` library seam, and the M1 integration test must live under a real Cargo package rather than the virtual workspace root.

The operator explicitly approved the corrective ownership amendment. The amended frozen ownership
map and regenerated M1–M8 roadmap now assign both corrected paths to M1.

Run two exact, disjoint foundation lanes concurrently in independent worktrees:

- `m1-release-catalog`
- `m1-mcp-transport`

After both foundation lanes integrate, run `m1-application-policy`; after that integrates, run
`m1-cli-integration`. These barriers are required because the application consumes the new release
API and the CLI consumes both the application and reusable MCP library.

The public interface lock for parallel work is:

- `legion_runtime::release_binding` owns the typed release manifest, verified binding, fail-closed mismatch, and the exact remediation string `legion setup --repair`.
- `legion_catalog` owns compact metadata loading and lazy body resolution; loading metadata must not read capability bodies.
- `legion_application` owns one native M1 operation returning status/version, one deterministic capability result, one Arcane policy evaluation/receipt, and one typed invocation receipt.
- `legion_mcp` is a reusable library plus binary. MCP initialization verifies the full binding before advertising tools, and one application instance serves the complete stdio session.
- `legion` owns `status` and `serve --stdio` front doors and delegates to those shared APIs without spawning Legion, Node, Python, or a shell.

Acceptance:

- release manifest and compact catalog are loaded and their hashes verified;
- runtime/provenance, release version, catalog, MCP schema, declarative assets, state schema, and RightKit AX identity reconcile;
- mismatch fails before tools are exposed with exact repair instruction;
- the same native application surface works through standalone CLI and reusable stdio MCP;
- one deterministic capability applies one Arcane decision and emits one typed result and receipt;
- lazy asset loading is demonstrated;
- no internal interpreter, shell, or self-spawn route exists;
- Cargo format, check, clippy, and focused tests pass;
- workers do not commit or push; one integration owner verifies, stages, commits, and pushes without editing lane-owned files;
- no Membrane changes and no legacy runtime deletion during M1.
