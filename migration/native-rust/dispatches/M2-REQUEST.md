# M2 portable integration package and adapters — parallel execution request

Execute M2 only from `main` at `475ff5d1931e1006f0b1f199129a4cf4a29713f3`, after accepted M1.

The authoritative contracts are:

- `migration/native-rust/m0/agent-plugins-contract.json`
- `migration/native-rust/m0/client-fidelity-matrix.json`
- `migration/native-rust/m0/command-resolution-proof.json`
- `migration/native-rust/m0/release-binding-contract.json`
- `migration/native-rust/m0/rightkit-ax-pin.json`
- `migration/native-rust/m0/rightkit-conformance-plan.json`
- `migration/native-rust/MIGRATION-PLAN-V2.md` section M2
- `migration/native-rust/PRODUCT-ARCHITECTURE-V2.md`
- `docs/LEGION-CANONICAL-SSOT.md`

Correct the broad roadmap packet's unnecessary single-worker serialization. Remove the host manifest
and two legacy Arcane compatibility modules from active M2 touch, add one portable skill template,
add a narrow `serve --plugin-root` CLI lease plus its actual-binary regression test, and add one
development-only assertion file required to keep adapter tests truthful. The resulting closed active
union is 30 paths. `hooks/stop-shape.mjs` and `hooks/user-intent.mjs` remain byte-identical
read-only legacy evidence until their M7 deletion because retained Arcane consumers still import them.
Run three disjoint foundation lanes concurrently in isolated worktrees:

- `m2-portable-assets`
- `m2-native-host`
- `m2-mechanical-adapters`

After all three integrate, run `m2-convergence-tests`. No lane may edit another lane's files. Workers
do not commit or push. The primary-checkout integration owner verifies and integrates worker patches
without editing lane-owned files.

Interface lock:

- The repository portable profile contains `plugin.json`, `mcp.json`, and one self-contained
  `skills/legion/SKILL.md`. The native assembler generates the bound identity, release manifest, and
  MCP schema into an external clean-room staging root. The resulting package is declarative only. It embeds no executable,
  source launcher, Node/Python/shell entrypoint, or arbitrary absolute command.
- `mcp.json` uses the bare command `legion` with arguments `serve --stdio --plugin-root
  ${PLUGIN_ROOT}` and the frozen canonical schema.
- `legion-host` owns clean-room package assembly, containment, release-bound projections, client detection, fidelity,
  command-resolution evidence, transactional mutation, ownership, verification, and reversible
  lifecycle primitives. It owns no Legion capability, routing, policy, workflow, or receipt semantics.
- The native `legion-hook` and retained JavaScript client adapters are mechanical protocol bridges.
  They may translate lifecycle events and invoke the installed Legion command, but may not implement
  Legion semantics or launch a source checkout.
- `legion` accepts `serve --stdio --plugin-root <root>`, validates the closed package, and binds its
  release manifest to the loaded native application before MCP startup. No other M1 CLI behavior changes.
- Two independent client profiles must expose identical bound release, capability-catalog, MCP tool,
  schema, and declarative-asset identities while retaining client-specific lifecycle evidence.

RightKit AX is the schema and qualification authority, pinned to version `0.2.0` and source commit
`01f52555202da3dffc6b649ca44e803b55238081`. Cargo may run directly in this cloud environment;
RightKit is not a Cargo wrapper. A missing pinned RightKit checkout or missing real-client environment
must be reported as a typed external qualification blocker and must never be replaced with fabricated
PASS evidence. Passing repository-local M2 implementation checks permits M3 implementation because
M3 installation is required to produce the real-client evidence. M6 alone owns release qualification;
publication and Full-support claims remain blocked until every external gate passes.

Acceptance:

- exact disjoint allowlists and wave barriers are honored;
- portable package has valid pinned schemas, closes references inside its root, and contains no runtime;
- release binding fails closed before activation with exact remediation `legion setup --repair`;
- two client integrations are identity-equivalent and mechanically inspectable;
- actual launch resolution, discovery, invocation, cancellation, restart, and shutdown are evidenced;
- typed qualification classification proves missing pinned RightKit, signed-artifact, or real-client
  evidence cannot become PASS; actual external gates remain M6-owned;
- Cargo format, check, clippy, and focused tests pass for the native components;
- retained development-only adapter tests are updated to assert installed-native launchers and pass;
- legacy runtime deletion is deferred; no Membrane files are changed.
