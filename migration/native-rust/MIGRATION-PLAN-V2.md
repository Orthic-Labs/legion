# Legion Rust Product Migration v2

**Target:** `PRODUCT-ARCHITECTURE-V2.md`
**Mode:** hard cut after bounded qualification; no indefinite dual runtime
**Primary optimization:** lowest practical system strain with one machine install and strong AX

## 1. Disposition of previous plan

Previous core-port work remains useful, but old host/runtime/product cutover contracts are retired.

| Previous area | Disposition |
|---|---|
| executable inventory and algorithm/data classification | retain and refresh against current `main` |
| contracts, catalog, policy, rules, Audit, Research, review Rust ports | retain where behavior matches v2 contracts |
| one effect executor | retain with clarified external-project-tool boundary |
| descriptor-driven host engine | retire; thin mechanical integration adapters replace it |
| CLI/hook/MCP binaries as equal target adapters | one Rust runtime; CLI and MCP share core |
| npm/plugin-root cutover | replace with machine package plus `legion setup` |
| per-client embedded native binary | remove; one installed executable per machine/platform architecture |
| Agent Plugins as universal installer | remove; keep as preferred portable integration contract |
| Blueprint as global Audit gate | remove; use optional typed capability degradation |
| always-on orchestrator language | remove; Legion is available and lazily active |
| immediate Node/Python deletion | defer until signed installed-product qualification and absence proof |

Existing L10, L15, L17, L18, L19, and L20 dispatches must not execute unchanged. Other legacy
dispatches require contract-delta review before reuse.

## 2. Migration principles

1. Prove install -> setup -> discover -> launch -> invoke -> receipt before porting breadth.
2. Keep Legion semantics in Rust/declarative assets; adapters remain mechanical.
3. Treat Agent Plugins as preferred integration format, not installer or client-support definition.
4. Install one native executable; allow one reusable stdio MCP subprocess per active client.
5. Keep shipped runtime Rust-only; leave development-only test/build languages alone.
6. Preserve one canonical owner for state, assets, tool schemas, and release identity.
7. Never delete legacy runtime before signed Mac and Windows installed qualification.
8. Switch once, verify absence, then remove compatibility code and stale registrations.
9. Preserve Membrane worktree; migration integration owns Legion only.

## 3. Workstreams

### M0 — Rebaseline and freeze contracts

Outputs:

- current executable/runtime and host-surface inventories;
- algorithm/data/dev-only/runtime disposition for every Node/Python path;
- canonical capability, policy, receipt, Audit, and Research semantic freeze;
- Supported Client Profile and fidelity matrix;
- official Pi integration path;
- setup adapter contract for detection, install, repair, disable, removal, and verification;
- Agent Plugins package contract with required `$schema` and bare-command behavior;
- executable-resolution proof method for each client launch environment;
- release-binding manifest and runtime handshake contract;
- persistent-state ownership, schema, lease, migration, snapshot, and rollback contract;
- macOS Homebrew packaging decision—formula (optionally bottled) versus cask—plus appropriate
  tap/distribution channel from measured release mechanics;
- Windows WinGet portable/alternative package disposition;
- exact RightKit AX version and source-commit pin;
- RightKit/spec discovery discrepancy disposition;
- AX, process, and strain benchmark protocol;
- narrow `LEGION-CANONICAL-SSOT.md` authority correction;
- revised file-ownership map.

Gate:

- every shipped executable and state root is classified;
- one normative owner exists for target topology and semantics;
- no adapter may own Legion semantics;
- package/install choice preserves signing, provenance, update, rollback, and command discovery;
- current RightKit pin provides clean-room static, conformance, behavioral, adversarial, and real-client matrix evidence;
- no implementation uses stale descriptor-host, embedded-binary, or per-client-install assumptions.

### M1 — Native core vertical slice

Implement minimum Rust path needed to demonstrate product shape:

```text
load release manifest
-> load compact catalog
-> return Legion status/version
-> execute one deterministic capability
-> apply one Arcane policy decision
-> emit one typed result and receipt
-> serve same surface over stdio MCP
```

Gate:

- same core API works through MCP and standalone CLI;
- MCP handshake verifies runtime/catalog/tool-schema/declarative-asset identity;
- mismatched binding fails closed with exact repair instruction;
- no internal Node/Python/self-spawn;
- lazy asset loading is demonstrated.

### M2 — Portable integration package and adapters

Build one Agent Plugins 1.0 package containing:

- valid `plugin.json` and `mcp.json` with canonical `$schema` values;
- canonical `skills/` with complete reference closure;
- `command: "legion"` plus `serve --stdio` arguments;
- release-binding manifest, identities, schemas, and declarative assets;
- optional reverse-domain extension directories;
- strict MCP schemas, typed errors, effect declarations, claim boundaries, and bounded results.

Implement thin adapters for two independent agent clients. Use each client's highest-fidelity
supported mechanism without embedding or duplicating Legion semantics.

Gate:

- portable package contains no platform executable;
- both clients expose identical release, capability, and tool identities;
- actual client environments prove bare-command lookup or use supported exact-path registration;
- skill discovery, MCP start, invocation, cancellation, restart, and shutdown pass;
- client-native bridge, if required, remains mechanically inspectable and semantic-free;
- RightKit pinned clean-room conformance, behavioral, and adversarial gates pass.

### M3 — Machine installation, `legion setup`, and AX

Implement and qualify:

- native signed macOS and Windows runtime artifacts;
- chosen Homebrew and WinGet installation paths;
- `legion setup` detection, fidelity display, selection, install, and verification;
- preference for supported client-native lifecycle APIs;
- transactional fallback config mutation with preview, confirmation, backup, and rollback;
- `setup --dry-run`, status, repair, disable, remove, and explicit state purge;
- release-binding refresh across every selected integration;
- state locks, runtime leases, snapshot migration, atomic rollback, and interrupted recovery;
- concise `legion status` and `legion setup status` diagnostics.

Gate:

- fresh machine install plus one setup flow enables Legion in two independent clients;
- later launches recognize Legion without project edits or manual config archaeology;
- PATH-sanitized and stale-PATH fixtures do not produce false Full support;
- update cannot mix runtime, plugin assets, catalogs, or schemas;
- repair restores damaged projection without touching unrelated client configuration;
- disable/remove are reversible; purge targets verified Legion-owned state only;
- Mac and Windows installed flows pass before broad porting resumes.

### M4 — Core capability migration

Port in dependency order:

1. contracts, catalog, policy model, and policy evaluator;
2. runtime/work graph, state compatibility, and receipts;
3. provider SDK and declarative rule engine;
4. Audit planning, providers, reasoning lenses, reconciliation, and reports;
5. Research evidence ledger and provider interfaces;
6. review, completion validation, handoff, dispatch, architecture, and remaining workflows;
7. standalone CLI/CI/hook surfaces sharing core APIs.

Each capability passes through installed client integration, not only crate tests.

Blueprint behavior:

- available: consume Membrane/Blueprint packet through typed interface;
- unavailable: continue applicable work and record exact structural-coverage loss;
- explicitly required Blueprint operation: provider-level typed degradation;
- never abort unrelated providers, crash, or silently substitute ad-hoc graph.

### M5 — Provider and external-tool boundary

Classify every provider as declarative rule, Rust algorithm, optional Blueprint evidence, host
service, or external project tool.

Gate:

- no unknown provider owner;
- no provider returns empty success after unavailability;
- selected reasoning-provider denominator is frozen and reconciled;
- every external executable request is typed, bounded, policy-evaluated, and receipt-backed;
- Audit and Research complete with truthful degradation when optional services are absent.

### M6 — Installed-product qualification

Qualify exact signed release artifacts:

- macOS install, setup, first/repeated launch, update, repair, disable, remove, rollback;
- Windows equivalent;
- two independent agent clients with same semantic release;
- Full, Degraded, Baseline, and Unavailable client behavior;
- Audit end to end with and without Blueprint;
- Research end to end with evidence ledger and real external-source use;
- command resolution, permission denial/revocation, cancellation, crash, restart, timeout;
- stale integration, runtime/asset mismatch, missing target, junction, and damaged cache;
- N-1 -> N migration, interruption, N -> N-1 rollback, uninstall/reinstall, corruption;
- concurrent active clients and active-work update behavior;
- strain benchmark against current Node release and same client without Legion.

Gate:

- signed installed artifact passes; source checkout success is insufficient;
- runtime provenance, capability-catalog hash, MCP tool-schema hash, and asset hash reconcile;
- one MCP subprocess per active client is reusable and client-owned;
- no per-tool Legion runtime births or idle daemon;
- Mac/Windows and cross-client semantic identities match;
- AX scenarios pass without manual dotfile edits;
- rollback restores compatible state and integrations atomically.

### M7 — Hard cut

Cut sequence:

1. publish private signed machine-runtime and portable-integration release candidate;
2. install through qualified Homebrew and WinGet paths;
3. run `legion setup` against both reference clients per platform;
4. verify installed release bindings and complete Audit/Research workflows;
5. switch canonical distribution and setup metadata to native release;
6. remove Node/Python runtime entrypoints using refreshed exact ledger;
7. remove npm runtime package, Node MCP server, Python product scripts, legacy shims, stale caches, and duplicate registrations;
8. update canonical docs and release claims;
9. prove losing routes, source-checkout/PATH fallbacks, and emitted variants absent;
10. publish signed release.

Rollback reinstalls previous signed machine runtime, restores pre-upgrade state snapshot, and restores
matching client integrations. It does not create indefinite dual execution.

GitHub governance and local release-gate enforcement must be complete before destructive hard cut;
they do not block M0/M1 architecture or vertical-slice work.

### M8 — Post-cut cleanup

- retain Node/Python only for classified development tooling;
- remove migration-only compatibility code and flags;
- archive parity corpus and qualification receipts;
- measure first production sessions;
- close only defects that invalidate requested behavior or strain/AX acceptance.

## 4. Vertical acceptance scenarios

### V1 — One-shot first use

Fresh Mac or Windows machine installs Legion through chosen native package manager, runs
`legion setup`, selects an agent client, confirms proposed changes, and receives discovered skills
plus native tools without repository setup.

### V2 — Two independent clients

Setup enables two different agent clients. Both invoke same installed runtime and expose same
release/capability/tool identities through their highest-fidelity supported mechanisms.

### V3 — Quiet idle and repeated work

No client open means no Legion process. Each active client owns at most one reusable Legion MCP
subprocess for repeated calls; multiple active clients may own separate processes.

### V4 — Command resolution failure

Agent Plugins package is valid but client cannot resolve bare `legion`. Setup uses supported native
exact-path registration or reports Degraded/Unavailable with exact remediation; it never claims Full.

### V5 — Skills-only client

Client exposes Baseline skills only. Legion does not claim Arcane enforcement, Audit execution,
Research execution, or native tool access.

### V6 — Blueprint absent

Audit runs every applicable provider, completes reports, records structural-coverage limits, and
recommends Membrane/Blueprint without global failure.

### V7 — Damaged or mismatched integration

Missing asset, junction escape, stale catalog, or runtime/schema mismatch is isolated, reported,
and repaired transactionally. No source-checkout fallback or silent mixed-version execution occurs.

### V8 — State migration and rollback

N-1 state migrates under exclusive lock with pre-upgrade snapshot. Interruption restores previous
generation. Rollback restores N-1 runtime, integrations, and state after incompatible leases close.

### V9 — Complete removal

`legion setup remove` removes selected integrations and preserves unrelated config. Package-manager
uninstall removes runtime. State remains unless user explicitly requests verified purge.

## 5. Evidence required before legacy deletion

- executable inventory with zero unknown runtime item;
- signed runtime artifact digest/provenance per platform and architecture;
- capability-catalog, MCP tool-schema, and declarative-asset hashes;
- pinned RightKit AX reports from clean-room artifacts and real-client matrix;
- package-manager install/update/rollback/removal evidence;
- setup dry-run/install/repair/disable/remove evidence;
- per-client executable-resolution and fidelity evidence;
- Mac/Windows semantic-equivalence results;
- Blueprint-present and Blueprint-absent Audit reports;
- Research evidence ledger and artifacts;
- process-tree and strain measurements;
- state upgrade/rollback/concurrency matrix;
- permission denial/revocation and degraded-client results;
- absence scan for losing entrypoints, imports, package dependencies, registrations, caches,
  source-checkout/PATH fallback, documentation, and protocol variants;
- independent Completion Validation against current user scope.

## 6. Execution order

```text
M0 contracts + inventory
  -> M1 minimal native vertical slice
  -> M2 portable package + two client adapters
  -> M3 machine install + legion setup + state lifecycle
  -> M4/M5 capability and provider migration
  -> M6 signed installed-product qualification
  -> M7 hard cut + legacy deletion
  -> M8 cleanup and production observation
```

Broad Audit/Research porting does not resume before M1–M3 prove actual product lifecycle. Parallel
work begins only after M0 freezes ownership and contracts. M4 capability families may run
concurrently; M2, M3, M6, and M7 each retain one integration owner.

## 7. Immediate next actions

1. Freeze stale host/cutover dispatches.
2. Refresh runtime, host, state, and integration inventories at current Legion `main`.
3. Land narrow canonical SSOT authority correction.
4. Freeze Supported Client Profile, Pi path, setup adapters, state, release binding, and package forms.
5. Pin RightKit AX qualification implementation and reconcile remaining spec discrepancy.
6. Implement M1–M3 vertical slice before broad capability porting.
7. Measure installed lifecycle against current Node runtime.
8. Resume reusable Rust ports only after product topology passes.
