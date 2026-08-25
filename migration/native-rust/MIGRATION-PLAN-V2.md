# Legion Rust Product Migration v2

**Target:** `PRODUCT-ARCHITECTURE-V2.md`
**Mode:** hard cut after bounded qualification; no indefinite dual runtime
**Primary optimization:** lowest practical system strain with one-shot installation and strong AX

## 1. Disposition of previous plan

Previous core-port work remains useful, but its host/runtime/product cutover is frozen pending this revision.

| Previous area | Disposition |
|---|---|
| executable inventory and algorithm/data classification | retain and refresh against current `main` |
| contracts, catalog, policy, rules, Audit, Research, review Rust ports | retain where behavior matches v2 contracts |
| one effect executor | retain with clarified external-project-tool boundary |
| descriptor-driven host engine | retire; Agent Plugins 1.0 is portable host contract |
| CLI/hook/MCP binaries as equal target adapters | make native Rust MCP server portable runtime; CLI remains standalone/CI |
| npm/plugin root cutover | replace with one Agent Plugins package validated by RightKit AX |
| Blueprint as global Audit gate | remove; use optional typed capability degradation |
| “always-on orchestrator” language | remove; Legion is always available and lazily active |
| immediate Node/Python deletion | defer until installed-product qualification and absence proof |

Existing L10, L15, L17, L18, L19, and L20 dispatches must not execute unchanged. Other dispatches require contract-delta review before reuse.

## 2. Migration principles

1. Prove one complete installed vertical slice before porting breadth.
2. Keep core semantics host-neutral; use hosts only as conformance fixtures.
3. Use Agent Plugins skills + one reusable client-owned native MCP server; no Legion-specific transport.
4. Keep shipped runtime Rust-only; leave dev-only test/build languages alone.
5. Never delete legacy runtime before signed installed artifacts pass Mac and Windows qualification.
6. Switch once, verify absence, then remove compatibility code and stale registrations.
7. Preserve current Legion and Membrane worktrees; migration integration owns Legion only.

## 3. Workstreams

### M0 — Rebaseline and freeze contracts

Outputs:

- current executable/runtime inventory;
- current host-surface inventory;
- algorithm/data/dev-only/runtime disposition for every Node/Python path;
- Agent Plugins 1.0 packaging disposition;
- MCP tool and runtime contract;
- client-extension dependency audit;
- RightKit AX/spec discrepancy disposition for non-skill directories under `skills/`;
- AX and strain benchmark protocol;
- revised file ownership map.

Gate:

- every shipped executable path classified;
- previous-plan contract contradictions identified;
- Legion packaged plugin root is distinct from mixed-purpose source layout;
- RightKit AX hard gate matches Agent Plugins 1.0 discovery semantics;
- no implementation dispatch uses stale L10/L15/L17 assumptions.

### M1 — Native core vertical slice

Implement minimum Rust path needed to demonstrate product shape:

```text
load release manifest
-> load compact catalog
-> return Legion status/version
-> execute one deterministic tool
-> apply one policy decision
-> emit one typed result and receipt
```

Do not port every capability first.

Gate:

- same core API callable through MCP and standalone CLI;
- no internal Node/Python/self-spawn;
- lazy asset loading demonstrated.

### M2 — Agent Plugins product package

Use existing RightKit AX to build and validate:

- Agent Plugins 1.0 `plugin.json`;
- canonical `skills/` tree with complete reference closure;
- `mcp.json` pointing to packaged Rust stdio server;
- client-owned `${PLUGIN_DATA}` state contract;
- optional reverse-domain extension directories;
- strict MCP tool schemas, typed errors, effects, claim boundaries, and bounded results;
- packaged-artifact conformance, behavioral, and adversarial evidence.

Use two compatible clients as conformance fixtures. Both consume same plugin directory without repackaging.

Gate:

- both clients expose identical Legion release, capability, and tool identities;
- plugin install, skill discovery, MCP start, tool invocation, cancellation, and shutdown pass;
- client-specific extensions remain optional and cannot own portable behavior.

### M3 — Client-native installation and AX

Integrate with client-native Agent Plugin installation before broad porting:

- publish one self-contained plugin artifact;
- install through each reference client's marketplace/CLI/plugin UI;
- let client own scope, cache, enablement, trust prompts, reload, update, disable, and uninstall;
- validate asset/reference closure with RightKit AX;
- verify packaged Mac and Windows native commands;
- expose concise `legion.status` runtime diagnostics;
- record client-specific fidelity separately from portable conformance.

Gate:

- one explicit native action installs Legion into each client;
- later client launches recognize Legion without setup;
- no project edit required;
- broken/missing symlink and junction fixtures fail plugin validation or component loading;
- plugin failure cannot corrupt unrelated client configuration.

### M4 — Core capability migration

Port in dependency order:

1. contracts, catalog, policy model, policy evaluator;
2. runtime/work graph and receipts;
3. provider SDK and declarative rules;
4. Audit planning, providers, reconciliation, reporting;
5. Research evidence and provider interfaces;
6. review, completion validation, handoff, dispatch, architecture, and remaining workflows;
7. standalone CLI/CI/hook surfaces sharing core APIs.

Each capability must pass through installed host integration, not only direct crate tests.

Blueprint behavior:

- Blueprint available: consume host/Membrane packet through typed source;
- Blueprint unavailable: continue applicable work, record recommendation and exact lost structural coverage;
- Blueprint method explicitly requested: return provider-level typed degradation if unavailable;
- never crash, abort unrelated providers, or silently substitute an ad-hoc graph.

### M5 — Provider and external-tool boundary

Classify each provider as declarative rule, Rust algorithm, optional Blueprint evidence, host service, or external project tool.

Gate:

- no unknown provider owner;
- no provider returns empty success after unavailability;
- every external executable request is typed, bounded, policy-evaluated, and receipt-backed;
- Audit and Research complete with truthful degradation when optional host services are absent.

### M6 — Installed-product qualification

Qualify signed artifacts through compatible clients:

- Mac install, first launch, repeated launch, tool use, update, disable, uninstall;
- Windows equivalent;
- same Agent Plugin loaded by two reference clients;
- Audit end to end with and without Blueprint;
- Research end to end with evidence ledger and external source use;
- cancellation, timeout, crash, stale cache, version mismatch, partial config, junction, and missing-target faults;
- strain benchmark against current Node release and same client without Legion.

Gate:

- signed installed artifact passes; source checkout success is insufficient;
- no repeated Legion process births during normal repeated operations;
- no idle daemon;
- exact capability/tool/version agreement across tested clients;
- AX acceptance scenarios pass without manual dotfile edits.

### M7 — Hard cut

Cut sequence:

1. publish signed native Agent Plugin release candidate privately;
2. install same artifact through reference clients;
3. switch canonical marketplace/package entry to native plugin;
4. run post-switch client-loaded verification;
5. remove Node/Python runtime entrypoints using refreshed exact ledger;
6. remove npm runtime package, Node MCP server, Python product scripts, legacy shims, stale plugin cache routes, and duplicate registrations;
7. update canonical docs and release claims;
8. prove losing routes and emitted variants absent;
9. publish signed release.

Rollback uses client-native plugin version rollback or reinstalls previous signed plugin. It does not create indefinite dual execution.

### M8 — Post-cut cleanup

- retain Node/Python only for explicitly classified development tooling;
- remove migration-only compatibility code and flags;
- archive parity corpus and qualification receipts;
- measure first production sessions;
- close only defects that invalidate requested behavior or strain/AX acceptance.

## 4. Vertical acceptance scenarios

### V1 — One-shot first use

Fresh Mac or Windows machine has a compatible client. User selects Install Legion once in that client, confirms client-required trust/permissions, then sees Legion skills plus native tools without repository setup or manual configuration. Same artifact installs unchanged in a second compatible client through that client's own install action.

### V2 — Quiet idle

No client is open. Legion runs no process. Client loads installed skills without loading full capability bodies. MCP lifecycle follows client behavior and is measured explicitly.

### V3 — Repeated tool use

One client session invokes multiple Legion operations. One native MCP server handles them; Legion creates no per-tool child runtime.

### V4 — Unsupported client

Client without Agent Plugins support is reported unsupported. Legion does not write custom configuration or claim portability. Temporary compatibility shim, if retained during migration, has expiry and no semantic ownership.

### V5 — Blueprint absent

Audit runs every applicable provider, completes reports, marks structural coverage limits, and recommends Membrane/Blueprint without treating absence as global failure.

### V6 — Damaged projection

An installed asset link is missing or stale. RightKit AX rejects release artifact before publication; a client encountering later damage isolates failing component and reports it without disabling valid siblings.

### V7 — Upgrade and rollback

Client update replaces one versioned plugin package. Plugin never points outside its root or mixes core, assets, schemas, and binaries from different versions. Client-native rollback or reinstall restores previous signed version.

### V8 — Complete removal

Client-native uninstall removes installed Legion plugin and its registration while preserving unrelated settings and repositories. Client may remove or retain `${PLUGIN_DATA}` according to its documented policy.

## 5. Evidence required before legacy deletion

- executable inventory with zero unknown runtime item;
- Agent Plugins and RightKit AX conformance reports;
- client-native install/enablement results;
- asset closure and link-target verification;
- client-loaded capability/tool/version inventories;
- Mac and Windows end-to-end results;
- Blueprint-present and Blueprint-absent Audit reports;
- Research end-to-end ledger and artifacts;
- process-count and strain measurements;
- update, disable, rollback, and uninstall results;
- absence scan for losing entrypoints, imports, package dependencies, registrations, caches, documentation, and protocol variants;
- independent completion validation against current user scope.

## 6. Revised execution order

```text
M0 contracts + inventory
  -> M1 minimal native vertical slice
  -> M2 Agent Plugins package + two client conformance fixtures
  -> M3 client-native install + RightKit AX lifecycle
  -> M4/M5 capability and provider migration
  -> M6 signed installed-product qualification
  -> M7 hard cut + legacy deletion
  -> M8 cleanup and production observation
```

Parallel work begins only after M0 freezes file ownership and contracts. M4 capability families may run concurrently; M2, M3, M6, and M7 each retain one integration owner.

## 7. Immediate next actions

1. Freeze old host/cutover dispatches.
2. Refresh L00 inventory at current Legion `main` without touching Membrane.
3. Replace old host contracts with Agent Plugins 1.0 + MCP + client-extension boundaries.
4. Use RightKit AX as existing packaging and AX authority; do not rebuild it in Legion.
5. Select two compatible clients solely for conformance coverage.
6. Implement M1–M3 vertical slice before resuming broad port work.
7. Measure it against current Node runtime.
8. Resume reusable Rust ports only after vertical slice proves product topology.
