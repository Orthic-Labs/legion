# Legion Product Architecture v2

**Status:** Revised target architecture
**Date:** 2026-08-25
**Repository baseline inspected:** `55836a7b`
**Supersedes:** `FINAL-ARCHITECTURE.md` for target topology, host integration, installation, runtime lifecycle, Blueprint handling, and release acceptance

## 1. Decision

Legion becomes a **harness-neutral, native Rust Agent Plugin** with declarative capability assets and one MCP tool surface.

Legion is always **available** after installation, but never an always-running daemon. A host loads Legion's identity and capability index when it starts. Native execution activates lazily only when requested.

User explicitly installs Legion through a compatible agent client's native plugin flow. That install is consent. Client then owns storage, enablement, updates, trust prompts, plugin discovery, MCP lifecycle, and removal. On every later session, client discovers Legion through Agent Plugins 1.0 fixed locations and makes its skills and tools available without project setup or repeated configuration.

Harness-neutral means Legion ships one standard `plugin.json` + `skills/` + `mcp.json` package. It does not invent a Legion-specific plugin protocol. Client-specific extension directories are optional presentation or hook enhancements and cannot own Legion semantics.

## 2. Product motive

Primary optimization axis: **lowest practical system strain during normal agent work**.

Required outcomes:

- no Legion daemon while no harness is using Legion;
- no Node or Python process required to execute Legion-owned product behavior;
- no per-tool or per-capability Legion process spawn;
- no duplicated Legion runtime inside one host session;
- lazy loading of expensive engines and rule packs;
- one explicit native plugin installation action per client and zero manual configuration afterward;
- identical Legion capability identity, contracts, policy, receipts, and failure semantics across hosts;
- truthful degradation when a host cannot expose a surface;
- atomic upgrade, rollback, repair, and removal;
- development tests and build tooling may remain Node or Python when excluded from shipped runtime.

`zero process spawn` is not used as a proxy for efficiency. Agent Plugins standardizes MCP as portable tool transport. A client may launch one native Rust stdio server for its plugin lifecycle or connect through Streamable HTTP. Legion uses local stdio by default: one reusable client-owned process, no daemon, no Node/Python, and no per-tool Legion spawn.

## 3. User model

Installation gives a user one stable plugin package, not one repackaged product per harness.

```text
compatible client's Install Plugin action
        |
        v
client obtains one Legion Agent Plugin
        |
        +-- plugin.json
        +-- skills/
        +-- mcp.json
        +-- native Rust MCP binary
        +-- optional client extension namespaces
        |
        v
client validates -> asks required trust/permission -> enables -> loads
```

After installation:

```text
client starts
  -> loads installed Legion plugin
  -> discovers compact skills from skills/
  -> reads mcp.json and exposes Legion tools through normal client UI
  -> starts native Rust MCP server according to client lifecycle
  -> stops it according to client lifecycle
```

“Legion is active” means the host is operating under Legion's identity and capability contract. It does not mean a background service is consuming resources.

## 4. Canonical boundaries

| Concern | Owner |
|---|---|
| Product semantics, capability catalog, work graph, Audit, Research, review, receipts | Legion Rust core |
| Deterministic effect authorization | Arcane policy data + Legion Rust evaluator |
| Context selection and evidence publication | Membrane |
| Repository truth | Blueprint |
| Harness conversation, model invocation, native tools, session lifecycle | Host |
| Model/provider selection | Host or OmniRouter |
| Portable plugin package and MCP declaration | Agent Plugins 1.0 |
| Plugin validation and AX gates | RightKit AX |
| Installation, enablement, permissions, cache, update UX | Compatible client |
| Signed native artifacts and release publication | RightKit Release |

Membrane is integrated through typed interfaces only. No Membrane source change is required by this migration.

Blueprint is an optional context accelerator, not a global Audit prerequisite. When Blueprint is unavailable, Audit continues with every applicable non-Blueprint provider and emits a visible recommendation plus provider-specific coverage limitations. Only a user-selected operation whose meaning inherently requires Blueprint may return a typed capability degradation; it cannot abort unrelated providers or report a machinery crash.

## 5. Runtime architecture

### 5.1 Shipped components

```text
legion-plugin/
├─ plugin.json              # Agent Plugins 1.0 identity/version
├─ skills/                  # standard Agent Skills packages
├─ mcp.json                 # standard local Rust MCP declaration
├─ bin/
│  ├─ legion               # macOS/Linux native binary
│  └─ legion.exe           # Windows native binary
├─ share/legion/
│  ├─ identity/
│  ├─ policy/
│  ├─ rules/
│  └─ schemas/
└─ com.<client>/            # optional client-owned extensions only
```

Release packaging must preserve one filesystem-contained plugin root. Platform binary selection must remain Agent Plugins conformant and is qualified against each supported client's command-resolution behavior.

### 5.2 Rust core

Rust owns all shipped Legion algorithms:

- contracts and schema validation;
- catalog parsing and dependency closure;
- work-graph validation and bounded orchestration;
- Arcane policy evaluation;
- Audit planning, execution, reconciliation, and reports;
- Research ledger and evidence controls;
- review and completion protocols;
- deterministic providers and rule engine;
- effect receipts and bounded external-tool requests;
- plugin/package self-diagnostics and state compatibility.

Markdown, JSON, YAML, schemas, prompts, lenses, recipes, and rule packs remain declarative assets.

### 5.3 Runtime mode

Portable runtime uses Agent Plugins MCP:

| Component | Standard behavior | Legion choice |
|---|---|---|
| Skills | Client discovers `skills/*/SKILL.md` | Progressive, no runtime process |
| Tools | Client reads `mcp.json` | Local native Rust stdio server |
| Client extensions | Client reads its reverse-domain namespace | Optional hooks/commands only |

Client owns MCP start, permission prompts, cancellation, restart, and shutdown. Legion server handles many tool calls in one lifecycle. No resident daemon or per-tool bootstrap exists.

### 5.4 Internal process rule

Legion-owned algorithms cannot invoke Node, Python, shell scripts, or another Legion process. External project tools remain intentional effects and use one policy-controlled executor. A target repository may therefore run its own compiler, browser, scanner, VCS client, Node, Python, or Cargo without making those Legion runtime dependencies.

## 6. Agent Plugins boundary

### 6.1 Portable contract

Agent Plugins 1.0 is Legion's only portable host contract:

- `plugin.json` identifies Legion and target specification version;
- `skills/` carries Agent Skills in fixed locations;
- `mcp.json` declares one native Rust MCP server;
- `${PLUGIN_ROOT}` references immutable package assets;
- `${PLUGIN_DATA}` references client-managed persistent state;
- independent component failure remains isolated and visible;
- client extension namespaces carry optional non-portable surfaces.

Legion does not maintain separate Claude, Codex, Cursor, Copilot, Pi, or VS Code package layouts for portable components.

### 6.2 Client responsibility

Compatible client owns:

1. user-facing install action and scope;
2. plugin storage/cache and version selection;
3. manifest validation and component discovery;
4. trust, permission, authentication, and sandbox prompts;
5. MCP process lifecycle and environment;
6. skill and tool presentation;
7. update, disable, and uninstall UX.

Install action is explicit consent to install. It is not blanket consent for later network, credential, destructive, or host-governed effects; client prompts remain authoritative.

### 6.3 RightKit AX responsibility

RightKit AX already owns:

- Agent Plugins 1.0 scaffold and pinned-schema validation;
- plugin-root and symlink/junction containment checks;
- SKILL.md reference closure;
- MCP static contract checks;
- packaged-artifact conformance probes;
- behavioral and adversarial AX evidence;
- JSON, SARIF, and Markdown gate reports.

Legion consumes RightKit AX; it does not rebuild this machinery. RightKit AX gates and reports. Release verdict authority remains outside RightKit AX.

Current adoption gap: Legion does not yet contain Agent Plugins root `plugin.json` or `mcp.json`. Current RightKit AX validation also treats every immediate `skills/` child directory without `SKILL.md` as an error, while Agent Plugins 1.0 discovers only immediate child directories that contain a regular `SKILL.md`. RightKit owner must reconcile that rule before Legion makes it a hard release gate. Legion validates a curated packaged plugin root, not its mixed-purpose source tree.

### 6.4 Client-specific extensions

Hooks, custom agents, commands, UI, and enforcement surfaces not standardized by Agent Plugins live only under reverse-domain client namespaces. Portable Legion behavior cannot depend on them. RightKit AX reports extension-specific fidelity separately.

### 6.5 Unsupported clients

A client that does not implement Agent Plugins cannot load Legion's portable package. Product response is to support or contribute to Agent Plugins adoption in that client, not build a second Legion packaging protocol. A temporary compatibility shim may exist only as a bounded migration artifact with an expiry and no semantic ownership.

## 7. Installation

### 7.1 User experience

User chooses **Install Legion** in a compatible client's normal plugin marketplace, CLI, or plugin UI. One client-owned action performs:

```text
obtain Legion Agent Plugin
-> validate plugin.json
-> select install scope
-> show client trust/permission prompt when required
-> store and enable plugin
-> discover skills/ and mcp.json
-> expose Legion skills and tools
```

Expected result:

```text
Legion installed
  skills ✓  tools ✓  native runtime ✓
```

User-scope install makes Legion available to future sessions in that client. Project/local scopes remain client choices. Installing into another client is another explicit install action using the same unchanged plugin artifact.

### 7.2 Installation invariants

- plugin release is self-contained and versioned;
- no installed skill, script, or binary points back into a source checkout;
- every symlink/junction target is resolved and verified before activation;
- assets use installation-root-relative resolution, never current-working-directory assumptions;
- Agent Plugins component failures remain isolated and reported;
- client owns atomic cache/update/disable/uninstall behavior;
- Legion package cannot mutate client registration or unrelated configuration itself;
- update cannot mix core, assets, schemas, or plugin versions;
- RightKit AX validates packaged artifact, not source tree.

These invariants directly prevent the missing Research symlink/projection class of failure.

## 8. Agent experience requirements

Agent experience (AX) is a release surface, not documentation polish.

### AX-1: immediate recognition

First client launch after installation discovers Legion without a project-specific prompt. Client receives compact skill metadata, not full doctrine.

### AX-2: progressive disclosure

Startup loads only identity, capability names, descriptions, and routing metadata. Full skills, references, rules, and engines load on demand.

### AX-3: native-feeling tools

Tools appear in client's normal tool catalog, use stable names and schemas, stream/cancel through MCP/client conventions, and return ordinary client artifacts. Users do not configure an MCP command or path manually.

### AX-4: no configuration archaeology

`legion.status` reports plugin version, tool count, capability count, runtime state, optional-service fidelity, and exact remediation. Client's plugin manager reports install, cache, update, enablement, and removal state.

### AX-5: honest capability truth

Full, degraded, baseline, and unavailable are distinct. A host lacking enforcement hooks cannot be described as fully Arcane-enforced. Optional Blueprint absence cannot masquerade as Audit failure.

### AX-6: quiet operation

No daemon, tray process, repeated startup chatter, visible terminal window, or per-operation bootstrap. Detailed receipts remain available without flooding normal responses.

### AX-7: predictable lifecycle

Install, update, disable, reload, and uninstall follow client-native lifecycle. Legion state migration is versioned and idempotent.

### AX-8: consistent identity

Every compatible client sees same plugin version, capability IDs, MCP tool schemas, and semantic results. Client presentation may differ; product meaning cannot.

## 9. Performance and strain acceptance

Release qualification records, per supported host:

- client cold-start delta with Legion installed;
- idle CPU and memory with no Legion operation;
- first-operation latency;
- repeated-operation latency;
- native MCP process count and births per client session;
- peak memory for Audit and Research workloads;
- runtime and asset bytes;
- shutdown and cancellation latency.

Acceptance is comparative against the current Node product and the same host without Legion. Required qualitative gates:

- no idle Legion daemon;
- no recurring process births during repeated Legion operations;
- no regression caused by loading unused capability bodies;
- one client-managed MCP server reused for repeated operations;
- native product path materially lowers total Legion overhead on representative workloads before legacy deletion.

Numeric budgets are frozen from measured baselines before cutover rather than invented in architecture.

## 10. Security and trust

- signed native binaries and release provenance;
- digest-bound core, assets, schemas, and plugin version;
- least-privilege host service negotiation;
- explicit effect intents evaluated immediately before effect;
- no shell command strings in native contracts;
- bounded outputs, deadlines, cancellation, and process-tree ownership;
- secrets remain host-owned and are referenced by handles;
- plugin contains no credentials and relies on client-managed authorization;
- stdio server accepts only its owning client connection and exposes no network listener;
- client extensions cannot replace portable Legion semantics.

## 11. Product commands

One native binary exposes MCP server mode plus optional standalone/CI commands:

```text
legion serve --stdio       # Agent Plugins MCP runtime
legion status
legion <workflow>          # explicit standalone/CI use
```

Client plugin manager owns installation. No Legion script edits client configuration.

## 12. Completion definition

Rust migration and product cutover are complete only when:

- shipped Legion-owned algorithms are Rust or declarative data;
- shipped product has no Node/Python runtime dependency;
- no always-on Legion daemon exists;
- no repeated Legion self-spawn path exists;
- plugin.json, skills, mcp.json, and native command conform to Agent Plugins 1.0;
- RightKit AX packaged-artifact static, conformance, behavioral, and adversarial gates pass;
- two compatible clients load same plugin artifact without repackaging;
- native binary passes Mac and Windows package qualification;
- installed assets contain no source-checkout links or missing targets;
- every tested compatible client receives identical release/capability/tool identities;
- unsupported surfaces report truthful fidelity;
- Blueprint absence never aborts Audit globally;
- representative strain measurements beat or justify replacement of current Node runtime;
- old Node/Python runtime entrypoints, packages, shims, registrations, caches, docs, and emitted protocol variants are proven absent;
- signed installed artifacts, not source-tree tests alone, pass end-to-end qualification.

## 13. Explicit non-goals

- a Legion-specific replacement for Agent Plugins;
- a Legion daemon or Hub replacement;
- reimplementing host conversations, models, browsers, or subagent systems;
- absorbing Membrane, Blueprint, Cortex, OmniRouter, or host responsibilities;
- porting development-only tests and generators solely to eliminate their languages;
- bypassing client install, trust, permission, authentication, update, or uninstall UX.
