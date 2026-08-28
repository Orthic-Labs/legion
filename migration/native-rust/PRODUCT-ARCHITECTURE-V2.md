# Legion Product Architecture v2

**Status:** Accepted target architecture; closed after this correction pass unless M0–M3 produce concrete contradictory evidence
**Date:** 2026-08-25
**Repository baseline inspected:** `0485c90b`
**Supersedes:** `FINAL-ARCHITECTURE.md` for target topology, host integration, installation, runtime lifecycle, Blueprint handling, and release acceptance

## 1. Decision

Legion becomes a **machine-installed, harness-neutral native Rust agent runtime** with portable
skills, one MCP tool surface, and thin client integrations.

Agent Plugins 1.0 is Legion's preferred portable integration and package contract where supported.
It is not a universal installer and does not define Legion's supported-client boundary.

One native Legion executable is installed for the machine's platform and architecture. The user
then runs `legion setup` to detect, select, install, and verify integrations for supported agent
clients. Every integration invokes that installed executable. Legion is available after setup but
never runs as a daemon while no client is using it.

All Legion-owned product semantics and executable workflows run in the shared Rust runtime.
Client-native integration shims may use a client's required extension language but remain
mechanical and contain no Legion semantic implementation.

## 2. Product motive

Primary optimization axis: **lowest practical system strain during normal agent work**.

Required outcomes:

- one machine installation, followed by explicit setup for selected agent clients;
- no Legion daemon while no client is using Legion;
- no Node or Python process required for Legion-owned product behavior;
- no per-tool or per-capability Legion runtime spawn;
- one reusable client-owned stdio MCP subprocess per active client integration;
- lazy loading of expensive engines, rule packs, and capability bodies;
- identical Legion identities, contracts, policy, receipts, and failure semantics across clients;
- truthful full, degraded, baseline, or unavailable fidelity;
- transactional setup, repair, disable, removal, state migration, and rollback;
- development tests and build tooling may remain Node or Python when excluded from shipped runtime.

`zero process spawn` is not used as a proxy for efficiency. Each active client may launch its own
reusable `legion serve --stdio` subprocess. Legion never self-spawns another runtime per tool call.
Client-controlled restart and recovery are permitted and measured.

## 3. Terms and user model

An **agent client/host** is an agent app, CLI, or harness that consumes Legion, such as Pi, Codex,
Claude Code, OpenCode, or Cursor. Agent Plugins may use *client* more narrowly for a conformant
package consumer; Legion docs use *agent client/host* when referring to the broader product class.

### 3.1 Machine installation

```text
macOS                                  Windows
brew install legion                    winget install legion
        |                                      |
        v                                      v
signed + notarized legion              signed + timestamped legion.exe
        |                                      |
        +------------------+-------------------+
                           v
                     legion setup
                           |
             detect supported agent clients
                           |
               show mechanisms and fidelity
                           |
           user selects integrations to enable
                           |
          install/register/verify each adapter
```

M0 freezes Homebrew packaging as formula (optionally bottled) versus cask, then selects appropriate
tap/distribution channel from release mechanics, signing, provenance, update, and rollback evidence.
Architecture does not pre-decide those choices.
WinGet portable packaging is acceptable when it preserves signing, aliases, updates, and removal.
Neither platform requires a desktop app, DMG, PKG, MSI, tray process, or setup wizard.

### 3.2 Active runtime

```text
Cursor      -> legion serve --stdio   process A
Codex       -> legion serve --stdio   process B
Claude Code -> legion serve --stdio   process C
```

Processes A–C are expected. Each belongs to its client, serves many tool calls, and exits under
that client's lifecycle. No machine-wide Legion daemon or socket exists.

## 4. Canonical boundaries

| Concern | Owner |
|---|---|
| Product semantics, capability catalog, work graph, Audit, Research, review, receipts | Legion Rust core |
| Deterministic effect authorization | Arcane policy data + Legion Rust evaluator |
| Context selection and evidence publication | Membrane |
| Repository truth | Blueprint |
| Conversation, model invocation, native tools, session lifecycle | Agent client/host |
| Model/provider selection | Agent client/host or OmniRouter |
| Portable plugin shape and MCP declaration | Agent Plugins 1.0 |
| Machine installation and client integration | platform package manager + `legion setup` |
| Client-specific lifecycle, permissions, and MCP process | agent client/host |
| Plugin validation and AX gates | pinned RightKit AX release |
| Signed native artifacts and release publication | RightKit Release |

Membrane remains context owner and is consumed through typed interfaces only. This migration does
not require Membrane source changes and does not absorb Membrane, Cortex, OmniRouter, Blueprint, or
host/model responsibilities into Legion.

Blueprint is an optional context accelerator, not a global Audit prerequisite. When Blueprint is
unavailable, Audit continues every applicable non-Blueprint provider and emits a visible
recommendation plus exact structural-coverage limits. Only an explicitly Blueprint-dependent
operation may return provider-level typed degradation; it cannot abort unrelated work or report a
machinery crash.

## 5. Packaging and runtime architecture

### 5.1 Machine-installed runtime

Platform package installs one active native command plus versioned Legion-owned runtime assets:

```text
legion or legion.exe
share/legion/
├─ release.json
├─ identity/
├─ policy/
├─ rules/
└─ schemas/
```

Package manager selects compatible OS and architecture artifact. `legion.exe` is Legion's Windows
runtime/MCP executable, not an installer.

### 5.2 Portable Agent Plugin

Agent Plugins-capable integrations consume one portable package with no embedded platform binary:

```text
legion-plugin/
├─ plugin.json
├─ skills/
├─ mcp.json
├─ share/legion/
│  ├─ release-binding.json
│  ├─ identity/
│  └─ schemas/
└─ com.<client>/            # optional client extension, mechanical only
```

Canonical `mcp.json` uses a bare installed command, which Agent Plugins 1.0 resolves through
platform executable search:

```json
{
  "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
  "mcpServers": {
    "legion": {
      "type": "stdio",
      "command": "legion",
      "args": ["serve", "--stdio", "--plugin-root", "${PLUGIN_ROOT}"]
    }
  }
}
```

Bare-command resolution is not assumed. `legion setup` proves resolution in each supported
client's actual launch environment. If an agent client sanitizes or omits required executable
search paths, setup uses that client's supported native registration mechanism with exact installed
path. If neither route works safely, fidelity is degraded or unavailable; setup never claims Full.

Agent Plugins does not permit an arbitrary absolute `command`, and package paths or links cannot
escape plugin root. Legion therefore never disguises an external machine binary as a contained
plugin-relative executable.

### 5.3 Release binding

Every installed integration binds its assets to one Legion release using at least:

- runtime artifact digest and provenance;
- release version;
- capability-catalog hash;
- MCP tool-schema hash;
- declarative-asset/schema hash.

MCP initialization verifies binding before exposing tools. Mismatch fails closed with exact
`legion setup repair --confirm` remediation; stale assets never run silently against a newer runtime.
Package-manager update and integration refresh may form a bounded skew window, but no mixed-version
execution is allowed: setup repairs each integration transactionally after update. Existing client
processes may finish under their bound release; incompatible state migration waits for old runtime
leases to close.

### 5.4 Rust core

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
- setup, integration diagnostics, release binding, and state compatibility.

Markdown, JSON, YAML, schemas, prompts, lenses, recipes, and rule packs remain declarative assets.

### 5.5 Internal process rule

Legion-owned algorithms cannot invoke Node, Python, shell scripts, or another Legion runtime.
External project tools remain intentional typed effects through one policy-controlled executor. A
target repository may run its compiler, browser, scanner, VCS client, Node, Python, or Cargo without
making those Legion runtime dependencies.

## 6. Integration architecture

### 6.1 Portable contract

Agent Plugins 1.0 is preferred where supported:

- `plugin.json` identifies Legion and specification version;
- `skills/` carries Agent Skills in fixed locations;
- `mcp.json` declares one installed native Rust MCP server;
- `${PLUGIN_ROOT}` references immutable integration assets;
- `${PLUGIN_DATA}` references client-managed integration-local data;
- independent component failure remains isolated and visible;
- reverse-domain extension namespaces carry optional non-portable surfaces.

Distribution, installation, enablement, permissions, update UX, and client-specific capabilities
remain outside Agent Plugins 1.0.

### 6.2 Thin adapters

`legion setup` selects each agent client's highest-fidelity supported mechanism:

1. supported native plugin install/update/remove API;
2. Agent Plugins package installation;
3. native MCP/config registration;
4. minimal client-native bridge where unavoidable.

Adapters may own detection, registration, projection, paths, enable/disable, verification, repair,
and cleanup. They cannot own routing, Audit, Research, Arcane policy, work graphs, receipts,
capability semantics, or another Legion ontology. This does not recreate retired descriptor-driven
semantic host engine.

Pi receives one explicit official integration path during M0. A tiny Pi-native bridge is allowed
only when Pi's extension model requires it and only under this mechanical-only rule.

### 6.3 Supported Client Profile

Agent Plugins conformance alone does not mean Full Legion support; a conformant client may expose
skills only.

| Fidelity | Required behavior |
|---|---|
| Full | skills, executable Legion tool surface, required MCP lifecycle, identity/version binding, and every claimed host enforcement surface |
| Degraded | meaningful subset works; missing surfaces are explicit and operationally safe |
| Baseline | instructions/skills only; no executable Legion workflow claims |
| Unavailable | required integration cannot be installed or operated safely |

Full Arcane enforcement, Audit execution, Research execution, or equivalent claims require measured
support for their actual runtime and host surfaces. Each released adapter records mechanism,
fidelity, missing surfaces, executable-resolution proof, and qualification evidence.

### 6.4 Agent client responsibility

After setup, agent client owns:

1. trust, permission, authentication, and sandbox prompts under its native policy;
2. MCP process start, cancellation, restart, and shutdown;
3. skill and tool presentation;
4. client-native enablement and session lifecycle.

Legion install/setup consent is not blanket consent for later network, credential, destructive, or
host-governed effects. Client prompts and Arcane policy remain authoritative at their boundaries.

### 6.5 RightKit AX responsibility

RightKit AX owns Agent Plugins scaffold/schema validation, containment, skill reference closure,
MCP static contracts, clean-room conformance, behavioral matrix, adversarial evidence, and
JSON/SARIF/Markdown gate reports. Legion consumes this capability and does not rebuild it.

Qualification pins exact RightKit version and source commit in release evidence. Current inspected
candidate is `@rightkit/ax` `0.2.0` at commit
`01f52555202da3dffc6b649ca44e803b55238081`; M0 freezes qualification pin after reconciling any
remaining Agent Plugins discovery discrepancy. RightKit gates and reports; release verdict remains
outside RightKit.

## 7. Installation, setup, and state

### 7.1 `legion setup`

`legion setup` is a first-class product capability. It:

- detects installed supported agent clients;
- reports available mechanisms and fidelity;
- lets user select clients to enable;
- prefers supported client-native lifecycle APIs;
- installs/registers canonical skills and native tool access;
- points integrations at installed `legion` command or supported exact path;
- verifies skill discovery, MCP startup, identity, version, hashes, and fidelity;
- supports `--dry-run`, repair, disable, removal, and explicit state purge;
- previews and confirms config mutations;
- applies fallback config edits transactionally with backup and exact rollback;
- never overwrites unrelated user configuration.

### 7.2 Installation invariants

- no installed asset points into source checkout;
- integration copies are versioned and release-bound;
- symlink, junction, and reparse targets are resolved before activation;
- native client APIs are preferred over internal config edits;
- update cannot mix runtime, assets, schemas, catalog, or tool contracts;
- client failures cannot corrupt unrelated client configuration;
- package-manager uninstall and `legion setup remove` have explicit, independent behavior;
- RightKit AX validates packaged clean-room artifacts, not mixed-purpose source tree.

These invariants prevent missing Research symlink/projection class of failure.

### 7.3 Persistent-state authority and compatibility

State ownership is explicit:

| State | Owner and rule |
|---|---|
| Legion setup registry and runtime-local durable state | Legion, in platform user-data location |
| Agent Plugins `${PLUGIN_DATA}` | client-owned integration cache/config only; never canonical Legion semantics |
| Repository context and evidence publication | Membrane/Blueprint typed interfaces |
| Durable memory | Cortex |
| Project workflow artifacts | owning workflow/project path |

Every Legion-written persistent-state root records:

```text
schema_version
writer_version
min_reader_version
migration_generation
```

Legion uses transactional migration with pre-upgrade snapshot and atomic restore for rollback.
Migration and setup acquire an exclusive state lock; incompatible migrations wait for active old
runtime leases to close. Interrupted migration restores previous generation. Corrupted or
incomplete state fails closed with repair guidance. Uninstall retains state by default; explicit
purge removes only verified Legion-owned roots.

Qualification covers N-1 to N upgrade, interruption, N to N-1 rollback, uninstall/reinstall,
corruption, concurrent clients, and active-work updates.

## 8. Agent experience requirements

Agent experience is a release surface.

- **Immediate recognition:** selected clients discover Legion after setup without project setup.
- **Progressive disclosure:** startup loads compact identity and capability metadata only.
- **Native-feeling tools:** tools use client catalogs, stable schemas, streaming, and cancellation.
- **No configuration archaeology:** `legion status` and `legion setup status` show exact health and remediation.
- **Honest fidelity:** Full, Degraded, Baseline, and Unavailable never collapse into one claim.
- **Quiet operation:** no daemon, tray, terminal window, repeated bootstrap, or per-tool runtime spawn.
- **Predictable lifecycle:** setup, update, repair, disable, remove, migration, and rollback are transactional.
- **Consistent identity:** clients receive same release, capability IDs, schemas, and semantic results.

## 9. Performance and strain acceptance

Release qualification records per supported agent client/host:

- cold-start delta with Legion integration enabled;
- idle CPU and memory with no Legion operation;
- first-operation and repeated-operation latency;
- native MCP process count and births per client session;
- peak memory for Audit and Research;
- runtime and asset bytes;
- shutdown, cancellation, crash, and restart latency;
- setup detection and verification time.

Acceptance compares current Node product and same client without Legion. Required gates:

- no idle Legion daemon;
- no recurring process births during repeated operations;
- one client-owned MCP subprocess reused within each client session;
- unused capability bodies stay unloaded;
- native path materially reduces Legion overhead before legacy deletion.

Numeric budgets are frozen from measured baselines before cutover.

## 10. Security and trust

- macOS artifacts use Developer ID signing and notarization; Windows uses Authenticode and trusted timestamp;
- runtime, assets, schemas, catalog, and plugin integrations are digest-bound;
- setup previews and confirms mutations, then writes transactionally;
- effect intents are evaluated immediately before effect;
- no shell command strings exist in native contracts;
- outputs, deadlines, cancellation, and process trees are bounded;
- secrets remain host-owned and referenced by handles;
- stdio server accepts only owning client connection and exposes no network listener;
- client adapters cannot replace portable Legion semantics.

## 11. Product commands

One native binary exposes runtime, setup, diagnostics, and optional standalone/CI workflows:

```text
legion serve --stdio
legion setup [--dry-run]
legion setup status|repair|disable|remove
legion status
legion <workflow>
```

## 12. Completion definition

Rust migration and hard cut are complete only when:

- shipped Legion algorithms are Rust or declarative assets;
- shipped product has no Node/Python runtime dependency;
- no always-on Legion daemon or per-tool Legion self-spawn exists;
- one platform-native Legion command installs through qualified Homebrew and WinGet paths;
- `legion setup` installs and verifies two independent agent-client implementations;
- portable plugin conforms to Agent Plugins 1.0 without embedded platform binary;
- every Full client proves installed-command resolution or supported exact-path registration;
- runtime and integration assets pass release-binding handshake;
- RightKit AX pinned clean-room static, conformance, behavioral, adversarial, and real-client gates pass;
- state upgrade, interrupted migration, rollback, reinstall, corruption, and concurrency matrix passes;
- Mac and Windows semantic identities match;
- permission denial/revocation and degraded-client behavior are truthful;
- Blueprint absence never globally aborts Audit;
- installed assets contain no source-checkout or stale projection routes;
- representative strain measurements justify replacement of current Node runtime;
- legacy runtime entrypoints, packages, shims, registrations, caches, and protocol variants are absent;
- signed installed artifacts, not source-tree tests alone, pass end-to-end qualification.

## 13. Explicit non-goals

- desktop app, DMG, PKG, MSI, tray app, or setup wizard;
- always-running Legion daemon or shared local socket;
- bundled native binary duplicated inside every portable client package;
- Legion-specific replacement for Agent Plugins;
- semantic implementation inside client adapters;
- reimplementing host conversations, models, browsers, or subagent systems;
- absorbing Membrane, Blueprint, Cortex, OmniRouter, or host responsibilities;
- porting development-only tests and generators solely to remove their languages;
- bypassing user consent, client permissions, or Arcane policy.

Architecture reopens only if M0–M3 produce concrete evidence that an accepted assumption is
impossible or materially worse than measured alternatives.
