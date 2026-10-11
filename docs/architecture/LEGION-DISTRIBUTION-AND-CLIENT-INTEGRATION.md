# Legion distribution & client integration architecture

**Status:** CANONICAL
**Adopted:** 28 August 2026
**Owner:** Legion product distribution, activation, & client reconciliation

This document is Legion's specialist architecture owner for public distribution & agent-client
integration. `docs/LEGION-CANONICAL-SSOT.md` remains system authority. Machine-readable release
policy derives from `release/distribution-contract.json`.

## 1. Decision

Public CI produces per-platform native release candidates, signs Windows through environment-scoped
GitHub OIDC, & signs/notarizes macOS through protected-environment Developer ID secrets. Protected
local release hosts seal & upload candidates through immutable GitHub Releases. Users install or update with
one branded command:

```powershell
irm https://legion.orthiclabs.com/install.ps1 | iex
```

GitHub Pages hosts only the custom-domain bootstrap wrapper. GitHub Releases host
immutable payloads. Package-manager, vendor, MSI, DMG, PKG, setup-application, & store lanes are
unsupported. Legion runs no machine-wide service, tray process, or background updater.

## 2. Trust & publication

```text
legion.orthiclabs.com TLS/DNS
  -> immutable versioned bootstrap with accepted manifest key IDs
  -> GitHub release-manifest.json + release-manifest.cat
  -> exact OS/architecture archive
  -> native signature + manifest-bound digests/provenance/SBOM
  -> staged activation
  -> exact setup health
```

`release-manifest.json` plus its Authenticode catalog is sole release trust authority.
`checksums.json` is discovery/convenience evidence whose digest is bound by release manifest.
Manifest binds product, version, tag, source commit, asset URL, OS, architecture, size, SHA-256,
executable path, native-signature policy, provenance digest, SBOM digest, minimum bootstrap
version, & signing-key ID. On Windows, `release-manifest.cat` is the Authenticode catalog bound
to manifest bytes & release asset digests.

GitHub release assets use these names when target is supported for tag `vX.Y.Z`:

```text
legion-X.Y.Z-windows-x86_64.zip
legion-X.Y.Z-windows-arm64.zip
legion-X.Y.Z-macos-x86_64.tar.gz
legion-X.Y.Z-macos-arm64.tar.gz
release-manifest.json
release-manifest.cat
checksums.json
provenance-<os>-<arch>.intoto.jsonl
sbom-<os>-<arch>.cdx.json
THIRD_PARTY_NOTICES.md
```

Only supported, signed, qualified targets publish. Absence of another target is truthful, not
filled with an unqualified artifact.

Stable GitHub Pages path resolves the latest immutable GitHub Release bootstrap. Release scripts
embed accepted manifest key IDs. GitHub Releases remain payload authority. Infrastructure owns DNS
& TLS; RightKit Release owns bootstrap publication. Legion contains configuration & product
activation, never a second uploader.

### 2.1 Public CI & protected release boundary

Public `Orthic-Labs/legion` GitHub Actions runs compile, test, candidate/package qualification, package smoke, SBOM,
provenance, candidate production, Windows Azure OIDC signing, & macOS Developer ID
signing/notarization from protected environment secrets. Package smoke stages each supplied candidate
into an isolated product-root `current` tree, then exercises installed-boundary runtime resolution on
its target OS. CI cannot upload a release.

Protected local release hosts consume exact candidate & evidence digests. They perform post-sign
installed-artifact qualification, release sealing, manifest-catalog signing, & upload to immutable
GitHub Releases & approved bootstrap publication. They do not rebuild candidates. Private repositories run same RightKit pipeline wholly locally, with
zero GitHub Actions; public & private differ only by runner, authentication, & spend boundary.

## 3. Install, update, rollback, removal

Bootstrap:

1. detects OS & architecture;
2. resolves an exact version, defaulting to latest authorized release;
3. verifies manifest catalog, archive digest, bound provenance/SBOM, & native platform signature;
4. extracts into a versioned user-local staging root;
5. preflights activation when supported & journals integration mutations;
6. atomically switches stable `current` path;
7. updates user PATH to stable `current/bin`;
8. invokes installed stable `current/bin/legion setup repair --confirm`;
9. requires bounded `legion setup status` & `legion doctor` success before completion, preserving
   lifecycle plus stdout/stderr diagnostics on failure.

macOS product root is `~/Library/Application Support/Orthic Labs/Legion`; its activation binary is
`~/Library/Application Support/Orthic Labs/Legion/current/bin/legion`. Installer-created
`~/.local/bin` links resolve only to this stable-current tree.

Harness registrations always bind stable `current` executable, never a disposable version path.
Activation is structural & offline: it never requires client login, model invocation, or authenticated
MCP qualification. `legion setup qualify` refreshes authenticated live-client evidence separately;
failed qualification returns separate `blocked` health, while setup status reports stored evidence as
`qualified`, `partial`, `not_run`, or `stale` without invalidating current structural activation.
Rerunning bootstrap updates. Explicit version pins are supported; downgrade requires an explicit
flag. Prior successful version is retained. Failure restores previous `current` pointer,
integration journal, & prior exact health. Removal deletes verified Legion-owned runtime &
integrations only; durable state remains unless explicit verified purge is requested.

## 4. Agent Plugins & client boundaries

Agent Plugin manifests declare portable public skills and MCP; supported host extensions may also
declare native hooks. The format does not own installation, updates, activation, host UI, or
Legion's bind policy. Legion portable core includes every public canonical skill with plain IDs &
no private/personal workspace content.

| Client | Canonical integration |
|---|---|
| Claude Code | Native marketplace plugin for MCP, hooks, agents, & namespaced skills; Legion-managed bind policy remains a separate project surface. |
| Codex | Native Agent Plugin for skills, MCP, & trust-gated lifecycle hooks; `legion bind --write` separately creates Codex role configuration & explicit-only invocation policy. |
| Cursor | Agent Plugins portable core: bundled skills plus MCP declaration. No Cursor sidecar ships in current release. |
| Pi | Native `.agents/skills` projection; Pi is not claimed as full Agent Plugins support or executable registration. |
| Antigravity | Agent Plugins portable core. Setup derives `mcp_config.json` from portable MCP declaration; no native hooks, agents, rules, or Antigravity schema are claimed. |
| Devin | Devin user surfaces: `skills/` & `agents/` projected into the Devin user config root; owned `mcp_config.json` MCP entry & `config.json` hooks block (packaged events mapped to Devin's event names) written into Devin's own config files. The account-gated `devin plugins install` path is not used; Devin CLI/Desktop picks up skills, subagent profiles, hooks, & MCP from these documented user surfaces. |

`legion setup repair --confirm` detects, reconciles, structurally verifies, & journals selected clients.
`legion setup status` reports actual runtime binding, projection generation, executable resolution,
stored authenticated MCP qualification, skill fidelity, & typed degradation. Authenticated live
qualification runs only through `legion setup qualify` & never gates activation. Client adapters remain mechanical; Legion
semantics stay canonical.

### 4.1 Native marketplace installation

The sealed payload's `current` directory is the local marketplace root for both native clients.
Claude Code reads `.claude-plugin/marketplace.json`; Codex reads `.agents/plugins/marketplace.json`.
Each catalog identifies marketplace `legion-installed` and resolves plugin `legion` from `./plugin`.
Setup registers each marketplace and installs through its host's native plugin lifecycle. Codex's
native cache is a copy, so setup reads back the installed identity, release binding, runtime digest,
and portable-core digest before retiring any legacy copied plugin or standalone skill projection.
`legion setup status` reports registration, installation, disablement, stale binding, missing client,
and incomplete CLI readback as separate states.

The plugin owns bundled skills, MCP, and hooks. Codex role definitions in `.codex/agents/` and their
registration in `.codex/config.toml` remain separate `legion bind --write` policy. Disabling the
plugin through Codex controls plugin-owned skills, MCP, and hooks; role files remain under bind's
ownership. Codex also skips plugin hooks until the user trusts the current hook definition. Legion
projects only `UserPromptSubmit` and `Stop` lifecycle hooks there; it does not claim pre-tool Guard
enforcement from Codex hooks. Doctor reports the native cache path, explicit plugin disablement,
hook definition presence, and recorded host trust separately; generic receipt traces do not prove
Codex hook execution or current-definition trust.

The native behavior follows [Claude Code's marketplace lifecycle](https://code.claude.com/docs/en/plugin-marketplaces)
and [OpenAI's Codex plugin packaging and hooks guidance](https://developers.openai.com/plugins/build/plugins).

## 5. Ownership

| Concern | Owner |
|---|---|
| Legion install UX, roots, PATH, activation, setup health, client matrix, plain skill IDs, rollback integration semantics, & data ownership | Legion |
| Asset naming, signed manifest schema, key rotation, protected-host finalization/upload, GitHub Pages bootstrap publication, shared install/update transaction primitives | `@rightkit/release` |
| Agent Plugins schema, portable package assembly/containment, public-resource closure, & conformance | `@rightkit/ax` |
| Public CI compile/test/qualification/package smoke/SBOM/provenance/candidate workflow plus Windows OIDC & macOS Developer ID/notarization signing | `@rightkit/git` |
| DNS & TLS policy | Orthic Labs infrastructure |

RightKit package acceptance includes one end-to-end contract spanning direct bootstrap, signed
manifest, stable-current activation, rollback, & product/client projections. Component-local
signing, schema, or workflow success cannot claim distribution readiness alone.

## 6. Retirement & evolution

The superseded package-manager M0 distribution contract records
provenance only. Active release gates reject package-manager metadata; GitHub Pages plus GitHub
Releases remain sole public channel.

Architecture reopens when official client specifications change, a target cannot satisfy native
signature/rollback guarantees, or measured activation evidence disproves client fidelity. Release
manifest schema changes require compatible bootstrap/key-rotation migration before publication.
