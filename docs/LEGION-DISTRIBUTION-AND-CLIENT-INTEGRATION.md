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

R2 hosts only small bootstrap scripts. It never duplicates release payloads. WinGet, Homebrew,
MSI, DMG, PKG, setup applications, & store listings are optional future aliases, not release
requirements. Legion runs no machine-wide service, tray process, or background updater.

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

Stable R2 paths serve or redirect to immutable `versions/<bootstrap-version>/` scripts. Versioned
scripts embed accepted manifest key IDs. GitHub assets remain payload authority. Infrastructure
owns R2 bucket, DNS, TLS, cache, & object policy; RightRelease owns bootstrap publication. Legion
contains configuration & product activation, never an R2 uploader.

### 2.1 Public CI & protected release boundary

Public `Orthic-Labs/legion` GitHub Actions runs compile, test, candidate/package qualification, package smoke, SBOM,
provenance, candidate production, Windows Azure OIDC signing, & macOS Developer ID
signing/notarization from protected environment secrets. Package smoke stages each supplied candidate
into an isolated product-root `current` tree, then exercises installed-boundary runtime resolution on
its target OS. CI cannot upload a release.

Protected local release hosts consume exact candidate & evidence digests. They perform post-sign
installed-artifact qualification, release sealing, manifest-catalog signing, & upload to immutable
GitHub Releases & approved bootstrap publication. They do not rebuild candidates. Private `bogusyogi`
repos run same RightKit pipeline wholly locally, with
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
8. invokes stable `current/bin/legion setup repair --confirm`;
9. requires exact `legion setup status` health before success.

Harness registrations always bind stable `current` executable, never a disposable version path.
Rerunning bootstrap updates. Explicit version pins are supported; downgrade requires an explicit
flag. Prior successful version is retained. Failure restores previous `current` pointer,
integration journal, & prior exact health. Removal deletes verified Legion-owned runtime &
integrations only; durable state remains unless explicit verified purge is requested.

## 4. Agent Plugins & client boundaries

Agent Plugins 1.0 owns portable public skills + MCP declaration. It does not own installation,
updates, activation, UI, hooks, agents, rules, or unsupported client projections. Legion portable
core includes every public canonical skill with plain IDs & no private/personal workspace content.

| Client | Canonical integration |
|---|---|
| Claude Code | Native `.claude-plugin` for MCP, hooks, & agents; separate Legion-owned standalone skill projection preserves plain `/name` commands because plugin skills are namespaced. |
| Codex | Agent Plugins core plus Codex metadata/policy sidecar, including explicit-only invocation policy. |
| Cursor | Agent Plugins core; thin Cursor sidecar only for rules, agents, or hooks outside portable core. |
| Pi | Native `.agents/skills` projection; Pi is not claimed as full Agent Plugins support or executable registration. |
| Antigravity | Dedicated native plugin projection using its schema, `mcp_config.json`, hooks, skills, agents, & rules. |

`legion setup repair --confirm` detects, reconciles, verifies, & journals selected clients.
`legion setup status` reports actual runtime binding, projection generation, executable resolution,
MCP qualification, skill fidelity, & typed degradation. Client adapters remain mechanical; Legion
semantics stay canonical.

## 5. Ownership

| Concern | Owner |
|---|---|
| Legion install UX, roots, PATH, activation, setup health, client matrix, plain skill IDs, rollback integration semantics, & data ownership | Legion |
| Asset naming, signed manifest schema, key rotation, protected-host finalization/upload, R2 bootstrap publication, shared install/update transaction primitives | `@rightkit/release` |
| Agent Plugins schema, portable package assembly/containment, public-resource closure, & conformance | `@rightkit/ax` |
| Public CI compile/test/qualification/package smoke/SBOM/provenance/candidate workflow plus Windows OIDC & macOS Developer ID/notarization signing | `@rightkit/git` |
| R2 buckets, DNS, TLS, cache, & object policy | Orthic Labs infrastructure |

RightKit package acceptance includes one end-to-end contract spanning direct bootstrap, signed
manifest, stable-current activation, rollback, & product/client projections. Component-local
signing, schema, or workflow success cannot claim distribution readiness alone.

## 6. Retirement & evolution

`migration/native-rust/m0/distribution-contract.json` records superseded Homebrew/WinGet M0
provenance only. Active release gates must not require package-manager metadata. Package-manager
aliases may be added later only as derived consumers of same immutable manifest & assets; they
cannot become another trust authority.

Architecture reopens when official client specifications change, a target cannot satisfy native
signature/rollback guarantees, or measured activation evidence disproves client fidelity. Release
manifest schema changes require compatible bootstrap/key-rotation migration before publication.
