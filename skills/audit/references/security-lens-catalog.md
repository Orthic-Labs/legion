# Legion security lens catalogue

Generated from `src/registry/security-lenses.json`. Status describes what the engine actually runs today; a lens is never listed as implemented without a registered provider or a pattern card that the engine consumes.

## Status vocabulary

- `native-provider`: a registered native provider in `src/registry/providers.json` implements the detection rules.
- `partial-native-provider`: providers or scanners cover part of the lens; the gaps column names the rest.
- `card-only`: draft pattern cards on the `reasoning.security` lens (`native_providers/reasoning/pattern_cards.rs`) are the only consumer. These are model-reviewed with no deterministic detector.
- `not-implemented`: no engine consumer; a planning label only. It supports no coverage and no clean claim.

Every lens is benchmark `unproven` at the lens level and carries `cleanClaim: none`: no lens status here supports a "no security issues" statement. Absent scanner or card evidence is `unknown`, never clean.

## Applicability modes

- `provider-selector`: the provider's own frozen selector decides, as registered in `src/registry/providers.json`.
- `always-on-core`: the `reasoning.security` core (secrets, injection, authorization, unsafe code, Tauri, serialization) is never selected away.
- `evidence-selected`: a card group retained from inventory path evidence. Without evidence the card stays `unknown` in the packet; it is never excluded.
- `specialist-strong-evidence`: smart-contract, embedded/IoT, and ICS/OT cards apply only on strong path evidence. They are excluded only when every selected path is a recognized source kind and none carries domain evidence; an unrecognized path, a manifest, or an empty selection keeps them `unknown`. Dependency content (for example a protocol library named only in a manifest) is not read, so that evidence alone does not select a specialist card.
- `none`: not applicable (no consumer).

## Lenses

| Lens | Family | Status | Backed by | Applicability | Gaps |
|---|---|---|---|---|---|
| `security.credentials` | credentials | native-provider | providers: `security.credentials`, `legacy.security.secrets` | provider-selector | Git-history and client-bundle exposure depend on the history and secrets providers' own coverage. |
| `security.injection` | injection | partial-native-provider | providers: `security.misuse-resistance`, `security.opengrep`, `legacy.security.sast` | provider-selector | Native rule coverage is command injection and unsafe deserialization only; SQL, NoSQL, template, LDAP, and XML injection rely on external scanner rulesets and reasoning.security, and are not lens-owned. |
| `security.insecure-defaults` | insecure-defaults | native-provider | providers: `security.insecure-defaults` | provider-selector | Framework-specific defaults beyond the three native rules are not covered. |
| `security.cicd-automation` | cicd-automation | partial-native-provider | providers: `security.agentic-ci`, `legacy.security.github-actions-lint`, `security.scanner-zizmor` | provider-selector | Cloud, IaC, and release-signing trust paths are outside this lens. |
| `security.native-workspace` | native-workspace | partial-native-provider | providers: `security.agent-skill-mcp`, `legacy.tauri.capabilities`; cards: `tauri-ipc-command-boundary`, `tauri-capability-scope-breadth`, `tauri-deeplink-and-update-trust`, `native-workspace-trust-auto-exec` | evidence-selected | Pre-trust execution in non-agent CLIs and editors is covered only by the draft card. |
| `security.authorization-tenant` | authorization | card-only | cards: `tenant-authorization-scope` | always-on-core | No deterministic detector; IDOR, function-level, and mass-assignment review are reasoning-only. |
| `security.authentication-session` | authentication-session | card-only | cards: `auth-session-state-machine` | evidence-selected | No deterministic detector; session-store and identity-provider behavior outside the source stays unknown. |
| `security.business-logic` | business-logic | card-only | cards: `admin-workflow-impersonation-bulk-abuse`, `commerce-money-and-inventory-invariants`, `webhook-idempotency-and-verification-order` | evidence-selected | Two of the three cards belong to data-safety, not reasoning.security. |
| `security.request-boundaries` | request-boundaries | partial-native-provider | providers: `security.misuse-resistance`; cards: `ssrf-egress-url-fetch`, `qwik-loader-action-validation`, `qwik-server-client-serialization` | evidence-selected | Upload and archive boundaries are not covered by any provider or card. |
| `security.browser-http` | browser-http | card-only | cards: `http-proxy-cache-smuggling` | evidence-selected | CORS, CSP, and CSRF review are reasoning-only with no card; framing disagreement needs both tiers in the source. |
| `security.crypto-data-privacy` | crypto-data-privacy | partial-native-provider | providers: `security.insecure-defaults`; cards: `secret-serialization-through-logs-and-telemetry`, `privacy-collection-consent-and-disclosure` | always-on-core | Weak-primitive, randomness, and encryption-at-rest checks have no detector. |
| `security.supply-developer` | supply-developer | partial-native-provider | providers: `legacy.security.dependency-pinning`, `legacy.security.node-dependencies`, `legacy.security.python-dependencies`, `legacy.security.rust-advisories`, `legacy.security.vendored-dependencies`, `legacy.security.binary-pins`, `legacy.security.docker`, `legacy.security.js-licenses`; cards: `tauri-deeplink-and-update-trust` | provider-selector | Developer-machine trust is covered only through the workspace-trust lens. |
| `security.ai-prompt-injection` | ai | partial-native-provider | providers: `security.agent-skill-mcp` | provider-selector | Application prompt assembly outside agent and skill files is reasoning-only. |
| `security.ai-excessive-agency` | ai | partial-native-provider | providers: `security.agent-skill-mcp` | provider-selector | Approval and identity-scope review are reasoning-only. |
| `security.ai-integrity` | ai | card-only | cards: `ai-memory-rag-poisoning-grounding` | evidence-selected | Evaluation-integrity review has no card. |
| `security.smart-contract` | high-consequence | card-only | cards: `smart-contract-reentrancy-access-oracle` | specialist-strong-evidence | Signature replay, upgradeability, and bridge assumptions are not carded. |
| `security.embedded-iot` | high-consequence | card-only | cards: `embedded-firmware-update-debug-keys` | specialist-strong-evidence | Native parser safety and radio configuration are not carded. |
| `security.ics-ot` | high-consequence | card-only | cards: `ics-ot-unauthenticated-control-safety` | specialist-strong-evidence | Never performs live probing; segmentation and remote-maintenance review are not carded. |
| `security.ai-output-handling` | ai | not-implemented | none | none | No provider, pattern card, or reasoning cue is bound to this lens; it must not support any coverage or clean claim. |
| `security.mobile` | mobile | not-implemented | none | none | No provider, pattern card, or reasoning cue is bound to this lens; it must not support any coverage or clean claim. |
| `security.repository-footprint` | repository-footprint | not-implemented | none | none | No provider, pattern card, or reasoning cue is bound to this lens; it must not support any coverage or clean claim. |
| `security.output-handling` | output-handling | not-implemented | none | none | No provider, pattern card, or reasoning cue is bound to this lens; it must not support any coverage or clean claim. |
| `security.abuse-observability` | abuse-observability | not-implemented | none | none | No provider, pattern card, or reasoning cue is bound to this lens; it must not support any coverage or clean claim. |

## Notes

- `security.high-consequence` was an umbrella with no consumer; it is replaced by `security.smart-contract`, `security.embedded-iot`, and `security.ics-ot`.
- The former `module` paths (the `src/providers/security/packs/` JavaScript module files) pointed at deleted modules and are removed. The native heuristic packs are `security.credentials`, `security.insecure-defaults`, `security.misuse-resistance`, `security.agentic-ci`, and `security.agent-skill-mcp`, run through `native_providers/security/packs.rs`.
- Pattern cards are `draft` maturity; see `pattern-cards.md` for routing and `evals/patterns/cases.json` for the authored finding / no-finding / unknown fixtures.
