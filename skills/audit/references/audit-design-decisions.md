# Audit — locked design decisions

The decisions below govern how `/audit` proves its work. They came out of an adversarial review
that rejected the first design, and they are cited by `references/manual.md`. Change them
deliberately or not at all; the rationale column says which concern each one answers.

## Locked decisions

| # | Decision | Why (which lens) |
|---|---|---|
| D1 | **Proof = out-of-band re-run, not hashing.** Report prints the literal command per check; user/CI re-runs any line. No `content_hash`, no per-file `sha256`, no in-agent verify gate. | Trust (verifier-capture), Ponytail (self-referential scaffolding), Architecture (non-determinism) |
| D2 | **Required-checks set in `manifest.json`.** A check that is *applicable* (its stack detected, its tool present) but did not reach `ran` stamps the report **INCOMPLETE**. Kills silent skip-flood. | Trust |
| D3 | **"NOT SCANNED — unverified LLM hints only" banner** on any security section whose scanner ≠ `ran`. No clean-bill language without a scanner. | AppSec |
| D4 | **Redact secrets before persisting any log** (field-redact known scanners + entropy/token sweep); owner-only perms; delete logs on success. | AppSec |
| D5 | **JSON is canonical, Markdown is rendered from it.** Keeps `evals.json audit-report-shape` valid (the eval *is* the JSON consumer) while humans read the MD. | overrode Ponytail "drop sidecar" |
| D6 | **One new lens (`minimize` = ponytail fold-in).** `decompose` + `architecture-quality` fold into the existing `architecture` lens as threshold-gated questions — not 3 new lenses. | overrode Ponytail "collapse to one"; kept distinct ops |
| D7 | **Jury/council claim dropped.** `human-eyes-gate` is the *human sign-off* checkpoint, not a verification gate. Council stays unwired (don't build it). | Architecture |
| D8 | **Signal discipline:** per-lens cap (~5 to body, rest to appendix); subjective lenses threshold-gated; one dedup pass; fix tiers AUTO/GUIDED/MANUAL; top-10 triage at head. | Signal/noise |

---

## Non-goals (deliberately not built)

- ❌ No content-hash / sha256 binding subsystem (D1).
- ❌ No in-agent verify gate (verifier-capture; D1/Trust).
- ❌ No jury/council wiring (unbuilt; D7).
- ❌ No external plugin dependency (ponytail folded in as a lens).
- ❌ No 40-scanner engine — ~6 required + ~5 optional, on-demand, graceful-skip.
- ❌ No agent-native MCP / browser stack — a Markdown file + `open-for-review` is the lazy equal.
- ❌ No auto-apply — report-only (fixes are *in* the report; applying is a deliberate follow-up).
- ❌ No global tool auto-install — use what's present; loudly report what's absent.
