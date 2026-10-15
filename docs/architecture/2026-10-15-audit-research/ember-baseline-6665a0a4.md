# Ember Audit v2 phase-1 baseline (installed Legion)

Status: **incomplete**. Plan-only and full deterministic runs both exited 2 before any report was written. No provider, finding, gap or `lensWork` numbers exist for this baseline. The lens plan refused to freeze, so the run stopped before `report.json`, `execution.json`, `report.sarif` or `facts.json` were produced.

## Environment and subject

| Item | Value |
| --- | --- |
| Legion binary | `~/Library/Application Support/Orthic Labs/Legion/current/bin/legion` |
| Reported version (`legion --version`) | `0.3.23` |
| Build `6665a0a4` / runtime sha `764026be` | Not verified. The binary reports `0.3.23` and no build or runtime sha was exposed. |
| Ember subject | `ember/` (sibling checkout, read-only for this run) |
| Ember HEAD | `657f7f48cf95267b490e5acd62d2cfed1636513d` |
| Ember `git status --short` before runs | 1 line (`7d3:1`, pre-existing, not created by these runs) |
| Ember `git status --short` after runs | 2 lines: the above plus `?? .audit/` (run output only) |
| Host | macOS (Darwin 27.0.0), Mac |
| Lens seats dispatched | 0 (no reasoning-lens seats or subagents were dispatched) |

## Commands and results

| # | Command (paths abbreviated) | Wall clock | Exit | Max RSS | Block in / out | Output |
| --- | --- | --- | --- | --- | --- | --- |
| 2 | `/usr/bin/time -l legion audit ember --out ember/.audit/baseline-plan-20261015T095428Z --plan-only` | 5.17 s | 2 | 208,617,472 B | 0 / 0 | No run dir created. stderr: `native audit requires host-injected AUDIT_PLAN_SIGNING_KEY` |
| 3 | `/usr/bin/time -l legion audit ember --out ember/.audit/baseline-run-20261015T095438Z --profile standard` | 22.45 s | 2 | 285,147,136 B | 0 / 0 | Run dir holds `epoch.key` (mode 600, contents not read), `lens-dispatch.json`, `lens-size.json` only. No `report.json`. stderr: `refusing to freeze the plan: lens seats do not fit the run budget` |

Notes on the two failures:

- Plan-only (step 2) requires a host-injected plan signing key (`AUDIT_PLAN_SIGNING_KEY`). The key was not provided to this run, and it was not searched for. This is a host-environment gap, not an Ember defect.
- The standard run (step 3) did not need the signing key. It planned lenses, then refused to freeze because one seat (bundle `J1`, part 7) exceeds the per-seat budget and the run total exceeds the run budget. The CLI suggested narrowing scope (`--base-commit`, `--base`, `--dir`, `--only`, `--skip`), raising budgets, or `--allow-oversize-lenses`. None was applied: each changes the baseline's meaning, so the choice is left to the owner.

## Lens plan (from the refused run's `lens-dispatch.json`; `lens-size.json` is byte-identical)

| Field | Value |
| --- | --- |
| `coverageMode` | `risk-sampled` (auto-selected; the run budget did not fit an exhaustive review) |
| `withinLimits` | `false` |
| `overridden` | `false` |
| Limits | seat budget 150,000 est. tokens; wave width 16; run budget 6,000,000 est. tokens; max seats 48 |
| Lenses | 16 |
| Required seats | 37 |
| Waves | 3 |
| Seat tiers | mechanical 5, specialist 14, judgment 18 |
| Estimated tokens, total (top-level) | 4,415,497 |
| Packet bytes, total (top-level `packetBytes`) | 17,661,943 |
| Packet bytes, sum over the 16 lens entries | 34,826,988 (does not equal the top-level figure; the lens sum may count shared parts more than once, unverified) |
| `du -sh lens-packets` | Not applicable: no `lens-packets` directory was written by the refused run |
| Violations | 1: seat 8 (bundle `J1` part 7), ~151,567 est. tokens, over the 150,000 per-seat budget |
| Warnings | 1: bundle `S3`, ~776,681 est. tokens, 476,681 over its 300,000 run-budget share |

Per bundle (estimated tokens; seats; over-share):

| Bundle | Seats | Est. tokens | Over share |
| --- | --- | --- | --- |
| ADJ | 1 | 297 | 0 |
| J1 | 11 | 1,465,814 | 0 |
| J2 | 6 | 820,344 | 0 |
| M1 | 5 | 609,856 | 0 |
| S1 | 4 | 337,316 | 0 |
| S2 | 4 | 405,189 | 0 |
| S3 | 6 | 776,681 | 476,681 |

Per-lens review-set sizes were not captured by this summary and are not reported. Refusal: yes, at freeze (see above).

## Inventory

| Measure | Value | Source |
| --- | --- | --- |
| Files in Ember excluding `.git` and `.audit` (`find`) | 2,003 | Filesystem count, not an audit inventory |
| Tracked files (`git ls-files`) | 1,070 | Git index |
| Inventory file count from the audit run | Not available | Refused run wrote no inventory |

The 2,003 vs 1,070 gap is expected to come from untracked or ignored content in the checkout (for example build output or vendored trees). It has not been analysed.

## Walk and hash pass count (step 4)

No trace flag was used and `dtruss` was not run (not permitted). The proxy the brief specified is `block input operations` from `time -l`. It was **0 for every run**, so it does not discriminate between plan-only and full execution on this host and gives no walk count. The walk/hash pass count is therefore **not measured**.

## Deterministic run: not reached

Step 3 requested these fields. None could be read because the run refused before writing any report: `auditStatus`, `qualityGate`, `coverageMode` (from report), provider counts executed/skipped/unavailable, deterministic finding counts by severity, gaps count and top gap kinds, `lensWork` pending count, and sizes of `report.json`, `execution.json`, `report.sarif`, `facts.json`.

## Failures and open decisions

1. **Plan-only needs `AUDIT_PLAN_SIGNING_KEY`.** Host-injected; not provided to this run. Requires the host or owner to supply it, through the sanctioned path.
2. **Standard run refuses to freeze the lens plan.** Seat budget and run budget are both exceeded, mainly in bundles `J1` and `S3`. Options for the owner: (a) narrow scope with `--dir`, `--only` or `--skip`; (b) raise budgets; (c) `--allow-oversize-lenses`, which freezes and records the overrun; (d) accept `risk-sampled` coverage explicitly. Each changes what the baseline measures, so none was chosen here.
3. **Version identity unverified.** The brief names build `6665a0a4` and runtime sha `764026be`; the binary reports `0.3.23`.
4. **Packet-byte accounting inconsistent** between the top-level total and the per-lens sum (see above).

Nothing in Ember was edited, committed or branch-switched. The only writes are the `ember/.audit/baseline-run-20261015T095438Z/` run dir and this report.
