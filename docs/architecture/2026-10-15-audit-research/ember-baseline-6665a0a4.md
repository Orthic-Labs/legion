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

## Baseline 2 (build 56a82271)

Status: **incomplete**. Both runs exited 2. The plan-only run wrote a plan (`auditStatus: incomplete`, `qualityGate: unproven`, gap `plan-only`). The standard run completed its process (`processExecution: complete`) and wrote all four output files, but its lens dispatch is over budget and every reasoning lens is still `pending-host`. No completion validation ran.

### Build and environment

| Item | Value |
| --- | --- |
| Artifact | `Orthic-Labs/legion` actions artifact 11968914504, 48,447,809 bytes |
| Artifact sha256 | `186d5e56dff27ebc9ec2b591799a97c57878d6806badc0e2b8d0f5906fc838c0` |
| Inner `app.zip` sha256 | `8f5302cf9023c2497940778a8be4a005f3d0896d128f92a4f200bbba5b0474ca` |
| Installer | headless `Legion Installer.app`, exit 0, log ends `installation complete`, no rollback lines |
| Installed binary sha256 | `3d0c3641a5c9bdbffd7cffaa45d711eaf419235a6eeb51b27a3cdafe90502cab` |
| `share/legion/release.json` runtime.sha256 | `3d0c3641a5c9bdbffd7cffaa45d711eaf419235a6eeb51b27a3cdafe90502cab` (match) |
| Previous binary sha256 | `764026be8435afa0d65cfb31ee705d2849139ddb6badae17c359eafa2a5ba578` (replaced) |
| `legion --version` | `0.3.23` (the build id `56a82271` is not exposed by the binary) |
| Ember HEAD | `657f7f48cf95267b490e5acd62d2cfed1636513d` |
| Ember `git status --short` after runs | `?? .audit/` (run output) and the pre-existing `?? 7d3:1` |

The installed binary matches the manifest and differs from the previous build. The binary still reports `0.3.23`, so the build identity rests on the artifact hash and the install log.

### Commands and results

| Run | Command (paths relative to the Ember checkout) | Wall clock | Exit | Max RSS | Output dir |
| --- | --- | --- | --- | --- | --- |
| Plan-only | `legion audit ember --plan-only --profile standard` | 28.99 s | 2 | 288,030,720 B | `ember/.audit/baseline2-plan-20261015T121607Z/` |
| Standard | `legion audit ember --profile standard` | 115.71 s | 2 | 702,660,608 B | `ember/.audit/baseline2-run-20261015T121650Z/` |

The plan-only run printed no stderr. Exit 2 coincides with `auditStatus: incomplete` and the `plan-only` gap. The plan-only run reported no `AUDIT_PLAN_SIGNING_KEY` error, unlike Baseline 1.

### Plan-only dispatch (`lens-dispatch.json`)

| Field | Value |
| --- | --- |
| `coverageMode` | `risk-sampled` |
| `withinLimits` | `true`, no violations |
| Limits | seat budget 150,000; wave width 16; run budget 6,000,000; max seats 48 |
| Lenses | 16 |
| Required seats / seats / waves | 42 / 42 / 3 (tiers: judgment 20, specialist 17, mechanical 5) |
| Estimated tokens, total | 4,243,664 |
| `packetBytes` = `seatReadBytes` | 16,974,606 |
| `perLensPacketBytes` | 33,397,421 |
| `uniqueExcerptBytes` | 16,383,305 |
| `sharedExcerptBytesSaved` | 16,422,815 |
| `planSignature` | present (`hmac-sha256:7b6be65f…`) |
| `epoch.key` | present in the run dir |

Per bundle (estimated tokens, seats, over-share):

| Bundle | Seats | Est. tokens | Over share |
| --- | --- | --- | --- |
| ADJ | 1 | 297 | 0 |
| J1 | 12 | 1,394,161 | 0 |
| J2 | 7 | 817,075 | 0 |
| M1 | 5 | 544,344 | 0 |
| S1 | 5 | 330,702 | 0 |
| S2 | 5 | 378,088 | 0 |
| S3 | 7 | 778,997 | 478,997 |

The only warning is bundle S3, which exceeds its 300,000 allocation target. The run budget is the limit that applies.

### Standard run

| Measure | Value |
| --- | --- |
| Exit | 2 |
| `auditStatus` / `qualityGate` | `incomplete` / `unproven` |
| `coverageMode` / `auditLabel` | `sampled` / `whole-repository risk-sampled audit` (`lens-dispatch.json` says `risk-sampled`) |
| `processExecution` / `processState` | `complete` / `complete` |
| `completionValidation` | `not-run` |
| Providers in report | 87 total: 78 applicable, 9 not applicable |
| Provider `status` | ok 27, partial 50, complete 5, failed 5 |
| Provider `complete` | true 20, false 67 |
| Unavailable | 27 gap records of kind `unavailable`. The report has no separate unavailable field, so this is the best count available. |
| Findings (all provider-sourced; `advisoryFindings` = 0) | 825: medium 445, warning 302, low 63, error 15 |
| Top finding providers | code.rust 500, test-quality.core 126, docs.contract 96, legacy.quality.negative-space 75, code.javascript 15 |
| Gaps (report) | 212 |
| Top gap kinds | provider-incomplete 54, provider-degradation 48, unavailable 27, reasoning-lens-pending-host 16, unparsed JSON gap 12, code.rust 7, code.python 6 |
| `lensWork` | 16 entries, all `pending-host`; 23 selected lenses; 103 seat references across waves 1 to 4 (the references may double-count shared seats) |
| `report.json` | 2,675,073 B |
| `execution.json` | 3,508,419 B |
| `report.sarif` | 1,490,211 B |
| `facts.json` | 1,690,701 B |

### Standard run dispatch (`lens-dispatch.json` in the run dir)

The run re-dispatched with more seats than the plan-only pass.

| Field | Value |
| --- | --- |
| `withinLimits` | `false` |
| Required seats / seats / waves | 56 / 56 / 4 (tiers: judgment 23, specialist 28, mechanical 5) |
| Estimated tokens, total | 6,125,674 (run budget 6,000,000) |
| `packetBytes` = `seatReadBytes` | 24,502,612 |
| `perLensPacketBytes` | 44,468,972 |
| `uniqueExcerptBytes` | 22,473,637 |
| Violations | seat 1 (bundle ADJ) at ~250,412 tokens exceeds the 150,000 per-seat budget; 56 seats exceed the 48-seat cap; the run total exceeds the 6,000,000 budget |

Per bundle over budget: J2 by 146,847; S1 by 150,315; S2 by 138,476; S3 by 1,175,087 (estimated 1,475,087 against 300,000).

The 6.0M run budget and 48-seat cap are the likely cause of exit 2, but the CLI did not state a cause on stderr.

### Failures and open items

1. Standard run is over budget in the run dir (`withinLimits: false`, 56 seats against a 48-seat cap). Reducing scope or raising budgets is an owner decision and was not applied.
2. Run `auditStatus` is `incomplete`, so no quality gate passed. No completion validation ran.
3. All 16 reasoning lenses are `pending-host`, so no reasoning findings exist for this baseline.
4. The plan-only and standard dispatches disagree (42 vs 56 seats, 4.24M vs 6.13M tokens). Dispatch is not stable across the two runs on the same source.
5. The run's `lensWork` seat references (103) do not match its `lens-dispatch.json` seat count (56). The discrepancy is not explained.
6. The auditor's `contextNotices` asks for `.audit/` to be added to `.gitignore` or `.git/info/exclude`. Nothing was edited in Ember, so `.audit/` still shows as untracked.
7. Build identity: the binary does not expose build `56a82271`. Identity rests on the artifact and runtime hashes above.

Nothing in Ember was edited, committed or branch-switched. No reasoning-lens seats or subagents were dispatched. The writes are the two run dirs under `ember/.audit/` and this section.
