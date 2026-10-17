# Ember bounded audit — pending result

**Status:** incomplete; CI qualification passed. Shared signing release, canonical installation, continuation & final audit result pending. Frozen Ember revision: `a297ccc145df28943978db97e5e2e547a7858f92`. The immutable failed parent run is `/Volumes/D/scratch/ember-audit-c16e0166-20261016/run`.

## Spend to date

| Measure | Recorded |
|---|---:|
| Physical provider calls | 1; Sonnet 5.5 call failed/refused |
| Input / output / total | 10,938 / 289 / 11,227 tokens; input was 2 uncached + 10,936 cache-creation tokens (1h) |
| Output thinking | 214 tokens |
| Retry tokens | 0 |
| API-equivalent cost | USD 0.046638 |
| Invoice charge | Unknown; API-equivalent cost does not establish invoice billing |

Exact cache/thinking breakdown comes from `observation.rawUsage` in parent `runtime-calls/69585b7f237640a9bbe3b7fc694adba4ccbac2a2ef1cda8e318fe669ef0ed7f4.json`; normalized spend summary does not expose separate cache creation. Read only selected usage fields, never authentication material.

The call exceeded its 10,000-token cap by 1,227. It stayed within the 50,000-token run cap, 2,500-token output cap & five-call cap. Remaining total allowance is 38,773 tokens; this supports at most three full 10,000-token reservations, with no more than two author calls plus a fresh verifier. Preserve original limits: 50,000 total, 10,000 per call, 2,500 output, five physical calls & concurrency one. Do not reset or raise them. No further provider calls have occurred.

## Audit outcome

The deterministic run produced 817 raw candidates, zero duplicate IDs & no confirmed semantic findings. The failed call yielded no usable semantic completion. Verification reports `incomplete`, `clean: false`; no 10/10 or clean-audit claim is supported.

Coverage remains partial: no reasoning lens completed; 16 reasoning/security lanes remain pending. Verification also records selection narrower than repository denominators, missing language providers or tool evidence, project checks deferred by policy or missing configuration, several unparseable legacy outputs & an unqualified executable-version probe. These gaps prevent an Ember quality or security conclusion.

## Continuation & delivery state

Candidate `59f451ae28c58ec318f7340cf8f22033afc90a10` passed [CI 39001031529](https://github.com/Orthic-Labs/legion/actions/runs/39001031529): Mac 5,254 & Windows 5,216 tests, zero failed & seven ignored each. Mac passed all 14 actual Swift installer scenarios. Windows installed qualification verified fixed `current`/`current.previous`, concurrent-install rejection, foreign-state preservation, legacy-junction migration, runtime execution from stable path, rollback after partial receipt writes & bounded stalled children. Native Audit simulations passed on both platforms; Mac installed MCP smoke passed with plugin-root false & true. These are CI results, not installation on Adrian's Mac.

Exact Mac CI artifact `12089612527` is downloaded & unpacked under `/Volumes/D/scratch/legion-verified-59f451ae`. Its 52,614,056-byte outer ZIP matches GitHub SHA-256 `9b57c44d97e90c2a311246974ae427ef06512e7114ee8620ede99802ade4e6fe`. Unsigned payload CLI SHA-256 is `b3ad65e6f7cf106dc46b7c106aafad5b7118b1f06bcd765c9f2ccfcc23fc5179`; signing will change bytes & requires new signed-payload evidence. Installer bundle ID remains `com.orthiclabs.legion.installer`.

Canonical installed build remains `c16e0166`. Installation is held for [RightKit #257](https://github.com/Orthic-Labs/rightkit/issues/257): shared route must sign these existing qualified dev bytes with stable per-file IDs/team, refresh metadata & return hash/identity evidence without rebuilding. Shared RightKit lead reports this gap is being included in its pending publish; no published route has been verified here. Stable-ID declarations remain a saved patch until supported. Fixed activation & signing delivery remain tracked in [Legion #42](https://github.com/Orthic-Labs/legion/issues/42).

Linked continuation will retain immutable parent history, original cumulative caps & permanent per-call breach. No child run or additional model call has occurred. CI planning/performance gates use separate public Ember fixture `9961562ed4c652b0bc6a9b3bc3a63142d885f583`, not frozen audit target `a297ccc145df28943978db97e5e2e547a7858f92`. Earlier [CI 38982861979](https://github.com/Orthic-Labs/legion/actions/runs/38982861979) measured cold/warm planning at 69.697s / 67.514s & full deterministic production at 149.437s, with zero model calls. Latest CI passed these bounded coverage/reservation gates again. Independent source Oracle passed distinct dev-wiring scope; installer source review ended after two BLOCKs, with subsequent fault repairs verified by CI. No third installer Oracle validation is claimed.

Independent Oracle reviewed this delivery status against raw CI counts, qualification logs, artifact hashes, installed CLI hash & selected native usage fields: PASS for status accuracy. That review excludes installer source certification, signing, installation completion & Ember completion. Public-repository signing remains bound to managed GitHub CI; pending shared route must support existing qualified artifact without rebuilding.

## Remaining source work

Browser fixture source now executes pure fixtures through native `FixtureSession`, binds terminal evidence to session-issued attestation & awaits cancellation cleanup. Fresh source-only Oracle review passed. CI gate now explicitly invokes both native qualification tests & requires exactly two passes, preventing a stale selector from passing without execution. Both CI hosts need pinned Chrome assets; Windows also needs matching headless shell & sandbox ACLs. Shared RightKit provisioning entry point is pending publication. No browser runtime qualification is claimed for this candidate.

Review/Ponytail projections now retain native action/failureScenario fields, supplied fixes, graph uncertainty & deterministic metadata. Source Oracle recheck passed all four prior defects after repair. Their output remains labelled “inspired by”; installed semantic qualification has not run. These browser/report edits postdate CI candidate `59f451ae` & require a new CI qualification before signing or installation.

Issue [#39](https://github.com/Orthic-Labs/legion/issues/39) now has a RuboCop source adapter: separate Ruby lint identity, bounded frozen snapshots, owned configuration, sandboxed execution & strict JSON/path/count/exit validation. Source Oracle recheck passed after fixing incompatible flags & downstream path loss; full-pipeline mock regression was added. Compilation, tests & real-tool qualification remain pending; installed Ruby lint coverage is not claimed. Sqllint, SQLFluff, Checkov, Bandit & Oxlint remain unimplemented optional adapters. Typed language build/test plans exist but remain `executed: false` where host containment or dependency policy denies execution. Graph consumption is implemented; optional Membrane producer transport remains external integration work. These items remain open; they are not counted as executable coverage.

## Delivery evidence

| Item | Result |
|---|---|
| CI for `ce0b8c87e07fd6d6babbcff5699e1f6423769357` | Passed on macOS & Windows |
| Fixed-install/dev-wiring CI for `53b55dea403a58d4b3005083f4be75f698aabc04` | Mac passed; Windows installed qualification failed on activation receipt path binding |
| Path-spelling repair CI for `9ef17f4d3f9d15c47c5f22cdc275096ef0ca29fd` | Mac passed; Windows rejected-state runtime-execution assertion failed |
| Concurrency-probe repair CI for `59f451ae28c58ec318f7340cf8f22033afc90a10` | Passed on macOS & Windows |
| Qualification of installer repair in CI | Passed; exact signed artifact & local install pending |
| Canonical install & verified installed identity | Pending |
| Resumed audit outcome & exact cumulative spend | Pending |
| Final verification status & remaining gaps | Pending |

Evidence: CI records `/Volumes/D/scratch/legion-ci-59f451ae-final.json`, `/Volumes/D/scratch/legion-ci-59f451ae-{macos,windows}.log`, `/Volumes/D/scratch/legion-ci-59f451ae-qualified/{macos,windows}-qualification.json`; native ledger `/Volumes/D/scratch/ember-audit-c16e0166-20261016/spend-summary.json`, `/Volumes/D/scratch/ember-audit-c16e0166-20261016/resume-summary.json`, `/Volumes/D/scratch/ember-audit-c16e0166-20261016/verification.json`, and [audit execution & historical coverage](2026-10-16-audit-execution-and-history.md).
