# Release pipeline recovery Covenant record

Status: `SUPPORTED`

- Record: `CV-9`
- Request: `req_01ARZ3NDEKTSV4RRFFQ69G5FAV`
- Packet digest: `sha256:7eac4a362ed5cc5258efc0aa62d2de81ddcb24ebb988817f5e107f87a0f63e89`
- Reviewed main revision: `52cd3ad0f0eb76aa8b9df78cc24c151c3d76feda`
- Failed release revision: `042c71f1f73793ce3ff654dbcc111bc8f30b9019`
- Final verdict: two isolated fresh seats returned `SUPPORTED`; no findings, missing evidence, or risks.

## User instruction

> how much longer, i will ask you very simply. if the answer is not 10 minutes. I want you to check whjat you're doing wrong. present the entire pipelien to covenant along with every thing you've tried, each and every failure plus why you're such a failure at achieving a mechanical task that should be well documented online as well as by github. do not proceed till you get a pass

## Pipeline reviewed

1. Main push runs public CI.
2. Release candidate builds unsigned Windows & macOS artifacts.
3. Protected jobs sign Windows, sign/notarize macOS, then install & qualify exact Windows installer.
4. Publish runs only after platform finalization & installed qualification.

Existing tag-triggered design creates tag before qualification. Main CI was Windows-only for Rust, so it was not release-path equivalent.

## Attempts, failures, & mistakes

### v0.3.5 — `4cf7b2d7`

- Separated structural activation from live authentication qualification.
- Added `legion setup qualify`.
- Corrected installed plugin source to `current/plugin`.
- Ignored inactive projections in setup health.
- Normalized `client_id`/`clientId`.
- Added real install → repair → status → doctor → uninstall qualification.
- Public CI run `33408476262` passed.
- Release run `33409536007` built & signed both platforms, then installed qualification failed.
- Failure detail was blank because empty `stderr` was selected before `error.message` & `stdout`.

Mistake: local direct proof bypassed nested capture, signed installer, hosted path aliases, & GitHub-only execution policy.

### v0.3.6 — `fc9eb96e`

- Added shared process boundary with 64 MiB capture, explicit timeout, exit/signal/error/stdout/stderr diagnostics, compact evidence, & large-output tests.
- Public CI run `33414239349` passed.
- Release run `33415054310` built & signed both platforms, then installed qualification failed again.
- Improved diagnostics exposed setup repair exit `2` under `C:\Users\RUNNER~1\...`.

Mistake: blank output plus roughly sixty-second duration was treated as enough evidence for max-buffer root cause. Capture defect was real but secondary. Primary defect was Windows 8.3 alias versus canonical long-path lexical containment.

### v0.3.7 — `042c71f1`

- Canonicalized declared install root before containment comparison.
- Added regression test & compact long-JSON diagnostics.
- Public CI run `33417537147` passed, but Rust CI covered Windows only.
- Release run `33418288565` started.
- macOS candidate failed `resolved_binding_accepts_canonical_installed_root`: test hardcoded `bin/legion.exe`, while production correctly requires `bin/legion` outside Windows.
- Windows candidate was still compiling when operator ordered stop.
- Run was cancelled; signing, qualification, & publish did not run. v0.3.7 remains unpublished.

Mistakes:

- Fixed visible failures serially instead of proving full release path first.
- Added Windows-specific fixture inside cross-platform Rust test.
- Used Windows-only CI as release confidence for cross-platform code.
- Cut tag before exact macOS candidate proof.
- Initially said work was paused while remote workflow could still publish; run was then explicitly cancelled.
- Gave duration estimate after starting another full release cycle instead of before it.

## Covenant revisions

R1 through R8 were rejected for material gaps. Findings added:

- genuine 8.3 proof rather than a path containing spaces;
- signed-installer qualification rather than assembled-payload substitute;
- same-run artifact identity;
- diagnostics for every stage;
- installed verification before publish;
- fixed-SHA dispatch;
- existing tag/release collision checks;
- evidence upload as publish prerequisite;
- main-tip & workflow-ref admission;
- normalized admission job;
- version concurrency lock;
- run/producer/matrix artifact identity;
- dual-OS Rust manifests;
- typed alias-unavailable outcomes;
- summary-initialization failure handling;
- immutable post-tag failure disposition;
- rerun policy;
- complete version-source inventory;
- full-SHA action pins;
- verifier-side artifact rehashing;
- exact installed-command contract;
- versioned diagnostic schemas;
- least-privilege GitHub permissions & protected signing environments.

## Frozen R9 contract

1. Preserve cancelled, unpublished v0.3.7 tag unchanged. Next version is v0.3.8.
2. Fix fixture executable: `legion.exe` on Windows, `legion` elsewhere. Keep production canonical containment behavior.
3. Windows signed-installed contract requires exact digest-bound installer; silent install; installed `--version`; JSON repair/status with complete installed activation, stable current binding, Full Claude/Codex fidelity, current projections; doctor; silent uninstall; removed install root; command evidence throughout. macOS claim remains exact-SHA tests plus signed/notarized finalization evidence.
4. 8.3 evidence uses actual temporary/install path, native realpath results, typed `DISTINCT | GENERATION_DISABLED | NO_DISTINCT_ALIAS`, & fatal query/parse/permission failures. Only `DISTINCT` claims alias coverage.
5. Versioned stage-summary schema binds run, producer, stage, version, source, workflow ref, platform, architecture, status, command result, evidence digests, unavailable reason, & exact initialization-failure marker.
6. Canonical RightGit generator owns workflow. Tag-triggered publication is removed. Dispatch is accepted only from `refs/heads/main`; actions & reusable workflows use immutable full-SHA pins.
7. Workflow default is `contents: read`. Admission/tests/candidates receive no secrets or write token. Windows signer alone receives protected release environment plus Azure OIDC. macOS signer alone receives Apple secrets with always-run cleanup. Publish alone receives protected environment plus `contents: write`.
8. Admission rejects reruns, malformed inputs, publish without signing, non-main workflow ref, source not equal remote main tip, detached checkout mismatch, version-inventory mismatch, & existing tag/release.
9. Canonical version inventory enumerates every release-facing version source & rejects missing, extra, stale, or newly unlisted declarations.
10. Exact-SHA Rust tests run on Windows & macOS before finalization.
11. Artifact identity includes run, producer, stage, version, source, platform, architecture, & content digest. Expected producer matrix is frozen at admission.
12. Evidence verifier downloads every required artifact, recomputes bytes/digests, validates schema/identity/cardinality, & blocks publish on missing, duplicate, substituted, malformed, non-final, or unuploaded evidence.
13. Nonpublishing full signed qualification runs first. Publishing uses a fresh full run at same source/version & promotes only its own verifier-approved artifacts without rebuild.
14. Publish rechecks tag/release absence, creates exact-SHA tag/release, uploads, downloads, rehashes, & verifies ref target.
15. Failure after tag creation permanently strands that version as failed/unpublished. Tag is never moved, deleted, or reused; recovery uses next version.
16. Implementation is one main commit, pushed once, then exact-SHA CI, nonpublishing full run, main-SHA reconfirmation, publishing full run, asset/tag evidence, & Oracle validation.

## Time estimate

Not ten minutes. Historical candidate builds alone take roughly 10–15 minutes. Two complete signed runs are expected to take 50–90 minutes after implementation is ready. No release action resumes before implementation contract is applied.
