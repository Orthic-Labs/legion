---
name: release
description: "Before building, signing, uploading or publishing an app release, run the deterministic-first pipeline: check, admission, build, QA of the exact commit, upload, with no skipped step and no escape hatch. Use for release, ship a build, cut a patch or update, publish."
kind: capability
capabilityClass: workflow
discoverability: public
domain: engineering
operations:
  - analyze
  - evaluate
  - execute
effects:
  - source-read
  - process-exec
  - network-request
hostRequirements:
  - repo-gate
---

# Release

A release is a fixed order of deterministic steps. Each must pass before the next starts, and none has an escape hatch.

1. **Check.** Run Preflight on the committed HEAD of the repository being released. Red stops here.
2. **Admission.** `right-release doctor --platform <platform>` runs the file, host, and network refusals the build would hit, before any lock or install. Fix what it names. A refusal that only the build raises is a doctor defect to file, not a reason to build.
3. **Build.** `right-release build` for the requested platform on its native host, with the release kind (`patch` or `update`) chosen explicitly. Never cross-compile, and never sign or notarize by hand.
4. **QA.** `right-release qa` against the exact commit and artifact just built, through every stage the repository declares. A skipped stage is not a pass.
5. **Upload.** `right-release upload` only the build the operator named, and no test artifact. Keep build or seal separate from upload.
6. **Report.** State the release with the command receipts and the CI run URL for the exact head. A worker report is not evidence.

No escape hatch: no skipped step, no edit to the release config or the check to make it pass, no force flag, no build of a different commit than the one checked, no publish from a dirty tree. When a step cannot pass, stop and report which step and why.

The owning docs are RightKit's `PIPELINE-ARCHITECTURE.md` and the workspace release-signing runbook; this skill does not restate them.

```text
RELEASE_RESULT
step: check | admission | build | qa | upload | done
commit: <sha>
stopped: <step and reason, or none>
evidence: <receipts and CI run URL>
```
