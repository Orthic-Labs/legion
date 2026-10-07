# Rubric pack: GitHub workflow YAML (`.github/workflows/*.yml`, `*.yaml`)

Loaded by `security` and `release-readiness` when scoped files match. Cite the workflow file and the
step line. `actionlint` output, when present, is the first evidence; this pack covers what it does not.

## Security
- Triggers that run untrusted code with secrets or a write token: `pull_request_target` or
  `workflow_run` that checks out and executes the pull request head, builds it, or runs its scripts.
- Expression injection: `${{ github.event.* }}`, `github.head_ref`, issue/PR titles, branch names, or
  commit messages interpolated into `run:` or `script:`. Pass them through `env:` and quote the shell
  variable instead.
- Missing or broad `permissions:`. Expect a top-level least-privilege block (`contents: read`) with
  per-job widening only where a step needs it; flag `write-all` and workflows relying on the default
  token scope.
- Third-party actions pinned to a tag or branch rather than a full commit SHA; `@main` / `@master`
  references; actions from unmaintained or unknown owners that receive secrets.
- Secrets exposed to steps that do not need them (job-level `env:` holding a secret), echoed, written
  to artifacts or caches, or passed to forks. `secrets: inherit` into reusable workflows from other repos.
- Self-hosted runners on public repositories or on workflows reachable from fork pull requests.
- `curl | sh`, unpinned tool downloads without a checksum, and `npm install` / `pip install` of
  unpinned packages inside a release job.
- Cache keys or artifact names an untrusted job can poison for a trusted job.

## Release readiness and correctness
- No `concurrency:` group on deploy or release jobs; two runs can publish at once.
- `continue-on-error: true` or `|| true` on a gate step (a check that cannot fail is not a gate).
- Required jobs conditioned with `if:` expressions that skip them silently on the path that matters;
  `needs:` missing between build, test, and publish.
- Matrix without `fail-fast` consideration, missing OS coverage the project claims to support, or a
  runner label that is deprecated or `latest` for a reproducibility-sensitive build.
- Release or signing steps that run on pull requests, or that can be triggered by a tag anyone can push.
- Missing `timeout-minutes` on jobs that run project code.
- Artifacts uploaded without a retention decision, or published without a recorded digest.

## Not findings
- Pinning policy for first-party actions in the same organisation when the repo documents an exception.
- Style: step naming, key order.
