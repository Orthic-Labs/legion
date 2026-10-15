# Brief: Alibaba's code-review repo and OpenQodex, and what Legion Audit can take from them

## 1. Alibaba candidates

No Alibaba repo called "audit skill" turned up. Two searches found nothing of that name.

**Best match: `alibaba/open-code-review` (`ocr` CLI), Apache-2.0.**
- It ships an agent skill at `skills/open-code-review/SKILL.md`. It was open-sourced around September 2026.
- InfoQ covered it on 2026-09-20 ([InfoQ](https://www.infoq.com/news/2026/09/alibaba-opencodereview/)). Repo: [alibaba/open-code-review](https://github.com/alibaba/open-code-review).
- It began as Alibaba's internal review assistant. InfoQ reports it was used by tens of thousands of Alibaba developers for two years. That claim is second-hand and unverified.
- `ocr scan` is the audit mode. It reviews whole files or directories with no diff ([GitHub](https://github.com/alibaba/open-code-review)).

**Non-Alibaba look-alikes the search also returned:**
- scottconverse/codex-audit-skills
- wwwazzz/audit-skill
- xiaolai/cc-suite
- cloudflare/security-audit-skill, described as multi-phase with independently verified findings

I did not open any of these. They are mentioned only as search hits ([search result](https://awesome.ecosyste.ms/projects/github.com%2Fscottconverse%2Fcodex-audit-skills)).

An Alibaba Cloud `alibabacloud-*` skills collection also appeared in search ([listing](https://claudemarketplaces.com/skills/aliyun/alibabacloud-aiops-skills/alibabacloud-governance-evaluation-report)). It looks like cloud-governance reports, not code audit. Unverified.

## 2. open-code-review (Alibaba)

All of this is from the [repo page](https://github.com/alibaba/open-code-review), the [InfoQ article](https://www.infoq.com/news/2026/09/alibaba-opencodereview/), the [SKILL.md](https://github.com/alibaba/open-code-review/blob/main/skills/open-code-review/SKILL.md) and the [redreamality write-up](https://redreamality.com/blog/alibaba-open-code-review-deterministic-pipeline/).

- **What it audits:** bugs, security, performance and maintainability. Rules cover NPE, thread-safety, XSS and SQL injection. It is a Go CLI.
- **Scoping:**
  - `ocr review` takes the workspace, a merge-base range (`--from/--to`), or a single commit. It supports `--exclude` and `--resume <id>`.
  - `ocr scan` takes whole files or directories.
  - The SKILL.md gives scan a 58,888-token prompt budget against 200,000 for review.
- **Pipeline, deterministic first (no LLM):**
  1. Select the must-review files and drop generated and vendor paths.
  2. Bundle related files into review units, for example i18n pairs or an interface and its implementation.
  3. Bind rule packs to each file by template matching.
- **Agent:**
  - Each bundle runs as an isolated sub-agent, which allows concurrency and per-bundle retry.
  - The agent can read full files, search the repo and inspect other changed files.
  - The toolset was pruned using production tool-call traces (call frequency and repetition).
  - Git arguments are explicit and paths are bounded to the repo root.
- **Model split:** one configured model by default. "Delegation mode" lets the host coding agent's own LLM do the review.
- **False-positive control:**
  - A positioning module pins each comment to an exact line.
  - A separate reflection module checks whether the comment holds up.
  - Structural validation checks model output against diff line bounds.
  - Comments with start and end line 0 count as failed positioning.
  - The SKILL.md tells the host agent to drop low-severity items likely to be false positives.
  - The project trades recall for precision on purpose.
- **Outputs:**
  - Formats are text, JSON and SARIF, and `--output <path>` avoids truncation.
  - Findings carry path, lines, category (bug, security, performance, and so on) and severity.
  - It integrates with GitHub, GitLab, GitFlic and Gerrit CI. GitHub gets inline comments plus a sticky summary updated incrementally.
  - There is also OpenTelemetry, an MCP server and a local session viewer.
- **Incremental and caching:** only session resume. No content cache is described. Both claims come from the [repo page](https://github.com/alibaba/open-code-review) and the [write-up](https://redreamality.com/blog/alibaba-open-code-review-deterministic-pipeline/).
- **Benchmark claims (first-party except where noted):**
  - On AACR-Bench (50 repos, 200 PRs, 10 languages, 1,505 annotated issues), it reports higher precision and F1 than Claude Code on the same model. It uses about 1/9 the tokens and is faster, but recall is lower.
  - No absolute scores are published in the text I could read.
  - An independent Martian run reportedly measured about 12% precision on 10 PRs. The maintainer called that a tool-call anomaly that has since been fixed, with no re-validation.
  - One reviewer cited about 20% best-case recall on AACR-Bench. A critic says deterministic dispatch limits cross-file and architectural findings ([InfoQ](https://www.infoq.com/news/2026/09/alibaba-opencodereview/)).

## 3. OpenQodex (`openqodex/openqodex`)

Sources: [repo](https://github.com/openqodex/openqodex), [AGENTS.md](https://github.com/openqodex/openqodex/blob/main/AGENTS.md), [graph.md](https://raw.githubusercontent.com/openqodex/openqodex/main/docs/graph.md), [for-agents.md](https://raw.githubusercontent.com/openqodex/openqodex/main/docs/for-agents.md) and [benchmark-results.md](https://raw.githubusercontent.com/openqodex/openqodex/main/docs/benchmark-results.md).

- **What it is:** a local pre-push reviewer, Apache-2.0, on npm (version 0.12.0 cited), maintained by Qodex. Node 22+, macOS or Linux. The repo shows 1,212 commits and 702 stars. The page shows no creation date.
- **Scope:** unpushed commits plus uncommitted and untracked changes. `review.paths.exclude` trims the change. Reviewer time limits are 30 minutes per change, or 2 hours with `--all`.
- **Pipeline:**
  1. Run 22 pinned scanners (secrets, SAST, dependencies, lint, GitHub Actions, IaC, SQL). Findings are kept only on changed lines.
  2. Start a separate Claude Code or Codex reviewer process on a copy of the repo, using the user's own login.
  3. The reviewer must raise or drop every scanner finding with a reason.
  4. Scripts check that every scanner finding was answered and every changed line was shown to the reviewer.
  5. If a stage did not run, the result is "Review incomplete" and exit code 2, with unchecked findings saved.
- **Code graph:** it is built locally with no model call.
  - It indexes TS/JS, Python, Go and Ruby, with framework plugins.
  - Every edge is tagged certain, likely or possible. Unbound calls are kept as "unknowns" with a cause.
  - Queries include `callers`, `implementers`, `tests`, `impact` and `unknowns`. An MCP server exposes them.
  - Parsing is cached per file content, and builds are checksummed and pinned by git refs.
  - The reviewer brief gets a "What this change reaches" block: touched symbols, 1- and 2-hop callers, implementers, importers and unknowns.
  - The block has explicit caps, such as 40 callers. The docs warn that "Zero callers on a floor never means unused."
- **Lenses:** `packages/core` contains "lenses". I could not read their content ([AGENTS.md](https://github.com/openqodex/openqodex/blob/main/AGENTS.md)). The protocol lives in a skill read with `openqodex guide skill`, which I did not open.
- **Outputs:** HTML, Markdown, JSON and SARIF reports, plus a terminal receipt. There is also a GitHub Action, a pre-push gate and an MCP server. Severity runs critical, major, minor, nitpick, info. `block_on_severity` is unset by default.
- **Cost controls:** the benchmark doc shows per-review mean cost and time. The server "Library" path (gpt-6.1-sol) cost $0.084 per review, against $0.338 for Claude Code, on the AACR-Bench subset.
- **Benchmark** (planted-bug dev split, 3 repeats; each model figure is a single configuration):

| Run | Issue recall | Precision |
|---|---|---|
| Claude Code (claude-opus-5-5) | 84.3% (129/153) | 97.3–100% |
| Codex (gpt-6.1-sol) | 75.2% (115/153) | 85.6–100% |
| Scanner only | 62.7% (32/51) | 77.8–88.9% |

  - The precision columns are bounds that count unresolved findings as wrong, then as correct.
  - An A/A twin run (same build rerun) differed by about 2.3 issues per repeat, so smaller gaps may be noise.
  - AACR-Bench model-row recall is "not yet ruled" because human rulings are missing.

## 4. Ideas for Legion Audit

Adopt these only where the audit does not already do them. I have not read Legion's audit skill or code.

1. **Deterministic front end before any model.**
   - Select and filter files by pure code, drop generated and vendor paths, then bundle related units for isolated per-bundle agents with retry.
   - Evidence: [open-code-review pipeline](https://redreamality.com/blog/alibaba-open-code-review-deterministic-pipeline/).
2. **Coverage ledger and a hard "incomplete" state.**
   - Every scanner finding must be answered and every scoped line or file shown to a reviewer, with machine checks. If a stage did not run, exit non-clean with the unchecked findings saved.
   - This maps to Legion's "no false clean" rule. Evidence: [OpenQodex README](https://github.com/openqodex/openqodex).
3. **Separate reflection and positioning pass.**
   - After generation, a different pass pins each finding to exact line coordinates and checks that the claim holds. Drop findings with failed positioning (line 0).
   - Evidence: [repo](https://github.com/alibaba/open-code-review) and [SKILL.md](https://github.com/alibaba/open-code-review/blob/main/skills/open-code-review/SKILL.md).
   - Run it as a cheap-tier adjudicator, not as the original author.
4. **Model-free "blast radius" brief.**
   - Use an offline symbol and call graph, with confidence-tagged edges, named unknowns and explicit caps, to hand each reviewer "what this change reaches" instead of rereading the repo.
   - Keep "floor, not proof of absence" semantics. Evidence: [graph.md](https://raw.githubusercontent.com/openqodex/openqodex/main/docs/graph.md).
5. **Content-addressed per-file fact cache** with checksum validation, so repeat audits reparse and re-review only changed content. Evidence: [graph.md](https://raw.githubusercontent.com/openqodex/openqodex/main/docs/graph.md).
6. **Separate proven from possible.**
   - Report certain, likely and possible findings separately, plus an explicit "unknowns" list. Never merge them into the clean count.
   - Evidence: [graph.md](https://raw.githubusercontent.com/openqodex/openqodex/main/docs/graph.md).
7. **Prune the agent toolset from real traces.** Measure tool-call frequency and repetition in Legion audit runs, then cut or bound tools. Evidence: [repo](https://github.com/alibaba/open-code-review).
8. **Measure, don't assert.**
   - Build a planted-bug plus clean-change suite with repeats, an A/A noise twin, and precision stated as lower and upper bounds. Report recall, location recall, clean rate, cost and time.
   - Evidence: [benchmark-results.md](https://raw.githubusercontent.com/openqodex/openqodex/main/docs/benchmark-results.md). Their dev-laptop AACR-Bench run (3 repeats, human rulings pending) shows why un-ruled rows must not be scored.
9. **Cost routing.**
   - Alibaba claims about 1/9 the tokens by bounding bundles and tools. OpenQodex shows about 4x cheaper reviews on the server path.
   - These are vendor numbers, so validate on Legion's own suite before relying on them.
10. **Standard outputs:** SARIF, JSON and Markdown from one finding schema (path, lines, category, severity, suggestion), plus sticky-summary CI comments. Evidence: both repos.
11. **Known weakness to design against.**
    - Deterministic dispatch lowers recall on cross-file and architectural issues ([InfoQ](https://www.infoq.com/news/2026/09/alibaba-opencodereview/)).
    - Keep a graph-driven or whole-repo lens alongside the bundled per-file pass.

## 5. Unverified items

- OpenQodex lenses and the `guide skill` protocol: not read.
- OpenQodex `docs/faq.md` and the rest of `docs/`: not read.
- Alibaba's exact tool list, the reflection prompt and absolute AACR-Bench scores: not published in anything I could open.
- Alibaba star counts and "tens of thousands of users": second-hand.
- Whether a distinct Alibaba "audit" skill exists beyond `ocr scan`: not found.