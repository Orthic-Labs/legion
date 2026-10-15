**Brief: CodeRabbit-style and Ponytail-style audits.** Everything below was read on pages I opened. The one correction is that the Ponytail comment convention sources conflict, and I could not read the SKILL.md source file itself.

## 1. CodeRabbit (as of Oct 2026)

**Flow**
- A new PR gets a full review. Later pushes get incremental reviews limited to the new changes. [docs overview](https://docs.coderabbit.ai/guides/code-review-overview)
- Each PR gets a Walkthrough comment at the top. It holds the change summary, sequence diagrams and a review-effort estimate. Same source.
- Line comments carry a category (Security, Performance and so on) and a severity from Critical to Info. Many include a one-click fix. Same source.

**Context**
- The code graph is rebuilt on each review. It maps definitions, references and files that often change together. [context-engineering blog](https://www.coderabbit.ai/blog/context-engineering-ai-code-reviews), [code graph docs](https://docs.coderabbit.ai/integrations/code-graph-analysis)
- It also indexes linked issues (Jira, Linear, GitHub, GitLab) and checks whether the PR meets them. It reads past PR titles, descriptions and commit ranges, plus learnings from chat. It does web lookups for fresh docs. Same blog, vendor's own claims.

**Tools**
- It runs 50+ linters and scanners, such as Semgrep, Ruff, ESLint, Gitleaks and ast-grep, all on by default. [config reference](https://docs.coderabbit.ai/reference/configuration)
- A verification agent checks linter output.

**Noise control**
- Verification scripts run in a sandbox, and each comment is checked against the code and your guidelines before it posts. Same blog, vendor's own claims.
- The profile setting has three values: `chill` (default), `quiet` and `assertive`. Path filters exclude files. Path instructions give per-glob guidance, up to 20,000 characters each. [config reference](https://docs.coderabbit.ai/reference/configuration)
- Auto-review pauses after 5 reviewed commits by default and skips draft PRs. Same source.

**Chat and learnings**
- `@coderabbitai` commands can pause or resume reviews, resolve threads, and ask questions. [docs overview](https://docs.coderabbit.ai/guides/code-review-overview)
- Corrections in chat become learnings. `knowledge_base.learnings.scope` is `auto` (local for public repos, org-wide for private). `approval_delay` is 0–30 days. [config reference](https://docs.coderabbit.ai/reference/configuration)

**Config**
- Everything lives in `.coderabbit.yaml` in the repo root. Pre-merge checks (title, description, docstring coverage at 80%, linked issue, custom checks) run in `off`, `warning` or `error` mode. Linked repositories catch cross-repo breaking changes. Same source.

**CLI (local review)**
- `cr review` covers committed, staged and unstaged changes. `--committed` and `--uncommitted` narrow it, and `--include-untracked` adds untracked files. `--base <branch>` sets the base, defaulting to `main`. [CLI docs](https://docs.coderabbit.ai/cli)
- `--agent` emits NDJSON, and `--deep` applies the PR review policy. Reviews take 7 to 30+ minutes. Same source.
- Coding agents are meant to evaluate the findings, fix the important ones, re-run once, and cap the loops. Same source.
- I could not confirm an IDE extension from the pages I opened.

**Not found:** a CodeRabbit "how reviews work" reference page beyond the overview. The `learnings.scope` detail was first seen in a third-party guide and then confirmed on the official config reference.

## 2. "Ponytail"

**Best match:** `DietrichGebert/ponytail`, an MIT-licensed skill and prompt pack that makes agents write less code. It works with about 20 agents, including Claude Code and Codex. [GitHub repo](https://github.com/DietrichGebert/ponytail)

**Other candidates:** none found. A search for "Ponytail code review tool agent skill" returned only this project and articles about it. [claudemarketplaces](https://claudemarketplaces.com/skills/DietrichGebert/ponytail/ponytail-review)

**Review commands**
- `/ponytail-review` reviews the current diff and the code it touches (callers, called functions, tests). The target can be `uncommitted`, `staged`, `branch` or a PR link. With none named, it uses uncommitted changes, or the last commit if there are none. [claudemarketplaces](https://claudemarketplaces.com/skills/DietrichGebert/ponytail/ponytail-review)
- `/ponytail-audit` runs the same check on the whole repo. It maps entry points and data flow, then ranks findings. [GitHub repo](https://github.com/DietrichGebert/ponytail)
- `/ponytail-debt` collects deferred-shortcut comments into a ledger. [GitHub repo](https://github.com/DietrichGebert/ponytail)
- Intensity modes are `lite`, `full` (default) and `ultra`. [GitHub repo](https://github.com/DietrichGebert/ponytail)

**Conflicting detail on scope:** The repo README says review checks bugs, security, real load, missing tests, slow paths and what to cut. The marketplace summary says the review focuses on complexity and should run alongside a correctness review. [DEV Community article](https://dev.to/arshtechpro/ponytail-the-ai-coding-skill-that-makes-your-agent-write-less-code-29l3)'s snippet says the same as the marketplace. I trust the README for the current skill, but the SKILL.md source file itself was not read.

**Comment convention:** The README documents `shortcut:` comments, and the word is configurable. A search summary mentioned `ponytail:` comments, which I could not confirm. Treat `ponytail:` as unverified.

**Output format** (marketplace page)
- It opens with "What this change does:" in 2–3 sentences.
- Findings are numbered across three groups: Must fix, Should fix, Nice to have.
- Each finding has four parts: what the code is, the problem, the fix, and the consequence of skipping it.
- It ends with a verdict ("Ship", or "fix 1 and 3 first"), a "Lean: -N lines possible" line, and an optional "Not checked" line.
- Finding types are Bug, Risk, Scale, Missing test, Speed and Lean. Lean sub-tags are delete, reuse, stdlib/native, yagni, merge and split.

**Rules** (marketplace page)
- Every finding needs a concrete input or situation that causes a wrong result, confirmed by re-reading the code.
- No style opinions or vague "consider" suggestions. Prefer fixes that delete code. Split functions by job, not by line count. Use plain English.
- Documented shortcuts with a limit comment are respected unless expected load exceeds the limit.
- Review changes no code.

**Self-reported benchmarks** (the author's own, not independently verified): 53% less code across 39 tasks. [GitHub repo](https://github.com/DietrichGebert/ponytail)

## 3. What Legion's audit must reproduce

**CodeRabbit-style**
1. **Scope modes.**
   - PR, branch, commit range, uncommitted, committed-only, plus an optional `--base`.
   - Incremental by default: after the first pass, review only what changed since the last reviewed commit, and record which commit that was.
   - Full re-review on request.
2. **Walkthrough header.** One top summary with change summary, a sequence diagram where flow changed, and an effort estimate.
3. **Context retrieval before judging.** Definitions, references and co-changed files for touched symbols. Also linked issue or request, prior related commits, and stored learnings.
4. **Tool pass with verification.** Run available linters and scanners, then have a verifier confirm each finding against the code before it is reported.
5. **Line-anchored comments.** File and line, a category, a severity (Critical to Info), and a concrete suggested fix.
6. **Noise profile.** A quiet/chill/assertive setting, path filters, and per-path instructions in a config file.
7. **Learnings loop.** Corrections are saved per repo and applied to later reviews, with a visible scope.
8. **Pre-merge checks.** Custom pass/fail checks in off/warning/error modes. Without this you have a review, not CodeRabbit-style.

**Ponytail-style**
1. **Read beyond the diff.** Callers, callees, tests and data flow, with the load assumption stated.
2. **Cut-first lens.** Look for reinvented stdlib, speculative abstraction, dead flexibility and duplication. Prefer deletion and report an estimated line reduction.
3. **Evidence rule.** Every finding names a concrete failing input, and style opinions are banned.
4. **Fixed output.** What it does; Must/Should/Nice, numbered; four parts per finding; verdict; Lean line; Not checked.
5. **Scope modes.** `uncommitted`, `staged`, `branch`, PR, plus whole-repo audit with entry-point mapping and ranking.
6. **Debt ledger.** Collect deliberate shortcut comments so deferrals stay visible.
7. **Read-only.** Intensity levels (lite, full, ultra) are optional.

**Honest-claim threshold:** Say "CodeRabbit-style" only if items 1, 2, 4, 5 and 7 are real. Say "Ponytail-style" only if items 2, 3 and 4 are real and the output matches the template. Otherwise say "inspired by".

Sources:
- [Ponytail GitHub repo](https://github.com/DietrichGebert/ponytail)
- [claudemarketplaces: ponytail-review](https://claudemarketplaces.com/skills/DietrichGebert/ponytail/ponytail-review)
- [DEV Community: Ponytail article](https://dev.to/arshtechpro/ponytail-the-ai-coding-skill-that-makes-your-agent-write-less-code-29l3)
- [CodeRabbit docs overview](https://docs.coderabbit.ai/guides/code-review-overview)
- [CodeRabbit configuration reference](https://docs.coderabbit.ai/reference/configuration)
- [CodeRabbit CLI docs](https://docs.coderabbit.ai/cli)
- [CodeRabbit context engineering blog](https://www.coderabbit.ai/blog/context-engineering-ai-code-reviews)
- [CodeRabbit code graph docs](https://docs.coderabbit.ai/integrations/code-graph-analysis)