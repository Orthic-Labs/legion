# Covenant lens — SEO

**What this is:** a recovered domain review lens from Council, deleted at workspace commit
`d810d827` (the engine was ported to `skills/covenant/`; this content was not — same gap as
the Sage manuals recovered in J-1). Source: `git show d810d827^:tools/skills/council/references/seo.md`
(25 lines). Assigned to a Covenant seat at convene time — **one lens per seat**, per
`doctrine/covenant-seat.md` §"lens index" — this file IS the specialization a seat reads once
assigned.

**Read `doctrine/covenant-seat.md` and `$WORKSPACE/docs/plans/legion/COVENANT.md` first.** This bundle is domain craft under
that constitution, not a replacement for it. Everything below is preserved verbatim from Council
except where a `> **Superseded:**` note marks a doctrine conflict.

> **Superseded:** the frontmatter and body below describe the retired Council SEO slash command
> and the retired `tools/review/dual_review.py` CLI (multi-provider jury, `jury.verdict.json`,
> SHIP/REVISE/REJECT gate). That machinery does not exist in Covenant — Covenant convenes seats
> from `covenant-seat.md`, disposition belongs to the caller (Sage/Alchemist), and there is no
> standalone verdict-issuing CLI. The trigger phrase is `/covenant seo` (or an SEO artifact routed
> through `/covenant`); a convened seat reads this file as its assigned lens and returns advisory
> findings, not a SHIP/REVISE/REJECT verdict. The rubric content — technical foundation, on-page,
> answer-first/AEO, E-E-A-T, GEO/presence, schema hygiene, white-hat-only off-page, keyword
> targeting — is preserved verbatim below as the review craft; only the delivery mechanism changed.

---

---
name: jury-seo
description: >
  Multi-LLM jury review of SEO work — a page, blog draft, or an SEO audit/action-plan report —
  against 2026 search reality (fundamentals + E-E-A-T first, AI-search a thin layer, schema/llms.txt
  = hygiene not ranking levers). Scores technical foundation, on-page, answer-first/AEO, E-E-A-T,
  GEO/presence, schema hygiene, off-page (white-hat only — black-hat = auto REJECT), keyword
  targeting. Verdict SHIP / REVISE / REJECT. Use when user says "/covenant seo", "review my SEO",
  "is this page SEO-ready", "jury my audit", "SEO verdict". Distinct from the blogs review (draft
  voice/hook) — this is the SEO/GEO gate. Pairs with the /seo skill (which produces the analysis)
  and the SEO Field Manual playbook.
---
# /covenant seo

Real multi-LLM API jury for SEO/GEO. Feed it a page's content, a blog draft, or a `/seo audit`
report (`FULL-AUDIT-REPORT.md` / `ACTION-PLAN.md`). Add brand + target keyword as context if known.

```bash
py -3.11 D:/workspace/tools/review/dual_review.py jury-seo --stage advisory --input audit-or-page.md --output-dir <review-dir>
```

4 text jurors (reasoning · kimi-thinking · generalist · content-voice), no escalation. Verdict:
SHIP / REVISE / REJECT + per-dimension scores + blockers. The rubric hard-fails any black-hat
off-page tactic and flags schema/llms.txt being treated as a ranking lever. Run `/seo <area>` first
to generate the artifact; run this to gate it.
