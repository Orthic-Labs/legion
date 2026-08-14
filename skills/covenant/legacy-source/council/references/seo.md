---
name: jury-seo
description: >
  Multi-LLM jury review of SEO work — a page, blog draft, or an SEO audit/action-plan report —
  against 2026 search reality (fundamentals + E-E-A-T first, AI-search a thin layer, schema/llms.txt
  = hygiene not ranking levers). Scores technical foundation, on-page, answer-first/AEO, E-E-A-T,
  GEO/presence, schema hygiene, off-page (white-hat only — black-hat = auto REJECT), keyword
  targeting. Verdict SHIP / REVISE / REJECT. Use when user says "/council seo", "review my SEO",
  "is this page SEO-ready", "jury my audit", "SEO verdict". Distinct from the blogs review (draft
  voice/hook) — this is the SEO/GEO gate. Pairs with the /seo skill (which produces the analysis)
  and the SEO Field Manual playbook.
---
# /council seo

Real multi-LLM API jury for SEO/GEO. Feed it a page's content, a blog draft, or a `/seo audit`
report (`FULL-AUDIT-REPORT.md` / `ACTION-PLAN.md`). Add brand + target keyword as context if known.

```bash
py -3.11 D:/Claude/tools/review/dual_review.py jury-seo --stage advisory --input audit-or-page.md --output-dir <review-dir>
```

4 text jurors (reasoning · kimi-thinking · generalist · content-voice), no escalation. Verdict:
SHIP / REVISE / REJECT + per-dimension scores + blockers. The rubric hard-fails any black-hat
off-page tactic and flags schema/llms.txt being treated as a ranking lever. Run `/seo <area>` first
to generate the artifact; run this to gate it.
