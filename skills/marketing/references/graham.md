---
name: plan-graham
description: Generate the 5-stage Paul Graham startup validation plan for an idea. Use when user says "/marketing strategy-graham", "graham 5-step", "validate this idea", "5-stage plan", "first 10 customers", "MVP plan", or after `/review-idea` returns BUILD/PIVOT and user wants the actionable next steps. This is the GENERATOR (outputs artifacts you act on). The verdict gate is `/review-idea` (separate skill).
---

# /marketing strategy-graham — Paul Graham 5-stage validation plan

Generator for the 5-stage Graham framework. Outputs the artifacts you actually use to validate, not a verdict.

Pair with `/review-idea` (verdict) — `/marketing strategy-graham` runs after the idea passes the kill gate, OR before if you want a structured plan to feed into the verdict.

## Inputs (ask if missing)

- **Idea (1-2 sentences):** what it is, what problem it solves
- **Target customer (specific, not "small businesses"):** the early-adopter persona
- **Founder advantage (optional):** why YOU specifically can build this

## The 5 stages

Generate ALL FIVE — don't stop early. Each stage produces a concrete deliverable.

### Stage 1 — Pressure-Test (Fatal Flaws + Verdict)

- **Core assumption** — the one thing that MUST be true (≤30 words)
- **Top 3 fatal flaws** — ranked by severity, specific to THIS idea (not generic startup advice). Each ≤40 words.
- **Vitamin or painkiller** — explicit verdict + 1-sentence why
- **Founder-market fit** — does the founder have an unfair advantage here? Yes/no/maybe + why
- **Brutal verdict** — direct, no hedging: BUILD / KILL / PIVOT + 1 sentence

### Stage 2 — Validate the Real Problem (Discovery Questions)

Generate the actual customer-discovery interview kit. Output:

- **Specific pain (≤40 words)** — the concrete frustration the target customer feels and WHEN they feel it
- **Early-adopter profile** — specific person, not a demographic. Where they hang out (subreddits, forums, communities — name 3-5 specific places)
- **5 discovery questions** — open-ended, ASK ABOUT PAST BEHAVIOR not hypothetical intent. Each starts with "Tell me about the last time you..." or "Walk me through how you currently..." or "What did you try before..."
- **Cobbled-solution test** — "Are people currently hacking together a workaround? If yes → real pain. If no → no pain." Apply to this idea, give verdict.
- **Vitamin/painkiller verdict** — explicit (can repeat from Stage 1 if confirmed)

### Stage 3 — Map Real Competition (4 layers + Real Enemy)

Most founders see only direct competitors. Map all four. Output:

- **Layer 1 — Current behavior** — what target customers do TODAY instead of using your product (status quo: spreadsheet, manual process, doing nothing)
- **Layer 2 — Direct competitors** — companies solving the exact same problem the same way
- **Layer 3 — Indirect competitors** — alternative solutions that solve the problem differently (e.g. virtual assistant vs SaaS tool)
- **Layer 4 — Real enemy** — the ONE thing your product must defeat to win. Almost never the obvious competitor. Often "doing nothing." Name it explicitly.
- **Genuine differentiator** — what you do that's defensibly different (not "better UX" — be specific)

### Stage 4 — First 10 Customers (Manual Outreach Plan)

Graham's "do things that don't scale." Output:

- **Where they live** — 3-5 specific places (subreddit names, exact communities, conferences, Slack groups). No "LinkedIn." Be specific.
- **Outreach approach** — 1-on-1, manual, personal. Not blasts. How you'll find them and reach out.
- **First message script** — actual paste-ready text. Asks for a CONVERSATION, not a sale. ≤80 words.
- **Success criteria** — what behavior proves real demand from these 10 (not "they said yes" — actual paying / committing / handing over an email + use)
- **4-week milestone plan** — week-by-week, zero to 10 customers, specific actions per week

### Stage 5 — 2-Week MVP (Cut-List + Day-by-Day)

The MVP exists to test ONE assumption fast. Output:

- **Riskiest assumption** — the single thing the MVP must validate (NOT a feature list)
- **Minimum feature set** — only what's needed to test that assumption. Bullet list, ≤5 items.
- **Cut-list** — features people will tell you to add but you WILL NOT build for the MVP. Bullet list, ≤8 items.
- **Behavioral success criterion** — what specific user action proves/disproves the assumption (not "users said they liked it" — what did they DO)
- **Day-by-day 14-day plan** — Day 1 → Day 14. Each day has ONE concrete output. Day 14 ends with real users (not internal testing).
- **Pivot trigger** — what result tells you to abandon this assumption

## Output format

Run all 5 stages in one pass. Output as a single markdown doc with H2 per stage. Append at the end:

```
---

NEXT ACTION: <one specific thing the user does today>
KILL TRIGGER: <one specific signal that says "abandon and rebuild" before week 2>
```

## Hard rules

- Verdicts must be DIRECT. Never "it has potential but..." Either BUILD/KILL/PIVOT or "vitamin/painkiller", not both-and.
- Every flaw, competitor, and assumption must be SPECIFIC to this idea. Generic startup wisdom is not allowed.
- Discovery questions ask about PAST behavior. "Would you use this?" is banned.
- First-10 outreach is manual and personal. Mass-message scripts are not allowed.
- MVP day-by-day must end with real users, not internal demo.
- Total output ≤1500 words. Brutality and specificity beat thoroughness.
