---
name: research-source-claim-fitness
description: Evaluate whether a source is fit to support one specific proposition; never assign a universal credibility score detached from the claim.
---

# Source–claim fitness

A source is not globally "credible" or "not credible." Evaluate the source against the exact
claim it is asked to support.

For each source–claim pair record:

- `authority_role`: official self-report, regulator, statute, judgment, primary study,
  independent measurement, review, commentary, community report, or lead-only.
- `proposition_fit`: whether that source is authoritative for this proposition. A vendor pricing
  page is primary for its listed price and weak for comparative superiority; a press release is
  primary for what the issuer announced and not independent corroboration that the announcement is
  true.
- `method_strength`: documented population/sample, controls, measurement, and limitations where
  the proposition depends on methodology.
- `independence_cluster`: derivative reporting counts as one voice.
- `current_as_of` / `valid_until`: volatility is claim-specific, not a fixed domain-wide age rule.
- `conflicts`: financial, institutional, ideological, or litigation interests.

## Admission rules

- Search snippets, AI summaries, and NotebookLM answers are leads only. Open the underlying source
  and locate the supporting passage before evidence admission.
- Load-bearing price, feature, legal, benchmark, regulatory, guideline, medical effect, adverse
  event, interaction, and dosing claims require a source whose `authority_role` is fit for the
  proposition.
- Comparative, causal, prevalence, benchmark, effect-size, and adverse-event claims need at least
  two independent sources for `high` confidence unless a domain guide imposes a stricter rule.
- Legal and medical routes apply their typed domain extensions; never flatten them into this generic
  rubric.
- When no fit source exists, keep the question as a gap or the claim as `unresolved`; do not make a
  weak source look strong with a numeric score.
