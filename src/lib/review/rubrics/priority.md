RUBRIC: review-priority
FRAMING: portfolio-aware. Default DEFER unless this work clearly out-scores other in-flight venture work.
SCOPE: meta-skill — for any in-flight project (a feature, a launch, a content piece, a campaign) score it against the OPERATOR'S 9 ACTIVE VENTURES. Inputs should describe both: (1) the project being considered + (2) what other venture work it competes with for attention this week.
THOUGHT_FRAMES: Goldratt constraints (where's the actual bottleneck), Andy Grove output metrics (output not activity), Naval leverage (does this create compounding asset?), Kahneman cognitive bias (am I picking the shiny thing?), Buffett opportunity cost ("the difference between successful people and very successful people is that very successful people say no to almost everything")
DIMENSIONS (1-10): expected_revenue_impact, opportunity_cost, compounding_asset_creation, bottleneck_relief, downside_containment, time_to_signal, founder_attention_efficiency, irreversibility_risk
QUESTIONS_5:
  what_else_drops: if you do this, which OTHER venture work this week gets dropped or delayed? name it
  bottleneck_match: per Goldratt — does this attack the actual constraint (sales/supply/cash/team/judgment) or a non-constraint?
  compounding_asset: does this build an asset that pays you again next month? or is it one-shot output?
  time_to_signal: how soon do you know if this is working? days/weeks/months. shorter = better priority unless reversibility is high
  shiny_object_check: per Kahneman — what would a friend who doesn't share your enthusiasm say about why you're really doing this?
PORTFOLIO_CONTEXT (active ventures the user runs in parallel — score against this list):
  DD (Northwind Tools — premium EDC, established revenue)
  RH (Harbor Coffee — slow fashion, building)
  HR (SampleApp — pre-launch dictation app)
  TS (Static Riot — streetwear, launching)
  KDP/Etsy POD
  Amazon dropship
  Faceless YouTube/IG
  Services (Vendure migrations, US brand setup, India sourcing)
  + SS (passion project, exempt from optimization)
FAIL_MODES: shiny_new_thing_no_distribution, attacks_non_constraint, founder_attention_arbitrage_against_self, one_shot_output_no_compounding, time_to_signal_too_long_for_reversibility_low, compounds_judgment_spread_thin, irreversible_with_low_signal, defending_sunk_cost, peer_pressure_FOMO, copying_someone_elses_priority
  missing_evidence: ≤200c — what would you need to see that ISN't in this packet? (added 2026-07-14 per Fable review)
OUTPUT (strict JSON, ≤900 tokens):
{
  "verdict": "DO-NOW" | "DEFER" | "DROP",
  "score": 1-10,
  "top_concern": "≤120c — single biggest reason for verdict",
  "scores": {"expected_revenue_impact":n, "opportunity_cost":n, "compounding_asset_creation":n, "bottleneck_relief":n, "downside_containment":n, "time_to_signal":n, "founder_attention_efficiency":n, "irreversibility_risk":n},
  "answers": {"what_else_drops":"≤140c name the dropped venture/work", "bottleneck_match":"≤140c name the constraint", "compounding_asset":"≤140c yes/no + what asset", "time_to_signal":"≤120c", "shiny_object_check":"≤140c"},
  "blockers": [{"tier": "P0|P1|P2", "text": "what would change DEFER to DO-NOW; ≤200c each; P1+P2 share max 8; P0 unbounded"}]
}
