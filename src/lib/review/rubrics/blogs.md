RUBRIC: review-blogs
FRAMING: constructive but rigorous. Default REVISE.
SCOPE: blog drafts AND published posts. Absorbs SEO content quality + E-E-A-T + AI citation readiness (replaces /seo-content).
DIMENSIONS (1-10): hook_strength, voice_fidelity, factual_accuracy, info_density, structure, action_clarity, eeat_signals, ai_citation_readiness
QUESTIONS_5:
  bounce_point: paragraph or moment the average reader closes the tab
  claim_to_verify: pick most specific claim/stat that needs verification before publish (cite + scope)
  voice_drift: cite specific phrase that drifts from brand voice (DD/RH/HR/TS if specified)
  ai_default_tendency: em-dashes mid-sentence, "it's worth noting", three-item lists, hedging — find one
  reader_next_action: explicit/implicit CTA — what does reader do next?
EEAT_SIGNALS_TO_CHECK:
  experience: does writer show first-hand use? specific lived examples vs research summary
  expertise: cited credentials, references to primary sources, technical accuracy
  authoritativeness: links to/from authoritative domains, subject-matter consistency over time
  trust: source citations, byline, date, contact, no fabricated stats, no AI hallucinations passed off as fact
AI_CITATION_READINESS (for ChatGPT/Perplexity/Claude/Google AIO citation):
  scannable: clear H2/H3 structure, lists, tables for bot extraction
  passage_level_quotability: short self-contained paragraphs that answer specific questions
  schema_friendly: defined terms, FAQ blocks, how-to steps, comparison tables
  citation_anchor: includes specific data, dates, attributable claims AI can quote
  unique_pov: not just rephrased competitor content; has angle/data only this source has
FAIL_MODES: listicle_padding, stat_no_source_no_scope, ai_hedging, voice_mismatch_brand, stale_regulatory, headers_dont_match_section, internal_contradiction, missing_target_keyword_in_open, in_conclusion_wrap, generic_open, no_first_hand_experience, no_primary_sources, no_byline_no_date, no_passage_quotable_chunks, fully_rephrased_competitor_content_no_unique_pov
  missing_evidence: ≤200c — what would you need to see that ISN't in this packet? (added 2026-07-14 per Fable review)
OUTPUT (strict JSON, ≤900 tokens):
{
  "verdict": "PUBLISH" | "REVISE" | "REJECT",
  "score": 1-10,
  "top_concern": "≤100c",
  "scores": {"hook_strength":n, "voice_fidelity":n, "factual_accuracy":n, "info_density":n, "structure":n, "action_clarity":n, "eeat_signals":n, "ai_citation_readiness":n},
  "answers": {"bounce_point":"≤120c", "claim_to_verify":"≤120c", "voice_drift":"≤120c", "ai_default_tendency":"≤120c", "reader_next_action":"≤120c"},
  "blockers": [{"tier": "P0|P1|P2", "text": "concrete edits; ≤200c each; P1+P2 share max 8; P0 unbounded"}]
}
