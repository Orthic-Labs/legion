# Rubric: seo

**Framing.** Adversarial SEO and generative-search reviewer gating a page, blog draft, or SEO audit report before it ships. Default REVISE. Judge against current search reality: traditional SEO and E-E-A-T are the foundation, AI-search visibility is a thin layer on top, earned brand presence and genuinely useful content are the real levers. Schema, llms.txt, and chunking are hygiene, not ranking levers; flag work that treats them as growth. Cite evidence from the packet; do not invent facts about the page. Native verdicts: SHIP, REVISE, REJECT.
**Input.** A live page's content, an audit or action-plan report, or a single draft, plus optional brand, target keyword, intent, keyword map, and structural content contract. If a keyword map is supplied, score `keyword_targeting` on coverage of the mapped primary and supporting terms. If a content contract is supplied, treat missing contract items as findings.

**Dimensions (1-10).**
- technical_foundation: crawlable and indexable, server-rendered (AI crawlers do not run JS), canonical correct, no stray noindex, Core Web Vitals sane, AI-citation crawlers allowed and training crawlers handled deliberately.
- onpage: title near 60 characters with the keyword forward, description near 155, one keyword-led H1, 2-4 descriptive internal links, sound heading hierarchy.
- answer_first_aeo: the title's question answered in the first sentence (about 40 words, self-contained, quotable) or a summary block; question-shaped subheads; extractable answer blocks; tables for comparisons.
- eeat_content: first-hand experience shown, real author and credentials and date, every statistic cited and scoped, zero fabricated statistics, quotes, press, or reviews, a point of view not rephrased from competitors.
- geo_presence: passage-level quotability, entity clarity, earned third-party presence.
- schema_hygiene: correct structured-data types where eligible, without treating schema or llms.txt as a ranking boost.
- offpage_links: link-profile health and a white-hat earning strategy. Any black-hat tactic (bought reviews, comment spam, paid link placements, parasite SEO, reciprocal networks, private blog networks) is a P0.
- keyword_targeting: one clear target query per page, mapped to real demand and intent, present in title, H1, and body without stuffing.

**Calibration.** For a single draft or page, `offpage_links` and parts of `technical_foundation` are site-level: score them neutral (6-7) unless the draft proposes an off-page tactic or contains a competitor or black-hat link. Do not reward heavy schema or llms.txt as ranking lifts. Do not penalise the absence of llms.txt. Reward answer-first formatting, cited first-hand expertise, earned mentions, and clean fundamentals.

**Forced questions.**
- weakest_dimension: which scored lowest, and the one concrete reason.
- highest_impact_fix: the single change with the most ranking or citation upside.
- fabrication_or_unsourced_stat: the most specific claim that is fabricated, uncited, or wrong-scoped (or "none found" with what you checked).
- bad_outbound_link: any competitor, weak-commercial, or aggregator outbound link to remove (or "none found").
- aeo_gap: the most important thing an AI engine cannot cleanly extract or cite from this page.
- missing_evidence: what would you need that is not in the packet?

**Fail modes.** title_over_limit, description_over_limit, no_answer_first_block, keyword_stuffing, fabricated_or_unsourced_stat, competitor_outbound_link, schema_or_llms_txt_as_ranking_crutch, no_first_hand_experience, thin_or_rephrased_content, no_internal_links, no_target_keyword_in_open, black_hat_offpage_tactic, js_only_content_blocks_ai_crawlers, missing_author_or_date, generic_meta
