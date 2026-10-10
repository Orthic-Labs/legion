# Rubric: compliance-risk

**Framing.** Adversarial. Default REVISE with P0 findings until cleared. The biggest source of catastrophic loss for platform-dependent operators is account loss: find the violation before the platform or regulator does. Native verdicts: CLEAR, REVIEW, BLOCK.
**Scope.** Platform policy, advertising claims, IP and trademark, publishing and marketplace copyright, endorsement disclosure, health and finance claims, refund and payment-processor risk, AI-disclosure rules. Quote only rules the packet supplies or that you can name precisely; mark the rest unverified.

**Dimensions (1-10).** platform_policy_fit, claim_defensibility, ip_clearance, disclosure_completeness, payment_processor_risk, refund_chargeback_exposure, account_ban_risk

**Forced questions.**
- policy_violation: which platform's specific policy clause does this risk violating? Name the rule pattern.
- unbacked_claim: which claim cannot be backed with primary evidence ("competent and reliable" evidence for health claims)?
- ip_exposure: any trademark, character, music, font, image, or trade dress used without an explicit licence?
- disclosure_gap: AI-assisted, sponsored, affiliate, health, or financial disclosure missing or insufficient?
- worst_case_consequence: ban, takedown, chargeback, lawsuit, or refund storm; quantify.
- missing_evidence: what would you need that is not in the packet?

**Platform areas to check as relevant.** Print-on-demand and ebook marketplaces (AI-content disclosure, trademarked terms, derivative works); handmade marketplaces (IP, handmade rules); resale and dropship (counterfeit, brand gating, listing manipulation); social and search ads (prohibited and restricted categories, health, financial, political, before-and-after imagery, personal-attribute targeting); video platforms (monetisation, music rights, misleading thumbnails, children's content); email (consent and sender-reputation law); payment processors (high-risk categories, refund and chargeback thresholds); tax and worker classification where the artifact touches them.

**Fail modes.** hand_drawn_claimed_when_ai_assisted, unsourced_health_claim, financial_advice_without_disclaimer, before_after_body_imagery, fabricated_testimonial, unauthorised_likeness, music_without_sync_licence, font_outside_allowed_use, competitor_dashboard_screenshot, scraping_terms_violation, endorsement_undisclosed
