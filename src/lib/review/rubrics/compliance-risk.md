RUBRIC: review-compliance-risk
FRAMING: adversarial. Default BLOCK. Single biggest source of catastrophic loss for KDP/Amazon/ads operators is account ban. Find the violation before the platform finds it.
SCOPE: platform policy, ads claims, IP/trademark, KDP/Etsy/POD copyright, FTC disclosures, health/finance claims, refund/payment processor risk, AI-disclosure rules.
DIMENSIONS (1-10): platform_policy_fit, claim_defensibility, ip_clearance, disclosure_completeness, payment_processor_risk, refund_chargeback_exposure, account_ban_risk
QUESTIONS_5:
  policy_violation: which platform's specific policy clause does this work risk violating? quote the rule pattern.
  unbacked_claim: which claim cannot be backed up with primary evidence (FTC: "competent and reliable scientific evidence")?
  ip_exposure: any trademark, character, music, font, image, or trade dress used without explicit license?
  disclosure_gap: AI-assisted/sponsored/affiliate/health/financial disclosure missing or insufficient?
  worst_case_consequence: ban / takedown / chargeback / lawsuit / refund-storm — quantify
PLATFORMS_AND_FAILURE_MODES:
  KDP: AI-content disclosure, trademarked terms in title/keywords, copyrighted text, derivative work without permission, low-content PI block, format violations
  Etsy: handmade rules, prohibited items, IP infringement, sustainability claims, AI-assisted disclosure
  Amazon_dropship: counterfeit, brand-gating, IP violation, listing manipulation, product safety, ASIN hijack risk
  Meta_ads: prohibited categories, restricted health/financial/political claims, before-after, body sensationalism, personal-attribute targeting
  Google_ads: misrepresentation, dangerous products, healthcare restrictions, financial certification
  TikTok_ads: prohibited products, restricted health, age-gating
  YouTube: monetization rules, copyright music, misleading thumbnails, kids content (COPPA)
  IG/FB_organic: community guidelines, copyrighted music in reels, branded-content disclosure
  Email: CAN-SPAM, GDPR, sender reputation, spam-trap risk
  Stripe/PayPal: high-risk categories, prohibited goods, refund-rate threshold, chargeback ratio
  US_tax_employment: contractor classification, sales tax nexus, state-by-state ad tax (Maryland)
  India_GST_TDS: applies to services to/from India
GENERAL_FAIL_MODES: hand_drawn_when_ai_assisted, unsourced_health_claim, financial_advice_without_disclaimer, before_after_skin_body, fabricated_testimonial, unauthorized_celebrity_likeness, music_without_sync_license, font_outside_allowed_use, screenshot_of_competitor_dashboard, scraping_TOS_violation, FTC_endorsement_undisclosed
  missing_evidence: ≤200c — what would you need to see that ISN't in this packet? (added 2026-07-14 per Fable review)
OUTPUT (strict JSON, ≤900 tokens):
{
  "verdict": "CLEAR" | "REVIEW" | "BLOCK",
  "score": 1-10,
  "top_concern": "≤120c — biggest specific risk + which platform/regulator",
  "scores": {"platform_policy_fit":n, "claim_defensibility":n, "ip_clearance":n, "disclosure_completeness":n, "payment_processor_risk":n, "refund_chargeback_exposure":n, "account_ban_risk":n},
  "answers": {"policy_violation":"≤140c name platform+rule", "unbacked_claim":"≤140c quote claim", "ip_exposure":"≤140c", "disclosure_gap":"≤140c", "worst_case_consequence":"≤140c"},
  "blockers": [{"tier": "P0|P1|P2", "text": "concrete fixes before ship; ≤200c each; P1+P2 share max 8; P0 unbounded"}]
}
