# Technical SEO — crawl, index, render and delivery evidence

Use for technical search eligibility and delivery. This reference follows the canonical five-state control model and current platform authority; it does not emit a universal technical score.

## Evidence order

1. HTTP/DNS/TLS/status/redirect evidence.
2. robots.txt + X-Robots/meta robots + sitemap/feed intent.
3. canonical/hreflang and URL-state consistency.
4. static vs rendered main content/metadata/schema/internal links.
5. Search Console URL Inspection/sitemaps/search evidence when authorized.
6. field CWV (CrUX) where available; lab/browser diagnostics separately.
7. server/CDN/WAF/log evidence where supplied.
8. crawler-policy evidence by purpose.

## Crawlability

Check:
- robots syntax and applicable rules;
- robots-discovered sitemap files/indexes;
- reachable internal graph and orphan/dead-end states;
- redirect chains/loops and soft-error patterns;
- parameter/facet/calendar/search traps;
- important asset blocking where it changes rendering;
- server/WAF/CDN denials, throttling or bot challenges;
- crawl evidence from logs/GSC when available.

Do not apply a universal “three clicks” or site-size threshold as a ranking gate. Depth and crawl efficiency are impact signals conditioned on architecture and observed behavior.

## Indexability

Reconcile:

`HTTP state -> robots access -> X-Robots/meta robots -> canonical -> rendered content -> sitemap intent -> hreflang -> Search Console indexed-version evidence`

Conflicts are findings. A self-canonical is common but not mandatory when a different canonical is intentional and valid. Canonical is a hint; do not report it as guaranteed selection.

Noindex, canonical and robots have different semantics. Blocking crawl can prevent a crawler from seeing page-level directives; do not recommend robots blocking as a generic removal mechanism.

## Crawler purpose

Use `ai-search-2026.md` and `workflow-packs.md` bot-policy rules. Keep at minimum:

- Google Search/AI Overview/AI Mode eligibility → Googlebot/search indexing controls;
- Google model/grounding use preference → Google-Extended;
- ChatGPT Search citability → OAI-SearchBot;
- OpenAI model training → GPTBot;
- Claude search citability → Claude-SearchBot;
- Anthropic model training → ClaudeBot;
- user-triggered agents/fetchers → separate access/authority class.

Never infer search eligibility from a training crawler, or vice versa.

## Security/delivery

Check HTTPS validity, mixed content and security/WAF behavior that materially affects crawl/render/access. Security headers may be useful security controls but are not generic SEO ranking requirements. Escalate hacked/injected/spam/private-data issues through the policy/security pack.

## URL structure

Judge stability, normalization, duplication, hierarchy and user/search meaning. Long URLs and query parameters are diagnostic signals, not automatic failures. Query parameters can be correct canonical URLs; path shape alone does not decide indexability.

Redirects should express real moves/replacements. Minimize unnecessary hops but do not invent a universal “maximum one hop” ranking rule.

## Mobile/accessibility

Verify viewport, responsive layout, critical content parity, interaction usability and accessibility of search-critical tasks. Do not enforce universal font/touch-pixel values as SEO ranking gates. Use actual browser/accessibility evidence and current standards.

## Core Web Vitals

Use current `cwv-thresholds.md`. Prefer field CrUX at the appropriate URL/origin scope and 75th percentile where available. Keep Lighthouse/lab data as a different evidence tier. Missing CrUX is `Not testable` for field experience, not Pass or Fail.

## JavaScript/rendering

Compare initial response and rendered DOM for:

- title/meta robots/canonical;
- H1/main text;
- internal links;
- structured data;
- status/error/soft-404 behavior;
- lazy/interaction-loaded critical content.

Framework identity alone is not a problem. Flag observed render/index consequences. Critical directives should not conflict across server and rendered states.

## Structured data

Validate syntax, visible-content agreement, entity identity and current rich-result eligibility. Schema is not proof of a rich result/ranking/citation.

## IndexNow / submissions

Treat submissions as controlled external effects. Verify current engine support before use. A successful submission receipt proves submission only, not crawl/index/rank. Google general web indexing must not be represented as supported by the restricted Indexing API where it is not.

## Output

For each control record:

`control | subject | evidence/source/time/market | status | impact | confidence | affected reach | missing evidence | remediation | validation`

Use `Pass | Partial | Fail | N/A | Not testable`. Keep critical gates (indexability, canonical/redirect integrity, security/private-data, measurement and authority boundaries) outside any optional score.

Use deterministic scripts first: `site_audit.py`, `fetch_page.py`, render/browser evidence, `gsc_inspect.py`, `pagespeed_check.py`, `crux_history.py`, and provider/log evidence as applicable.