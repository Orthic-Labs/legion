# site_audit.py — deterministic crawl checks (Ahrefs Site Audit taxonomy)

`scripts/site_audit.py` is the deterministic evidence layer for `/seo audit`. It crawls a
site from its sitemap + internal links (stdlib only, no browser, sites up to ~300 URLs) and
flags the **mechanical, no-judgment** issue classes that Ahrefs Site Audit / Screaming Frog
report. Run it FIRST on any full/site audit — the LLM lenses reason over its JSON, they don't
re-eyeball these.

```
python skills/seo/scripts/site_audit.py --url https://site.com --json out/site_audit.json --summary
```
Exit code 1 when any error-class issue is present (CI-friendly). Output JSON: `{crawled,
sitemap_urls, broken_links_all, redirects, issues{class: [loci]}, severity{errors[], warnings[]}}`.

## Checks → Ahrefs issue mapping

| site_audit class | Ahrefs Site Audit issue | Band |
|---|---|---|
| `broken_internal_links` | 4XX page / Broken link (internal) | Error |
| `4xx_in_sitemap` | 4XX page in sitemap | Error |
| `redirect_in_sitemap` | 3XX redirect in sitemap | Warning |
| `redirects` (3xx internal targets) | Page has links to redirect / redirect chain | Notice |
| `missing_title` | Empty/missing title | Error |
| `duplicate_title` | Duplicate title tag | Warning |
| `title_too_long` (>60) / `title_too_short` (<15) | Title too long / too short | Notice |
| `missing_meta_desc` | Missing meta description | Warning |
| `duplicate_meta_desc` | Duplicate meta description | Warning |
| `meta_desc_too_long` (>160) / `_too_short` (<50) | Meta description too long / short | Notice |
| `missing_h1` | Missing H1 | Warning |
| `multiple_h1` | Multiple H1 | Warning/Error |
| `missing_canonical` | Canonical missing | Warning |
| `canonical_points_elsewhere` | Canonical points to another page (non-self) | Warning |
| `thin_content` (<200 words) | Low word count / low text-HTML ratio | Warning |
| `img_missing_alt` | Image missing alt text | Warning |
| `missing_viewport` | Viewport not set (mobile) | Warning |
| `orphan_in_sitemap` | Orphan page (in sitemap, no internal inlinks) | Warning |
| `noindex_in_sitemap` | Noindex page in sitemap | Warning |
| `mixed_content` | HTTPS page loads HTTP resource | Warning |

## What it deliberately does NOT flag (false-positive guards)

- **Qwik `q:base="/build/"`** — the module-loader base, not a link. The scanner reads real
  `<a href>` anchors only, so `/build/` never false-flags (the earlier hand-crawl bug).
- **Cloudflare `/cdn-cgi/...`** (email-obfuscation) — CF infrastructure, skipped.
- **Trailing-slash URL variants** — `/p` and `/p/` (and root `x` vs `x/`) collapse to one page,
  so no phantom "duplicate title/meta" from crawling both forms.

## Not covered here (use the paired tools / lanes)

- **JS-rendered signals** (Qwik/React runtime schema, client-only content) → `render_gap.mjs`
  (raw-vs-rendered DOM diff). site_audit reads server HTML; run render-gap when a framework
  hydrates content client-side.
- **Field CWV / real Core Web Vitals** → `pagespeed_check.py` + `crux_history.py` (need
  `GOOGLE_API_KEY`). site_audit does not measure performance.
- **Indexation status, impressions, clicks, positions** → `gsc_inspect.py` / `gsc_query.py`
  (need GSC OAuth). site_audit checks crawlability, not what Google actually indexed/ranks.
- **Backlinks, DR, keyword volume, competitor SERPs** → Ahrefs/DataForSEO MCP lanes.
- **Judgment classes** (E-E-A-T, search-intent match, cannibalization, GEO/AI-citability,
  content quality) → native seo sub-agents (sonnet judgment / haiku mechanical; no external model APIs).

## Provenance

Ported from the hand-built crawler used in the 2026-07-04 Right Suite audit
(`SEO/snapshots/2026-07-04/ahrefs_crawl.py`) after it found SampleApp's real errors — every
page emitted two `<meta name="description">` (layout default + route), so 52 pages read the
identical default = Ahrefs "duplicate meta description" — plus 12 broken internal links. Both
were invisible to the rubric-only audit; the crawler is why they surfaced.
