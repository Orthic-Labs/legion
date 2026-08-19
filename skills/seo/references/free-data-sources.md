# Free SEO data providers — the 100% free automated stack

Every provider here is **free forever** (not a trial) and has a **real API** the audit can
call unattended. This is the whole owned-site SEO data layer — no Ahrefs/Semrush needed.

## Why you don't need a paid tool for your own sites

Ahrefs/Semrush cost money because they run a **web-scale crawler** (AhrefsBot is the #2 crawler
on Earth) that visits billions of pages a day, records every `<a href>` across the entire web to
build the **backlink graph**, and scrape Google SERPs continuously for keyword volumes and
rankings. You cannot reproduce that — it's petabytes and thousands of servers. That is the moat,
and the *only* thing worth paying for.

But that moat only matters for **competitor** data. For **sites you own**, the search engines
themselves hand you the same facts for free — and more accurately, because it's their real index:

| Question about YOUR site | Free source | Paid tool needed? |
|---|---|---|
| Crawl/technical issues (titles, meta, h1, links, canonicals…) | `site_audit.py` | No |
| Rankings, clicks, impressions, positions | Google Search Console | No |
| Is this URL indexed? | GSC URL Inspection | No |
| My backlinks | GSC + Bing Webmaster | No |
| Core Web Vitals (lab + field) | PageSpeed + CrUX | No |
| Traffic, conversions | GA4 | No |
| **Competitor** backlinks / keywords / rankings | — | **Yes (Ahrefs/Semrush/DataForSEO)** |

So the rule: **owned-site audit = 100% free. Competitor espionage = paid.** All 7 Right-Suite/brand
sites are owned, so the free stack below covers them completely.

## The providers

| Provider | Gives | Credential | Env var(s) | Auto? |
|---|---|---|---|---|
| **PageSpeed Insights** | CWV lab (Lighthouse) | API key | `GOOGLE_API_KEY` | ✅ |
| **CrUX** | CWV **field** data (real users) | same API key | `GOOGLE_API_KEY` | ✅ |
| **Search Console** | queries, clicks, impressions, position, indexation | service account | `GOOGLE_APPLICATION_CREDENTIALS`, `GSC_PROPERTY` | ✅ |
| **GA4 Data API** | sessions, conversions, landing pages | same service account | `GOOGLE_APPLICATION_CREDENTIALS`, `GA4_PROPERTY_ID` | ✅ |
| **Bing Webmaster** | Bing rankings, crawl issues, **your backlinks**, URL submit | free API key | `BING_API_KEY` | ✅ |
| **IndexNow** | instant-index push (Bing/Yandex/others) | self-hosted key file | `INDEXNOW_KEY` | ✅ |

> **Ahrefs Webmaster Tools (AWT)** is free to *use* but has **no free API** — the data is only in
> the dashboard / manual CSV export. So it is NOT in this automated stack. If you download an AWT
> CSV by hand, drop it in `SEO/exports/<site>/` and the audit will parse it as a manual lane.
> Google's **Indexing API** (`indexing_notify.py`) is free but officially only honors JobPosting/
> VideoObject pages — use IndexNow for general pages instead.

## Where to get each credential

1. **Google API key** (PageSpeed + CrUX) — [Google Cloud Console → Credentials](https://console.cloud.google.com/apis/credentials).
   Create project → **Create credentials → API key**. Then **enable** these APIs in
   [API Library](https://console.cloud.google.com/apis/library): *PageSpeed Insights API*,
   *Chrome UX Report API*. (No billing needed; both are free-quota.)
2. **Service account** (GSC + GA4) — [Cloud Console → Service Accounts](https://console.cloud.google.com/iam-admin/serviceaccounts).
   Create service account → **Keys → Add key → JSON** → download. Save the JSON somewhere private
   outside the repo — do not commit it or hardcode its path in shared config. Enable *Search Console API* and
   *Google Analytics Data API* in the API Library. Then **grant that service-account email access**:
   - GSC: [Search Console](https://search.google.com/search-console) → your property → Settings →
     Users & permissions → **Add user** → paste the `...@...iam.gserviceaccount.com` email → Full.
   - GA4: [GA4 Admin](https://analytics.google.com) → Property → Property Access Management →
     **+** → add the same email → Viewer.
3. **GSC property** — the exact property string, e.g. `sc-domain:example.com` (domain property)
   or `https://example.com/` (URL-prefix). One per site.
4. **GA4 property ID** — GA4 Admin → Property Settings → the numeric **Property ID** (e.g. `123456789`).
5. **Bing API key** — [Bing Webmaster Tools](https://www.bing.com/webmasters) → verify your site →
   Settings (gear) → **API access → API Key** → generate. One key covers all your BWT sites.
6. **IndexNow key** — no signup. Run `python scripts/indexnow.py genkey`, then host the printed key
   as a text file at the site root: `https://<host>/<key>.txt` whose *contents are exactly the key*
   (for the Right-Suite Qwik sites: drop `<key>.txt` in `public/`).

## Setting the env vars (PowerShell, Windows)

`SetEnvironmentVariable(..., 'User')` persists across reboots; the `$env:` line makes it live in the
**current** session without a restart. Do both. (Restart Claude/Codex after, so the new session
inherits them — env is captured at process start.)

```powershell
# Google (PageSpeed + CrUX)
[Environment]::SetEnvironmentVariable('GOOGLE_API_KEY','PASTE_KEY','User'); $env:GOOGLE_API_KEY='PASTE_KEY'

# Google service account (GSC + GA4) — path to the downloaded JSON
[Environment]::SetEnvironmentVariable('GOOGLE_APPLICATION_CREDENTIALS','<path-to-service-account-json>','User'); $env:GOOGLE_APPLICATION_CREDENTIALS='<path-to-service-account-json>'

# Per-site: which property (change per site before its audit, or pass --property on the call)
[Environment]::SetEnvironmentVariable('GSC_PROPERTY','sc-domain:example.com','User'); $env:GSC_PROPERTY='sc-domain:example.com'
[Environment]::SetEnvironmentVariable('GA4_PROPERTY_ID','123456789','User'); $env:GA4_PROPERTY_ID='123456789'

# Bing Webmaster
[Environment]::SetEnvironmentVariable('BING_API_KEY','PASTE_BING_KEY','User'); $env:BING_API_KEY='PASTE_BING_KEY'

# IndexNow (value from `python scripts/indexnow.py genkey`)
[Environment]::SetEnvironmentVariable('INDEXNOW_KEY','PASTE_INDEXNOW_KEY','User'); $env:INDEXNOW_KEY='PASTE_INDEXNOW_KEY'
```

Verify (should print the values):
```powershell
$env:GOOGLE_API_KEY, $env:GOOGLE_APPLICATION_CREDENTIALS, $env:BING_API_KEY, $env:INDEXNOW_KEY
```

`GOOGLE_API_KEY` and `GOOGLE_APPLICATION_CREDENTIALS` are one-time (all sites share them). Only
`GSC_PROPERTY` / `GA4_PROPERTY_ID` change per site — set them before each site's audit, or the audit
runner passes them as `--property` / `--property-id` per call.

## Which script consumes which

| Script | Provider | Reads |
|---|---|---|
| `pagespeed_check.py` | PageSpeed + CrUX | `GOOGLE_API_KEY` |
| `crux_history.py` | CrUX | `GOOGLE_API_KEY` |
| `gsc_query.py`, `gsc_inspect.py` | Search Console | `GOOGLE_APPLICATION_CREDENTIALS`, `GSC_PROPERTY` |
| `ga4_report.py` | GA4 | `GOOGLE_APPLICATION_CREDENTIALS`, `GA4_PROPERTY_ID` |
| `bing_webmaster.py` | Bing Webmaster | `BING_API_KEY` |
| `indexnow.py` | IndexNow | `INDEXNOW_KEY` |
| `site_audit.py` | (none — crawls directly) | — |

Once the env vars are set and the service account is granted access to each property, the audit
pulls all six providers automatically — no per-run auth.
