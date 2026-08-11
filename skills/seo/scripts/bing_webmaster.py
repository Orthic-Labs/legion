#!/usr/bin/env python3
"""
bing_webmaster.py — Bing Webmaster Tools API client (100% free, owned sites only).

BWT is the free counterpart to Google Search Console for Bing/Yahoo/DuckDuckGo
(all powered by Bing's index). It gives, for sites YOU have verified in Bing
Webmaster Tools:

  - rank & traffic stats (impressions, clicks over time)
  - top query stats (keyword, impressions, clicks, avg position)
  - top page stats
  - inbound links (your OWN backlinks, from Bing's crawl — a free backlink source)
  - crawl issues (4xx/5xx, blocked, malware, etc. Bing found)
  - instant URL submission (SubmitUrl — Bing's "Instant Indexing")

Auth: a single free API key. Bing Webmaster Tools dashboard → Settings (gear)
→ API access → generate key. One key covers every site on the account.
Set it as the BING_API_KEY environment variable (see references/free-data-sources.md).

Transport: JSON over HTTPS at
  https://ssl.bing.com/webmaster/api.svc/json/<Method>?apikey=KEY[&siteUrl=...]
GET for reads; POST (JSON body) for SubmitUrl. Stdlib only.

Usage:
  python bing_webmaster.py traffic   --site https://example.com/
  python bing_webmaster.py queries   --site https://example.com/
  python bing_webmaster.py pages     --site https://example.com/
  python bing_webmaster.py links     --site https://example.com/
  python bing_webmaster.py crawl     --site https://example.com/
  python bing_webmaster.py submit    --site https://example.com/ --url https://example.com/new-page/
  python bing_webmaster.py raw GetRankAndTrafficStats --site https://example.com/
Add --json out.json to persist. Exit 2 if BING_API_KEY is missing.

This is the deterministic Bing evidence layer for `/seo audit`; the LLM lenses
reason over the JSON it emits.
"""
import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
import urllib.error

BASE = "https://ssl.bing.com/webmaster/api.svc/json"


def _key() -> str:
    k = os.environ.get("BING_API_KEY")
    if not k:
        print("Error: BING_API_KEY not set. Get a free key at Bing Webmaster Tools "
              "→ Settings → API access, then set BING_API_KEY. "
              "See references/free-data-sources.md.", file=sys.stderr)
        sys.exit(2)
    return k


def call(method: str, params: dict | None = None, body: dict | None = None) -> dict:
    """Call a BWT JSON method. GET when body is None, else POST the JSON body."""
    q = {"apikey": _key()}
    if params:
        q.update({k: v for k, v in params.items() if v is not None})
    url = f"{BASE}/{method}?{urllib.parse.urlencode(q)}"
    data = None
    headers = {"User-Agent": "seo-audit/1.0"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    try:
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method="POST" if data else "GET")
        r = urllib.request.urlopen(req, timeout=30)
        raw = r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        detail = (e.read().decode("utf-8", "ignore") if e.fp else "")[:500]
        return {"error": f"HTTP {e.code}", "method": method, "detail": detail}
    except Exception as e:
        return {"error": str(e), "method": method}
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {"error": "non-JSON response", "method": method, "raw": raw[:500]}
    # BWT wraps results in {"d": ...}; unwrap for convenience.
    return {"method": method, "d": parsed.get("d", parsed)}


SUBCOMMANDS = {
    "traffic": "GetRankAndTrafficStats",
    "queries": "GetQueryStats",
    "pages": "GetPageStats",
    "links": "GetUrlLinks",
    "crawl": "GetCrawlIssues",
}


def main():
    ap = argparse.ArgumentParser(description="Bing Webmaster Tools API client (free, owned sites).")
    ap.add_argument("command", help="traffic|queries|pages|links|crawl|submit|raw")
    ap.add_argument("method", nargs="?", help="for 'raw': the BWT method name")
    ap.add_argument("--site", help="verified siteUrl, e.g. https://example.com/")
    ap.add_argument("--url", help="for 'submit': the page URL to instant-index")
    ap.add_argument("--json", dest="out", help="write full JSON result here")
    a = ap.parse_args()

    if a.command == "submit":
        if not (a.site and a.url):
            ap.error("submit needs --site and --url")
        res = call("SubmitUrl", body={"siteUrl": a.site, "url": a.url})
    elif a.command == "raw":
        if not a.method:
            ap.error("raw needs a method name")
        res = call(a.method, params={"siteUrl": a.site})
    elif a.command in SUBCOMMANDS:
        if not a.site:
            ap.error(f"{a.command} needs --site")
        res = call(SUBCOMMANDS[a.command], params={"siteUrl": a.site})
    else:
        ap.error(f"unknown command '{a.command}'")

    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=1)
    print(json.dumps(res, indent=1)[:4000])
    sys.exit(1 if res.get("error") else 0)


if __name__ == "__main__":
    main()
