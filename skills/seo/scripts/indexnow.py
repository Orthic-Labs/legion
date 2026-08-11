#!/usr/bin/env python3
"""
indexnow.py — IndexNow instant-index submission (100% free, no account).

IndexNow lets you ping search engines the moment a URL changes; Bing, Yandex,
Seznam, Naver (and others) honor it. Google does NOT — it ignores IndexNow — so
this COMPLEMENTS Google Search Console, it does not replace it. Submitting a URL
to one participating engine shares it with all of them.

How it authenticates (no API key service): you pick a key (a 8-128 char hex-ish
string), host it as a text file at https://<yourhost>/<key>.txt whose contents are
exactly that key. That file proves you own the host. Set the key as INDEXNOW_KEY.

  1. Generate a key:            python indexnow.py genkey
  2. Save the printed key as INDEXNOW_KEY (see references/free-data-sources.md)
     and write the key file: create /<key>.txt at the site root containing the key.
  3. Submit URLs:
       python indexnow.py submit --host example.com --url https://example.com/new/
       python indexnow.py submit --host example.com --urls urls.txt   # one URL/line, up to 10000

Endpoint: POST https://api.indexnow.org/indexnow  (fans out to all engines).
Stdlib only. Exit 2 if INDEXNOW_KEY missing on submit; exit 1 on HTTP failure.
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error
import hashlib

ENDPOINT = "https://api.indexnow.org/indexnow"


def genkey() -> str:
    # 32 hex chars derived from OS entropy (Math.random/Date are unavailable in some
    # sandboxes, but os.urandom always is). IndexNow accepts [a-zA-Z0-9-] 8..128.
    return hashlib.sha256(os.urandom(32)).hexdigest()[:32]


def submit(host: str, urls: list[str], key: str, key_location: str | None) -> dict:
    body = {
        "host": host,
        "key": key,
        "urlList": urls,
    }
    if key_location:
        body["keyLocation"] = key_location
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        ENDPOINT, data=data,
        headers={"Content-Type": "application/json; charset=utf-8",
                 "User-Agent": "seo-audit/1.0"},
        method="POST",
    )
    try:
        r = urllib.request.urlopen(req, timeout=30)
        # 200/202 = accepted. Body is usually empty.
        return {"status": r.getcode(), "submitted": len(urls), "host": host}
    except urllib.error.HTTPError as e:
        # 403 = key not found/valid at keyLocation; 422 = URLs don't match host; 429 = rate.
        return {"status": e.code, "error": e.reason,
                "detail": (e.read().decode("utf-8", "ignore") if e.fp else "")[:300],
                "submitted": 0, "host": host}
    except Exception as e:
        return {"status": 0, "error": str(e), "submitted": 0, "host": host}


def main():
    ap = argparse.ArgumentParser(description="IndexNow instant-index submitter (free).")
    ap.add_argument("command", help="genkey | submit")
    ap.add_argument("--host", help="bare host, e.g. example.com (no scheme)")
    ap.add_argument("--url", help="single URL to submit")
    ap.add_argument("--urls", help="file with one URL per line (up to 10000)")
    ap.add_argument("--key-location", help="explicit https URL of the key file "
                                           "(default: https://<host>/<key>.txt)")
    ap.add_argument("--json", dest="out", help="write result JSON here")
    a = ap.parse_args()

    if a.command == "genkey":
        print(genkey())
        return

    if a.command != "submit":
        ap.error(f"unknown command '{a.command}'")

    key = os.environ.get("INDEXNOW_KEY")
    if not key:
        print("Error: INDEXNOW_KEY not set. Run 'python indexnow.py genkey', set the "
              "value as INDEXNOW_KEY, and host it at https://<host>/<key>.txt. "
              "See references/free-data-sources.md.", file=sys.stderr)
        sys.exit(2)
    if not a.host:
        ap.error("submit needs --host")

    urls = []
    if a.url:
        urls.append(a.url)
    if a.urls:
        with open(a.urls, encoding="utf-8") as f:
            urls += [ln.strip() for ln in f if ln.strip()]
    if not urls:
        ap.error("submit needs --url or --urls")

    loc = a.key_location or f"https://{a.host}/{key}.txt"
    res = submit(a.host, urls, key, loc)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=1)
    print(json.dumps(res, indent=1))
    sys.exit(0 if res.get("status") in (200, 202) else 1)


if __name__ == "__main__":
    main()
