#!/usr/bin/env python3
"""Normalize first-party AI-search exports without inventing unsupported APIs.

Supports manual CSV/JSON exports from Google Search Console Generative AI reports
and Bing Webmaster Tools AI Performance. Schemas evolve, so column mapping is
explicit and source metadata is preserved. This tool never equates impressions,
citations, visits, or conversions.
"""
from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_rows(path: Path) -> list[dict]:
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(data, list):
            return data
        for key in ("rows", "data", "items"):
            if isinstance(data.get(key), list):
                return data[key]
        raise SystemExit("JSON export must be a list or contain rows/data/items[]")
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def value(row: dict, names: list[str]):
    lower = {str(k).strip().casefold(): v for k, v in row.items()}
    for name in names:
        if name.casefold() in lower:
            return lower[name.casefold()]
    return None


def num(v):
    if v in (None, ""):
        return None
    try:
        return float(str(v).replace(",", "").replace("%", "").strip())
    except ValueError:
        return None


def google(rows: list[dict], source: str) -> dict:
    out = []
    for row in rows:
        out.append({
            "date": value(row, ["date", "day"]),
            "page": value(row, ["page", "url", "landing page"]),
            "country": value(row, ["country"]),
            "device": value(row, ["device"]),
            "impressions": num(value(row, ["impressions", "generative ai impressions", "ai impressions"])),
            "raw": row,
        })
    return {
        "schema_version": 1,
        "provider": "google",
        "surface": "search_console_generative_ai",
        "measurement": "impressions",
        "imported_at": now(),
        "source_file": source,
        "rows": out,
        "limitations": [
            "Generative impressions are visibility evidence, not citations, clicks, rankings, visits, or conversions.",
            "Report availability and dimensions depend on Google's current product and property eligibility.",
        ],
    }


def bing(rows: list[dict], source: str) -> dict:
    out = []
    for row in rows:
        out.append({
            "date": value(row, ["date", "day"]),
            "page": value(row, ["cited page", "page", "url"]),
            "grounding_query": value(row, ["grounding query", "query"]),
            "topic": value(row, ["topic"]),
            "intent": value(row, ["intent"]),
            "citations": num(value(row, ["citations", "citation count", "total citations"])),
            "citation_share": num(value(row, ["citation share", "share"])),
            "raw": row,
        })
    return {
        "schema_version": 1,
        "provider": "bing",
        "surface": "webmaster_ai_performance",
        "measurement": "citations",
        "imported_at": now(),
        "source_file": source,
        "rows": out,
        "limitations": [
            "Bing AI Performance is aggregated/sampled citation activity, not ranking, authority, visits, or conversions.",
            "Grounding queries are provider-derived retrieval phrases, not exact user prompts.",
            "Citation Share is not market share or traffic share.",
        ],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("provider", choices=["google", "bing"])
    ap.add_argument("input")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    src = Path(args.input)
    rows = load_rows(src)
    result = google(rows, str(src)) if args.provider == "google" else bing(rows, str(src))
    Path(args.out).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"provider": args.provider, "rows": len(result["rows"]), "out": args.out}, indent=2))


if __name__ == "__main__":
    main()
