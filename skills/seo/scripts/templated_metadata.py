#!/usr/bin/env python3
"""Detect site-scale templated meta descriptions.

Input is JSON from a crawler or extractor: either a list of objects with
`url`, `title`, and `meta_desc`/`meta_description`, or an object containing
`pages` with that shape. This is heuristic evidence, not a ranking verdict.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

CTA_RE = re.compile(
    r"\b(learn more|find out more|get started|discover more|read more|shop now|buy now|"
    r"contact us|book now|try now|sign up|explore now|start today|see more)\b[.! ]*$",
    re.I,
)


def norm(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", (text or "").casefold())).strip()


def analyze(rows: list[dict]) -> dict:
    findings = []
    ctas = Counter()
    checked = 0
    for row in rows:
        title = str(row.get("title") or "").strip()
        desc = str(row.get("meta_desc") or row.get("meta_description") or "").strip()
        if not desc:
            continue
        checked += 1
        ntitle, ndesc = norm(title), norm(desc)
        restates = bool(ntitle and (ndesc.startswith(ntitle) or ntitle in ndesc[: max(len(ntitle) + 25, 60)]))
        m = CTA_RE.search(desc)
        cta = m.group(1).casefold() if m else None
        if cta:
            ctas[cta] += 1
        if restates and cta:
            findings.append({
                "url": row.get("url"),
                "title": title,
                "meta_description": desc,
                "signals": ["title_restatement", "stock_cta"],
                "cta": cta,
                "method": "heuristic",
            })

    ratio = (len(findings) / checked) if checked else 0.0
    if ratio >= 0.5 and checked >= 4:
        risk = "high"
    elif ratio >= 0.2 and checked >= 4:
        risk = "medium"
    elif findings:
        risk = "low"
    else:
        risk = "none"
    return {
        "method": "heuristic",
        "pages_checked": checked,
        "templated_pages": len(findings),
        "templated_ratio": round(ratio, 4),
        "shared_cta_phrases": ctas.most_common(10),
        "site_risk": risk,
        "findings": findings,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="JSON list or object containing pages")
    ap.add_argument("--json", dest="out")
    a = ap.parse_args()
    payload = json.loads(Path(a.input).read_text(encoding="utf-8"))
    rows = payload.get("pages", []) if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise SystemExit("input must be a list or object with pages[]")
    result = analyze(rows)
    text = json.dumps(result, indent=2)
    if a.out:
        Path(a.out).write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
