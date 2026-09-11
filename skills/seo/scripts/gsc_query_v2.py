#!/usr/bin/env python3
"""Provenance-safe Google Search Console Search Analytics helper.

Unlike the legacy helper, aggregate totals are queried separately from dimension rows.
The script reports row truncation/completeness metadata and never presents summed
query/page rows as authoritative property totals.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta
from typing import Optional

try:
    from googleapiclient.discovery import build
except ImportError:
    print("google-api-python-client is required", file=sys.stderr)
    sys.exit(2)

try:
    from google_auth import get_oauth_credentials, load_config
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from google_auth import get_oauth_credentials, load_config

GSC_SCOPES = ["https://www.googleapis.com/auth/webmasters.readonly"]


def service():
    creds = get_oauth_credentials(GSC_SCOPES)
    return build("searchconsole", "v1", credentials=creds) if creds else None


def _query(svc, site_url: str, body: dict) -> dict:
    return svc.searchanalytics().query(siteUrl=site_url, body=body).execute()


def query(
    site_url: str,
    start_date: str,
    end_date: str,
    dimensions: list[str],
    search_type: str,
    page_size: int,
    max_rows: int,
    filters: Optional[list] = None,
    data_state: str = "final",
) -> dict:
    svc = service()
    if not svc:
        return {"error": "could not build Search Console service"}

    common = {
        "startDate": start_date,
        "endDate": end_date,
        "type": search_type,
        "dataState": data_state,
    }
    if filters:
        common["dimensionFilterGroups"] = [{"filters": filters}]

    try:
        aggregate = _query(svc, site_url, {**common, "dimensions": [], "rowLimit": 1})
        aggregate_rows = aggregate.get("rows", [])
        aggregate_row = aggregate_rows[0] if aggregate_rows else {}

        rows = []
        start_row = 0
        page_size = min(max(1, page_size), 25000)
        hit_cap = False
        while start_row < max_rows:
            size = min(page_size, max_rows - start_row)
            response = _query(
                svc,
                site_url,
                {**common, "dimensions": dimensions, "rowLimit": size, "startRow": start_row},
            )
            batch = response.get("rows", [])
            rows.extend(batch)
            if len(batch) < size:
                break
            start_row += len(batch)
            if start_row >= max_rows:
                hit_cap = True
                break
    except Exception as exc:
        return {"error": str(exc), "property": site_url}

    processed = []
    for row in rows:
        item = {
            "clicks": row.get("clicks", 0),
            "impressions": row.get("impressions", 0),
            "ctr": round(row.get("ctr", 0) * 100, 4),
            "position": round(row.get("position", 0), 3),
        }
        keys = row.get("keys", [])
        for i, dim in enumerate(dimensions):
            item[dim] = keys[i] if i < len(keys) else None
        processed.append(item)

    query_clicks = sum(x.get("clicks", 0) for x in rows)
    query_impressions = sum(x.get("impressions", 0) for x in rows)
    agg_clicks = aggregate_row.get("clicks", 0)
    agg_impressions = aggregate_row.get("impressions", 0)

    return {
        "property": site_url,
        "date_range": {"start": start_date, "end": end_date},
        "search_type": search_type,
        "dimensions": dimensions,
        "rows": processed,
        "aggregate": {
            "clicks": agg_clicks,
            "impressions": agg_impressions,
            "ctr": round(aggregate_row.get("ctr", 0) * 100, 4),
            "position": round(aggregate_row.get("position", 0), 3),
            "provenance": "dimensionless Search Analytics query",
        },
        "dimension_sum": {
            "clicks": query_clicks,
            "impressions": query_impressions,
            "provenance": "sum of returned dimension rows; not authoritative property total",
        },
        "coverage": {
            "returned_rows": len(processed),
            "max_rows": max_rows,
            "hit_client_cap": hit_cap,
            "query_click_coverage": round(query_clicks / agg_clicks, 4) if agg_clicks else None,
            "query_impression_coverage": round(query_impressions / agg_impressions, 4) if agg_impressions else None,
            "note": "Search Console can omit anonymized/low-volume rows in dimensioned queries; aggregate totals are intentionally separate.",
        },
        "error": None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--property", "-p")
    ap.add_argument("--start-date")
    ap.add_argument("--end-date")
    ap.add_argument("--days", type=int, default=28)
    ap.add_argument("--dimensions", default="query,page")
    ap.add_argument("--type", default="web")
    ap.add_argument("--page-size", type=int, default=25000)
    ap.add_argument("--max-rows", type=int, default=100000)
    ap.add_argument("--device", choices=["desktop", "mobile", "tablet"])
    ap.add_argument("--country")
    ap.add_argument("--out")
    args = ap.parse_args()

    prop = args.property or load_config().get("default_property")
    if not prop:
        raise SystemExit("--property required unless default_property is configured")
    end = args.end_date or (datetime.now() - timedelta(days=3)).strftime("%Y-%m-%d")
    start = args.start_date or (datetime.now() - timedelta(days=args.days)).strftime("%Y-%m-%d")
    filters = []
    if args.device:
        filters.append({"dimension": "device", "operator": "equals", "expression": args.device.upper()})
    if args.country:
        filters.append({"dimension": "country", "operator": "equals", "expression": args.country.upper()})
    result = query(
        prop,
        start,
        end,
        [x.strip() for x in args.dimensions.split(",") if x.strip()],
        args.type,
        args.page_size,
        args.max_rows,
        filters or None,
    )
    text = json.dumps(result, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    raise SystemExit(1 if result.get("error") else 0)


if __name__ == "__main__":
    main()
