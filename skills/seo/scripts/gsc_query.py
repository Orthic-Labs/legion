#!/usr/bin/env python3
"""Google Search Console compatibility CLI with provenance-safe aggregate semantics.

`query` delegates to gsc_query_v2 so aggregate totals always come from a separate
dimensionless Search Analytics query. `sites` and `sitemaps` are retained for compatibility.
Do not sum query/page rows and call them property totals.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta

try:
    from googleapiclient.discovery import build
except ImportError:
    print('google-api-python-client is required', file=sys.stderr)
    raise SystemExit(2)

try:
    from google_auth import get_oauth_credentials, load_config
    from gsc_query_v2 import query as query_v2
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from google_auth import get_oauth_credentials, load_config
    from gsc_query_v2 import query as query_v2

GSC_SCOPES = ['https://www.googleapis.com/auth/webmasters.readonly']


def service():
    creds = get_oauth_credentials(GSC_SCOPES)
    return build('searchconsole', 'v1', credentials=creds) if creds else None


def list_sites() -> dict:
    svc = service()
    if not svc:
        return {'sites': [], 'error': 'could not build Search Console service'}
    try:
        response = svc.sites().list().execute()
        return {
            'sites': [{'url': s.get('siteUrl'), 'permission': s.get('permissionLevel')} for s in response.get('siteEntry', [])],
            'error': None,
        }
    except Exception as exc:
        return {'sites': [], 'error': str(exc)}


def list_sitemaps(site_url: str) -> dict:
    svc = service()
    if not svc:
        return {'property': site_url, 'sitemaps': [], 'error': 'could not build Search Console service'}
    try:
        response = svc.sitemaps().list(siteUrl=site_url).execute()
        return {
            'property': site_url,
            'sitemaps': [
                {
                    'path': sm.get('path'), 'last_submitted': sm.get('lastSubmitted'),
                    'is_pending': sm.get('isPending'), 'is_index': sm.get('isSitemapsIndex'),
                    'type': sm.get('type'), 'warnings': sm.get('warnings', 0),
                    'errors': sm.get('errors', 0), 'contents': sm.get('contents', []),
                }
                for sm in response.get('sitemap', [])
            ],
            'error': None,
        }
    except Exception as exc:
        return {'property': site_url, 'sitemaps': [], 'error': str(exc)}


def main() -> int:
    ap = argparse.ArgumentParser(description='Search Console helper; query uses provenance-safe v2 semantics')
    ap.add_argument('command', nargs='?', default='query', choices=['query', 'sitemaps', 'sites'])
    ap.add_argument('--property', '-p')
    ap.add_argument('--days', '-d', type=int, default=28)
    ap.add_argument('--start-date')
    ap.add_argument('--end-date')
    ap.add_argument('--dimensions', default='query,page')
    ap.add_argument('--type', default='web')
    ap.add_argument('--limit', type=int, default=100000, help='maximum dimension rows returned')
    ap.add_argument('--page-size', type=int, default=25000)
    ap.add_argument('--device', choices=['desktop', 'mobile', 'tablet'])
    ap.add_argument('--country')
    args = ap.parse_args()

    prop = args.property or load_config().get('default_property') or os.environ.get('GSC_PROPERTY')
    if args.command != 'sites' and not prop:
        ap.error('--property required unless configured')

    if args.command == 'sites':
        result = list_sites()
    elif args.command == 'sitemaps':
        result = list_sitemaps(prop)
    else:
        end = args.end_date or (datetime.now() - timedelta(days=3)).strftime('%Y-%m-%d')
        start = args.start_date or (datetime.now() - timedelta(days=args.days)).strftime('%Y-%m-%d')
        filters = []
        if args.device:
            filters.append({'dimension': 'device', 'operator': 'equals', 'expression': args.device.upper()})
        if args.country:
            filters.append({'dimension': 'country', 'operator': 'equals', 'expression': args.country.upper()})
        result = query_v2(
            prop, start, end,
            [x.strip() for x in args.dimensions.split(',') if x.strip()],
            args.type, args.page_size, args.limit, filters or None,
        )

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 1 if result.get('error') else 0


if __name__ == '__main__':
    raise SystemExit(main())
