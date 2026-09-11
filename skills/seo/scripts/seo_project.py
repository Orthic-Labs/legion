#!/usr/bin/env python3
"""Legion SEO project state, provider doctor, budget preflight and cache helpers.

Secrets never belong in project state. JSON is written to ``site.yaml`` because JSON is a
valid YAML 1.2 subset and keeps this utility dependency-free.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATE_DIR = Path('.legion') / 'seo'
SITE_FILE = 'site.yaml'
PROVIDER_ENV = {
    'google_api': ('GOOGLE_API_KEY',),
    'google_oauth_or_service': ('GOOGLE_APPLICATION_CREDENTIALS',),
    'gsc_property': ('GSC_PROPERTY',),
    'ga4_property': ('GA4_PROPERTY_ID',),
    'bing_webmaster': ('BING_API_KEY',),
    'indexnow': ('INDEXNOW_KEY',),
    'dataforseo': ('DATAFORSEO_LOGIN', 'DATAFORSEO_PASSWORD'),
}
REQUIRED_STATE_DIRS = (
    'strategy', 'baselines', 'gsc', 'ga4', 'bing', 'ai-visibility', 'crawls',
    'keywords', 'rank-tracking', 'competitors', 'backlinks', 'briefs',
    'interventions', 'reports', 'cache',
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def root_path(root: str | Path) -> Path:
    return Path(root).resolve()


def state_path(root: str | Path) -> Path:
    return root_path(root) / STATE_DIR


def load_site(root: str | Path = '.') -> dict[str, Any]:
    path = state_path(root) / SITE_FILE
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f'invalid project state {path}: {exc}') from exc


def save_site(data: dict[str, Any], root: str | Path = '.') -> Path:
    path = state_path(root) / SITE_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return path


def setup_project(root: str | Path, *, domain: str, market: str, language: str,
                  gsc_property: str | None = None, ga4_property: str | None = None,
                  bing_site: str | None = None, currency: str | None = None,
                  devices: list[str] | None = None) -> dict[str, Any]:
    base = state_path(root)
    base.mkdir(parents=True, exist_ok=True)
    for name in REQUIRED_STATE_DIRS:
        (base / name).mkdir(exist_ok=True)
    existing = load_site(root)
    project = {
        **existing,
        'schema_version': 1,
        'domain': domain,
        'market': market,
        'language': language,
        'currency': currency or existing.get('currency'),
        'devices': devices or existing.get('devices') or ['desktop', 'mobile'],
        'properties': {
            **(existing.get('properties') or {}),
            'gsc': gsc_property or (existing.get('properties') or {}).get('gsc'),
            'ga4': ga4_property or (existing.get('properties') or {}).get('ga4'),
            'bing': bing_site or (existing.get('properties') or {}).get('bing'),
        },
        'updated_at': utc_now(),
    }
    project.setdefault('goals', [])
    project.setdefault('primary_conversions', [])
    project.setdefault('secondary_conversions', [])
    project.setdefault('competitors', {'business': [], 'serp': [], 'generative': [], 'backlink': []})
    project.setdefault('important_page_families', [])
    project.setdefault('risk_flags', [])
    save_site(project, root)
    return project


def env_state(names: tuple[str, ...]) -> str:
    values = [os.environ.get(name) for name in names]
    if all(values):
        return 'present'
    if any(values):
        return 'partial'
    return 'absent'


def doctor(root: str | Path = '.') -> dict[str, Any]:
    site = load_site(root)
    providers = {name: {'state': env_state(envs), 'env': list(envs)} for name, envs in PROVIDER_ENV.items()}
    state = state_path(root)
    checks = {
        'project_state': 'present' if site else 'absent',
        'state_dir_writable': os.access(state if state.exists() else state.parent, os.W_OK),
        'python': sys.version.split()[0],
    }
    missing_mapping = []
    if site:
        props = site.get('properties') or {}
        for key in ('gsc', 'ga4', 'bing'):
            if not props.get(key):
                missing_mapping.append(key)
    return {
        'checked_at': utc_now(),
        'root': str(root_path(root)),
        'domain': site.get('domain'),
        'market': site.get('market'),
        'language': site.get('language'),
        'providers': providers,
        'checks': checks,
        'missing_property_mappings': missing_mapping,
        'secrets_exposed': False,
    }


def cache_key(provider: str, capability: str, target: str, *, country: str = '', language: str = '',
              device: str = '', freshness_class: str = '') -> str:
    payload = json.dumps({
        'provider': provider, 'capability': capability, 'target': target,
        'country': country, 'language': language, 'device': device,
        'freshness_class': freshness_class,
    }, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def cache_put(root: str | Path, key: str, value: dict[str, Any]) -> Path:
    path = state_path(root) / 'cache' / f'{key}.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    envelope = {'stored_at': utc_now(), 'value': value}
    path.write_text(json.dumps(envelope, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return path


def cache_get(root: str | Path, key: str) -> dict[str, Any] | None:
    path = state_path(root) / 'cache' / f'{key}.json'
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


@dataclass(frozen=True)
class PlannedCall:
    provider: str
    capability: str
    count: int
    estimated_unit_cost_usd: float = 0.0
    cache_hits: int = 0

    @property
    def billable_count(self) -> int:
        return max(0, self.count - self.cache_hits)

    @property
    def estimated_cost_usd(self) -> float:
        return round(self.billable_count * self.estimated_unit_cost_usd, 6)


def preflight(calls: list[PlannedCall], ceiling_usd: float | None = None) -> dict[str, Any]:
    total = round(sum(c.estimated_cost_usd for c in calls), 6)
    status = 'ok' if ceiling_usd is None or total <= ceiling_usd else 'needs_authority'
    return {
        'status': status,
        'estimated_paid_cost_usd': total,
        'ceiling_usd': ceiling_usd,
        'calls': [asdict(c) | {'billable_count': c.billable_count, 'estimated_cost_usd': c.estimated_cost_usd} for c in calls],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description='Legion SEO project state and provider doctor')
    ap.add_argument('--root', default='.')
    sub = ap.add_subparsers(dest='command', required=True)

    p_setup = sub.add_parser('setup')
    p_setup.add_argument('--domain', required=True)
    p_setup.add_argument('--market', required=True)
    p_setup.add_argument('--language', required=True)
    p_setup.add_argument('--currency')
    p_setup.add_argument('--gsc-property')
    p_setup.add_argument('--ga4-property')
    p_setup.add_argument('--bing-site')
    p_setup.add_argument('--devices', default='desktop,mobile')

    sub.add_parser('doctor')

    p_key = sub.add_parser('cache-key')
    p_key.add_argument('--provider', required=True)
    p_key.add_argument('--capability', required=True)
    p_key.add_argument('--target', required=True)
    p_key.add_argument('--country', default='')
    p_key.add_argument('--language', default='')
    p_key.add_argument('--device', default='')
    p_key.add_argument('--freshness-class', default='')

    args = ap.parse_args()
    if args.command == 'setup':
        out = setup_project(
            args.root, domain=args.domain, market=args.market, language=args.language,
            currency=args.currency, gsc_property=args.gsc_property,
            ga4_property=args.ga4_property, bing_site=args.bing_site,
            devices=[x.strip() for x in args.devices.split(',') if x.strip()],
        )
    elif args.command == 'doctor':
        out = doctor(args.root)
    else:
        out = {'cache_key': cache_key(args.provider, args.capability, args.target,
                                      country=args.country, language=args.language,
                                      device=args.device, freshness_class=args.freshness_class)}
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
