#!/usr/bin/env python3
"""Deterministic owned-site SEO crawler.

Crawls sitemap + internal anchors, records mechanical page signals and link status,
and emits evidence rather than an LLM verdict. Designed for bounded audits (~300 URLs).
"""
import argparse
import collections
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121 Safari/537.36'
ASSET_RE = re.compile(r'\.(css|js|mjs|svg|png|jpe?g|webp|gif|woff2?|ttf|ico|xml|txt|json|pdf|zip|mp4|webm|avif)(\?|$)', re.I)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def get(url, method='GET'):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': UA}, method=method)
        r = urllib.request.urlopen(req, timeout=20)
        body = r.read().decode('utf-8', 'ignore') if method == 'GET' else ''
        return r.getcode(), r.geturl(), body, dict(r.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, url, '', dict(exc.headers or {})
    except Exception as exc:
        return 0, url, str(exc), {}


def status_only(url):
    for method in ('HEAD', 'GET'):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': UA}, method=method)
            r = urllib.request.build_opener(NoRedirect).open(req, timeout=15)
            return r.getcode(), r.headers.get('Location')
        except urllib.error.HTTPError as exc:
            return exc.code, (exc.headers or {}).get('Location')
        except Exception:
            continue
    return 0, None


def normalize(url):
    url = urllib.parse.urldefrag(url)[0]
    sp = urllib.parse.urlsplit(url)
    if sp.path == '':
        return url + '/'
    if '.' not in sp.path.rsplit('/', 1)[-1] and not url.endswith('/') and not sp.query:
        url += '/'
    return url


def parse(html):
    sig = {}
    title = re.search(r'<title[^>]*>(.*?)</title>', html, re.S | re.I)
    sig['title'] = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', title.group(1))).strip() if title else ''
    md = re.search(r'<meta(?=[^>]*\bname\s*=\s*["\']description["\'])[^>]*\bcontent\s*=\s*["\'](.*?)["\']', html, re.S | re.I)
    sig['meta_desc'] = md.group(1).strip() if md else ''
    sig['h1'] = re.findall(r'<h1\b[^>]*>(.*?)</h1>', html, re.S | re.I)
    canonical = re.search(r'<link(?=[^>]*\brel\s*=\s*["\'][^"\']*canonical[^"\']*["\'])[^>]*\bhref\s*=\s*["\']([^"\']+)', html, re.I)
    sig['canonical'] = canonical.group(1).strip() if canonical else None
    body = re.sub(r'<script\b.*?</script>|<style\b.*?</style>|<!--.*?-->', ' ', html, flags=re.S | re.I)
    sig['words'] = len(re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', body)).split())
    imgs = re.findall(r'<img\b[^>]*>', html, re.I)
    sig['imgs'] = len(imgs)
    sig['img_no_alt'] = sum(1 for tag in imgs if not re.search(r'\balt\s*=\s*["\'][^"\']*["\']', tag, re.I))
    sig['viewport'] = bool(re.search(r'<meta[^>]+name\s*=\s*["\']viewport["\']', html, re.I))
    sig['noindex'] = bool(re.search(r'<meta[^>]+name\s*=\s*["\']robots["\'][^>]+content\s*=\s*["\'][^"\']*noindex', html, re.I))
    sig['mixed_content'] = bool(re.search(r'\b(?:src|href)\s*=\s*["\']http://', html, re.I))
    return sig, imgs


def discover_sitemaps(origin, robots_text):
    urls = [m.strip() for m in re.findall(r'^\s*Sitemap\s*:\s*(\S+)\s*$', robots_text or '', re.I | re.M)]
    if not urls:
        urls = [origin + '/sitemap.xml']
    return list(dict.fromkeys(urls))


def sitemap_urls(url, seen=None):
    seen = seen or set()
    if url in seen:
        return set()
    seen.add(url)
    code, _, xml, _ = get(url)
    if code != 200:
        return set()
    locs = [x.strip() for x in re.findall(r'<loc>\s*([^<\s]+)', xml, re.I)]
    if '<sitemapindex' in xml.lower():
        out = set()
        for loc in locs[:50]:
            out |= sitemap_urls(loc, seen)
        return out
    return {normalize(x) for x in locs}


def audit(start, maxpages):
    start = start.rstrip('/')
    sp = urllib.parse.urlsplit(start)
    origin, host = f'{sp.scheme}://{sp.netloc}', sp.netloc
    _, _, robots, _ = get(origin + '/robots.txt')
    sitemap = set()
    for sm in discover_sitemaps(origin, robots):
        sitemap |= sitemap_urls(sm)

    queue = collections.deque([normalize(start)] + sorted(sitemap))
    seen, pages = set(), {}
    inlinks = collections.defaultdict(set)
    link_targets = set()

    while queue and len(pages) < maxpages:
        url = queue.popleft()
        if url in seen or urllib.parse.urlsplit(url).netloc != host:
            continue
        seen.add(url)
        code, final, html, headers = get(url)
        sig = {'status': code, 'final': final, 'x_robots_tag': headers.get('X-Robots-Tag') or headers.get('x-robots-tag')}
        if code == 200 and '<html' in html.lower():
            parsed, _ = parse(html)
            if parsed.get('canonical'):
                parsed['canonical'] = urllib.parse.urljoin(final, parsed['canonical'])
            sig.update(parsed)
            for href in re.findall(r'<a\b[^>]*\bhref\s*=\s*["\']([^"\'#]+)', html, re.I):
                if href.startswith(('mailto:', 'tel:', 'javascript:', 'data:')):
                    continue
                absolute = urllib.parse.urljoin(final, href)
                asp = urllib.parse.urlsplit(absolute)
                if asp.scheme not in ('http', 'https') or ASSET_RE.search(absolute) or '/cdn-cgi/' in asp.path:
                    continue
                link_targets.add(absolute)
                if asp.netloc == host:
                    normalized = normalize(absolute)
                    inlinks[normalized].add(url)
                    if normalized not in seen:
                        queue.append(normalized)
        pages[url] = sig

    checked, broken, redirects = {}, {}, {}
    for target in link_targets:
        base = normalize(target)
        if urllib.parse.urlsplit(target).netloc == host and base in pages:
            status, location = pages[base]['status'], None
        else:
            status, location = status_only(target)
        checked[target] = status
        if status >= 400 or status == 0:
            broken[target] = {'status': status, 'inlinks': len(inlinks.get(normalize(target), ())) }
        elif status in (301, 302, 303, 307, 308):
            redirects[target] = {'status': status, 'to': location, 'inlinks': len(inlinks.get(normalize(target), ())) }

    ok = {u: s for u, s in pages.items() if s.get('status') == 200 and 'title' in s}
    titles = collections.Counter(s['title'] for s in ok.values() if s['title'])
    metas = collections.Counter(s['meta_desc'] for s in ok.values() if s['meta_desc'])
    issues = collections.defaultdict(list)
    for url, sig in ok.items():
        if not sig['title']:
            issues['missing_title'].append(url)
        else:
            if titles[sig['title']] > 1: issues['duplicate_title'].append(url)
            if len(sig['title']) > 60: issues['title_too_long'].append(f'{url} ({len(sig["title"])})')
            elif len(sig['title']) < 15: issues['title_too_short'].append(f'{url} ({len(sig["title"])})')
        if not sig['meta_desc']:
            issues['missing_meta_desc'].append(url)
        else:
            if metas[sig['meta_desc']] > 1: issues['duplicate_meta_desc'].append(url)
            if len(sig['meta_desc']) > 160: issues['meta_desc_too_long'].append(f'{url} ({len(sig["meta_desc"])})')
            elif len(sig['meta_desc']) < 50: issues['meta_desc_too_short'].append(f'{url} ({len(sig["meta_desc"])})')
        if len(sig['h1']) == 0: issues['missing_h1'].append(url)
        elif len(sig['h1']) > 1: issues['multiple_h1'].append(f'{url} ({len(sig["h1"])})')
        if not sig['canonical']:
            issues['missing_canonical'].append(url)
        elif normalize(sig['canonical']) != normalize(url) and urllib.parse.urlsplit(sig['canonical']).netloc == host:
            issues['canonical_points_elsewhere'].append(f'{url} -> {sig["canonical"]}')
        noindex = sig['noindex'] or ('noindex' in str(sig.get('x_robots_tag') or '').lower())
        if sig['words'] < 200 and not noindex: issues['thin_content'].append(f'{url} ({sig["words"]}w)')
        if sig['img_no_alt'] > 0: issues['img_missing_alt'].append(f'{url} ({sig["img_no_alt"]}/{sig["imgs"]})')
        if not sig['viewport']: issues['missing_viewport'].append(url)
        if urllib.parse.urlsplit(url).scheme == 'https' and sig.get('mixed_content'): issues['mixed_content'].append(url)
        if normalize(url) in sitemap and len(inlinks.get(normalize(url), ())) == 0: issues['orphan_in_sitemap'].append(url)
        if noindex and normalize(url) in sitemap: issues['noindex_in_sitemap'].append(url)

    for loc in sitemap:
        status = checked.get(loc) or (pages.get(loc, {}) or {}).get('status')
        if status and 300 <= status < 400: issues['redirect_in_sitemap'].append(f'{loc} ({status})')
        elif status and status >= 400: issues['4xx_in_sitemap'].append(f'{loc} ({status})')

    issues['broken_internal_links'] = [f'[{v["status"]}] {u} (from {v["inlinks"]} pages)' for u, v in broken.items() if urllib.parse.urlsplit(u).netloc == host and v['inlinks'] > 0]
    errors = ('broken_internal_links', 'redirect_in_sitemap', '4xx_in_sitemap', 'missing_title', 'multiple_h1', 'noindex_in_sitemap')
    warnings = ('duplicate_title', 'duplicate_meta_desc', 'missing_h1', 'missing_canonical', 'canonical_points_elsewhere', 'missing_meta_desc', 'orphan_in_sitemap', 'mixed_content', 'thin_content', 'img_missing_alt', 'missing_viewport')
    return {
        'url': start,
        'crawled': len(pages),
        'sitemap_urls': len(sitemap),
        'robots_sitemaps': discover_sitemaps(origin, robots),
        'broken_links_all': broken,
        'redirects': redirects,
        'pages': pages,
        'issues': {k: v for k, v in issues.items() if v},
        'severity': {
            'errors': [k for k in errors if issues.get(k)],
            'warnings': [k for k in warnings if issues.get(k)],
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--url', required=True)
    ap.add_argument('--max', type=int, default=300)
    ap.add_argument('--json')
    ap.add_argument('--summary', action='store_true')
    args = ap.parse_args()
    result = audit(args.url, args.max)
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as fh:
            json.dump(result, fh, indent=2)
    if args.summary or not args.json:
        print(f'{result["url"]} — crawled {result["crawled"]} pages, sitemap {result["sitemap_urls"]} urls')
        for band, keys in (('ERRORS', result['severity']['errors']), ('WARNINGS', result['severity']['warnings'])):
            if keys:
                print(f'  {band}:')
                for key in keys:
                    values = result['issues'].get(key, [])
                    print(f'    {key}: {len(values)}')
                    for value in values[:6]: print(f'        {value}')
    return 1 if result['severity']['errors'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
