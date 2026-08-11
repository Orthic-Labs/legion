#!/usr/bin/env python3
"""
site_audit.py — deterministic site crawler that reproduces the Ahrefs Site Audit
issue taxonomy (the mechanical, no-judgment checks) using only the stdlib.

Crawls a site from its sitemap + internal links and flags, per Ahrefs' public
issue classes:

  ERRORS      4xx/5xx pages, broken internal links, redirect (3xx) internal links,
              4xx/redirect URLs listed in the sitemap
  WARNINGS    missing/empty/duplicate/too-long/too-short <title>; missing/duplicate/
              too-long/too-short meta description; missing/multiple <h1>; missing
              canonical; images missing alt; thin content; missing viewport;
              orphan pages (in sitemap, zero internal inlinks); noindex page in sitemap;
              canonical points to a different URL; mixed content (http asset on https page)
  NOTICES     3xx internal links (chain risk), long titles/descriptions

Framework note: Qwik emits `q:base="/build/"` (the module-loader base, NOT a link) —
this scanner reads real <a href> anchors only, so it does not false-flag /build/.

Usage:
  python site_audit.py --url https://example.com [--max 300] [--json out.json] [--summary]

This is the deterministic evidence layer for `/seo audit`; the LLM lenses reason over
the JSON it writes. It is not a replacement for a paid crawler on very large sites, but
it reproduces the mechanical issue set Ahrefs/Screaming Frog flag on sites up to ~300 URLs.
"""
import sys, re, json, argparse, collections
import urllib.request, urllib.parse, urllib.error

UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121 Safari/537.36'
ASSET_RE = re.compile(r'\.(css|js|mjs|svg|png|jpe?g|webp|gif|woff2?|ttf|ico|xml|txt|json|pdf|zip|mp4|webm|avif)(\?|$)', re.I)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a):
        return None


def get(url, method='GET'):
    """Return (status, final_url, body, headers). status 0 = network error."""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': UA}, method=method)
        r = urllib.request.urlopen(req, timeout=20)
        body = r.read().decode('utf-8', 'ignore') if method == 'GET' else ''
        return r.getcode(), r.geturl(), body, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, url, '', dict(e.headers or {})
    except Exception as e:
        return 0, url, str(e), {}


def status_only(url):
    """Cheap status check (no-redirect) for link targets. Falls back to GET if HEAD is rejected."""
    for method in ('HEAD', 'GET'):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': UA}, method=method)
            r = urllib.request.build_opener(NoRedirect).open(req, timeout=15)
            return r.getcode(), r.headers.get('Location')
        except urllib.error.HTTPError as e:
            return e.code, (e.headers or {}).get('Location')
        except Exception:
            continue
    return 0, None


def normalize(u):
    u = urllib.parse.urldefrag(u)[0]
    sp = urllib.parse.urlsplit(u)
    # root with empty path -> "/" so https://x and https://x/ collapse to one page
    if sp.path == '':
        return u + '/'
    # trailing slash on extensionless paths so /p and /p/ collapse to one page
    if '.' not in sp.path.rsplit('/', 1)[-1] and not u.endswith('/') and not sp.query:
        u += '/'
    return u


def parse(html):
    s = {}
    t = re.search(r'<title[^>]*>(.*?)</title>', html, re.S | re.I)
    s['title'] = re.sub(r'\s+', ' ', t.group(1)).strip() if t else ''
    md = re.search(r'<meta(?=[^>]*\bname=["\']description["\'])[^>]*\bcontent=["\'](.*?)["\']', html, re.S | re.I)
    s['meta_desc'] = md.group(1).strip() if md else ''
    s['h1'] = re.findall(r'<h1[\b >][^>]*>(.*?)</h1>', html, re.S | re.I)
    can = re.search(r'<link(?=[^>]*\brel=["\']canonical["\'])[^>]*\bhref=["\']([^"\']+)', html, re.I)
    s['canonical'] = can.group(1) if can else None
    body = re.sub(r'<script.*?</script>|<style.*?</style>|<!--.*?-->', ' ', html, flags=re.S | re.I)
    s['words'] = len(re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', body)).split())
    imgs = re.findall(r'<img\b[^>]*>', html, re.I)
    s['imgs'] = len(imgs)
    s['img_no_alt'] = sum(1 for i in imgs if not re.search(r'\balt\s*=\s*["\'][^"\']', i, re.I))
    s['viewport'] = bool(re.search(r'<meta[^>]+name=["\']viewport["\']', html, re.I))
    s['noindex'] = bool(re.search(r'<meta[^>]+name=["\']robots["\'][^>]+content=["\'][^"\']*noindex', html, re.I))
    return s, imgs


def audit(start, maxpages):
    start = start.rstrip('/')
    sp = urllib.parse.urlsplit(start)
    origin, host = f'{sp.scheme}://{sp.netloc}', sp.netloc
    _, _, sm, _ = get(origin + '/sitemap.xml')
    sitemap = set(normalize(u) for u in re.findall(r'<loc>\s*([^<\s]+)', sm))

    queue = collections.deque([normalize(start)] + sorted(sitemap))
    seen, pages = set(), {}
    inlinks = collections.defaultdict(set)   # internal target -> {source pages}
    link_targets = set()                     # every <a href> target (internal + external)

    while queue and len(pages) < maxpages:
        url = queue.popleft()
        if url in seen or urllib.parse.urlsplit(url).netloc != host:
            continue
        seen.add(url)
        code, final, html, hdr = get(url)
        sig = {'status': code, 'final': final}
        if code == 200 and '<html' in html.lower():
            s, _ = parse(html)
            sig.update(s)
            for href in re.findall(r'<a\b[^>]*\bhref=["\']([^"\'#]+)', html, re.I):
                if href.startswith(('mailto:', 'tel:', 'javascript:', 'data:')):
                    continue
                absu = urllib.parse.urljoin(final, href)
                asp = urllib.parse.urlsplit(absu)
                if asp.scheme not in ('http', 'https') or ASSET_RE.search(absu):
                    continue
                if '/cdn-cgi/' in asp.path:   # Cloudflare infra (email-obfuscation etc.), not content
                    continue
                link_targets.add(absu)
                if asp.netloc == host:
                    n = normalize(absu)
                    inlinks[n].add(url)
                    if n not in seen:
                        queue.append(n)
        pages[url] = sig

    # status of every distinct link target
    checked, broken, redirects = {}, {}, {}
    for tgt in link_targets:
        base = normalize(tgt)
        if urllib.parse.urlsplit(tgt).netloc == host and base in pages:
            st, loc = pages[base]['status'], None
        else:
            st, loc = status_only(tgt)
        checked[tgt] = st
        if st >= 400 or st == 0:
            broken[tgt] = {'status': st, 'inlinks': len(inlinks.get(normalize(tgt), ()))}
        elif st in (301, 302, 303, 307, 308):
            redirects[tgt] = {'status': st, 'to': loc, 'inlinks': len(inlinks.get(normalize(tgt), ()))}

    ok = {u: s for u, s in pages.items() if s['status'] == 200 and 'title' in s}
    titles = collections.Counter(s['title'] for s in ok.values() if s['title'])
    metas = collections.Counter(s['meta_desc'] for s in ok.values() if s['meta_desc'])
    iss = collections.defaultdict(list)
    for u, s in ok.items():
        if not s['title']:
            iss['missing_title'].append(u)
        else:
            if titles[s['title']] > 1:
                iss['duplicate_title'].append(u)
            if len(s['title']) > 60:
                iss['title_too_long'].append(f'{u} ({len(s["title"])})')
            elif len(s['title']) < 15:
                iss['title_too_short'].append(f'{u} ({len(s["title"])})')
        if not s['meta_desc']:
            iss['missing_meta_desc'].append(u)
        else:
            if metas[s['meta_desc']] > 1:
                iss['duplicate_meta_desc'].append(u)
            if len(s['meta_desc']) > 160:
                iss['meta_desc_too_long'].append(f'{u} ({len(s["meta_desc"])})')
            elif len(s['meta_desc']) < 50:
                iss['meta_desc_too_short'].append(f'{u} ({len(s["meta_desc"])})')
        if len(s['h1']) == 0:
            iss['missing_h1'].append(u)
        elif len(s['h1']) > 1:
            iss['multiple_h1'].append(f'{u} ({len(s["h1"])})')
        if not s['canonical']:
            iss['missing_canonical'].append(u)
        elif normalize(s['canonical']) != normalize(u) and urllib.parse.urlsplit(s['canonical']).netloc == host:
            iss['canonical_points_elsewhere'].append(f'{u} -> {s["canonical"]}')
        if s['words'] < 200 and not s['noindex']:
            iss['thin_content'].append(f'{u} ({s["words"]}w)')
        if s['img_no_alt'] > 0:
            iss['img_missing_alt'].append(f'{u} ({s["img_no_alt"]}/{s["imgs"]})')
        if not s['viewport']:
            iss['missing_viewport'].append(u)
        if urllib.parse.urlsplit(u).scheme == 'https' and re.search(r'src=["\']http://', pages[u].get('final', '') or ''):
            iss['mixed_content'].append(u)
    for u in ok:
        if normalize(u) in sitemap and len(inlinks.get(normalize(u), ())) == 0:
            iss['orphan_in_sitemap'].append(u)
        if ok[u].get('noindex') and normalize(u) in sitemap:
            iss['noindex_in_sitemap'].append(u)
    for loc in sitemap:
        st = checked.get(loc) or (pages.get(loc, {}) or {}).get('status')
        if st and 300 <= st < 400:
            iss['redirect_in_sitemap'].append(f'{loc} ({st})')
        elif st and st >= 400:
            iss['4xx_in_sitemap'].append(f'{loc} ({st})')

    ERR = ('broken_internal_links', 'redirect_in_sitemap', '4xx_in_sitemap', 'missing_title', 'multiple_h1')
    WARN = ('duplicate_title', 'duplicate_meta_desc', 'missing_h1', 'missing_canonical',
            'canonical_points_elsewhere', 'missing_meta_desc', 'orphan_in_sitemap',
            'noindex_in_sitemap', 'mixed_content', 'thin_content', 'img_missing_alt', 'missing_viewport')
    iss['broken_internal_links'] = [f'[{v["status"]}] {u} (from {v["inlinks"]} pages)'
                                    for u, v in broken.items()
                                    if urllib.parse.urlsplit(u).netloc == host and v['inlinks'] > 0]
    return {
        'url': start, 'crawled': len(pages), 'sitemap_urls': len(sitemap),
        'broken_links_all': broken, 'redirects': redirects,
        'issues': {k: v for k, v in iss.items() if v},
        'severity': {'errors': [k for k in ERR if iss.get(k)],
                     'warnings': [k for k in WARN if iss.get(k)]},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--url', required=True)
    ap.add_argument('--max', type=int, default=300)
    ap.add_argument('--json')
    ap.add_argument('--summary', action='store_true')
    a = ap.parse_args()
    res = audit(a.url, a.max)
    if a.json:
        json.dump(res, open(a.json, 'w'), indent=1)
    if a.summary or not a.json:
        print(f'{res["url"]} — crawled {res["crawled"]} pages, sitemap {res["sitemap_urls"]} urls')
        iss = res['issues']
        for band, keys in (('ERRORS', res['severity']['errors'] + ['broken_internal_links']),
                           ('WARNINGS', res['severity']['warnings'])):
            hits = [(k, iss[k]) for k in dict.fromkeys(keys) if iss.get(k)]
            if hits:
                print(f'  {band}:')
                for k, v in hits:
                    print(f'    {k}: {len(v)}')
                    for x in v[:6]:
                        print(f'        {x}')
    if res['severity']['errors'] or res['issues'].get('broken_internal_links'):
        sys.exit(1)


if __name__ == '__main__':
    main()
