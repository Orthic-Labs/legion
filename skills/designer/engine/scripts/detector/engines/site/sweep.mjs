/**
 * Site sweep — internal-link integrity and required-page presence.
 *
 * Fetches the target page's HTML, collects same-origin links, verifies each
 * responds (< 400), and checks that the pages a site of this type must have
 * are linked somewhere on the page (nav/footer/body).
 *
 * Static-HTML link collection: fine for SSR/static sites (all of the approving human's).
 * A JS-only SPA that renders its nav client-side will under-report links —
 * the sweep says so in that case rather than passing silently.
 *
 * Findings: `broken-internal-link`, `missing-required-page`.
 */
import { finding } from '../../findings.mjs';

// Required-page profiles. A page "exists" when some same-origin link's href
// or text matches its pattern. `universal` applies to every site type.
const REQUIRED_PAGES = {
  universal: [
    { name: 'privacy policy', pattern: /privacy/i },
    { name: 'terms / T&C', pattern: /terms|conditions|tos\b/i },
  ],
  app: [
    { name: 'pricing', pattern: /pricing|price/i },
    { name: 'download', pattern: /download/i },
  ],
  ecommerce: [
    { name: 'returns/refunds', pattern: /return|refund/i },
    { name: 'shipping', pattern: /shipping|delivery/i },
    { name: 'contact', pattern: /contact/i },
    { name: 'about', pattern: /about/i },
  ],
  content: [
    { name: 'about', pattern: /about/i },
  ],
};

function extractLinks(html, baseUrl) {
  const links = [];
  const re = /<a\b[^>]*href\s*=\s*("([^"]*)"|'([^']*)')[^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const href = (m[2] ?? m[3] ?? '').trim();
    const text = m[4].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    if (!href || href.startsWith('#') || /^(mailto|tel|javascript):/i.test(href)) continue;
    // Cloudflare-injected obfuscation endpoints (email-protection etc.) are
    // not site content and 404 to plain fetches by design.
    if (href.includes('/cdn-cgi/')) continue;
    let resolved;
    try { resolved = new URL(href, baseUrl); } catch { continue; }
    links.push({ href, url: resolved, text });
  }
  return links;
}

async function checkStatus(url, timeoutMs = 15000) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    let res = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: ctl.signal });
    // Some servers reject HEAD; retry those with GET before calling it broken.
    if (res.status >= 400 && res.status !== 404) {
      res = await fetch(url, { method: 'GET', redirect: 'follow', signal: ctl.signal });
    }
    return res.status;
  } catch {
    return 0; // network failure / abort
  } finally {
    clearTimeout(timer);
  }
}

async function sweepSite(url, options = {}) {
  const siteType = options.siteType || null;
  const base = new URL(url);
  const findings = [];

  let html = '';
  try {
    const res = await fetch(url, { redirect: 'follow' });
    html = await res.text();
  } catch (e) {
    findings.push(finding('broken-internal-link', url, `Sweep could not fetch the page itself: ${e.message}`));
    return findings;
  }

  const links = extractLinks(html, url);
  const internal = links.filter((l) => l.url.origin === base.origin);

  if (internal.length === 0) {
    findings.push(finding(
      'missing-required-page',
      url,
      'No same-origin links found in the static HTML — either the page has no internal navigation (a finding in itself) or the nav is rendered client-side and this sweep cannot see it. Verify manually.',
    ));
    return findings;
  }

  // Broken internal links — dedupe by resolved URL, cap the request count.
  const unique = [...new Map(internal.map((l) => [l.url.href.replace(/#.*$/, ''), l])).values()]
    .slice(0, 80);
  const results = await Promise.all(unique.map(async (l) => ({ l, status: await checkStatus(l.url.href) })));
  for (const { l, status } of results) {
    if (status === 0 || status >= 400) {
      findings.push(finding(
        'broken-internal-link',
        url,
        `"${l.text || l.href}" → ${l.url.pathname} responds ${status === 0 ? 'network error' : status}`,
      ));
    }
  }

  // Required pages for the declared profile.
  const profiles = ['universal', ...(siteType && REQUIRED_PAGES[siteType] ? [siteType] : [])];
  for (const profile of profiles) {
    for (const page of REQUIRED_PAGES[profile]) {
      const found = internal.some((l) => page.pattern.test(l.url.pathname) || page.pattern.test(l.text));
      if (!found) {
        findings.push(finding(
          'missing-required-page',
          url,
          `No link to a ${page.name} page found on this page${profile === 'universal' ? '' : ` (required for site-type "${siteType}")`}`,
        ));
      }
    }
  }

  return findings;
}

export { sweepSite, REQUIRED_PAGES };
