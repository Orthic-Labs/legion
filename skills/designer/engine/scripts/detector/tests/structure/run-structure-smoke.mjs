#!/usr/bin/env node
/**
 * Smoke test for the website-structure detector rule pack.
 *
 * Serves the four fixtures on an ephemeral local port, scans each through the
 * real URL engine (puppeteer, or the CDP fallback against installed
 * Chrome/Edge), and asserts the exact structure-rule set per fixture.
 *
 * Run: node tools/skills/designer/engine/scripts/detector/tests/structure/run-structure-smoke.mjs
 * Exit 0 = all pass, 1 = mismatch or scan failure.
 */
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { detectUrl } from '../../engines/browser/detect-url.mjs';
import { sweepSite } from '../../engines/site/sweep.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const STRUCTURE_RULES = new Set([
  'cta-below-fold', 'hero-cta-competition', 'headline-word-wall',
  'one-word-lines', 'missing-hero-media', 'hero-viewport-hog',
  'hover-contrast', 'oversized-header',
]);

// fixture -> exact expected structure-rule ids at 1440x900
const EXPECTATIONS = {
  'bad-landing.html': ['cta-below-fold', 'headline-word-wall', 'hero-viewport-hog', 'missing-hero-media', 'one-word-lines'],
  'good-landing.html': [],
  'app-shell.html': [],
  'cta-competition.html': ['hero-cta-competition'],
  'hover-header.html': ['hover-contrast', 'oversized-header'],
};

const server = http.createServer((req, res) => {
  const file = path.join(here, path.basename(new URL(req.url, 'http://x').pathname));
  try {
    const body = fs.readFileSync(file);
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(body);
  } catch {
    res.writeHead(404);
    res.end('not found');
  }
});

await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;

let failed = 0;
try {
  for (const [fixture, expected] of Object.entries(EXPECTATIONS)) {
    const url = `http://127.0.0.1:${port}/${fixture}`;
    const findings = await detectUrl(url, { viewport: { width: 1440, height: 900 } });
    const got = [...new Set(findings.map((f) => f.antipattern).filter((id) => STRUCTURE_RULES.has(id)))].sort();
    const want = [...expected].sort();
    const ok = JSON.stringify(got) === JSON.stringify(want);
    if (!ok) failed += 1;
    console.log(`${ok ? 'PASS' : 'FAIL'} ${fixture}: got [${got.join(', ')}]${ok ? '' : ` want [${want.join(', ')}]`}`);
  }
  // Site sweep: one broken internal link, no privacy/terms links.
  const sweepFindings = await sweepSite(`http://127.0.0.1:${port}/site-index.html`, {});
  const broken = sweepFindings.filter((f) => f.antipattern === 'broken-internal-link').length;
  const missing = sweepFindings.filter((f) => f.antipattern === 'missing-required-page').length;
  const sweepOk = broken === 1 && missing === 2;
  if (!sweepOk) failed += 1;
  console.log(`${sweepOk ? 'PASS' : 'FAIL'} site-sweep: broken=${broken} (want 1), missing-required=${missing} (want 2)`);
} finally {
  server.close();
}

if (failed > 0) {
  console.error(`${failed} fixture(s) failed`);
  process.exit(1);
}
console.log('structure smoke: all fixtures pass');
process.exit(0);
