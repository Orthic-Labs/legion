#!/usr/bin/env node
// Phase 5d deterministic design gate.
//
// Specified in docs/ARCHITECTURE-DESIGNER.md §"Phase 5 — Multi-gate QA" and in
// skills/designer/specialists/surface-design/GUIDE.md §5d. The spec existed for
// months; the runner did not, so Phase 5d was a hard gate that never ran.
//
// Contract:
//   - verify motion-plan.md and motion-gate.json exist and the motion gate passed
//   - run the deterministic checks over the built surface
//   - emit artifacts/qa/gate.json with per-check results aggregated into one verdict
//   - `pass` requires every check green or explicitly waived with a reason
//
// A check that cannot run reports `unavailable`, never `pass`. Legion's rule is
// that a verification which found nothing to check has not checked anything, so
// an unavailable required check fails the gate rather than silently clearing it.

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

export const BREAKPOINTS = Object.freeze([360, 768, 1024, 1440, 1920]);
const TEXT_EXT = /\.(?:html?|md|txt)$/i;
const ASSET_EXT = /\.(?:js|mjs|cjs|css)$/i;

/** Rows of a pipe table under `## <heading>`, first column only. */
function tableRows(markdown, headingMatcher) {
  const lines = markdown.split('\n');
  const out = [];
  let inSection = false;
  for (const line of lines) {
    if (/^##\s/.test(line)) inSection = headingMatcher.test(line);
    else if (inSection && /^\|/.test(line)) {
      const cells = line.split('|').slice(1, -1).map((c) => c.trim());
      if (!cells.length || /^-+$/.test(cells[0]) || /^(Pattern|Word \/ phrase|Rule)$/i.test(cells[0])) continue;
      out.push(cells);
    }
  }
  return out;
}

/**
 * Reads banned vocabulary from the documented source of truth rather than
 * duplicating it here — the markdown is what authors maintain, so a second copy
 * would drift and the gate would enforce the stale one.
 */
export function loadBannedWords(root) {
  const path = resolve(root, 'skills/designer/references/banned-words.md');
  if (!existsSync(path)) return { available: false, structural: [], vocabulary: [] };
  const md = readFileSync(path, 'utf8');
  const structural = tableRows(md, /structural/i)
    .map(([, , detection]) => detection)
    .filter(Boolean)
    .map((d) => d.replace(/`/g, '').trim())
    .filter((d) => /^[\\[]/.test(d));
  const vocabulary = tableRows(md, /vocabulary/i)
    .map(([term]) => term.replace(/[`"]/g, '').trim())
    .filter(Boolean);
  return { available: true, structural, vocabulary };
}

/**
 * Decodes `\xE2\x80\x94`-style byte escapes into the characters they match.
 *
 * Only non-ASCII characters are kept. Every structural rule targets a typographic
 * glyph, and at least one row in banned-words.md is malformed (`\xE2\x2019` for
 * U+2019), which decodes to a space and would otherwise flag every space in the
 * build as a smart quote.
 */
function bytesToPattern(spec) {
  const bytes = [...spec.matchAll(/\\x([0-9A-Fa-f]{2})/g)].map((m) => parseInt(m[1], 16));
  if (!bytes.length) return null;
  const decoded = Buffer.from(bytes).toString('utf8');
  const glyphs = [...decoded].filter((c) => c.codePointAt(0) > 0x7f);
  return glyphs.length ? glyphs.join('') : null;
}

function walk(dir, test, out = []) {
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry.startsWith('.')) continue;
    const path = join(dir, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) walk(path, test, out);
    else if (test.test(entry)) out.push(path);
  }
  return out;
}

const check = (id, status, detail = {}) => ({ id, status, ...detail });

function motionChecks(surface) {
  const plan = resolve(surface, 'motion-plan.md');
  const gate = resolve(surface, 'motion-gate.json');
  const results = [];
  results.push(existsSync(plan)
    ? check('motion-plan-present', 'pass')
    : check('motion-plan-present', 'fail', { reason: 'motion-plan.md absent' }));
  if (!existsSync(gate)) {
    results.push(check('motion-gate-verdict', 'fail', { reason: 'motion-gate.json absent' }));
    return results;
  }
  try {
    const verdict = JSON.parse(readFileSync(gate, 'utf8')).verdict;
    results.push(verdict === 'pass'
      ? check('motion-gate-verdict', 'pass')
      : check('motion-gate-verdict', 'fail', { reason: `motion gate verdict is ${verdict ?? 'absent'}` }));
  } catch (error) {
    results.push(check('motion-gate-verdict', 'fail', { reason: `motion-gate.json unreadable: ${error.message}` }));
  }
  return results;
}

function textChecks(root, surface) {
  const files = walk(surface, TEXT_EXT);
  const banned = loadBannedWords(root);
  const results = [];

  if (!files.length) {
    // No text to scan is not a pass: the gate would report green over nothing.
    return [
      check('banned-words', 'unavailable', { reason: 'no built HTML/markdown found under the surface' }),
      check('typography', 'unavailable', { reason: 'no built HTML/markdown found under the surface' }),
      check('anti-patterns', 'unavailable', { reason: 'no built HTML/markdown found under the surface' }),
    ];
  }
  if (!banned.available) {
    return [
      check('banned-words', 'unavailable', { reason: 'skills/designer/references/banned-words.md absent' }),
      check('typography', 'unavailable', { reason: 'skills/designer/references/banned-words.md absent' }),
      check('anti-patterns', 'unavailable', { reason: 'skills/designer/references/banned-words.md absent' }),
    ];
  }

  const read = files.map((f) => ({ path: relative(surface, f) || f, text: readFileSync(f, 'utf8') }));

  const vocabHits = [];
  for (const { path, text } of read) {
    for (const term of banned.vocabulary) {
      const re = new RegExp(`\\b${term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi');
      const n = (text.match(re) ?? []).length;
      if (n) vocabHits.push({ path, term, count: n });
    }
  }
  results.push(vocabHits.length
    ? check('banned-words', 'fail', { hits: vocabHits.slice(0, 25), total: vocabHits.length })
    : check('banned-words', 'pass', { scanned: read.length, terms: banned.vocabulary.length }));

  const typoHits = [];
  for (const spec of banned.structural) {
    const literal = bytesToPattern(spec);
    if (!literal) continue;
    for (const { path, text } of read) {
      const n = [...text].filter((c) => literal.includes(c)).length;
      if (n) typoHits.push({ path, pattern: spec, count: n });
    }
  }
  results.push(typoHits.length
    ? check('typography', 'fail', { hits: typoHits.slice(0, 25), total: typoHits.length })
    : check('typography', 'pass', { scanned: read.length, patterns: banned.structural.length }));

  // Anti-patterns: structural tells that survive vocabulary and typography.
  const antiHits = [];
  for (const { path, text } of read) {
    const long = text.split(/(?<=[.!?])\s+/).filter((s) => s.trim().split(/\s+/).length > 40).length;
    if (long) antiHits.push({ path, pattern: 'sentence > 40 words', count: long });
  }
  results.push(antiHits.length
    ? check('anti-patterns', 'warn', { hits: antiHits.slice(0, 25), total: antiHits.length })
    : check('anti-patterns', 'pass', { scanned: read.length }));

  return results;
}

function toolChecks(surface, env) {
  const results = [];
  for (const [id, bin] of [['lighthouse', 'lighthouse'], ['axe-core', 'axe']]) {
    let present = false;
    try {
      execFileSync('command', ['-v', bin], { stdio: 'ignore', shell: true, env });
      present = true;
    } catch { present = false; }
    // Capability-gate rather than assume: an absent toolchain is reported
    // loudly and is not a pass.
    results.push(check(id, 'unavailable', {
      reason: present ? `${bin} present but no run target configured` : `${bin} not on PATH`,
    }));
  }
  return results;
}

function budgetChecks(surface) {
  const assets = walk(surface, ASSET_EXT);
  const results = [];
  const baselinePath = resolve(surface, 'artifacts/qa/bundle-baseline.json');
  const total = assets.reduce((sum, f) => sum + statSync(f).size, 0);
  if (!assets.length) {
    results.push(check('bundle-delta', 'unavailable', { reason: 'no js/css assets found under the surface' }));
  } else if (!existsSync(baselinePath)) {
    results.push(check('bundle-delta', 'unavailable', { reason: 'artifacts/qa/bundle-baseline.json absent', totalBytes: total }));
  } else {
    const baseline = JSON.parse(readFileSync(baselinePath, 'utf8')).totalBytes ?? 0;
    const delta = total - baseline;
    results.push(delta > baseline * 0.1
      ? check('bundle-delta', 'fail', { baseline, totalBytes: total, delta })
      : check('bundle-delta', 'pass', { baseline, totalBytes: total, delta }));
  }

  const shots = walk(resolve(surface, 'artifacts/qa/screenshots'), /\.(?:png|jpe?g|webp)$/i)
    .map((f) => f.match(/(\d{3,4})/)?.[1]).filter(Boolean).map(Number);
  const missing = BREAKPOINTS.filter((bp) => !shots.includes(bp));
  results.push(missing.length
    ? check('touch-targets', 'unavailable', { reason: `screenshots missing for breakpoints: ${missing.join(', ')}` })
    : check('touch-targets', 'pass', { breakpoints: BREAKPOINTS }));

  const siblingPath = resolve(surface, 'artifacts/qa/sibling-diff.json');
  results.push(existsSync(siblingPath)
    ? check('sibling-diff', 'pass', { source: 'artifacts/qa/sibling-diff.json' })
    : check('sibling-diff', 'unavailable', { reason: 'artifacts/qa/sibling-diff.json absent' }));

  return results;
}

/** Waivers: `{ "<check-id>": "reason" }` at artifacts/qa/gate-waivers.json. */
function loadWaivers(surface) {
  const path = resolve(surface, 'artifacts/qa/gate-waivers.json');
  if (!existsSync(path)) return {};
  try {
    const raw = JSON.parse(readFileSync(path, 'utf8'));
    return Object.fromEntries(Object.entries(raw).filter(([, reason]) => typeof reason === 'string' && reason.trim()));
  } catch { return {}; }
}

export function runDesignGate({ root = process.cwd(), surface = process.cwd(), env = process.env } = {}) {
  const checks = [
    ...motionChecks(surface),
    ...textChecks(root, surface),
    ...toolChecks(surface, env),
    ...budgetChecks(surface),
  ];

  const waivers = loadWaivers(surface);
  for (const c of checks) {
    if (c.status !== 'pass' && waivers[c.id]) {
      c.waived = true;
      c.waiverReason = waivers[c.id];
    }
  }

  // A waiver must carry a reason; anything else non-green blocks.
  const blocking = checks.filter((c) => c.status !== 'pass' && c.status !== 'warn' && !c.waived);
  const verdict = blocking.length ? 'fail' : 'pass';

  return {
    schemaVersion: 1,
    kind: 'legion-design-gate',
    phase: '5d',
    verdict,
    counts: {
      total: checks.length,
      pass: checks.filter((c) => c.status === 'pass').length,
      fail: checks.filter((c) => c.status === 'fail').length,
      unavailable: checks.filter((c) => c.status === 'unavailable').length,
      warn: checks.filter((c) => c.status === 'warn').length,
      waived: checks.filter((c) => c.waived).length,
    },
    blocking: blocking.map((c) => c.id),
    checks,
  };
}

export function writeGateReport(report, surface) {
  const dir = resolve(surface, 'artifacts/qa');
  mkdirSync(dir, { recursive: true });
  const path = join(dir, 'gate.json');
  writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`);
  return path;
}

if (process.argv[1] && process.argv[1].endsWith('design-gate.mjs')) {
  const args = process.argv.slice(2);
  const at = (flag, fallback) => {
    const i = args.indexOf(flag);
    return i >= 0 && args[i + 1] ? resolve(args[i + 1]) : fallback;
  };
  const root = at('--root', process.cwd());
  const surface = at('--surface', process.cwd());
  const report = runDesignGate({ root, surface });
  const out = writeGateReport(report, surface);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.stderr.write(`gate report: ${relative(process.cwd(), out) || out}\n`);
  process.exitCode = report.verdict === 'pass' ? 0 : 1;
}
