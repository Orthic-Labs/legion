#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { basename, join } from 'node:path';

const SOURCE_EXTENSIONS = new Set(['html', 'htm', 'jsx', 'tsx', 'vue', 'svelte', 'astro', 'css', 'scss', 'sass', 'less']);

function read(root, path) {
  try { return readFileSync(join(root, path), 'utf8'); } catch { return null; }
}
function lineAt(text, index) { return text.slice(0, Math.max(index, 0)).split('\n').length; }
function finding(ruleId, level, message, file, line) {
  return {
    id: `sha256:${createHash('sha256').update(`${ruleId}\0${file}\0${line}`).digest('hex')}`,
    ruleId, level, message, file, line,
  };
}

const RULES = Object.freeze([
  {
    id: 'a11y.image-alt', level: 'error', message: 'Image has no alt text or explicit decorative alt="".',
    pattern: /<img\b(?![^>]*\balt\s*=)[^>]*>/gi,
  },
  {
    id: 'a11y.positive-tabindex', level: 'error', message: 'Positive tabindex overrides natural focus order.',
    pattern: /\btabindex\s*=\s*["']?[1-9][0-9]*["']?/gi,
  },
  {
    id: 'a11y.empty-button-name', level: 'error', message: 'Button appears to have no visible or accessible name.',
    pattern: /<button\b(?![^>]*(?:aria-label|aria-labelledby|title)\s*=)[^>]*>\s*(?:<[^>]+>\s*)*<\/button>/gi,
  },
  {
    id: 'a11y.pointer-only-handler', level: 'warning', message: 'Pointer handler has no matching keyboard/focus handler.',
    pattern: /<(?:div|span)\b(?=[^>]*(?:onClick|@click|v-on:click)=)(?![^>]*(?:onKeyDown|onKeyUp|@keydown|@keyup|role=|tabIndex=))[^>]*>/gi,
  },
  {
    id: 'a11y.hover-without-focus', level: 'warning', message: 'Hover behavior has no corresponding focus behavior.',
    pattern: /<[^>]+\b(?:onMouseOver|onMouseEnter|@mouseover|@mouseenter)=(?![^>]*(?:onFocus|@focus))[^>]*>/gi,
  },
  {
    id: 'a11y.autofocus', level: 'warning', message: 'Autofocus can move focus unexpectedly; require a documented interaction reason.',
    pattern: /\b(?:autoFocus|autofocus)\b/gi,
  },
  {
    id: 'a11y.focus-outline-removed', level: 'error', message: 'Focus outline is removed without a visible replacement proven here.',
    pattern: /(?:outline\s*:\s*(?:none|0)\b|outline-none\b)/gi,
  },
]);

export function runAccessibilitySuite({ root, files }) {
  const findings = [];
  const scanned = [];
  for (const file of [...new Set(files ?? [])].sort()) {
    const ext = basename(file).split('.').at(-1)?.toLowerCase();
    if (!SOURCE_EXTENSIONS.has(ext)) continue;
    const text = read(root, file);
    if (text === null) continue;
    scanned.push(file);
    for (const rule of RULES) {
      rule.pattern.lastIndex = 0;
      for (const match of text.matchAll(rule.pattern)) {
        findings.push(finding(rule.id, rule.level, rule.message, file, lineAt(text, match.index ?? 0)));
      }
    }
    if (['css', 'scss', 'sass', 'less'].includes(ext)
      && /(?:animation\s*:|@keyframes\b)/i.test(text)
      && !/prefers-reduced-motion/i.test(text)) {
      findings.push(finding('a11y.reduced-motion', 'warning', 'Animation exists without a visible prefers-reduced-motion alternative in this stylesheet.', file, 1));
    }
  }
  return {
    provider: 'accessibility.internal-suite', phase: 'runtime', applicable: scanned.length > 0, required: scanned.length > 0,
    status: findings.length ? 'fail' : 'pass', complete: true,
    coverage: { expectedFiles: files?.length ?? 0, scannedFiles: scanned.length, rules: RULES.length + 1, scanned },
    findings, receipts: [], coverageGaps: [], degradation: [],
  };
}
export function analyze({root,projection}={}){const result=runAccessibilitySuite({root,files:(projection?.files??[]).map((file)=>file.path??file)});const zero=result.coverage.expectedFiles===0;return{status:zero?'unproven':result.status,complete:!zero&&result.complete,denominator:{kind:'accessibility-source-files',expected:result.coverage.expectedFiles,examined:result.coverage.scannedFiles},findings:result.findings,coverageGaps:zero?[{kind:'accessibility-denominator-zero'}]:result.coverageGaps};}
