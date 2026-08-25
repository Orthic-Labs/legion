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

// Remotion & other non-DOM media pipelines render video frames, not focusable DOM UI —
// keyboard-focus rules do not apply there. Exclude by path segment or by a remotion
// module import (bare `remotion` or any `@remotion/...` scope).
function isNonDomMediaSource(file, text) {
  if (/(?:^|[\\/])(?:remotion|\.remotion)(?:[\\/]|$)/i.test(String(file))) return true;
  return /(?:from\s*|require\(\s*)["'](?:@remotion\/[^"']*|remotion)["']/.test(text);
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
]);

// ---- contextual focus-outline check ----
// Replaces the old bare regex rule (`outline: none | outline-none` anywhere = error),
// which false-flagged every outline reset even where a visible focus indicator was
// provably restored. An occurrence is now a finding only when the surrounding context
// shows NO replacement:
//   1. same declaration block whose selector matches :focus/:focus-visible also paints a
//      visible style (non-none/0 outline, box-shadow, solid/dashed/dotted border), or
//   2. a :focus/:focus-visible rule elsewhere in the same file restores one (the accepted
//      global reset + restore pattern), or
//   3. Tailwind pairing on the same element: `outline-none` next to a focus-visible
//      ring/shadow/border/underline utility.
const OUTLINE_RULE = Object.freeze({
  id: 'a11y.focus-outline-removed', level: 'error',
  message: 'Focus outline is removed without a visible replacement proven here.',
});
const OUTLINE_REMOVAL_RE = /(?:\boutline\s*:\s*(?:none|0)\b|(?<![\w-])outline-none\b)/gi;
const BLOCK_RE = /([^{}]+)\{([^{}]*)\}/g;
const FOCUS_SELECTOR_RE = /:(?:focus-visible|focus)\b/i;
const VISIBLE_FOCUS_STYLE_RE = /(?:outline(?:-color|-width|-style)?\s*:\s*(?!\s*(?:none|0)\b)|box-shadow\s*:\s*(?!\s*none\b)|border(?:-color|-width)?\s*:[^;}]*(?:solid|dashed|dotted))/i;

function hasVisibleFocusRule(text) {
  for (const m of text.matchAll(BLOCK_RE)) {
    if (FOCUS_SELECTOR_RE.test(m[1]) && VISIBLE_FOCUS_STYLE_RE.test(m[2])) return true;
  }
  return false;
}
function tailwindFocusReplacement(windowText) {
  for (const m of windowText.matchAll(/\bfocus(?:-visible)?[:-]([\w[\].:-]+)/gi)) {
    const util = m[1];
    if (/^(?:ring|shadow|underline)/.test(util)) return true;
    if (/^outline(?![\-:]?(?:none|hidden|transparent))/.test(util)) return true;
    if (/^border(?![\-:]?(?:0|none|transparent))/.test(util)) return true;
  }
  return false;
}
function hasLocalFocusReplacement(text, index) {
  const start = Math.max(0, index - 400);
  const windowText = text.slice(start, Math.min(text.length, index + 400));
  if (tailwindFocusReplacement(windowText)) return true;
  for (const m of windowText.matchAll(BLOCK_RE)) {
    if (FOCUS_SELECTOR_RE.test(m[1]) && VISIBLE_FOCUS_STYLE_RE.test(m[2])) return true;
  }
  return false;
}
function collectOutlineFindings(text, file, findings) {
  const globalRestore = hasVisibleFocusRule(text);
  OUTLINE_REMOVAL_RE.lastIndex = 0;
  for (const match of text.matchAll(OUTLINE_REMOVAL_RE)) {
    if (!globalRestore && !hasLocalFocusReplacement(text, match.index ?? 0)) {
      findings.push(finding(OUTLINE_RULE.id, OUTLINE_RULE.level, OUTLINE_RULE.message, file, lineAt(text, match.index ?? 0)));
    }
  }
}

export function runAccessibilitySuite({ root, files }) {
  const findings = [];
  const scanned = [];
  for (const file of [...new Set(files ?? [])].sort()) {
    const ext = basename(file).split('.').at(-1)?.toLowerCase();
    if (!SOURCE_EXTENSIONS.has(ext)) continue;
    const text = read(root, file);
    if (text === null) continue;
    if (isNonDomMediaSource(file, text)) continue; // Remotion / non-DOM media — out of scope for DOM focus rules
    scanned.push(file);
    for (const rule of RULES) {
      rule.pattern.lastIndex = 0;
      for (const match of text.matchAll(rule.pattern)) {
        findings.push(finding(rule.id, rule.level, rule.message, file, lineAt(text, match.index ?? 0)));
      }
    }
    collectOutlineFindings(text, file, findings);
    if (['css', 'scss', 'sass', 'less'].includes(ext)
      && /(?:animation\s*:|@keyframes\b)/i.test(text)
      && !/prefers-reduced-motion/i.test(text)) {
      findings.push(finding('a11y.reduced-motion', 'warning', 'Animation exists without a visible prefers-reduced-motion alternative in this stylesheet.', file, 1));
    }
  }
  return {
    provider: 'accessibility.internal-suite', phase: 'runtime', applicable: scanned.length > 0, required: scanned.length > 0,
    status: findings.length ? 'fail' : 'pass', complete: true,
    coverage: { expectedFiles: files?.length ?? 0, scannedFiles: scanned.length, rules: RULES.length + 2, scanned },
    findings, receipts: [], coverageGaps: [], degradation: [],
  };
}
export function analyze({root,projection}={}){const result=runAccessibilitySuite({root,files:(projection?.files??[]).map((file)=>file.path??file)});const zero=result.coverage.expectedFiles===0;return{status:zero?'unproven':result.status,complete:!zero&&result.complete,denominator:{kind:'accessibility-source-files',expected:result.coverage.expectedFiles,examined:result.coverage.scannedFiles},findings:result.findings,coverageGaps:zero?[{kind:'accessibility-denominator-zero'}]:result.coverageGaps};}
