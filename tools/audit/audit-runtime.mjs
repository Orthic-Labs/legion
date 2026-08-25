#!/usr/bin/env node
// audit-runtime.mjs — the RUNTIME pass for /audit (app-only). Static lenses read code at rest;
// this boots a headless debug browser against a running dev server, sweeps every reachable
// surface, and captures three classes per surface:
//   visual   — screenshot + layout overflow + console errors on load
//   runtime  — JS exceptions + console errors/warnings + (a primary interaction not crashing)
//   perf     — type into the main input and measure scripting cost / long tasks / React commits
//              per keystroke (catches "typing re-renders every tab").
//
// Usage: node audit-runtime.mjs --url http://127.0.0.1:1422/?qa=1 [--out <dir>] [--keys 12]
//        [--surfaces targets.json] [--cdp-port 9333] [--width 1280] [--height 800]
// Output: <out>/runtime.json (findings) + <out>/shot-<surface>.png screenshots.
//
// Surfaces: the entry surface + auto-enumerated tabs/nav-links are tested automatically (SAFE —
// arbitrary buttons are NOT auto-clicked; actions like "Open file…" hang headless on a native dialog).
// To reach button/card-driven views (e.g. an editor behind a "New text" card), pass --surfaces with a
// JSON array of click-targets: [{"label":"editor","text":"New text"}, {"label":"prefs","selector":"#settings-btn"}].
// If nothing typeable is reached the report is marked incomplete/shallow — never a false "clean".//
// Typed degradation: every input/environment shortfall (--url absent, --surfaces unreadable,
// browser/CDP unavailable, app never loads) emits an exact machine-readable report — kind
// 'audit-runtime', status 'unproven', coverageGaps/degradation entries with BOUNDED denominators
// {kind, expected, examined} — written to <out>/runtime.json before exiting:
//   exit 2 = invalid input (no --url), exit 3 = environment failure (browser/CDP/app load).
// A supplied --url with reachable targets is unaffected and launches/captures deterministically.
//
// Reuses the qa.mjs CDP approach (raw node:net WebSocket, zero deps). ponytail: the WS+launch
// plumbing is copied from tools/skills/qa/scripts/qa.mjs deliberately — audit owns its tooling
// and must not depend on / mutate the qa skill; the protocol is stable.

import { spawn } from 'node:child_process';
import { createConnection, createServer } from 'node:net';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync, readFileSync, openSync, realpathSync } from 'node:fs';
import { join, isAbsolute, resolve as resolvePath } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

const args = process.argv.slice(2);
const flag = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
const URL_ = flag('--url');   // absence is handled by typedDegradationExit under the CLI guard
const KEYS = Math.max(1, Number(flag('--keys', '12')));
const W = Number(flag('--width', '1280')), H = Number(flag('--height', '800'));
const OUT = flag('--out', join(process.cwd(), '.audit', 'runtime'));
const PERKEY_MS = Number(flag('--perkey-threshold', '8'));   // scripting ms/keystroke that flags
const CLICK_MS = Number(flag('--perclick-threshold', '100'));   // scripting ms/click that flags (routes/toggles cost more than a keystroke)
const CLICK_COMMITS = Number(flag('--click-commit-burst', '8')); // React commits from ONE click that flags a re-render storm
const LONGTASK_MS = 50;
const SURF_FILE = flag('--surfaces');   // optional JSON [{label, text|selector}] — deep click-targets
const AXE_OVERRIDE = flag('--axe');      // optional explicit path to axe.min.js

// Resolve axe-core source for the deterministic a11y pass. "Use what's present": runs if axe-core is
// resolvable (target's node_modules, this skill's, or --axe path); a clean skip otherwise — never a
// false "accessible". `npm i -D axe-core` in the target enables it.
function loadAxeSource() {
  const candidates = [];
  if (AXE_OVERRIDE) candidates.push(AXE_OVERRIDE);
  for (const base of [import.meta.url, join(process.cwd(), 'x.js')]) {
    try { candidates.push(createRequire(base).resolve('axe-core/axe.min.js')); } catch {}
  }
  for (const p of candidates) { try { return readFileSync(p, 'utf8'); } catch {} }
  return null;
}

// ---------- WebSocket framing (CDP over raw socket) ----------
function makeFrame(text) {
  const payload = Buffer.from(text, 'utf8'); let header;
  if (payload.length < 126) { header = Buffer.alloc(2); header[0] = 0x81; header[1] = 0x80 | payload.length; }
  else if (payload.length < 65536) { header = Buffer.alloc(4); header[0] = 0x81; header[1] = 0x80 | 126; header.writeUInt16BE(payload.length, 2); }
  else { header = Buffer.alloc(10); header[0] = 0x81; header[1] = 0x80 | 127; header.writeBigUInt64BE(BigInt(payload.length), 2); }
  const mask = randomBytes(4), masked = Buffer.alloc(payload.length);
  for (let i = 0; i < payload.length; i++) masked[i] = payload[i] ^ mask[i % 4];
  return Buffer.concat([header, mask, masked]);
}
function readFrames(buffer) {
  const frames = []; let offset = 0;
  while (buffer.length - offset >= 2) {
    const b1 = buffer[offset + 1]; const opcode = buffer[offset] & 0x0f; const masked = (b1 & 0x80) !== 0;
    let len = b1 & 0x7f; let pos = offset + 2;
    if (len === 126) { if (buffer.length - pos < 2) break; len = buffer.readUInt16BE(pos); pos += 2; }
    else if (len === 127) { if (buffer.length - pos < 8) break; len = Number(buffer.readBigUInt64BE(pos)); pos += 8; }
    let mask; if (masked) { if (buffer.length - pos < 4) break; mask = buffer.subarray(pos, pos + 4); pos += 4; }
    if (buffer.length - pos < len) break;
    const payload = Buffer.from(buffer.subarray(pos, pos + len));
    if (masked && mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
    frames.push({ opcode, text: payload.toString('utf8') }); offset = pos + len;
  }
  return { frames, rest: buffer.subarray(offset) };
}
function cdpConnect(wsUrl) {
  return new Promise((resolve, reject) => {
    const u = new URL(wsUrl); const socket = createConnection({ host: u.hostname, port: Number(u.port) || 80 });
    const key = randomBytes(16).toString('base64'); const callbacks = new Map(); const eventHandlers = new Map();
    let id = 0, handshaken = false, buffer = Buffer.alloc(0); socket.setNoDelay(true);
    socket.on('connect', () => socket.write(`GET ${u.pathname}${u.search} HTTP/1.1\r\nHost: ${u.host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`));
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (!handshaken) {
        const idx = buffer.indexOf('\r\n\r\n'); if (idx < 0) return;
        if (!buffer.subarray(0, idx).toString('utf8').includes('101')) { reject(new Error('CDP handshake failed')); socket.destroy(); return; }
        handshaken = true; buffer = buffer.subarray(idx + 4);
        resolve({
          send(method, params = {}) { const cid = ++id; socket.write(makeFrame(JSON.stringify({ id: cid, method, params }))); return new Promise((res, rej) => callbacks.set(cid, { res, rej, method })); },
          on(method, h) { const l = eventHandlers.get(method) || []; l.push(h); eventHandlers.set(method, l); },
          close() { socket.end(); },
        });
      }
      if (!handshaken || buffer.length === 0) return;
      const parsed = readFrames(buffer); buffer = parsed.rest;
      for (const f of parsed.frames) {
        if (f.opcode !== 1) continue; const msg = JSON.parse(f.text);
        if (!msg.id) { const hs = eventHandlers.get(msg.method); if (hs) for (const h of hs) { try { h(msg.params); } catch {} } continue; }
        const cb = callbacks.get(msg.id); if (!cb) continue; callbacks.delete(msg.id);
        if (msg.error) cb.rej(new Error(`${cb.method}: ${msg.error.message}`)); else cb.res(msg.result);
      }
    });
    socket.on('error', reject);
  });
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function evalJs(client, expr, timeoutMs = 10000) {
  const r = await client.send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true, timeout: timeoutMs });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text || 'eval failed');
  return r.result.value;
}
async function metrics(client) {
  const { metrics } = await client.send('Performance.getMetrics');
  const m = Object.fromEntries(metrics.map((x) => [x.name, x.value]));
  return { script: m.ScriptDuration || 0, layout: m.LayoutCount || 0, recalc: m.RecalcStyleCount || 0, task: m.TaskDuration || 0 };
}

// ---------- browser ----------
function findBrowser() {
  const cands = process.platform === 'win32'
    ? ['C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Microsoft/Edge/Application/msedge.exe']
    : process.platform === 'darwin'
      ? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge', '/Applications/Chromium.app/Contents/MacOS/Chromium']
      : ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/microsoft-edge'];
  const hit = cands.find((p) => existsSync(p));
  if (!hit) throw new Error('No Chrome/Edge found for the runtime pass.');
  return hit;
}
function freePort(start) {
  return new Promise((resolve) => { const s = createServer(); s.listen(start, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); s.on('error', () => resolve(freePort(start + 1))); });
}
async function waitForHttp(url, timeoutMs) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) { try { const r = await fetch(url); if (r.ok) return; } catch {} await wait(300); }
  throw new Error(`timed out waiting for ${url}`);
}

// ---------- typed degradation ----------
// Every shortfall below the launch path degrades EXACTLY: one structured gap with a bounded
// denominator ({kind, expected, examined}), persisted to <out>/runtime.json so downstream
// reconcilers see an honest unproven result instead of an exit code alone. Never a false clean.
export function parseSurfacesInput(text) {
  try {
    const parsed = JSON.parse(text);
    if (!Array.isArray(parsed)) return { ok: false, error: '--surfaces must contain a JSON array of {label, text|selector} targets' };
    return { ok: true, targets: parsed.filter((t) => t && typeof t === 'object') };
  } catch (e) { return { ok: false, error: `--surfaces parse failed: ${e.message}` }; }
}
function classifyRuntimeFailure(error) {
  const m = String(error?.message ?? error);
  if (/No Chrome\/Edge found/.test(m)) return 'browser-unavailable';
  if (/timed out waiting for app load/.test(m)) return 'app-load-timeout';
  if (/timed out waiting|CDP|page target|handshake/i.test(m)) return 'cdp-unavailable';
  return 'runtime-execution';
}
function buildDegradedReport(gaps, denominator, extra = {}) {
  return { kind: 'audit-runtime', url: URL_ ?? null, generated_at: new Date().toISOString(),
    status: 'unproven', complete: false, incomplete: true, shallow: false,
    denominator, surfaces_found: denominator.expected, surfaces_tested: denominator.examined, keystrokes: KEYS,
    findings: [], degradation: gaps, coverageGaps: gaps, console_total: 0, a11y_axe: 'not-run', a11y_violations_total: 0, ...extra };
}
function typedDegradationExit(gaps, denominator, exitCode, outDir = OUT) {
  const report = buildDegradedReport(gaps, denominator);
  try { mkdirSync(resolvePath(outDir), { recursive: true }); writeFileSync(join(resolvePath(outDir), 'runtime.json'), JSON.stringify(report, null, 2)); } catch {}
  console.error(JSON.stringify(report, null, 2));
  process.exit(exitCode);
}


// ---------- instrumentation injected before the app loads ----------
const INSTRUMENT = `
(() => {
  window.__lt = [];
  try { new PerformanceObserver(l => { for (const e of l.getEntries()) window.__lt.push(Math.round(e.duration)); }).observe({ type: 'longtask', buffered: true }); } catch (e) {}
  window.__commits = 0; window.__renders = {};
  // best-effort React commit counter via the DevTools hook (zero app changes). Reliable for
  // commit COUNT; per-component is a PerformedWork-flag heuristic and may under/over-count.
  if (!window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
    window.__REACT_DEVTOOLS_GLOBAL_HOOK__ = {
      renderers: new Map(), supportsFiber: true, isDisabled: false,
      inject(r) { this.renderers.set(this.renderers.size + 1, r); return this.renderers.size; },
      onCommitFiberRoot(id, root) {
        window.__commits++;
        try { const seen = new Set(); (function walk(f) { if (!f || seen.has(f)) return; seen.add(f);
          const n = f.type && (f.type.displayName || f.type.name);
          if (n && (f.flags & 1)) window.__renders[n] = (window.__renders[n] || 0) + 1;
          walk(f.child); walk(f.sibling); })(root && root.current); } catch (e) {}
      },
      onCommitFiberUnmount() {}, onPostCommitFiberRoot() {}, checkDCE() {}, isSupportedRenderer: () => true,
    };
  }
  window.__resetPerf = () => { window.__lt = []; window.__commits = 0; window.__renders = {}; };
})();
`;

const FIND_INPUT = `(() => {
  const els = [...document.querySelectorAll('input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([disabled]), textarea:not([disabled]), [contenteditable=true], .cm-content, [role=textbox]')];
  const vis = els.find(el => { const r = el.getBoundingClientRect(); const cs = getComputedStyle(el); return r.width > 20 && r.height > 8 && cs.visibility !== 'hidden' && cs.display !== 'none'; });
  if (!vis) return { ok: false };
  const r = vis.getBoundingClientRect();
  return { ok: true, x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2), tag: vis.tagName.toLowerCase() };
})()`;

const SURFACES = `(() => {
  const out = []; const seen = new Set();
  for (const el of document.querySelectorAll('[role=tab], nav a[href], [data-testid*=tab i], .tab, [role=link]')) {
    const r = el.getBoundingClientRect(); const label = (el.textContent || el.getAttribute('aria-label') || '').trim().slice(0, 40);
    if (r.width < 4 || r.height < 4 || !label || seen.has(label)) continue; seen.add(label);
    out.push({ label, x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2) });
  }
  return out.slice(0, 12);
})()`;

// In-panel click targets for the interaction pass: buttons / toggles / disclosure controls on the
// CURRENT surface — deliberately NOT nav/tabs (those are crawled by SURFACES; clicking them here would
// desync that loop). In-viewport only. DESTRUCTIVE/irreversible controls are excluded by label — a QA
// click must never delete, send, pay, submit, or publish.
const CLICK_TARGETS = `(() => {
  const out = []; const seen = new Set();
  const BAD = /\\b(delete|remove|discard|trash|logout|log ?out|sign ?out|buy|pay|purchase|checkout|order|submit|send|publish|post|confirm|save|apply|reset|clear ?all|deactivate|disable|uninstall|revoke)\\b/i;
  const sel = 'button:not([disabled]), [role=button], [role=switch], [role=checkbox], [aria-expanded], [aria-haspopup], summary, .btn:not([disabled])';
  for (const el of document.querySelectorAll(sel)) {
    const r = el.getBoundingClientRect(); const cs = getComputedStyle(el);
    if (r.width < 8 || r.height < 8 || cs.visibility === 'hidden' || cs.display === 'none') continue;
    if (r.top < 0 || r.left < 0 || r.bottom > innerHeight || r.right > innerWidth) continue;   // in-viewport only
    const label = (el.textContent || el.getAttribute('aria-label') || el.getAttribute('title') || '').trim().slice(0, 40);
    if (!label || seen.has(label) || BAD.test(label)) continue; seen.add(label);
    if (el.closest('form') && /^submit$/i.test(el.getAttribute('type') || '')) continue;        // never trip a form submit
    out.push({ label, x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2) });
  }
  return out.slice(0, 6);
})()`;

// Resolve an operator-named --surfaces target ({selector} CSS, or {text} substring on a clickable)
// to a click point. Used to reach button/card-driven views the safe auto-enum won't touch.
const locate = (spec) => `(() => {
  const sel = ${JSON.stringify(spec.selector || '')}, txt = ${JSON.stringify((spec.text || '').toLowerCase())};
  let el = sel ? document.querySelector(sel) : null;
  if (!el && txt) el = [...document.querySelectorAll('button,a,[role=button],[role=tab],[role=menuitem],[role=link],[tabindex],.card')].find(e => (e.textContent || '').toLowerCase().includes(txt));
  if (!el) return { ok: false };
  try { el.scrollIntoView({ block: 'center' }); } catch (e) {}
  const r = el.getBoundingClientRect();
  if (r.width < 2 || r.height < 2) return { ok: false };
  return { ok: true, x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2) };
})()`;

async function click(client, x, y) {
  await client.send('Input.dispatchMouseEvent', { type: 'mousePressed', x, y, button: 'left', clickCount: 1 });
  await client.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x, y, button: 'left', clickCount: 1 });
}
async function typeKeys(client, text) {
  for (const ch of text) {
    await client.send('Input.dispatchKeyEvent', { type: 'keyDown', text: ch, key: ch });
    await client.send('Input.dispatchKeyEvent', { type: 'keyUp', key: ch });
    await wait(15);
  }
}
function shot(client, file) { return client.send('Page.captureScreenshot', { format: 'png', fromSurface: true }).then((s) => { writeFileSync(file, Buffer.from(s.data, 'base64')); }); }

async function runAxe(client) {
  // Deterministic a11y. No-op (returns null) if axe-core wasn't injected. Runs WCAG 2 A/AA on the
  // current surface; returns a compact violation list or {axeError}.
  const expr = `(async()=>{ if(!window.axe) return null; try{
    const r = await window.axe.run(document, { resultTypes:['violations'], runOnly:{ type:'tag', values:['wcag2a','wcag2aa'] } });
    return r.violations.map(v=>({ id:v.id, impact:v.impact, help:v.help, count:v.nodes.length, target:((v.nodes[0]||{}).target||[])[0]||'', helpUrl:v.helpUrl }));
  } catch(e){ return { axeError:String((e&&e.message)||e) }; } })()`;
  return evalJs(client, expr, 15000).catch(() => null);
}

async function measureSurface(client, name, consoleRef, outDir) {
  const f = { surface: name, flags: [] };
  await evalJs(client, 'window.__resetPerf && window.__resetPerf()').catch(() => {});
  const before = consoleRef.length;
  const file = join(outDir, `shot-${name.replace(/[^a-z0-9]+/gi, '_').slice(0, 40)}.png`);
  try { await shot(client, file); f.screenshot = file; } catch {}
  // visual: layout overflow + how much interactive content rendered (readiness signal)
  try { f.overflow = await evalJs(client, '(() => { const d = document.documentElement; return d.scrollWidth > d.clientWidth + 2; })()'); } catch {}
  if (f.overflow) f.flags.push('horizontal-overflow');
  try { f.interactive = await evalJs(client, INTERACTIVE_COUNT); } catch {}
  // perf: focus the main input and type
  const inp = await evalJs(client, FIND_INPUT).catch(() => ({ ok: false }));
  if (inp?.ok) {
    await click(client, inp.x, inp.y); await wait(120);
    const m0 = await metrics(client);
    await typeKeys(client, 'the quick brown fox'.slice(0, KEYS));
    await wait(350); // let debounced renders settle
    const m1 = await metrics(client);
    const perKeyMs = ((m1.script - m0.script) * 1000) / KEYS;
    const lt = (await evalJs(client, 'window.__lt || []').catch(() => [])) || [];
    const commits = await evalJs(client, 'window.__commits || 0').catch(() => 0);
    const renders = await evalJs(client, '(() => Object.entries(window.__renders||{}).sort((a,b)=>b[1]-a[1]).slice(0,8))()').catch(() => []);
    f.typed = { into: inp.tag, keystrokes: KEYS, perKeyMs: Math.round(perKeyMs * 10) / 10, layoutDelta: m1.layout - m0.layout, recalcDelta: m1.recalc - m0.recalc, longTasksMs: lt.filter((d) => d >= LONGTASK_MS), commits, topRenderers: renders };
    if (perKeyMs > PERKEY_MS) f.flags.push(`expensive-typing: ${f.typed.perKeyMs}ms scripting/keystroke (threshold ${PERKEY_MS})`);
    if (f.typed.longTasksMs.length) f.flags.push(`long-tasks-while-typing: ${f.typed.longTasksMs.join(',')}ms`);
    // commits >> keystrokes, or one component re-rendering on most keystrokes, is the "re-renders everything" smell
    const heavy = renders.filter(([, c]) => c >= KEYS * 0.8);
    if (heavy.length > 3) f.flags.push(`wide-rerender: ${heavy.length} components re-render on ~every keystroke (e.g. ${heavy.slice(0, 3).map(([n, c]) => `${n}:${c}`).join(', ')})`);
  } else {
    f.typed = { note: 'no editable input found on this surface' };
  }
  // perf: click-driven re-render cost — the typing pass only catches keystroke re-renders; tabs,
  // toggles, disclosure controls, and route swaps are the other half. Click a few in-viewport,
  // NON-destructive in-panel controls and measure the React commit burst + scripting per click.
  const clickTargets = (await evalJs(client, CLICK_TARGETS).catch(() => [])) || [];
  if (Array.isArray(clickTargets) && clickTargets.length) {
    await evalJs(client, 'window.__resetPerf && window.__resetPerf()').catch(() => {});   // separate click attribution from typing
    const k0 = await metrics(client);
    const perClick = [];
    const N = Math.min(3, clickTargets.length);
    for (let i = 0; i < N; i++) {
      const t = clickTargets[i];
      const cb = await evalJs(client, 'window.__commits || 0').catch(() => 0);
      try { await click(client, t.x, t.y); } catch {}
      await wait(300);   // let the view swap + debounced renders settle
      const ca = await evalJs(client, 'window.__commits || 0').catch(() => 0);
      perClick.push({ label: t.label, commits: ca - cb });
    }
    // press Escape once to dismiss any transient overlay a click opened, so the outer surface crawl
    // isn't left clicking through a modal.
    try { await client.send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 }); await client.send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 }); await wait(80); } catch {}
    const k1 = await metrics(client);
    const lt = (await evalJs(client, 'window.__lt || []').catch(() => [])) || [];
    const renders = await evalJs(client, '(() => Object.entries(window.__renders||{}).sort((a,b)=>b[1]-a[1]).slice(0,8))()').catch(() => []);
    const avgMs = Math.round(((k1.script - k0.script) * 1000) / N);
    f.clicked = { targets: N, avgScriptMsPerClick: avgMs, perClick, longTasksMs: lt.filter((d) => d >= LONGTASK_MS), topRenderers: renders };
    if (avgMs > CLICK_MS) f.flags.push(`expensive-click: ${avgMs}ms scripting/click (threshold ${CLICK_MS})`);
    if (f.clicked.longTasksMs.length) f.flags.push(`long-tasks-while-clicking: ${f.clicked.longTasksMs.join(',')}ms`);
    // one click causing a burst of commits is the click-side "re-renders everything" smell
    const burst = perClick.filter((p) => p.commits > CLICK_COMMITS);
    if (burst.length) f.flags.push(`heavy-click-rerender: ${burst.slice(0, 3).map((p) => `${p.label}:${p.commits} commits`).join(', ')} (threshold ${CLICK_COMMITS})`);
  } else {
    f.clicked = { note: 'no non-destructive in-panel click targets on this surface' };
  }
  // runtime: console errors that appeared on/after this surface
  f.consoleErrors = consoleRef.slice(before);
  if (f.consoleErrors.length) f.flags.push(`${f.consoleErrors.length} console error/exception(s)`);
  // a11y: deterministic axe pass (no-op if axe-core wasn't injected)
  const axe = await runAxe(client);
  if (Array.isArray(axe) && axe.length) {
    f.a11y = axe;
    const serious = axe.filter((v) => v.impact === 'critical' || v.impact === 'serious').length;
    f.flags.push(`a11y: ${axe.length} axe violation(s)${serious ? `, ${serious} serious+` : ''} (wcag2a/aa)`);
  } else if (axe && axe.axeError) {
    f.flags.push(`a11y: axe error — ${String(axe.axeError).slice(0, 80)}`);
  }
  return f;
}

async function main() {
  const outDir = resolvePath(OUT);          // Chrome needs an absolute --user-data-dir
  mkdirSync(outDir, { recursive: true });
  // Bound denominator before any launch: a supplied --url commits the pass to at least the entry surface.
  const launchBound = { kind: 'runtime-surfaces', expected: URL_ ? 1 : 0, examined: 0 };
  let browser;
  try { browser = findBrowser(); } catch (e) {
    typedDegradationExit([{ kind: 'browser-unavailable', detail: String(e.message), denominator: launchBound }], launchBound, 3, outDir);
  }
  let cdpPort;
  try { cdpPort = Number(flag('--cdp-port')) || (await freePort(9333)); } catch (e) {
    typedDegradationExit([{ kind: 'cdp-unavailable', detail: String(e.message), denominator: launchBound }], launchBound, 3, outDir);
  }
  const profile = join(outDir, `_chrome-${Date.now()}`); mkdirSync(profile, { recursive: true });
  const chromeLogPath = join(outDir, '_chrome.log');
  console.error(`[audit-runtime] launch ${browser} · cdp :${cdpPort} · profile ${profile}`);
  const chrome = spawn(browser, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', `--remote-debugging-port=${cdpPort}`, `--user-data-dir=${profile}`, `--window-size=${W},${H}`, 'about:blank'], { windowsHide: true, stdio: ['ignore', 'ignore', openSync(chromeLogPath, 'w')] });
  chrome.on('error', (e) => console.error(`[audit-runtime] chrome spawn error: ${e.message}`));
  const consoleErrors = []; let client; const findings = [];
  let inflight = 0, lastNet = Date.now();   // network-idle tracking for the readiness gate
  try {
    await waitForHttp(`http://127.0.0.1:${cdpPort}/json/version`, 30000);
    const targets = await (await fetch(`http://127.0.0.1:${cdpPort}/json/list`)).json();
    const target = targets.find((t) => t.type === 'page' && t.webSocketDebuggerUrl);
    if (!target) throw new Error('no CDP page target');
    client = await cdpConnect(target.webSocketDebuggerUrl);
    client.on('Runtime.consoleAPICalled', (p) => { if (p.type === 'error' || p.type === 'warning') consoleErrors.push(`console.${p.type}: ${(p.args || []).map((a) => a.value ?? a.description ?? '').join(' ').slice(0, 200)}`); });
    client.on('Runtime.exceptionThrown', (p) => { const d = p.exceptionDetails || {}; consoleErrors.push(`exception: ${(d.exception?.description || d.text || 'unknown').slice(0, 200)}`); });
    // A click in the interaction pass can trigger a native dialog (confirm/alert/beforeunload) that
    // blocks CDP indefinitely in headless. Auto-dismiss (cancel) every dialog so the pass can't hang.
    client.on('Page.javascriptDialogOpening', () => { client.send('Page.handleJavaScriptDialog', { accept: false }).catch(() => {}); });
    client.on('Network.requestWillBeSent', () => { inflight++; lastNet = Date.now(); });
    const netDone = () => { if (inflight > 0) inflight--; lastNet = Date.now(); };
    client.on('Network.loadingFinished', netDone); client.on('Network.loadingFailed', netDone);
    await client.send('Runtime.enable'); await client.send('Page.enable'); await client.send('Performance.enable'); await client.send('Network.enable');
    await client.send('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: 1, mobile: false });
    await client.send('Page.addScriptToEvaluateOnNewDocument', { source: INSTRUMENT });
    const AXE_SOURCE = loadAxeSource();   // deterministic a11y, if axe-core is resolvable
    if (AXE_SOURCE) await client.send('Page.addScriptToEvaluateOnNewDocument', { source: AXE_SOURCE });
    await client.send('Page.navigate', { url: URL_ });
    await waitForEval(client, "document.readyState !== 'loading' && !!document.body", 30000);
    // A React/Tauri SPA shows only a loader when document.body first exists. Wait for the app to
    // actually render: network quiet AND interactive content present & stable (not just a spinner).
    await waitForAppReady(client, () => inflight, () => lastNet, 15000);

    // surface 0: the loaded surface
    findings.push(await measureSurface(client, 'default', consoleErrors, OUT));
    // Auto-enumerate surfaces — SAFE ones only: tabs + nav links. We deliberately do NOT auto-click
    // arbitrary buttons/cards: actions like "Open file…" launch a native dialog that hangs headless.
    const surfaces = (await evalJs(client, SURFACES).catch(() => [])) || [];
    let tested = 1;
    for (const s of surfaces) {
      try { await click(client, s.x, s.y); await wait(450); findings.push(await measureSurface(client, s.label, consoleErrors, OUT)); tested++; }
      catch (e) { findings.push({ surface: s.label, flags: [`could not test: ${String(e.message).slice(0, 80)}`] }); }
    }
    // Operator-named deep targets (--surfaces): reach button/card-driven views the safe auto-enum
    // can't, e.g. the editor behind "New text". Each {label, text|selector} is clicked from the entry.
    let manual = [];
    let surfacesFileError = null;
    if (SURF_FILE) {
      try {
        const parsed = parseSurfacesInput(readFileSync(SURF_FILE, 'utf8'));
        if (parsed.ok) manual = parsed.targets;
        else surfacesFileError = parsed.error;
      } catch (e) { surfacesFileError = `--surfaces read failed: ${e.message}`; }
      if (surfacesFileError) console.error(`[audit-runtime] ${surfacesFileError}`);
    }
    let unreachableManual = 0;
    for (const spec of manual) {
      const label = spec.label || spec.text || spec.selector || 'target';
      try {
        const loc = await evalJs(client, locate(spec)).catch(() => ({ ok: false }));
        if (!loc.ok) { findings.push({ surface: label, flags: ['could not locate surface (no element matched text/selector)'] }); unreachableManual++; continue; }
        await click(client, loc.x, loc.y); await wait(500);
        findings.push(await measureSurface(client, label, consoleErrors, OUT)); tested++;
      } catch (e) { findings.push({ surface: label, flags: [`could not test: ${String(e.message).slice(0, 80)}`] }); unreachableManual++; }
    }
    const reachable = surfaces.length + manual.length;
    // Honesty #1 — nothing rendered: do NOT report "clean". App likely never mounted (stuck loader /
    // unmocked Tauri IPC in a plain browser). False "clean" is the exact silent-failure this exists to prevent.
    const testedAnything = findings.some((f) => f.typed?.perKeyMs != null || f.clicked?.targets > 0);
    const incomplete = !testedAnything && reachable === 0 && (findings[0]?.interactive ?? 0) < 3;
    if (incomplete && findings[0]) findings[0].flags.push('app-not-ready: no testable input or surfaces rendered (only ' + (findings[0].interactive ?? 0) + ' interactive elements — likely a stuck loader or unmocked IPC). The runtime pass tested NOTHING here; do not read this as clean.');
    // Honesty #2 — app rendered but the entry surface had no input and nothing was navigable. Not clean.
    const shallow = !testedAnything && !incomplete && reachable === 0;
    if (shallow && findings[0]) findings[0].flags.push('shallow-coverage: entry surface has no text input and no tab/nav surfaces were found. Button/card-driven views (e.g. an editor behind "New text") were NOT crawled — pass --surfaces <json> of {label, text|selector} click-targets to reach and perf-test them. NOT a clean bill of health.');
    // Exact typed degradation with BOUNDED denominators for every coverage shortfall.
    const surfacesDenominator = { kind: 'runtime-surfaces', expected: reachable + 1, examined: tested };
    const manualDenominator = { kind: 'manual-surface-targets', expected: manual.length, examined: Math.max(0, manual.length - unreachableManual) };
    const degradation = [];
    if (surfacesFileError) degradation.push({ kind: 'surfaces-file-invalid', detail: String(surfacesFileError).slice(0, 200), denominator: { kind: 'manual-surface-targets', expected: 0, examined: 0 } });
    if (unreachableManual) degradation.push({ kind: 'surface-unreachable', detail: `${unreachableManual} of ${manual.length} operator-supplied surface targets could not be tested`, denominator: manualDenominator });
    if (incomplete && findings[0]) degradation.push({ kind: 'app-not-ready', detail: 'app did not render testable content; runtime pass proved nothing here', denominator: surfacesDenominator });
    else if (shallow && findings[0]) degradation.push({ kind: 'shallow-coverage', detail: 'entry surface only; button/card-driven views were NOT crawled without --surfaces', denominator: surfacesDenominator });
    const a11yTotal = findings.reduce((n, f) => n + (Array.isArray(f.a11y) ? f.a11y.length : 0), 0);
    const flaggedCount = findings.filter((f) => (f.flags || []).length).length;
    const report = { kind: 'audit-runtime', url: URL_, generated_at: new Date().toISOString(), status: flaggedCount || consoleErrors.length ? 'candidates' : 'pass', complete: !incomplete && !shallow && !degradation.length, incomplete, shallow, denominator: surfacesDenominator, surfaces_found: reachable + 1, surfaces_tested: tested, keystrokes: KEYS, findings, degradation, coverageGaps: degradation, console_total: consoleErrors.length, a11y_axe: AXE_SOURCE ? 'ran' : 'skipped (axe-core not installed — npm i -D axe-core to enable deterministic a11y)', a11y_violations_total: a11yTotal };
    writeFileSync(join(OUT, 'runtime.json'), JSON.stringify(report, null, 2));
    // console summary
    const flagged = findings.filter((f) => (f.flags || []).length);
    console.log(`\naudit-runtime → ${join(OUT, 'runtime.json')}`);
    const note = incomplete ? ' · ⚠ INCOMPLETE: app did not render' : (shallow ? ' · ⚠ SHALLOW: only entry surface reached — pass --surfaces' : '');
    const a11yNote = AXE_SOURCE ? ` · a11y: ${a11yTotal} axe violation(s)` : ' · a11y: axe skipped (no axe-core)';
    console.log(`surfaces tested: ${tested}/${reachable + 1} · console errors: ${consoleErrors.length} · flagged surfaces: ${flagged.length}${a11yNote}${note}`);
    for (const f of findings) {
      const perKey = f.typed?.perKeyMs != null ? `${f.typed.perKeyMs}ms/key` : (f.typed?.note ? 'no-input' : '');
      const perClick = f.clicked?.targets ? `${f.clicked.avgScriptMsPerClick}ms/click×${f.clicked.targets}` : '';
      console.log(`  ${(f.surface || '?').padEnd(22)} ${perKey.padEnd(12)} ${perClick.padEnd(16)} ${(f.flags || []).join(' | ') || 'clean'}`);
    }
  } catch (e) {
    // Launch/connect/load failure → exact typed degradation with a bounded denominator (entry surface
    // committed but unexamined). Supplied targets that DO load are unaffected by this path.
    try { client?.close(); } catch {}   // cleanup here: typedDegradationExit exits before finally runs
    try { chrome.kill(); } catch {}
    typedDegradationExit([{ kind: classifyRuntimeFailure(e), detail: String(e?.message ?? e).slice(0, 200), denominator: launchBound }], launchBound, 3, outDir);
  } finally {
    try { client?.close(); } catch {}
    try { chrome.kill(); } catch {}
  }
}
async function waitForEval(client, expr, timeoutMs) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) { try { if (await evalJs(client, `(() => { try { return !!(${expr}); } catch (e) { return false; } })()`)) return; } catch {} await wait(250); }
  throw new Error('timed out waiting for app load');
}
const INTERACTIVE_COUNT = "document.querySelectorAll('button,a[href],input,textarea,select,[role=tab],[role=button],[role=textbox],[role=menuitem],[contenteditable=true]').length";
// SPA readiness: don't measure a loading spinner. Phase 1 = network quiet (no inflight for 600ms).
// Phase 2 = interactive content present (>=3 actionable els) AND stable across two polls. Bounded.
async function waitForAppReady(client, getInflight, getLastNet, timeoutMs) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) { if (getInflight() <= 0 && Date.now() - getLastNet() > 600) break; await wait(150); }
  let prev = -1;
  while (Date.now() < end) {
    const n = await evalJs(client, INTERACTIVE_COUNT).catch(() => 0);
    if (n >= 1 && n === prev) return;   // something rendered and stopped changing (a spinner stays at 0)
    prev = n; await wait(300);
  }
}
// Direct-entrypoint detection with a NORMALIZED, Windows-safe comparison. Exact
// import.meta.url === pathToFileURL(argv[1]) equality is fragile: on Windows drive-letter case,
// short paths, and symlinks can diverge. Resolve both sides through realpath and compare
// case-insensitively on win32; fall back to the raw href check first for the fast common case.
const IS_CLI = (() => {
  try {
    if (!process.argv[1]) return false;
    if (pathToFileURL(resolvePath(process.argv[1])).href === import.meta.url) return true;
    const norm = (href) => { const p = fileURLToPath(href); try { return realpathSync(p); } catch { return p; } };
    const a = norm(import.meta.url);
    const b = norm(pathToFileURL(resolvePath(process.argv[1])).href);
    return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
  } catch { return false; }
})();
if (IS_CLI) {
  if (!URL_) {
    // Exact typed degradation for a missing app URL: bounded denominator (nothing was committed,
    // nothing examined), persisted report, exit 2. Never a bare usage line alone.
    const gap = [{ kind: 'runtime-url-missing', detail: '--url <running dev-server url> required: no app target was audited.', denominator: { kind: 'runtime-surfaces', expected: 0, examined: 0 } }];
    typedDegradationExit(gap, { kind: 'runtime-surfaces', expected: 0, examined: 0 }, 2);
  }
  main().catch((e) => { console.error(`[audit-runtime] ${e.stack || e.message}`); process.exit(1); });
}
