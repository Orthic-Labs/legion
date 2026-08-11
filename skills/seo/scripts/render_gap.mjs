#!/usr/bin/env node
// render_gap.mjs — SEO twin of audit-runtime: detects client-only content invisible to crawlers.
//
// Usage: node seo/scripts/render_gap.mjs --url <url> [--timeout 15000] [--cdp-port 9333]
//
// Fetches the URL twice:
//   1. Raw HTTP GET (plain fetch, no JS) — simulates a non-rendering crawler / Googlebot text-pass
//   2. JS-rendered DOM via raw-CDP headless Chrome/Edge — what a real browser sees
//
// Diffs both for 8 SEO signals and reports what is client-only (invisible to crawlers) or
// server-only (stripped by hydration). Output: JSON to stdout + a one-line human summary.
//
// No Playwright/Puppeteer — raw node:net WebSocket to Chrome DevTools Protocol only.
// No new npm dependencies.
//
// ponytail: diff-heuristic ceiling — text-length delta is character count only; semantic
// similarity, lazy-loaded images, and Shadow DOM slots are outside the diff boundary here.

import { spawn } from 'node:child_process';
import { createConnection, createServer } from 'node:net';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

// ---------- CLI ----------
const args = process.argv.slice(2);
if (args.includes('--help') || args.includes('-h')) {
  console.log(`
render_gap.mjs — Raw-vs-rendered DOM diff for SEO render-gap detection

Usage:
  node seo/scripts/render_gap.mjs --url <url> [options]

Options:
  --url <url>         Target URL (required)
  --timeout <ms>      Page load timeout in ms (default: 15000)
  --cdp-port <port>   CDP port for Chrome/Edge (default: auto)
  --width <px>        Viewport width (default: 1280)
  --height <px>       Viewport height (default: 800)
  --json              Output raw JSON only (default: JSON + summary line)
  --help, -h          Show this help and exit

Output (JSON):
  {
    url, raw_fetch_ms, render_ms,
    signals: {
      title:             { raw, rendered, client_only }
      meta_description:  { raw, rendered, client_only }
      canonical:         { raw, rendered, client_only }
      json_ld_count:     { raw, rendered, client_only, count_delta }
      h1:                { raw, rendered, client_only }
      main_text_length:  { raw, rendered, client_only, delta }
      internal_links:    { raw, rendered, client_only, delta }
      meta_robots:       { raw, rendered, client_only }
    },
    client_only_signals: [...],  // signal names invisible to crawlers
    server_only_signals: [...],  // signal names stripped post-render (rare)
    summary: "one-line human-readable summary"
  }

Notes:
  - "client_only" = present in rendered DOM but absent/shorter in raw HTML
  - "server_only" = present in raw HTML but absent/shorter after JS execution
  - Directly fixes the DD/RH Qwik false "no schema" false-positive: Qwik renders
    schema/meta at runtime, so raw HTML has no JSON-LD; rendered DOM does.
  - Requires Chrome or Edge installed at a standard path.

Exit codes:
  0 = success (even if gaps found)
  1 = error (URL fetch failed, no browser found, CDP error)
  2 = bad arguments
`);
  process.exit(0);
}

const flag = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
const URL_ = flag('--url');
if (!URL_) { console.error('Error: --url <url> is required. Run with --help for usage.'); process.exit(2); }
const TIMEOUT = Number(flag('--timeout', '15000'));
const W = Number(flag('--width', '1280'));
const H = Number(flag('--height', '800'));
const JSON_ONLY = args.includes('--json');

// ---------- WebSocket framing (CDP over raw socket) — copied from audit-runtime.mjs ----------
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
    let mask2; if (masked) { if (buffer.length - pos < 4) break; mask2 = buffer.subarray(pos, pos + 4); pos += 4; }
    if (buffer.length - pos < len) break;
    const payload2 = Buffer.from(buffer.subarray(pos, pos + len));
    if (masked && mask2) for (let i = 0; i < payload2.length; i++) payload2[i] ^= mask2[i % 4];
    frames.push({ opcode, text: payload2.toString('utf8') }); offset = pos + len;
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
async function evalJs(client, expr) {
  const r = await client.send('Runtime.evaluate', { expression: expr, awaitPromise: false, returnByValue: true, timeout: 10000 });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text || 'eval failed');
  return r.result.value;
}

// ---------- browser ----------
function findBrowser() {
  const cands = process.platform === 'win32'
    ? ['C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Microsoft/Edge/Application/msedge.exe']
    : process.platform === 'darwin'
      ? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge', '/Applications/Chromium.app/Contents/MacOS/Chromium']
      : ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/microsoft-edge'];
  const hit = cands.find((p) => existsSync(p));
  if (!hit) throw new Error('No Chrome or Edge found at standard paths. Install Chrome/Edge and retry.');
  return hit;
}
function freePort(start) {
  return new Promise((resolve) => { const s = createServer(); s.listen(start, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); s.on('error', () => resolve(freePort(start + 1))); });
}
async function waitForHttp(url, timeoutMs) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) { try { const r = await fetch(url); if (r.ok) return; } catch {} await wait(200); }
  throw new Error(`CDP endpoint not ready: ${url}`);
}
async function waitForLoad(client, timeoutMs) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try { const ready = await evalJs(client, "document.readyState === 'complete'"); if (ready) return; } catch {}
    await wait(200);
  }
}

// ---------- raw HTML extraction ----------
function extractRaw(html) {
  const lc = html.toLowerCase();
  // title
  const tm = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = tm ? tm[1].trim() : null;
  // meta description
  const dm = html.match(/<meta\s[^>]*name=["']description["'][^>]*content=["']([^"']*)/i)
           || html.match(/<meta\s[^>]*content=["']([^"']*)[^>]*name=["']description["']/i);
  const meta_description = dm ? dm[1].trim() : null;
  // canonical
  const cm = html.match(/<link\s[^>]*rel=["']canonical["'][^>]*href=["']([^"']*)/i)
           || html.match(/<link\s[^>]*href=["']([^"']*)[^>]*rel=["']canonical["']/i);
  const canonical = cm ? cm[1].trim() : null;
  // json-ld count
  const jlds = html.match(/<script[^>]*type=["']application\/ld\+json["'][^>]*>/gi) || [];
  const json_ld_count = jlds.length;
  // h1
  const h1m = html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i);
  const h1 = h1m ? h1m[1].replace(/<[^>]+>/g, '').trim() : null;
  // main text (body text length after stripping tags and scripts)
  const body = html.replace(/<script[\s\S]*?<\/script>/gi, '').replace(/<style[\s\S]*?<\/style>/gi, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  const main_text_length = body.length;
  // internal links (href starting with / or same domain)
  const hrefs = [...html.matchAll(/href=["']([^"'#?]+)/gi)].map(m => m[1]);
  const internal_links = hrefs.filter(h => h.startsWith('/') || h.startsWith(URL_)).length;
  // meta robots
  const rm = html.match(/<meta\s[^>]*name=["']robots["'][^>]*content=["']([^"']*)/i)
           || html.match(/<meta\s[^>]*content=["']([^"']*)[^>]*name=["']robots["']/i);
  const meta_robots = rm ? rm[1].trim() : null;
  return { title, meta_description, canonical, json_ld_count, h1, main_text_length, internal_links, meta_robots };
}

// ---------- CDP DOM extraction ----------
const DOM_EXTRACT = `(() => {
  const title = document.title || null;
  const metaDesc = (document.querySelector('meta[name="description"]') || document.querySelector('meta[name=description]'))?.getAttribute('content') || null;
  const canonical = document.querySelector('link[rel="canonical"]')?.getAttribute('href') || null;
  const jsonLdCount = document.querySelectorAll('script[type="application/ld+json"]').length;
  const h1El = document.querySelector('h1');
  const h1 = h1El ? (h1El.textContent || '').trim() : null;
  const body = (document.body?.innerText || document.body?.textContent || '').replace(/\\s+/g,' ').trim();
  const mainTextLength = body.length;
  const anchors = [...document.querySelectorAll('a[href]')].map(a => a.getAttribute('href') || '');
  const internalLinks = anchors.filter(h => h.startsWith('/') || h.startsWith(window.location.origin)).length;
  const metaRobots = (document.querySelector('meta[name="robots"]'))?.getAttribute('content') || null;
  return { title, meta_description: metaDesc, canonical, json_ld_count: jsonLdCount, h1, main_text_length: mainTextLength, internal_links: internalLinks, meta_robots: metaRobots };
})()`;

// ---------- main ----------
async function main() {
  // 1. Raw fetch
  const rawStart = Date.now();
  let rawHtml;
  try {
    const res = await fetch(URL_, { headers: { 'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)' }, redirect: 'follow', signal: AbortSignal.timeout(TIMEOUT) });
    rawHtml = await res.text();
  } catch (e) {
    console.error(`Error: raw fetch failed — ${e.message}`); process.exit(1);
  }
  const raw_fetch_ms = Date.now() - rawStart;
  const rawSignals = extractRaw(rawHtml);

  // 2. CDP render
  const browser = findBrowser();
  const cdpPort = Number(flag('--cdp-port')) || (await freePort(9333));
  const profile = join(process.env.TEMP || process.env.TMPDIR || '/tmp', `_rg_chrome_${Date.now()}`);
  mkdirSync(profile, { recursive: true });
  const chrome = spawn(browser, [
    '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    `--remote-debugging-port=${cdpPort}`, `--user-data-dir=${profile}`,
    `--window-size=${W},${H}`, 'about:blank',
  ], { windowsHide: true, stdio: 'ignore' });
  chrome.on('error', (e) => { console.error(`Browser spawn error: ${e.message}`); process.exit(1); });

  let renderedSignals;
  const renderStart = Date.now();
  let client;
  try {
    await waitForHttp(`http://127.0.0.1:${cdpPort}/json/version`, 30000);
    const targets = await (await fetch(`http://127.0.0.1:${cdpPort}/json/list`)).json();
    const target = targets.find((t) => t.type === 'page' && t.webSocketDebuggerUrl);
    if (!target) throw new Error('No CDP page target found');
    client = await cdpConnect(target.webSocketDebuggerUrl);
    await client.send('Runtime.enable');
    await client.send('Page.enable');
    await client.send('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: 1, mobile: false });
    await client.send('Page.navigate', { url: URL_ });
    await waitForLoad(client, TIMEOUT);
    await wait(1500); // allow JS frameworks (Qwik, React, Vue) to hydrate
    renderedSignals = await evalJs(client, DOM_EXTRACT);
  } catch (e) {
    console.error(`Error: CDP render failed — ${e.message}`); process.exit(1);
  } finally {
    try { client?.close(); } catch {}
    try { chrome.kill(); } catch {}
  }
  const render_ms = Date.now() - renderStart;

  // 3. Diff
  const signals = {};
  const clientOnly = [];
  const serverOnly = [];

  function diff(key, rawVal, rendVal) {
    const entry = { raw: rawVal, rendered: rendVal, client_only: false, server_only: false };
    if (typeof rawVal === 'number' && typeof rendVal === 'number') {
      entry.delta = rendVal - rawVal;
      entry.count_delta = rendVal - rawVal;
      if (rendVal > rawVal) { entry.client_only = true; clientOnly.push(key); }
      else if (rawVal > rendVal) { entry.server_only = true; serverOnly.push(key); }
    } else {
      const rawHas = rawVal !== null && rawVal !== '' && rawVal !== undefined;
      const rendHas = rendVal !== null && rendVal !== '' && rendVal !== undefined;
      if (rendHas && !rawHas) { entry.client_only = true; clientOnly.push(key); }
      else if (rawHas && !rendHas) { entry.server_only = true; serverOnly.push(key); }
      if (key === 'main_text_length' || key === 'internal_links') {
        entry.delta = (rendVal || 0) - (rawVal || 0);
        if (entry.delta > 200) { if (!entry.client_only) { entry.client_only = true; clientOnly.push(key); } }
        else if (entry.delta < -200) { if (!entry.server_only) { entry.server_only = true; serverOnly.push(key); } }
      }
    }
    signals[key] = entry;
  }

  diff('title',            rawSignals.title,            renderedSignals.title);
  diff('meta_description', rawSignals.meta_description, renderedSignals.meta_description);
  diff('canonical',        rawSignals.canonical,        renderedSignals.canonical);
  diff('json_ld_count',    rawSignals.json_ld_count,    renderedSignals.json_ld_count);
  diff('h1',               rawSignals.h1,               renderedSignals.h1);
  diff('main_text_length', rawSignals.main_text_length, renderedSignals.main_text_length);
  diff('internal_links',   rawSignals.internal_links,   renderedSignals.internal_links);
  diff('meta_robots',      rawSignals.meta_robots,      renderedSignals.meta_robots);

  // 4. Summary
  const total = clientOnly.length + serverOnly.length;
  let summary;
  if (total === 0) {
    summary = `render_gap: ${URL_} — NO render gap detected. All 8 signals match between raw HTML and JS-rendered DOM.`;
  } else {
    const parts = [];
    if (clientOnly.length) parts.push(`client-only (invisible to crawlers): ${clientOnly.join(', ')}`);
    if (serverOnly.length) parts.push(`server-only (stripped post-render): ${serverOnly.join(', ')}`);
    summary = `render_gap: ${URL_} — ${total} gap(s) found. ${parts.join('; ')}.`;
  }

  const report = { url: URL_, raw_fetch_ms, render_ms, signals, client_only_signals: clientOnly, server_only_signals: serverOnly, summary };

  if (JSON_ONLY) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(JSON.stringify(report, null, 2));
    console.log('\n' + summary);
  }
}

main().catch((e) => { console.error(`render_gap.mjs error: ${e.stack || e.message}`); process.exit(1); });
