/**
 * CDP fallback for URL scanning — no puppeteer required.
 *
 * Launches an installed Chrome/Edge headless with a DevTools port, injects the
 * same detect-antipatterns-browser.js bundle, and collects serialized findings
 * through raw CDP (WebSocket client adapted from tools/skills/qa/scripts/qa.mjs).
 * Used automatically by detect-url.mjs when `import('puppeteer')` fails, so a
 * machine without puppeteer still gets real rendered-geometry checks instead of
 * silently degrading to static scanning.
 *
 * Not covered in this mode: the screenshot-based visual-contrast fallback lane
 * (puppeteer-only). Everything impeccableDetect measures in-page runs normally.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createConnection } from 'node:net';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { finding } from '../../findings.mjs';
import { filterByProviders } from '../../registry/antipatterns.mjs';

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function findBrowserExecutable() {
  const override = process.env.CHROME_PATH || process.env.QA_BROWSER;
  if (override) {
    if (!fs.existsSync(override)) throw new Error(`CHROME_PATH/QA_BROWSER set but not found: ${override}`);
    return override;
  }
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const candidates = process.platform === 'win32'
    ? [
        path.join(process.env.ProgramFiles || '<local-path> Files', 'Google\\Chrome\\Application\\chrome.exe'),
        path.join(process.env['ProgramFiles(x86)'] || '<local-path> Files (x86)', 'Google\\Chrome\\Application\\chrome.exe'),
        path.join(process.env.ProgramFiles || '<local-path> Files', 'Microsoft\\Edge\\Application\\msedge.exe'),
        path.join(process.env['ProgramFiles(x86)'] || '<local-path> Files (x86)', 'Microsoft\\Edge\\Application\\msedge.exe'),
      ]
    : [
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
        '/Applications/Chromium.app/Contents/MacOS/Chromium',
        path.join(home, '.local/chrome-for-testing/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing'),
        path.join(home, '.local/chrome-for-testing/chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing'),
        '/usr/bin/google-chrome',
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser',
        '/usr/bin/microsoft-edge',
      ];
  const found = candidates.find((p) => fs.existsSync(p));
  if (!found) {
    throw new Error('URL scanning needs puppeteer or an installed Chrome/Edge. Neither was found.');
  }
  return found;
}

// ── Minimal WebSocket client for CDP (same frame logic as qa.mjs) ────────────

function makeFrame(text) {
  const payload = Buffer.from(text);
  let header;
  if (payload.length < 126) {
    header = Buffer.from([0x81, 0x80 | payload.length]);
  } else if (payload.length < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(payload.length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 0x80 | 127;
    header.writeBigUInt64BE(BigInt(payload.length), 2);
  }
  const mask = randomBytes(4);
  const masked = Buffer.alloc(payload.length);
  for (let i = 0; i < payload.length; i += 1) masked[i] = payload[i] ^ mask[i % 4];
  return Buffer.concat([header, mask, masked]);
}

function readFrames(buffer) {
  const frames = [];
  let offset = 0;
  while (buffer.length - offset >= 2) {
    const b0 = buffer[offset];
    const b1 = buffer[offset + 1];
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let len = b1 & 0x7f;
    let pos = offset + 2;
    if (len === 126) {
      if (buffer.length - pos < 2) break;
      len = buffer.readUInt16BE(pos);
      pos += 2;
    } else if (len === 127) {
      if (buffer.length - pos < 8) break;
      len = Number(buffer.readBigUInt64BE(pos));
      pos += 8;
    }
    let mask;
    if (masked) {
      if (buffer.length - pos < 4) break;
      mask = buffer.subarray(pos, pos + 4);
      pos += 4;
    }
    if (buffer.length - pos < len) break;
    const payload = Buffer.from(buffer.subarray(pos, pos + len));
    if (masked && mask) for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i % 4];
    frames.push({ opcode, text: payload.toString('utf8') });
    offset = pos + len;
  }
  return { frames, rest: buffer.subarray(offset) };
}

function cdpConnect(wsUrl) {
  return new Promise((resolveConnect, reject) => {
    const u = new URL(wsUrl);
    const socket = createConnection({ host: u.hostname, port: Number(u.port) || 80 });
    const key = randomBytes(16).toString('base64');
    const callbacks = new Map();
    const eventHandlers = new Map();
    let id = 0;
    let handshaken = false;
    let buffer = Buffer.alloc(0);
    socket.setNoDelay(true);
    socket.on('connect', () => {
      socket.write(
        `GET ${u.pathname}${u.search} HTTP/1.1\r\n` +
          `Host: ${u.host}\r\n` +
          'Upgrade: websocket\r\n' +
          'Connection: Upgrade\r\n' +
          `Sec-WebSocket-Key: ${key}\r\n` +
          'Sec-WebSocket-Version: 13\r\n\r\n',
      );
    });
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (!handshaken) {
        const idx = buffer.indexOf('\r\n\r\n');
        if (idx < 0) return;
        const header = buffer.subarray(0, idx).toString('utf8');
        if (!header.includes('101')) {
          reject(new Error(`CDP WebSocket handshake failed: ${header.split('\r\n')[0]}`));
          socket.destroy();
          return;
        }
        handshaken = true;
        buffer = buffer.subarray(idx + 4);
        resolveConnect({
          send(method, params = {}) {
            const callId = ++id;
            socket.write(makeFrame(JSON.stringify({ id: callId, method, params })));
            return new Promise((resolve, rejectCall) => callbacks.set(callId, { resolve, rejectCall, method }));
          },
          on(method, handler) {
            const list = eventHandlers.get(method) || [];
            list.push(handler);
            eventHandlers.set(method, list);
          },
          close() {
            socket.end();
          },
        });
      }
      if (!handshaken || buffer.length === 0) return;
      const parsed = readFrames(buffer);
      buffer = parsed.rest;
      for (const frame of parsed.frames) {
        if (frame.opcode !== 1) continue;
        let msg;
        try { msg = JSON.parse(frame.text); } catch { continue; }
        if (!msg.id) {
          const handlers = eventHandlers.get(msg.method);
          if (handlers) for (const h of handlers) { try { h(msg.params); } catch {} }
          continue;
        }
        const cb = callbacks.get(msg.id);
        if (!cb) continue;
        callbacks.delete(msg.id);
        if (msg.error) cb.rejectCall(new Error(`${cb.method}: ${msg.error.message}`));
        else cb.resolve(msg.result);
      }
    });
    socket.on('error', reject);
  });
}

async function runtimeEval(client, expression) {
  const result = await client.send('Runtime.evaluate', {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (result.exceptionDetails) {
    throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text || 'Runtime.evaluate failed');
  }
  return result.result?.value;
}

// ── Launch, navigate, inject, collect ────────────────────────────────────────

async function launchHeadless(executable, viewport) {
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'impeccable-cdp-'));
  const child = spawn(executable, [
    '--headless=new',
    '--remote-debugging-port=0',
    `--user-data-dir=${userDataDir}`,
    `--window-size=${viewport.width},${viewport.height}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-extensions',
    '--disable-background-networking',
    'about:blank',
  ], { stdio: 'ignore', windowsHide: true });
  child.unref?.();

  const portFile = path.join(userDataDir, 'DevToolsActivePort');
  const started = Date.now();
  let port = 0;
  while (Date.now() - started < 20000) {
    if (fs.existsSync(portFile)) {
      const first = fs.readFileSync(portFile, 'utf8').split(/\r?\n/)[0].trim();
      port = Number(first);
      if (port > 0) break;
    }
    if (child.exitCode !== null) throw new Error(`Browser exited before DevTools port was ready (code ${child.exitCode})`);
    await wait(150);
  }
  if (!port) {
    try { child.kill(); } catch {}
    throw new Error('Timed out waiting for the browser DevTools port');
  }
  return { child, port, userDataDir };
}

async function findPageTarget(port) {
  const started = Date.now();
  while (Date.now() - started < 10000) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/json/list`);
      if (res.ok) {
        const targets = await res.json();
        const page = targets.find((t) => t.type === 'page' && t.webSocketDebuggerUrl);
        if (page) return page;
      }
    } catch {}
    await wait(150);
  }
  throw new Error('No debuggable page target found');
}

function cleanup(child, userDataDir) {
  try { child.kill(); } catch {}
  // Chrome holds file locks briefly after kill; retry once, then leave the temp
  // dir for the OS cleaner rather than failing the scan.
  setTimeout(() => {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch {}
  }, 500).unref?.();
}

async function detectUrlCdp(url, options = {}) {
  const viewport = options?.viewport || { width: 1280, height: 800 };
  const settleMs = Number.isFinite(options?.settleMs) ? options.settleMs : 250;
  const browserScriptPath = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '..', '..', 'detect-antipatterns-browser.js',
  );
  const browserScript = fs.readFileSync(browserScriptPath, 'utf-8');

  const executable = findBrowserExecutable();
  const { child, port, userDataDir } = await launchHeadless(executable, viewport);
  let client;
  try {
    const target = await findPageTarget(port);
    client = await cdpConnect(target.webSocketDebuggerUrl);

    await client.send('Page.enable');
    await client.send('Emulation.setDeviceMetricsOverride', {
      width: viewport.width,
      height: viewport.height,
      deviceScaleFactor: 1,
      mobile: viewport.width < 600,
    });

    let loaded = false;
    client.on('Page.loadEventFired', () => { loaded = true; });
    await client.send('Page.navigate', { url });
    const started = Date.now();
    while (!loaded && Date.now() - started < 30000) {
      const ready = await runtimeEval(client, 'document.readyState').catch(() => '');
      if (ready === 'complete') loaded = true;
      else await wait(200);
    }
    if (!loaded) throw new Error(`Timed out loading ${url}`);
    if (settleMs > 0) await wait(settleMs);

    const designSystem = options?.designSystem && typeof options.designSystem === 'object'
      ? options.designSystem
      : null;
    await runtimeEval(client, `window.__IMPECCABLE_CONFIG__ = Object.assign({}, window.__IMPECCABLE_CONFIG__ || {}, { autoScan: false }${designSystem ? `, { designSystem: ${JSON.stringify(designSystem)} }` : ''});`);
    await runtimeEval(client, browserScript);
    const serializedGroups = await runtimeEval(client,
      'window.impeccableDetect ? window.impeccableDetect({ decorate: false, serialize: true }) : []');

    const results = (serializedGroups || []).flatMap(({ findings }) =>
      (findings || []).map((f) => ({ id: f.type, snippet: f.detail, ignoreValue: f.ignoreValue || '' })),
    );
    return filterByProviders(results.map((f) => {
      const item = finding(f.id, url, f.snippet);
      if (f.ignoreValue) item.ignoreValue = f.ignoreValue;
      return item;
    }), options.providers);
  } finally {
    try { client?.close(); } catch {}
    cleanup(child, userDataDir);
  }
}

export { detectUrlCdp };
