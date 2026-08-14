#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createConnection } from "node:net";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync, rmSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = process.cwd();

function usage() {
  console.log(`Usage:
  qa.mjs --shot [--route "/?qa=1"] [--out ".cache/qa-shots/app.png"]
  qa.mjs --actions actions.json [--route "/?qa=1"]
  qa.mjs --url "http://127.0.0.1:3000/?qa=1" --actions actions.json

Options:
  --shot                 Capture one viewport-only app screenshot.
  --actions <file>       JSON action file for hover/click/assert/screenshot QA.
  --url <url>            Use an already-running app URL.
  --start <command>      Start command. Use {port} placeholder for the selected port.
  --route <route>        Route to open on the local server. Default: /?qa=1
  --out <path>           Screenshot path for --shot. Default: .cache/qa-shots/app.png
  --width <px>           Viewport width. Default: 1365
  --height <px>          Viewport height. Default: 900
  --port <port>          Server port. Default: first free port from 1422.
  --cdp-port <port>      DevTools port for action mode. Default: first free port from 9222.
  --qa-env <NAME=VALUE>  Env var for server process. Default: VITE_APP_BROWSER_QA=1
  --viewport <spec>      Preset (desktop|tablet|mobile) or WxH (e.g. 390x844). Sets width/height/DPR/mobile.
  --slow-3g              Throttle network ~400 kbps / 400ms RTT (CDP). Reveals spinners/jank hidden on localhost.
  --slow-4g              Throttle network ~1.6 Mbps / 150ms RTT (CDP).
  --cpu-4x               Throttle CPU 4x (CDP). Shorthand for --cpu-throttle 4.
  --cpu-throttle <n>     Throttle CPU by factor n (CDP).
  --save-session <file>  After the run, save cookies + localStorage to <file>.
  --load-session <file>  Restore cookies + localStorage before first paint (skip re-login).
  --keep-open            Leave server running after the run.
  --sweep                Delete abandoned browser profiles under .cache and exit.
  --help                 Show help.

Any throttle/CPU/mobile/session flag routes --shot through the CDP path, because Chrome's
fire-and-forget --screenshot= flag cannot express those conditions.
`);
}

function parseArgs(argv) {
  const args = {
    route: "/?qa=1",
    out: ".cache/qa-shots/app.png",
    width: 1365,
    height: 900,
    port: 0,
    cdpPort: 0,
    qaEnv: "VITE_APP_BROWSER_QA=1",
    shot: false,
    keepOpen: false,
    mobile: false,
    dpr: 1,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--help" || a === "-h") args.help = true;
    else if (a === "--shot") args.shot = true;
    else if (a === "--sweep") args.sweep = true;
    else if (a === "--keep-open") args.keepOpen = true;
    else if (a === "--actions") args.actions = argv[++i];
    else if (a === "--url") args.url = argv[++i];
    else if (a === "--start") args.start = argv[++i];
    else if (a === "--route") args.route = argv[++i];
    else if (a === "--out") args.out = argv[++i];
    else if (a === "--width") args.width = Number(argv[++i]);
    else if (a === "--height") args.height = Number(argv[++i]);
    else if (a === "--port") args.port = Number(argv[++i]);
    else if (a === "--cdp-port") args.cdpPort = Number(argv[++i]);
    else if (a === "--qa-env") args.qaEnv = argv[++i];
    else if (a === "--viewport") { const p = parseViewport(argv[++i]); args.width = p.width; args.height = p.height; args.dpr = p.dpr; args.mobile = p.mobile; }
    else if (a === "--slow-3g") args.throttle = "slow-3g";
    else if (a === "--slow-4g") args.throttle = "slow-4g";
    else if (a === "--cpu-4x") args.cpu = 4;
    else if (a === "--cpu-throttle") args.cpu = Number(argv[++i]);
    else if (a === "--save-session") args.saveSession = argv[++i];
    else if (a === "--load-session") args.loadSession = argv[++i];
    else throw new Error(`Unknown argument: ${a}`);
  }
  return args;
}

const VIEWPORTS = {
  desktop: { width: 1440, height: 900, dpr: 1, mobile: false },
  tablet: { width: 768, height: 1024, dpr: 2, mobile: true },
  mobile: { width: 390, height: 844, dpr: 3, mobile: true },
};
function parseViewport(v) {
  if (!v) throw new Error("--viewport needs a value (desktop|tablet|mobile|WxH)");
  if (VIEWPORTS[v]) return VIEWPORTS[v];
  const m = /^(\d+)x(\d+)$/.exec(v);
  if (!m) throw new Error(`bad --viewport: ${v} (use desktop|tablet|mobile or 1440x900)`);
  return { width: Number(m[1]), height: Number(m[2]), dpr: 1, mobile: false };
}

// DevTools-style network presets: bytes/sec throughput + ms latency.
const THROTTLE = {
  "slow-3g": { downloadThroughput: 50 * 1000, uploadThroughput: 50 * 1000, latency: 400 },
  "slow-4g": { downloadThroughput: 200 * 1000, uploadThroughput: 94 * 1000, latency: 150 },
};

// Viewport + optional network/CPU throttling on a live CDP client, applied BEFORE navigate.
async function applyConditions(client, args) {
  await client.send("Emulation.setDeviceMetricsOverride", {
    width: args.width,
    height: args.height,
    deviceScaleFactor: args.dpr || 1,
    mobile: !!args.mobile,
  });
  if (args.throttle || args.cpu) {
    await client.send("Network.enable");
    if (args.throttle) {
      await client.send("Network.emulateNetworkConditions", { offline: false, ...THROTTLE[args.throttle] });
    }
    if (args.cpu) await client.send("Emulation.setCPUThrottlingRate", { rate: args.cpu });
  }
}

// Session persistence. Restore runs via addScriptToEvaluateOnNewDocument so localStorage is
// populated BEFORE the app's own scripts run — first paint is authenticated, no re-login flow.
async function loadSession(client, file) {
  let data;
  try { data = JSON.parse(readFileSync(abs(file), "utf8")); }
  catch (e) { throw new Error(`--load-session: cannot read ${file}: ${e.message}`); }
  if (Array.isArray(data.cookies) && data.cookies.length) {
    await client.send("Network.enable").catch(() => {});
    await client.send("Network.setCookies", { cookies: data.cookies });
  }
  if (data.localStorage && Object.keys(data.localStorage).length) {
    const src = `(() => { try { const s = ${JSON.stringify(data.localStorage)}; for (const k in s) localStorage.setItem(k, s[k]); } catch (e) {} })();`;
    await client.send("Page.addScriptToEvaluateOnNewDocument", { source: src });
  }
}
async function saveSession(client, file) {
  const out = abs(file);
  ensureParent(out);
  let cookies = [];
  try { cookies = (await client.send("Network.getCookies", {})).cookies || []; } catch {}
  let localStorage = {};
  try { localStorage = JSON.parse((await runtimeEval(client, "JSON.stringify(Object.assign({}, window.localStorage))")) || "{}"); } catch {}
  writeFileSync(out, JSON.stringify({ cookies, localStorage }, null, 2));
  console.log(`[qa] session saved ${out}`);
}

// Zombie guard: kill spawned children and delete throwaway profile dirs on interrupt/exit, not
// only in the happy-path finally. A crash or agent timeout otherwise leaks headless Chrome, the
// dev server (holding the port), and a .cache profile dir per run.
const _children = new Set();
const _profiles = new Set();
function track(child) { if (child) { _children.add(child); child.on("exit", () => _children.delete(child)); } return child; }
function trackProfile(dir) { _profiles.add(dir); return dir; }
function killTracked() {
  for (const c of _children) { try { c.kill(); } catch {} }
  _children.clear();
  // Chrome does not release its profile handles the instant it is killed, so on
  // Windows the first rmSync loses to EBUSY/EPERM and the directory survives.
  // A short synchronous retry wins the common case; sweepStaleProfiles covers the
  // rest, because an exit handler can never be made fully reliable here.
  for (const p of _profiles) {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try { rmSync(p, { recursive: true, force: true }); break; } catch {
        try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 150); } catch {}
      }
    }
  }
  _profiles.clear();
}

// Every throwaway profile this tool has ever created is named with a known
// prefix under .cache, so anything older than the cutoff belonged to a run that
// is long gone. Sweeping at startup is what actually keeps .cache from growing
// without bound — 71 directories and 765 MB had accumulated before this existed.
const PROFILE_PREFIXES = ["qa-browser-profile-", "qa-cdp-profile-"];
function sweepStaleProfiles({ olderThanMs = 60 * 60_000, now = Date.now() } = {}) {
  const cacheDir = abs(".cache");
  let entries;
  try { entries = readdirSync(cacheDir, { withFileTypes: true }); } catch { return 0; }
  let removed = 0;
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
    if (!PROFILE_PREFIXES.some((prefix) => entry.name.startsWith(prefix))) continue;
    const target = join(cacheDir, entry.name);
    if (_profiles.has(target)) continue;
    try {
      if (now - statSync(target).mtimeMs < olderThanMs) continue;
      rmSync(target, { recursive: true, force: true });
      removed += 1;
    } catch {}
  }
  if (removed > 0) console.log(`[qa] swept ${removed} abandoned browser profile${removed === 1 ? "" : "s"}`);
  return removed;
}
let _cleanupWired = false;
function wireCleanup() {
  if (_cleanupWired) return;
  _cleanupWired = true;
  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(sig, () => { killTracked(); process.exit(130); });
  process.on("exit", killTracked);
  sweepStaleProfiles();
}

function abs(path) {
  return isAbsolute(path) ? path : resolve(root, path);
}

function ensureParent(file) {
  mkdirSync(dirname(file), { recursive: true });
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function freePort(startAt) {
  return new Promise((resolvePort, reject) => {
    let candidate = startAt;
    const tryNext = () => {
      if (candidate > startAt + 200) {
        reject(new Error(`No free loopback port found from ${startAt} to ${startAt + 200}.`));
        return;
      }
      const server = createConnection({ host: "127.0.0.1", port: candidate });
      server.once("connect", () => {
        server.destroy();
        candidate += 1;
        tryNext();
      });
      server.once("error", () => resolvePort(candidate));
    };
    tryNext();
  });
}

async function waitForHttp(url, timeoutMs = 30000) {
  const started = Date.now();
  let last = "";
  while (Date.now() - started < timeoutMs) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
      last = `${res.status} ${res.statusText}`;
    } catch (error) {
      last = String(error?.message ?? error);
    }
    await wait(250);
  }
  throw new Error(`Timed out waiting for ${url}: ${last}`);
}

function findBrowser() {
  // Explicit override wins (Puppeteer / Lighthouse convention). Useful on
  // machines that only have a standalone "Chrome for Testing" build and no
  // system Chrome/Edge install.
  const override = process.env.CHROME_PATH || process.env.QA_BROWSER;
  if (override) {
    if (!existsSync(override)) {
      throw new Error(`CHROME_PATH/QA_BROWSER set but not found: ${override}`);
    }
    return override;
  }
  const home = process.env.HOME || process.env.USERPROFILE || "";
  const candidates = process.platform === "win32"
    ? [
        join(process.env.ProgramFiles || "C:\\Program Files", "Google\\Chrome\\Application\\chrome.exe"),
        join(process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "Google\\Chrome\\Application\\chrome.exe"),
        join(process.env.ProgramFiles || "C:\\Program Files", "Microsoft\\Edge\\Application\\msedge.exe"),
        join(process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "Microsoft\\Edge\\Application\\msedge.exe"),
      ]
    : [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        // Standalone "Chrome for Testing" extracted under ~/.local (no installer).
        join(home, ".local/chrome-for-testing/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"),
        join(home, ".local/chrome-for-testing/chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"),
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/microsoft-edge",
      ];
  const found = candidates.find((p) => existsSync(p));
  if (!found) throw new Error("No Chrome/Edge executable found.");
  return found;
}

function defaultStartCommand(port) {
  const vite = resolve(root, "node_modules", "vite", "bin", "vite.js");
  if (!existsSync(vite)) throw new Error("No --start command supplied and node_modules/vite/bin/vite.js was not found.");
  return `"${process.execPath}" "${vite}" --host 127.0.0.1 --port ${port} --strictPort`;
}

function startServer(args, port) {
  if (args.url) return null;
  const env = { ...process.env };
  const [name, ...valueParts] = String(args.qaEnv || "").split("=");
  if (name) env[name] = valueParts.length ? valueParts.join("=") : "1";
  const command = (args.start || defaultStartCommand(port)).replaceAll("{port}", String(port));
  const child = spawn(command, {
    cwd: root,
    env,
    shell: true,
    windowsHide: true,
    stdio: "ignore",
  });
  child.unref?.();
  return child;
}

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
    frames.push({ opcode, text: payload.toString("utf8") });
    offset = pos + len;
  }
  return { frames, rest: buffer.subarray(offset) };
}

function cdpConnect(wsUrl) {
  return new Promise((resolveConnect, reject) => {
    const u = new URL(wsUrl);
    const socket = createConnection({ host: u.hostname, port: Number(u.port) || 80 });
    const key = randomBytes(16).toString("base64");
    const callbacks = new Map();
    const eventHandlers = new Map();
    let id = 0;
    let handshaken = false;
    let buffer = Buffer.alloc(0);
    socket.setNoDelay(true);
    socket.on("connect", () => {
      socket.write(
        `GET ${u.pathname}${u.search} HTTP/1.1\r\n` +
          `Host: ${u.host}\r\n` +
          "Upgrade: websocket\r\n" +
          "Connection: Upgrade\r\n" +
          `Sec-WebSocket-Key: ${key}\r\n` +
          "Sec-WebSocket-Version: 13\r\n\r\n",
      );
    });
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (!handshaken) {
        const idx = buffer.indexOf("\r\n\r\n");
        if (idx < 0) return;
        const header = buffer.subarray(0, idx).toString("utf8");
        if (!header.includes("101")) {
          reject(new Error(`CDP WebSocket handshake failed: ${header}`));
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
        const msg = JSON.parse(frame.text);
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
    socket.on("error", reject);
  });
}

async function runtimeEval(client, expression, timeoutMs = 10000) {
  const result = await client.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
    timeout: timeoutMs,
  });
  if (result.exceptionDetails) {
    throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text || "Runtime.evaluate failed");
  }
  return result.result.value;
}

async function waitForEval(client, expression, timeoutMs = 10000) {
  const started = Date.now();
  let last;
  while (Date.now() - started < timeoutMs) {
    last = await runtimeEval(client, expression);
    if (last?.ok) return last;
    await wait(250);
  }
  throw new Error(`Timed out waiting for expression. Last result: ${JSON.stringify(last)}`);
}

function jsString(value) {
  return JSON.stringify(String(value));
}

async function elementPoint(client, selector) {
  const result = await waitForEval(
    client,
    `(() => {
      const el = document.querySelector(${jsString(selector)});
      if (!el) return { ok: false, reason: "missing" };
      const r = el.getBoundingClientRect();
      if (!r.width || !r.height) return { ok: false, reason: "empty rect" };
      return { ok: true, x: r.left + r.width / 2, y: r.top + r.height / 2, rect: { left: r.left, top: r.top, width: r.width, height: r.height } };
    })()`,
  );
  return result;
}

async function capture(client, out) {
  const file = abs(out);
  ensureParent(file);
  const shot = await client.send("Page.captureScreenshot", { format: "png", fromSurface: true });
  writeFileSync(file, Buffer.from(shot.data, "base64"));
  return file;
}

async function runAction(client, action, index) {
  const label = `${index + 1}:${action.type}`;
  if (action.type === "sleep") {
    await wait(action.ms ?? 250);
  } else if (action.type === "waitFor") {
    await waitForEval(client, `(() => ({ ok: !!document.querySelector(${jsString(action.selector)}) }))()`, action.timeout ?? 10000);
  } else if (action.type === "waitForText") {
    await waitForEval(client, `(() => ({ ok: (document.body?.innerText || "").includes(${jsString(action.text)}) }))()`, action.timeout ?? 10000);
  } else if (action.type === "click") {
    const p = await elementPoint(client, action.selector);
    await client.send("Input.dispatchMouseEvent", { type: "mousePressed", x: p.x, y: p.y, button: "left", clickCount: 1 });
    await client.send("Input.dispatchMouseEvent", { type: "mouseReleased", x: p.x, y: p.y, button: "left", clickCount: 1 });
  } else if (action.type === "hover") {
    const p = await elementPoint(client, action.selector);
    await client.send("Input.dispatchMouseEvent", { type: "mouseMoved", x: p.x, y: p.y });
    await wait(action.settle ?? 150);
  } else if (action.type === "type") {
    await client.send("Input.insertText", { text: action.text ?? "" });
  } else if (action.type === "press") {
    const key = action.key || "Enter";
    await client.send("Input.dispatchKeyEvent", { type: "keyDown", key });
    await client.send("Input.dispatchKeyEvent", { type: "keyUp", key });
  } else if (action.type === "eval") {
    const value = await runtimeEval(client, action.expression);
    if (value?.ok === false) throw new Error(`${label} eval returned not ok: ${JSON.stringify(value)}`);
  } else if (action.type === "assertVisible") {
    await waitForEval(
      client,
      `(() => {
        const el = document.querySelector(${jsString(action.selector)});
        if (!el) return { ok: false, reason: "missing" };
        const r = el.getBoundingClientRect();
        const cs = getComputedStyle(el);
        return { ok: !!(r.width && r.height && cs.visibility !== "hidden" && cs.display !== "none"), rect: { width: r.width, height: r.height }, display: cs.display, visibility: cs.visibility };
      })()`,
      action.timeout ?? 10000,
    );
  } else if (action.type === "assertText") {
    const value = await runtimeEval(
      client,
      `(() => {
        const el = document.querySelector(${jsString(action.selector)});
        const text = el?.textContent || "";
        return { ok: text.includes(${jsString(action.text)}), text };
      })()`,
    );
    if (!value.ok) throw new Error(`${label} text assertion failed: ${JSON.stringify(value)}`);
  } else if (action.type === "assertAriaLabel") {
    const value = await runtimeEval(
      client,
      `(() => {
        const el = document.querySelector(${jsString(action.selector)});
        const label = el?.getAttribute("aria-label") || el?.getAttribute("title") || "";
        return { ok: ${action.exact ? "label === " : "label.includes("}${jsString(action.label)}${action.exact ? "" : ")"}, label };
      })()`,
    );
    if (!value.ok) throw new Error(`${label} aria/title assertion failed: ${JSON.stringify(value)}`);
  } else if (action.type === "assertCursor") {
    const value = await runtimeEval(
      client,
      `(() => {
        const el = document.querySelector(${jsString(action.selector)});
        const cursor = el ? getComputedStyle(el).cursor : "";
        return { ok: cursor === ${jsString(action.cursor || "pointer")}, cursor };
      })()`,
    );
    if (!value.ok) throw new Error(`${label} cursor assertion failed: ${JSON.stringify(value)}`);
  } else if (action.type === "assertStyle") {
    const value = await runtimeEval(
      client,
      `(() => {
        const el = document.querySelector(${jsString(action.selector)});
        const actual = el ? getComputedStyle(el).getPropertyValue(${jsString(action.property)}) : "";
        const expected = ${jsString(action.value)};
        return { ok: ${action.exact ? "actual.trim() === expected" : "actual.includes(expected)"}, actual };
      })()`,
    );
    if (!value.ok) throw new Error(`${label} style assertion failed: ${JSON.stringify(value)}`);
  } else if (action.type === "wheel") {
    // real wheel input — the only way to test scroll-snap / scroll-jacked galleries.
    // programmatic scrollTo bypasses the snap logic and reports misleading positions.
    const x = action.x ?? 400, y = action.y ?? 400;
    const clicks = action.clicks ?? 1;
    for (let i = 0; i < clicks; i++) {
      await client.send("Input.dispatchMouseEvent", {
        type: "mouseWheel", x, y, deltaX: action.deltaX ?? 0, deltaY: action.deltaY ?? 100,
      });
      await wait(action.gap ?? 120);
    }
  } else if (action.type === "screenshot") {
    const file = await capture(client, action.out);
    console.log(`[qa] screenshot ${file}`);
  } else {
    throw new Error(`Unknown action type at ${index}: ${action.type}`);
  }
  console.log(`[qa] ${label} ok`);
}

async function runShot(args, url, browser) {
  const out = abs(args.out);
  ensureParent(out);
  const profile = abs(`.cache/qa-browser-profile-${Date.now()}`);
  mkdirSync(trackProfile(profile), { recursive: true });
  const shot = track(spawn(browser, [
    "--headless=new",
    "--disable-gpu",
    "--no-default-browser-check",
    "--no-first-run",
    "--force-device-scale-factor=1",
    `--user-data-dir=${profile}`,
    `--window-size=${args.width},${args.height}`,
    `--screenshot=${out}`,
    url,
  ], { windowsHide: true, stdio: "ignore" }));
  const code = await new Promise((resolveCode) => shot.on("exit", resolveCode));
  if (code !== 0 && !existsSync(out)) throw new Error(`Headless screenshot failed with exit code ${code}.`);
  console.log(`[qa] url ${url}`);
  console.log(`[qa] screenshot ${out}`);
}

// CDP screenshot path — used whenever a condition must genuinely apply (throttle, CPU, mobile,
// session). The fast --screenshot= path cannot express any of them, so a "throttled" shot taken
// that way would silently be unthrottled.
async function runShotCdp(args, url, browser, cdpPort) {
  const out = abs(args.out);
  ensureParent(out);
  const profile = abs(`.cache/qa-cdp-profile-${Date.now()}`);
  mkdirSync(trackProfile(profile), { recursive: true });
  const chrome = track(spawn(browser, [
    "--headless=new",
    "--disable-gpu",
    "--no-default-browser-check",
    "--no-first-run",
    `--remote-debugging-port=${cdpPort}`,
    `--user-data-dir=${profile}`,
    `--window-size=${args.width},${args.height}`,
    "about:blank",
  ], { windowsHide: true, stdio: "ignore" }));
  let client;
  try {
    await waitForHttp(`http://127.0.0.1:${cdpPort}/json/version`, 30000);
    const targets = await (await fetch(`http://127.0.0.1:${cdpPort}/json/list`)).json();
    const target = targets.find((t) => t.type === "page" && t.webSocketDebuggerUrl);
    if (!target) throw new Error("No CDP page target found.");
    client = await cdpConnect(target.webSocketDebuggerUrl);
    await client.send("Runtime.enable");
    await client.send("Page.enable");
    await applyConditions(client, args);
    if (args.loadSession) await loadSession(client, args.loadSession);
    await client.send("Page.navigate", { url });
    await waitForEval(client, "(() => ({ ok: document.readyState !== 'loading' && !!document.body }))()", 30000);
    await capture(client, out);
    if (args.saveSession) await saveSession(client, args.saveSession);
    const conds = [args.throttle, args.cpu ? `cpu ${args.cpu}x` : null, args.mobile ? `mobile dpr${args.dpr}` : null].filter(Boolean).join(" · ");
    console.log(`[qa] url ${url}`);
    console.log(`[qa] screenshot ${out}${conds ? `  (${conds})` : ""}`);
  } finally {
    try { client?.close(); } catch {}
    try { chrome.kill(); } catch {}
  }
}

async function runActions(args, url, browser, cdpPort) {
  const actionsPath = abs(args.actions);
  const actions = JSON.parse(readFileSync(actionsPath, "utf8"));
  if (!Array.isArray(actions)) throw new Error("--actions file must contain a JSON array.");
  const profile = abs(`.cache/qa-cdp-profile-${Date.now()}`);
  mkdirSync(trackProfile(profile), { recursive: true });
  // Launch on about:blank, connect, enable+subscribe, THEN navigate — so console
  // errors and exceptions from the very first paint are captured, not missed.
  const chrome = track(spawn(browser, [
    "--headless=new",
    "--disable-gpu",
    "--no-default-browser-check",
    "--no-first-run",
    `--remote-debugging-port=${cdpPort}`,
    `--user-data-dir=${profile}`,
    `--window-size=${args.width},${args.height}`,
    "about:blank",
  ], { windowsHide: true, stdio: "ignore" }));
  let client;
  const consoleErrors = [];
  try {
    await waitForHttp(`http://127.0.0.1:${cdpPort}/json/version`, 30000);
    const targets = await (await fetch(`http://127.0.0.1:${cdpPort}/json/list`)).json();
    const target = targets.find((t) => t.type === "page" && t.webSocketDebuggerUrl);
    if (!target) throw new Error("No CDP page target found.");
    client = await cdpConnect(target.webSocketDebuggerUrl);
    client.on("Runtime.consoleAPICalled", (p) => {
      if (p.type === "error" || p.type === "warning") {
        const text = (p.args || []).map((a) => a.value ?? a.description ?? a.unserializableValue ?? "").join(" ");
        consoleErrors.push(`console.${p.type}: ${text}`);
      }
    });
    client.on("Runtime.exceptionThrown", (p) => {
      const d = p.exceptionDetails || {};
      consoleErrors.push(`exception: ${d.exception?.description || d.text || "unknown"}`);
    });
    await client.send("Runtime.enable");
    await client.send("Page.enable");
    await applyConditions(client, args);
    if (args.loadSession) await loadSession(client, args.loadSession);
    await client.send("Page.navigate", { url });
    await waitForEval(client, "(() => ({ ok: document.readyState !== 'loading' && !!document.body }))()", 30000);
    for (let i = 0; i < actions.length; i += 1) await runAction(client, actions[i], i);
    if (args.saveSession) await saveSession(client, args.saveSession);
    console.log(`[qa] actions complete ${actionsPath}`);
  } finally {
    const logPath = abs(".cache/qa-console.log");
    try {
      ensureParent(logPath);
      writeFileSync(logPath, consoleErrors.join("\n") + (consoleErrors.length ? "\n" : ""));
    } catch {}
    if (consoleErrors.length) {
      console.log(`[qa] ${consoleErrors.length} console error/warning(s) — see ${logPath}`);
      for (const e of consoleErrors.slice(0, 20)) console.log(`[qa]   ${e}`);
    } else {
      console.log("[qa] no console errors or warnings");
    }
    try { client?.close(); } catch {}
    try { chrome.kill(); } catch {}
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.sweep) {
    // Reclaiming space must not require starting a browser, and a sweep that can
    // only run as a side effect of a QA run is a sweep nobody can verify.
    // Chrome keeps writing to a profile it is using, so the few-minute floor is
    // what stops an explicit sweep from deleting a concurrent run's profile.
    const removed = sweepStaleProfiles({ olderThanMs: 5 * 60_000 });
    if (removed === 0) console.log("[qa] no abandoned browser profiles under .cache");
    return;
  }
  if (args.help || (!args.shot && !args.actions)) {
    usage();
    return;
  }
  wireCleanup();
  const serverPort = args.url ? null : (args.port || await freePort(1422));
  const cdpPort = args.cdpPort || await freePort(9222);
  const url = args.url || `http://127.0.0.1:${serverPort}${args.route}`;
  const browser = findBrowser();
  const server = track(startServer(args, serverPort));
  const needsCdpShot = !!(args.throttle || args.cpu || args.mobile || args.loadSession || args.saveSession);
  try {
    if (!args.url) await waitForHttp(url, 30000);
    if (args.shot) await (needsCdpShot ? runShotCdp(args, url, browser, cdpPort) : runShot(args, url, browser));
    if (args.actions) await runActions(args, url, browser, cdpPort);
  } finally {
    if (server && !args.keepOpen) {
      try { server.kill(); } catch {}
    }
  }
}

main().catch((error) => {
  console.error(`[qa] ${error.stack || error.message || error}`);
  process.exit(1);
});
