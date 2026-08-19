#!/usr/bin/env node
import { existsSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const codex = Boolean(process.env.CODEX_HOME || process.env.CODEX_THREAD_ID || process.env.CODEX_SESSION_ID);
const adapter = codex ? "codex-adapter.mjs" : "claude-code-adapter.mjs";
// The gate runs out of the working tree while that tree is being edited, so a
// hardcoded package path turns any layout change into a machine-wide outage:
// every session fails closed with ARC_STORE_CORRUPT, including the one doing
// the move. Probe the known layouts, and if none resolves say so plainly
// rather than letting it surface as corrupt Arcane state.
const candidates = [
  join(root, "packages", "arcane", "host", adapter),
  join(root, "src", "packages", "arcane", "host", adapter),
];
const target = candidates.find((path) => existsSync(path));
if (!target) {
  process.stderr.write(`arcane-hook: adapter not found; looked in:\n${candidates.join("\n")}\n`);
  process.exit(1);
}
// The adapter is imported and called in-process rather than spawned. The
// previous spawnSync paid a second Node cold start on every hook event —
// ~400ms per event measured, against ~105ms for bare startup — which the
// PreToolUse/PostToolUse pair doubled on every tool call. The adapter's own
// `isMainModule` guard does not fire under import, so `main()` is called
// explicitly here. Failure behaviour is unchanged: a throw exits non-zero,
// which the host treats as a non-blocking hook error exactly as the
// non-zero child status did.
const mod = await import(pathToFileURL(target).href);
if (typeof mod.main !== "function") {
  process.stderr.write(`arcane-hook: ${target} exports no main()\n`);
  process.exit(1);
}
mod.main();
