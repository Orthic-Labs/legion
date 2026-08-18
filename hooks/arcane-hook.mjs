#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
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
const child = spawnSync(process.execPath, [target], { stdio: "inherit" });
if (child.error) throw child.error;
if (child.signal) process.kill(process.pid, child.signal);
process.exitCode = child.status ?? 1;
