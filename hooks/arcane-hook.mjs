#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const codex = Boolean(process.env.CODEX_HOME || process.env.CODEX_THREAD_ID || process.env.CODEX_SESSION_ID);
const child = spawnSync(process.execPath, [join(root, "packages", "arcane", "host", codex ? "codex-adapter.mjs" : "claude-code-adapter.mjs")], { stdio: "inherit" });
if (child.error) throw child.error;
if (child.signal) process.kill(process.pid, child.signal);
process.exitCode = child.status ?? 1;
