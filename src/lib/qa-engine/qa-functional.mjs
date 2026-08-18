#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const engine = join(here, "qa.mjs");
const args = process.argv.slice(2);
const finalArgs = args.includes("--actions") || args.some((a) => a.startsWith("--actions=")) ? args : ["--help"];
const result = spawnSync(process.execPath, [engine, ...finalArgs], { stdio: "inherit", shell: false });
process.exit(result.status ?? 1);
