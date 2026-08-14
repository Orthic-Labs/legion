#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const engine = join(here, "qa.mjs");
const args = process.argv.slice(2);
const result = spawnSync(process.execPath, [engine, "--shot", ...args], { stdio: "inherit", shell: false });
process.exit(result.status ?? 1);
