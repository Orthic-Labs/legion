#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../..");
const result = spawnSync(process.execPath, [resolve(root, "lib/qa-engine/qa-functional.mjs"), ...process.argv.slice(2)], { stdio: "inherit", shell: false });
process.exit(result.status ?? 1);
