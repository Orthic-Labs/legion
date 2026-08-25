#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(realpathSync(fileURLToPath(import.meta.url))), '../../..');
const result = spawnSync(process.execPath, [resolve(root, 'tools/audit/audit-finalize.mjs'), ...process.argv.slice(2)], { stdio: 'inherit', shell: false });
process.exit(result.status ?? 1);
