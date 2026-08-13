#!/usr/bin/env node
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkCanonicalNames } from '../lib/naming/check.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const report = checkCanonicalNames({ root });
if (process.argv.includes('--json')) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
else if (report.status === 'pass') process.stdout.write('canonical naming: PASS\n');
else for (const issue of report.unclassified) process.stderr.write(`${issue.path}${issue.line ? `:${issue.line}` : ''}: ${issue.reason}${issue.token ? ` (${issue.token})` : ''}\n`);
process.exitCode = report.status === 'pass' ? 0 : 1;
