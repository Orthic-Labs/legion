#!/usr/bin/env node
// Claude plugin development against the LIVE source tree — never a packaged copy.
//
// The installed marketplace plugin is a snapshot taken at install time; editing
// the working tree does not change it, and a stale snapshot that shares a version
// with the tree is invisible until it breaks. During development the plugin must
// load from source, so structural changes take effect immediately and the
// version/cache lifecycle (scripts/verify-plugin-parity.mjs) is reserved for
// actual releases.
//
// This prints the exact invocation and first proves the live surface resolves,
// so "it didn't load" is distinguished from "it loaded but a target is missing".
import { spawnSync } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

const parity = spawnSync(process.execPath, [resolve(ROOT, 'scripts/verify-plugin-parity.mjs'), '--check'], { encoding: 'utf8' });
process.stdout.write(parity.stdout ?? '');
if (parity.status !== 0) {
  process.stderr.write(parity.stderr ?? '');
  process.stderr.write('\nLive plugin surface does not resolve — fix the above before loading it.\n');
  process.exit(1);
}

process.stdout.write(
  `\nLoad the live plugin (not the installed cache):\n\n` +
  `    claude --plugin-dir ${ROOT}\n\n` +
  `Then in-session, after editing skills/agents/hooks/MCP:\n\n` +
  `    /reload-plugins\n\n` +
  `Keep the marketplace install disabled while developing so the two do not both\n` +
  `own the harness. Bump the version only for a real release, which regenerates the\n` +
  `surface digest via 'npm run plugin:surface'.\n`);
