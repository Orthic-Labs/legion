// A shipped skill must not instruct a reader to open a path the installed
// plugin has no copy of. The installed root holds skills/ and the plugin
// descriptors and nothing above them — no src/, docs/, tools/, bench/ or
// qualification/ — so an instruction naming one of those dangles for every
// installed user while resolving fine in a checkout. That is how the audit
// skill's _selfcheck fixtures, the research runtime and the consumer-law
// generator all went unnoticed.
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const SKILLS = join(root, 'skills');
const NEVER_SHIPS = /^(src|docs|tools|bench|qualification|tests)\//;
const INSTRUCTION = /\b(run|execute|invoke|open|read|see|call|use)\b/i;
const CANDIDATE = /`([A-Za-z0-9._][A-Za-z0-9._/-]*\.(?:mjs|js|cjs|py|sh|ts|md|json|rs))`/g;
// A path inside the repository being audited, not inside this package.
const EXEMPT = /not part of the installed|does not ship|not shipped|directory ships|resolves only in a repository|retired|prototype design|historical/i;
const TARGET_REPO = /SampleApp|the project|target repo|audited repo/i;

function scan(dir, skill, found) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) { scan(path, skill, found); continue; }
    if (!/\.(md|json)$/i.test(entry.name)) continue;
    const lines = readFileSync(path, 'utf8').split(/\r?\n/);
    for (const [index, line] of lines.entries()) {
      if (!INSTRUCTION.test(line) || TARGET_REPO.test(line)) continue;
      // A disclaimer often sits on the line before or after the path, so read a
      // small window rather than the single line.
      const context = lines.slice(Math.max(0, index - 2), index + 3).join(' ');
      if (EXEMPT.test(context)) continue;
      for (const match of line.matchAll(CANDIDATE)) {
        const target = match[1];
        if (!target.includes('/') || !NEVER_SHIPS.test(target)) continue;
        if (existsSync(join(SKILLS, skill, target))) continue;
        found.push(`${relative(root, path)} -> ${target}`);
      }
    }
  }
}

test('no shipped skill instructs a reader to open a path that never ships', () => {
  const found = [];
  for (const entry of readdirSync(SKILLS, { withFileTypes: true })) {
    if (entry.isDirectory()) scan(join(SKILLS, entry.name), entry.name, found);
  }
  assert.deepEqual([...new Set(found)].sort(), [], 'dangling instructions in shipped skills');
});

// The packaging validator resolves every markdown link in a shipped skill and
// refuses a core whose reference is missing, so an unresolvable link fails the
// build rather than the suite. Catch it here instead. Its regex does not skip
// code spans, so an example of link syntax inside backticks is rejected too —
// which is why this asserts exactly what the packager asserts.
test('every markdown link in a shipped skill resolves inside the package', () => {
  const missing = [];
  const scanLinks = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) { scanLinks(path); continue; }
      if (!/\.md$/i.test(entry.name)) continue;
      for (const match of readFileSync(path, 'utf8').matchAll(/\[[^\]]*\]\(([^):#?\s]+)\)/g)) {
        const target = match[1];
        if (/^(https?:|mailto:|#)/.test(target)) continue;
        if (!existsSync(resolve(dirname(path), target))) {
          missing.push(`${relative(root, path)} -> ${target}`);
        }
      }
    }
  };
  scanLinks(SKILLS);
  assert.deepEqual([...new Set(missing)].sort(), [], 'unresolvable links in shipped skills');
});
