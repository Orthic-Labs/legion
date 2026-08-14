#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { basename, join, relative, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const MANIFESTS = join(ROOT, 'skills', 'manifests');
const LEGACY = {
  architect: 'architect', debugger: 'debugger', tasklist: 'tasklist', dispatch: 'dispatch',
  handoff: 'handoff', qa: 'qa', coder: 'coder', alchemist: 'jfdi', covenant: 'council',
};

const walk = (root, current = root, out = []) => {
  for (const name of readdirSync(current).sort()) {
    if (name === '.DS_Store' || name === '__pycache__' || name.endsWith('.pyc')) continue;
    const path = join(current, name);
    if (statSync(path).isDirectory()) walk(root, path, out);
    else out.push(relative(root, path).replaceAll('\\', '/'));
  }
  return out;
};
const digest = (path) => `sha256:${createHash('sha256').update(readFileSync(path)).digest('hex')}`;
const select = (files, pattern) => files.filter(({ path }) => pattern.test(path)).map(({ path }) => path);

for (const name of readdirSync(MANIFESTS).filter((name) => name.endsWith('.json') && !name.endsWith('.import-receipt.json')).sort()) {
  const path = join(MANIFESTS, name);
  const manifest = JSON.parse(readFileSync(path, 'utf8'));
  const files = manifest.files ?? [];
  const legacyName = LEGACY[manifest.id];
  const legacyRoot = legacyName && join(ROOT, 'skills', manifest.id, 'legacy-source', legacyName);
  const legacyArtifacts = legacyRoot && existsSync(legacyRoot) ? walk(legacyRoot).map((item) => ({
    sourcePath: `tools/skills/${legacyName}/${item}`,
    migratedPath: `legacy-source/${legacyName}/${item}`,
    digest: digest(join(legacyRoot, item)),
  })) : [];
  const skillText = readFileSync(join(ROOT, 'skills', manifest.id, 'SKILL.md'), 'utf8');
  const description = /^description:\s*(.+)$/m.exec(skillText)?.[1]?.trim() ?? `/${manifest.id}`;
  manifest.parity = {
    frozenAt: '2026-08-14',
    triggers: [`/${manifest.id}`, description],
    outputs: select(files, /^(?:assets|examples|specialists|references)\//),
    scripts: select(files, /^(?:scripts|hooks)\//),
    templates: select(files, /(?:^|\/)(?:assets|templates)\/|template/i),
    schemas: select(files, /(?:^|\/)(?:schemas?|contracts?)\/|schema/i),
    receipts: select(files, /receipt/i),
    evals: select(files, /(?:^|\/)evals?\//),
    consumers: ['registry/skills/index.json', 'lib/skills/resolver.mjs', 'registry/routing/domains.json'],
    legacyRef: legacyName ? 'workspace:c1c7e818^' : null,
    legacyArtifacts,
  };
  writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(basename(path));
}
