import assert from 'node:assert/strict'; import { readFile } from 'node:fs/promises'; import test from 'node:test'; import { validateSkillBundle } from '../../src/lib/skills/contracts.mjs';
// A hand-maintained exact count drifts every time a bundle gains a file, and
// the manifest refresh gate already proves the manifest matches the tree. Keep
// a floor so a bundle cannot silently empty out.
for (const [id, minimum] of [['designer', 200], ['writing', 30]]) test(`${id} supplied bundle is complete and digest-bound`, async () => { const manifest = JSON.parse(await readFile(new URL(`../../skills/manifests/${id}.json`, import.meta.url), 'utf8')); validateSkillBundle(manifest); assert.ok(manifest.files.length >= minimum, `${id} bundle shrank to ${manifest.files.length}`); assert.ok(manifest.files.every((file) => file.digest.startsWith('sha256:'))); });
