import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');
const manifest = ['01-frame','02-context-stakeholders','03-drivers-quality-scenarios','04-domain-data-change','05-risk-uncertainty','06-candidates','07-evaluate-select','08-minimize','09-describe-views','10-assure-accept','11-govern-evolve-retire'];
const methods = ['qaw','add','atam','cbam','decision-analysis','assurance-case','technology-selection'];
const tagged = (text, tag) => {
  const contract = JSON.parse(text.match(/```json\n(\{[\s\S]*?\})\n```/)[1]);
  assert.equal(contract.schema, tag);
  return contract;
};

test('S06-01 exact workflow manifest & machine-readable phase contracts', async () => {
  const index = await read('doctrine/architecture/README.md');
  assert.deepEqual([...index.matchAll(/workflow\/(\d\d-[a-z-]+)\.md/g)].map((m) => m[1]), manifest);
  for (const [ordinal, name] of manifest.entries()) {
    const contract = tagged(await read(`doctrine/architecture/workflow/${name}.md`), 'architecture-workflow-module.v1');
    assert.equal(contract.ordinal, ordinal + 1); assert.equal(contract.module_id, name); assert.ok(contract.reads.length && contract.writes.length);
    for (const key of ['entry_conditions','exit_conditions','next_phase','reopen_requirements','prohibitions']) assert.ok(Object.hasOwn(contract, key), key);
  }
});
test('S06-01 gates, current-only resume, reopen & minimization sequence', async () => {
  const fixtures = JSON.parse(await read('tests/fixtures/stage6/workflow-fixtures.json'));
  const all = await Promise.all(manifest.map((name) => read(`doctrine/architecture/workflow/${name}.md`)));
  const text = all.join('\n');
  for (const value of fixtures.positive) assert.match(text, new RegExp(value, 'i'));
  for (const value of fixtures.negative) assert.match(text, new RegExp(value, 'i'));
  for (const phrase of ['current state', 'material delta', 'cause', 'scope', 'IDs', 'no REQUIRED expansion', 'objective self-upgrade', 'invented thresholds', 'risk acceptance', 'weighted comparison before gates', 'one review']) assert.match(text, new RegExp(phrase, 'i'));
  const evaluate = await read('doctrine/architecture/workflow/07-evaluate-select.md');
  assert.match(evaluate, /gates, then scenarios, economics/i);
});
test('S06-01 method contracts are conditional & reject prohibited automatic use', async () => {
  const fixtures = JSON.parse(await read('tests/fixtures/stage6/method-fixtures.json'));
  for (const name of methods) {
    const contract = tagged(await read(`doctrine/architecture/methods/${name}.md`), 'architecture-method-module.v1');
    assert.equal(contract.method_id, name); assert.ok(contract.when_to_use.length && contract.when_not_to_use.length && contract.allowed_phases.length && contract.inputs.length && contract.outputs.length && contract.prohibitions.length);
  }
  const text = await Promise.all(methods.map((name) => read(`doctrine/architecture/methods/${name}.md`))).then((all) => all.join('\n'));
  for (const value of fixtures.reject) assert.match(text, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'));
});
test('S06-01 Architect owns architecture method; no Sage bundle route remains active', async () => {
  const skill = await read('skills/architect/SKILL.md');
  for (const phrase of ['doctrine/architecture', 'owns', 'Architect', 'Sage attaches only']) assert.match(skill, new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'));
  assert.doesNotMatch(skill, /agents\/sage\.md/);
  assert.doesNotMatch(skill, /Sage Architect/i);
  const readme = await read('doctrine/architecture/README.md');
  assert.match(readme, /Canonical owner/);
  assert.match(readme, /skills\/architect\/SKILL\.md/);
});
test('canonical doctrine owns methods while roster owns abstract model tiers', async () => {
  for (const role of ['sage', 'alchemist', 'oracle']) {
    assert.doesNotMatch(await read(`doctrine/${role}.md`), /^model:/m);
    assert.match(await read(`src/roster/${role}.md`), /^modelTier:/m);
  }
  assert.doesNotMatch(await read('doctrine/covenant-seat.md'), /^model:/m);
});
