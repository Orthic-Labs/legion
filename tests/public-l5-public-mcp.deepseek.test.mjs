import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';

function fixtureRoot() {
  const root = mkdtempSync(join(tmpdir(), 'legion-deepseek-'));
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'fixture', version: '1.0.0' }));
  return root;
}

function runFixture(root) {
  const runDir = join(root, '.audit', 'run-1');
  mkdirSync(runDir, { recursive: true });
  writeFileSync(join(runDir, 'report.json'), JSON.stringify({
    schemaVersion: 1,
    kind: 'repository-audit-report',
    findings: [{ id: 'f-1', ruleId: 'xss', title: 'Unsafe call' }],
    coverage_gaps: [{ id: 'gap-1', kind: 'runtime', detail: 'device absent' }],
  }));
  return runDir;
}

test('B8-001 public surface stays explicit, versioned, and registry-free', async () => {
  const api = await import('../src/lib/index.mjs');
  assert.equal(api.PUBLIC_API_VERSION, 1);
  assert.deepEqual(Object.keys(api.COMPATIBILITY_SURFACES).sort(), ['audit-finalize', 'audit-plan', 'audit-run', 'audit-verify']);
  for (const entry of Object.values(api.COMPATIBILITY_SURFACES)) {
    assert.equal(entry.deprecated, true);
    assert.equal(typeof entry.replacement, 'string');
    assert.equal(typeof api[entry.replacement], 'function', `${entry.replacement} must exist as the replacement`);
  }
  assert.equal('registry' in api, false);
  assert.equal('loadProviderRegistry' in api, false);
  assert.equal('canonicalJson' in api, false);
  for (const name of ['inspectProduct', 'buildPlan', 'executePlan', 'reconcileRun', 'finalizeRun', 'verifyRun', 'loadReport', 'verifySkillBundle', 'renderHtmlReport', 'editorDiagnostics']) {
    assert.equal(typeof api[name], 'function', `${name} must be public`);
  }
});

test('B8-003 canonical core dispatch: doctor, plan, verify, and read tools execute in-process', async () => {
  const { listTools, callTool } = await import('../src/integrations/mcp/tools.mjs');
  const root = fixtureRoot();
  runFixture(root);
  // No injected core: every tool must dispatch through the canonical core.
  assert.deepEqual(listTools().map(({ name }) => name), [
    'legion_doctor', 'legion_plan', 'legion_audit', 'legion_verify',
    'legion_get_run', 'legion_get_finding', 'legion_explain',
    'legion_list_providers', 'legion_list_languages', 'legion_list_families', 'legion_list_skills',
  ]);
  assert.ok(listTools().every(({ inputSchema }) => inputSchema.additionalProperties === false));

  const doctor = await callTool({ name: 'legion_doctor', arguments: { root: '.' } }, { root, maxOutputBytes: 4_000_000 });
  assert.equal(doctor.isError, false);
  assert.equal(doctor.structuredContent.kind, 'legion-product-inspection');

  const plan = await callTool({ name: 'legion_plan', arguments: { root: '.', profile: 'fast' } }, { root, maxOutputBytes: 4_000_000 });
  assert.equal(plan.isError, false);
  assert.equal(plan.structuredContent.plan.kind, 'legion-sealed-plan');
  assert.match(plan.structuredContent.plan.planDigest, /^sha256:/);

  const verify = await callTool({ name: 'legion_verify', arguments: { root: '.', priorRun: join('.audit', 'run-1', 'report.json') } }, { root, maxOutputBytes: 4_000_000 });
  assert.equal(verify.isError, false);
  assert.equal(verify.structuredContent.kind, 'legion-verification-receipt');
  assert.equal(verify.structuredContent.valid, false);
  assert.ok(verify.structuredContent.gaps.some(({ kind }) => kind === 'binding-drift'));

  const run = await callTool({ name: 'legion_get_run', arguments: { run: '.audit/run-1', artifact: 'report.json' } }, { root });
  assert.equal(run.isError, false);
  assert.equal(run.structuredContent.artifact, 'report.json');
  assert.equal(run.structuredContent.content.findings[0].id, 'f-1');

  const finding = await callTool({ name: 'legion_get_finding', arguments: { run: '.audit/run-1', findingId: 'f-1' } }, { root });
  assert.equal(finding.isError, false);
  assert.equal(finding.structuredContent.finding.ruleId, 'xss');

  const explain = await callTool({ name: 'legion_explain', arguments: { run: '.audit/run-1', id: 'f-1' } }, { root });
  assert.equal(explain.isError, false);
  assert.equal(explain.structuredContent.kind, 'legion-explain');
  assert.equal(explain.structuredContent.found, true);
});

test('B8-003 canonical core dispatch: list tools read the sealed registry in-process', async () => {
  const { callTool } = await import('../src/integrations/mcp/tools.mjs');
  const root = fixtureRoot();
  const providers = await callTool({ name: 'legion_list_providers', arguments: {} }, { root });
  assert.equal(providers.isError, false);
  assert.ok(Array.isArray(providers.structuredContent.providers) && providers.structuredContent.providers.length > 0);
  assert.equal(typeof providers.structuredContent.version, 'string');
  const families = await callTool({ name: 'legion_list_families', arguments: {} }, { root });
  assert.equal(families.isError, false);
  assert.ok(families.structuredContent.families.includes('framework.react'));
  for (const name of ['legion_list_languages', 'legion_list_skills']) {
    const result = await callTool({ name, arguments: {} }, { root });
    assert.equal(result.isError, false);
    assert.ok(Array.isArray(result.structuredContent[name.slice('legion_list_'.length)]));
  }
});

test('B8-003 rejects scope escape and bounded outputs on canonical dispatch', async () => {
  const { callTool } = await import('../src/integrations/mcp/tools.mjs');
  const root = fixtureRoot();
  for (const args of [{ root: '..' }, { root: `..${sep}other` }]) {
    assert.equal((await callTool({ name: 'legion_doctor', arguments: args }, { root })).isError, true);
  }
  assert.equal((await callTool({ name: 'legion_verify', arguments: { root: '.', priorRun: join('..', 'report.json') } }, { root })).isError, true);
  assert.equal((await callTool({ name: 'legion_get_run', arguments: { run: '..' } }, { root })).isError, true);
  const oversized = await callTool({ name: 'legion_plan', arguments: { root: '.' } }, { root, maxOutputBytes: 16 });
  assert.equal(oversized.isError, true);
  assert.match(oversized.content[0].text, /limit/);
});

test('resources expose the canonical run report with bounded, escape-safe reads', async () => {
  const { listResources, readResource } = await import('../src/integrations/mcp/resources.mjs');
  const root = fixtureRoot();
  runFixture(root);
  const runDir = join('.audit', 'run-1');
  const list = listResources();
  assert.equal(list[0].uri, 'legion://run/report');
  assert.equal(list[0].mimeType, 'application/json');
  assert.throws(() => readResource({ uri: 'legion://other', run: runDir }, { root }), /unknown resource/);
  assert.throws(() => readResource({ uri: 'legion://run/report', run: '..' }, { root }), /escapes host root/);
  const read = readResource({ uri: 'legion://run/report', run: runDir }, { root });
  assert.equal(read.contents[0].uri, 'legion://run/report');
  assert.equal(JSON.parse(read.contents[0].text).findings[0].id, 'f-1');
  assert.throws(() => readResource({ uri: 'legion://run/report', run: runDir }, { root, maxBytes: 8 }), /exceeds configured limit/);
});
