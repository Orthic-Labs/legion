import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  DEPENDENCY_CLASSES, classifyResource, loadCapabilityRegistry,
  scanPackagedText, verifyManifestConsumers, verifyCapabilityAliases, verifyDependencyClosure,
} from '../src/lib/skills/dependency-closure.mjs';

const packageRoot = resolve(import.meta.dirname, '..');
const capabilities = loadCapabilityRegistry(packageRoot).capabilities;

test('the registry declares a degradation for every capability', () => {
  for (const [name, entry] of Object.entries(capabilities)) {
    assert.ok(entry.degradation, `${name} declares no degradation`);
    assert.ok(entry.kind, `${name} declares no kind`);
  }
});

test('every dependency class is documented in the registry', () => {
  const documented = Object.keys(loadCapabilityRegistry(packageRoot).classes);
  for (const klass of DEPENDENCY_CLASSES) assert.ok(documented.includes(klass), `${klass} is undocumented`);
});

test('a bare string is not a typed resource', () => {
  const result = classifyResource('references/manual.md', { packageRoot, skillRoot: packageRoot, capabilities });
  assert.equal(result.ok, false);
  assert.equal(result.code, 'untyped-resource');
});

test('an unresolved TODO cannot masquerade as a resource', () => {
  const findings = scanPackagedText('TODO: no in-package equivalent for providers/x.py', {
    path: 'references/route.md', skillRoot: packageRoot, packageRoot,
  });
  assert.ok(findings.some((finding) => finding.code === 'unresolved-marker'));
});

test('a HOST_CAPABILITY must be declared in the registry', () => {
  assert.equal(classifyResource({ class: 'HOST_CAPABILITY', capability: 'banana' },
    { packageRoot, skillRoot: packageRoot, capabilities }).ok, true);
  const undeclared = classifyResource({ class: 'HOST_CAPABILITY', capability: 'not-a-capability' },
    { packageRoot, skillRoot: packageRoot, capabilities });
  assert.equal(undeclared.ok, false);
  assert.equal(undeclared.code, 'undeclared-capability');
});

test('a PROJECT_OVERLAY must be optional and state its absent behaviour', () => {
  const mandatory = classifyResource({ class: 'PROJECT_OVERLAY', path: '<project-overlay>/x.md' },
    { packageRoot, skillRoot: packageRoot, capabilities });
  assert.equal(mandatory.code, 'mandatory-overlay');
  const silent = classifyResource({ class: 'PROJECT_OVERLAY', path: '<project-overlay>/x.md', optional: true },
    { packageRoot, skillRoot: packageRoot, capabilities });
  assert.equal(silent.code, 'undeclared-degradation');
  const concrete = classifyResource({ class: 'PROJECT_OVERLAY', path: 'D:/workspace/x.md', optional: true, absent: 'skip' },
    { packageRoot, skillRoot: packageRoot, capabilities });
  assert.equal(concrete.code, 'concrete-overlay-path');
  assert.equal(classifyResource({ class: 'PROJECT_OVERLAY', path: '<project-overlay>/x.md', optional: true, absent: 'skip' },
    { packageRoot, skillRoot: packageRoot, capabilities }).ok, true);
});

test('a PACKAGE_INTERNAL must exist and stay inside the package', () => {
  assert.equal(classifyResource({ class: 'PACKAGE_INTERNAL', path: 'package.json' },
    { packageRoot, skillRoot: packageRoot, capabilities }).ok, true);
  assert.equal(classifyResource({ class: 'PACKAGE_INTERNAL', path: 'no/such/file.md' },
    { packageRoot, skillRoot: packageRoot, capabilities }).code, 'missing-internal');
  assert.equal(classifyResource({ class: 'PACKAGE_INTERNAL', path: '../../etc/passwd' },
    { packageRoot, skillRoot: packageRoot, capabilities }).code, 'escapes-package');
});





test('a document may not promise a script the package does not ship', () => {
  const findings = scanPackagedText('run `scripts/ghost.mjs` to finish', {
    path: 'GUIDE.md', skillRoot: join(packageRoot, 'skills/audit'), packageRoot,
  });
  assert.ok(findings.some((finding) => finding.code === 'dangling-script'));
});

test('prose placeholders are not read as script promises', () => {
  const findings = scanPackagedText('paths look like `scripts/xxx.sh`', {
    path: 'GUIDE.md', skillRoot: join(packageRoot, 'skills/audit'), packageRoot,
  });
  assert.deepEqual(findings, []);
});

test('a manifest may not declare a consumer that no longer exists', () => {
  const findings = verifyManifestConsumers(packageRoot, {
    social: { id: 'social', parity: { consumers: ['registry/skills/index.json'] } },
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].code, 'stale-consumer');
  assert.deepEqual(verifyManifestConsumers(packageRoot, {
    social: { id: 'social', parity: { consumers: ['src/registry/skills/index.json'] } },
  }), []);
});

test('a route table of bare strings fails closure', () => {
  const root = mkdtempSync(join(tmpdir(), 'closure-'));
  try {
    mkdirSync(join(root, 'src/registry'), { recursive: true });
    mkdirSync(join(root, 'skills/demo/references'), { recursive: true });
    writeFileSync(join(root, 'src/registry/capabilities.json'), JSON.stringify({
      schemaVersion: 1, kind: 'legion-capability-registry', classes: {},
      capabilities: { demo: { kind: 'tool', summary: 'demo', degradation: 'skip' } },
    }));
    writeFileSync(join(root, 'skills/demo/references/route-resources.json'),
      JSON.stringify({ providers: { web: ['references/manual.md'] } }));
    const { ok, findings } = verifyDependencyClosure({
      packageRoot: root, manifests: { demo: { id: 'demo', parity: { consumers: [] } } },
    });
    assert.equal(ok, false);
    assert.ok(findings.some((finding) => finding.code === 'untyped-resource'));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('every shipped capability alias routes to a skill that exists', () => {
  assert.deepEqual(verifyCapabilityAliases(packageRoot), []);
});

test('an alias to a removed skill is a finding', () => {
  const root = mkdtempSync(join(tmpdir(), 'alias-'));
  try {
    mkdirSync(join(root, 'src/config'), { recursive: true });
    mkdirSync(join(root, 'skills/designer'), { recursive: true });
    writeFileSync(join(root, 'skills/designer/SKILL.md'), '# designer');
    writeFileSync(join(root, 'src/config/capability-aliases.json'), JSON.stringify({
      aliases: { '/glass': '/designer glass', '/illustrate': '/content illustration', '/adapt': 'tool:adapt' },
    }));
    const findings = verifyCapabilityAliases(root);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].code, 'dangling-alias');
    assert.match(findings[0].detail, /\/illustrate/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('the shipped package is dependency-closed', async () => {
  const { readdirSync, readFileSync } = await import('node:fs');
  const manifestDir = join(packageRoot, 'skills/manifests');
  const manifests = Object.fromEntries(readdirSync(manifestDir)
    .filter((name) => name.endsWith('.json') && !name.endsWith('.import-receipt.json'))
    .map((name) => {
      const manifest = JSON.parse(readFileSync(join(manifestDir, name), 'utf8'));
      return [manifest.id, manifest];
    }));
  const { ok, findings } = verifyDependencyClosure({ packageRoot, manifests });
  assert.deepEqual(findings, []);
  assert.equal(ok, true);
});
