import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  DEPENDENCY_CLASSES, classifyResource, loadCapabilityRegistry,
  parseDependencyDeclaration, scanHostCommandReferences, scanPackagedText,
  verifyManifestConsumers, verifyManifestCoverage, verifyCapabilityAliases, verifyDependencyClosure,
} from '../src/lib/skills/dependency-closure.mjs';
import { commandCapabilityMap } from '../src/lib/capabilities/registry.mjs';

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

test('every semantic bundle needs a canonical typed dependency declaration', () => {
  assert.throws(
    () => parseDependencyDeclaration('{"schemaVersion":1,"kind":"legion-skill-dependencies"}'),
    /resources must be an array/,
  );
  assert.throws(
    () => parseDependencyDeclaration('{"schemaVersion":1,"kind":"other","resources":[]}'),
    /unsupported schema/,
  );
});

test('a registry-owned command may not bypass hostRequirements', () => {
  const findings = scanHostCommandReferences('Run `pi --tools read -p` after `python3 worker.py`.', {
    path: 'SKILL.md', commandCapabilities: commandCapabilityMap(loadCapabilityRegistry(packageRoot)),
    hostRequirements: new Set(['python-runtime']),
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].code, 'undeclared-host-command');
  assert.match(findings[0].detail, /pi-cli/);
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

test('a semantic bundle cannot bypass closure by omitting its manifest', () => {
  const findings = verifyManifestCoverage(packageRoot, {});
  assert.ok(findings.some((finding) => finding.code === 'missing-skill-manifest' && finding.bundleId === 'coder'));
});

test('a route table of bare strings fails closure', () => {
  const root = mkdtempSync(join(tmpdir(), 'closure-'));
  try {
    mkdirSync(join(root, 'src/registry'), { recursive: true });
    mkdirSync(join(root, 'skills/demo/references'), { recursive: true });
    writeFileSync(join(root, 'src/registry/capabilities.json'), JSON.stringify({
      schemaVersion: 1, kind: 'legion-capability-registry', classes: {
        PACKAGE_INTERNAL: 'internal', HOST_CAPABILITY: 'host', PROJECT_OVERLAY: 'overlay', HISTORICAL_EVIDENCE: 'evidence',
      },
      capabilities: { demo: { kind: 'tool', summary: 'demo', degradation: 'skip', remedy: 'install demo' } },
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

test('dependencies and SKILL hostRequirements must agree for every bundle', () => {
  const root = mkdtempSync(join(tmpdir(), 'closure-requirements-'));
  try {
    mkdirSync(join(root, 'src/registry'), { recursive: true });
    mkdirSync(join(root, 'skills/demo'), { recursive: true });
    writeFileSync(join(root, 'src/registry/capabilities.json'), JSON.stringify({
      schemaVersion: 1,
      kind: 'legion-capability-registry',
      classes: { PACKAGE_INTERNAL: 'internal', HOST_CAPABILITY: 'host', PROJECT_OVERLAY: 'overlay', HISTORICAL_EVIDENCE: 'evidence' },
      capabilities: {
        'pi-cli': {
          kind: 'command-line-provider', summary: 'Pi', degradation: 'skip', remedy: 'install Pi',
          probe: { kind: 'command-any', commands: ['pi'] }, commands: ['pi'],
        },
      },
    }));
    writeFileSync(join(root, 'skills/demo/SKILL.md'), [
      '---', 'name: demo', 'description: demo', 'kind: entrypoint', 'discoverability: explicit',
      'operations:', '  - analyze', 'effects:', '  - source-read', 'hostRequirements:', '  - pi-cli', '---',
      '', 'Run `pi --tools read -p`.',
    ].join('\n'));
    writeFileSync(join(root, 'skills/demo/dependencies.json'), JSON.stringify({
      schemaVersion: 1, kind: 'legion-skill-dependencies', resources: [],
    }));
    const { findings } = verifyDependencyClosure({
      packageRoot: root, manifests: { demo: { id: 'demo', parity: { consumers: [] } } },
    });
    assert.ok(findings.some((finding) => finding.code === 'host-requirement-mismatch'));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a missing dependency declaration fails closure even without route-resources', () => {
  const root = mkdtempSync(join(tmpdir(), 'closure-missing-declaration-'));
  try {
    mkdirSync(join(root, 'src/registry'), { recursive: true });
    mkdirSync(join(root, 'skills/demo'), { recursive: true });
    writeFileSync(join(root, 'src/registry/capabilities.json'), JSON.stringify({
      schemaVersion: 1,
      kind: 'legion-capability-registry',
      classes: { PACKAGE_INTERNAL: 'internal', HOST_CAPABILITY: 'host', PROJECT_OVERLAY: 'overlay', HISTORICAL_EVIDENCE: 'evidence' },
      capabilities: {},
    }));
    const { findings } = verifyDependencyClosure({
      packageRoot: root, manifests: { demo: { id: 'demo', parity: { consumers: [] } } },
    });
    assert.ok(findings.some((finding) => finding.code === 'missing-dependency-declaration'));
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
  const { ok, findings, summary } = verifyDependencyClosure({ packageRoot, manifests });
  assert.deepEqual(findings, []);
  assert.equal(ok, true);
  assert.equal(summary.dependencyDeclarations, summary.semanticBundles);
  assert.ok(summary.typedResources > 0);
});
