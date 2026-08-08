// B7-006 — automation, package, update, and release extraction.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { extractAutomation } from '../../providers/security/model-extractors/automation.mjs';
import {
  ENTITY_KINDS,
  FACT_KINDS,
  RELATION_KINDS,
} from '../../providers/security/contracts.mjs';

const MODULE_PATH = new URL('../../providers/security/model-extractors/automation.mjs', import.meta.url);

function run(filesMap) {
  const files = Object.keys(filesMap).sort();
  const projection = { sourceText: filesMap };
  return extractAutomation({
    root: '/repo', plan: {}, projection, files, lensRegistry: {},
  });
}

function findEntity(model, predicate) {
  return model.entities.find(predicate);
}

function evidenceFiles(model, evidenceRefs) {
  return evidenceRefs.map((ref) => model.evidence.find((e) => e.id === ref)?.file);
}

function assertReferentialIntegrity(model) {
  const ids = new Set(model.entities.map((e) => e.id));
  for (const relation of model.relations) {
    assert.ok(ids.has(relation.from), `relation.from ${relation.from} must resolve to a known entity`);
    assert.ok(ids.has(relation.to), `relation.to ${relation.to} must resolve to a known entity`);
  }
  for (const collection of [model.entities, model.relations]) {
    for (const item of collection) {
      for (const ref of item.evidenceRefs) {
        assert.ok(model.evidence.some((e) => e.id === ref), `evidenceRef ${ref} must resolve to a known evidence entry`);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Source-level safety constraints.
// ---------------------------------------------------------------------------

test('the module performs no remote operation and reads no filesystem/network/process API', () => {
  const source = readFileSync(MODULE_PATH, 'utf8');
  for (const forbidden of ['node:child_process', 'node:http', 'node:https', 'node:net', 'node:fs']) {
    assert.ok(!source.includes(`'${forbidden}'`) && !source.includes(`"${forbidden}"`), `must not import ${forbidden}`);
  }
});

// ---------------------------------------------------------------------------
// Release trust path: workflow trigger -> step/sink -> identity -> artifact.
// ---------------------------------------------------------------------------

test('a fully-configured release workflow produces a complete, evidence-cited trust path with no unknown markers', () => {
  const file = '.github/workflows/release.yml';
  const text = [
    'name: Release',
    'on:',
    '  push:',
    '    tags:',
    "      - 'v*'",
    'permissions:',
    '  contents: write',
    '  id-token: write',
    'jobs:',
    '  release:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - uses: actions/checkout@v4',
    '      - uses: actions/cache@v4',
    '        with:',
    '          path: ~/.npm',
    '          key: npm-cache',
    '      - run: npm ci',
    '      - run: npm run build',
    '      - run: npm publish',
    '        env:',
    '          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}',
    '      - run: cosign sign dist/artifact.tgz',
    '      - uses: actions/upload-artifact@v4',
    '        with:',
    '          path: dist/',
  ].join('\n');

  const model = run({ [file]: text });
  assertReferentialIntegrity(model);

  const trigger = findEntity(model, (e) => e.kind === 'entrypoint' && e.attributes.entrypointType === 'release-trigger');
  const sink = findEntity(model, (e) => e.kind === 'sink' && e.name === `pipeline step ${file}`);
  const identity = findEntity(model, (e) => e.kind === 'identity' && e.name === `release identity ${file}`);
  const capability = findEntity(model, (e) => e.kind === 'tool-capability' && e.attributes.capabilityKind === 'package-publish');
  const artifact = findEntity(model, (e) => e.kind === 'asset' && e.attributes.assetKind === 'published-artifact');
  assert.ok(trigger && sink && identity && capability && artifact, 'the full chain must be present');

  // trigger -> step/sink -> identity -> published artifact.
  assert.ok(model.relations.some((r) => r.kind === 'executes' && r.from === trigger.id && r.to === sink.id));
  assert.ok(model.relations.some((r) => r.kind === 'runs-as' && r.from === sink.id && r.to === identity.id));
  assert.ok(model.relations.some((r) => r.kind === 'grants' && r.from === identity.id && r.to === capability.id));
  assert.ok(model.relations.some((r) => r.kind === 'publishes-to' && r.from === identity.id && r.to === artifact.id));

  // Configuration is fully resolved: permission scope, credential, and
  // publication target are all known, so no unknown-identity/permission gap.
  assert.deepEqual(identity.attributes.permissionScope, 'contents:write,id-token:write');
  assert.deepEqual(identity.attributes.credentialRefs, ['NPM_TOKEN']);
  assert.equal(artifact.attributes.publicationTarget, 'npm-registry');
  assert.equal(model.coverageGaps.some((g) => g.file === file), false);

  // Evidence cites the exact file for every entity/relation in the chain.
  for (const item of [trigger, sink, identity, capability, artifact]) {
    assert.deepEqual(new Set(evidenceFiles(model, item.evidenceRefs)), new Set([file]));
  }

  // Cache, signing control, and artifact flow are all captured.
  const cache = findEntity(model, (e) => e.kind === 'data-store' && e.attributes.dataStoreKind === 'build-cache');
  assert.ok(cache);
  assert.ok(model.relations.some((r) => r.kind === 'stores' && r.from === sink.id && r.to === cache.id));

  const signing = findEntity(model, (e) => e.kind === 'control' && e.attributes.controlType === 'signing');
  assert.equal(signing.attributes.controlState, 'present-unenforced');
  assert.ok(model.relations.some((r) => r.kind === 'protects' && r.from === signing.id && r.to === sink.id));

  const buildOutput = findEntity(model, (e) => e.kind === 'asset' && e.attributes.assetKind === 'build-artifact');
  assert.ok(model.relations.some((r) => r.kind === 'flows-to' && r.from === buildOutput.id && r.to === sink.id));

  // Secret reference is recorded as a fact, never a value.
  assert.ok(model.initialFacts.some((f) => f.kind === 'credential-possession' && f.object === 'NPM_TOKEN'));
  const secretFact = model.initialFacts.find((f) => f.kind === 'credential-possession' && f.object === 'NPM_TOKEN');
  assert.ok(JSON.stringify(secretFact).indexOf('${{') === -1, 'must never embed the raw templated value');
});

test('an unresolved permission scope and identity remain explicitly visible, never defaulted', () => {
  const file = '.github/workflows/release-no-perms.yml';
  const text = [
    'name: Manual Release',
    'on:',
    '  workflow_dispatch: {}',
    'jobs:',
    '  release:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - run: npm publish',
  ].join('\n');

  const model = run({ [file]: text });
  assertReferentialIntegrity(model);

  const identity = findEntity(model, (e) => e.kind === 'identity' && e.name === `release identity ${file}`);
  assert.equal(identity.attributes.permissionScope, 'unknown');
  assert.deepEqual(identity.attributes.credentialRefs, []);

  assert.ok(model.coverageGaps.some((g) => g.kind === 'unresolved-permission-scope' && g.file === file));
  assert.ok(model.coverageGaps.some((g) => g.kind === 'unresolved-identity' && g.file === file && g.entityId === identity.id));
  // The publish target is resolvable from the literal "npm publish" step, so
  // that dimension alone is not marked unknown -- only what is genuinely
  // unresolvable is.
  assert.equal(model.coverageGaps.some((g) => g.kind === 'unresolved-publication-target'), false);
});

test('untrusted-content triggers are modeled as hostile data crossing a trust boundary', () => {
  const file = '.github/workflows/fork-pr.yml';
  const text = [
    'name: PR Comment Handler',
    'on:',
    '  pull_request_target:',
    '    types: [opened]',
    'jobs:',
    '  comment:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - run: echo "handling PR"',
  ].join('\n');

  const model = run({ [file]: text });
  assertReferentialIntegrity(model);

  const hostileTrigger = findEntity(model, (e) => e.kind === 'entrypoint' && e.attributes.entrypointType === 'hostile-trigger');
  const boundary = findEntity(model, (e) => e.kind === 'trust-boundary' && e.attributes.boundaryType === 'untrusted-contribution');
  assert.ok(hostileTrigger && boundary);
  assert.ok(model.relations.some((r) => r.kind === 'crosses' && r.from === hostileTrigger.id && r.to === boundary.id));

  const attackerFact = model.initialFacts.find((f) => f.kind === 'attacker-position');
  assert.ok(attackerFact);
  assert.equal(attackerFact.subject, 'actor:external-contributor');
  assert.equal(attackerFact.object, file);
  assert.deepEqual(evidenceFiles(model, attackerFact.evidenceRefs), [file]);
});

// ---------------------------------------------------------------------------
// Package manifest: installers, dependencies, publish script, lockfile gap.
// ---------------------------------------------------------------------------

test('package manifest scripts, direct-URL dependencies, and a missing lockfile are all captured', () => {
  const file = 'package.json';
  const text = JSON.stringify({
    name: 'example-pkg',
    version: '1.0.0',
    private: false,
    scripts: {
      postinstall: 'curl -fsSL https://example.com/setup.sh | bash',
      publish: 'np',
    },
    publishConfig: { registry: 'https://registry.example.com' },
    dependencies: {
      'left-pad': '^1.3.0',
      'some-fork': 'git+https://github.com/example/some-fork.git',
    },
  });

  const model = run({ [file]: text });
  assertReferentialIntegrity(model);

  const installerSource = findEntity(model, (e) => e.kind === 'source' && e.attributes.sourceKind === 'network-fetch');
  const installerSink = findEntity(model, (e) => e.kind === 'sink' && e.attributes.sinkKind === 'shell');
  assert.ok(installerSource && installerSink);
  assert.ok(model.relations.some((r) => r.kind === 'flows-to' && r.from === installerSource.id && r.to === installerSink.id));
  assert.ok(model.initialFacts.some((f) => f.kind === 'capability' && f.action === 'execute-remote-script' && f.subject === installerSink.id));

  const identity = findEntity(model, (e) => e.kind === 'identity' && e.name === `release identity ${file}`);
  const artifact = findEntity(model, (e) => e.kind === 'asset' && e.attributes.assetKind === 'published-artifact');
  assert.equal(artifact.attributes.publicationTarget, 'https://registry.example.com');
  // A manifest alone never carries permission scope or a literal credential
  // -- both dimensions must remain explicitly unresolved, not defaulted.
  assert.equal(identity.attributes.permissionScope, 'unknown');
  assert.deepEqual(identity.attributes.credentialRefs, []);
  assert.ok(model.coverageGaps.some((g) => g.kind === 'unresolved-permission-scope' && g.file === file));
  assert.ok(model.coverageGaps.some((g) => g.kind === 'unresolved-identity' && g.file === file));

  const dependencySource = findEntity(model, (e) => e.kind === 'source' && e.attributes.sourceKind === 'direct-url-dependency');
  assert.ok(dependencySource);
  assert.equal(dependencySource.name, 'non-registry dependency some-fork');

  assert.ok(model.coverageGaps.some((g) => g.kind === 'missing-dependency-lockfile' && g.file === file));
});

test('a matching lockfile in the denominator suppresses the missing-lockfile gap and is itself modeled', () => {
  const files = {
    'package.json': JSON.stringify({ name: 'example-pkg', version: '1.0.0' }),
    'package-lock.json': JSON.stringify({ lockfileVersion: 3 }),
  };
  const model = run(files);
  assertReferentialIntegrity(model);

  assert.equal(model.coverageGaps.some((g) => g.kind === 'missing-dependency-lockfile'), false);
  const lockEntity = findEntity(model, (e) => e.kind === 'repository-artifact' && e.attributes.lockfile === true);
  assert.ok(lockEntity);
  assert.ok(model.initialFacts.some((f) => f.kind === 'capability' && f.action === 'pin-dependency-resolution' && f.subject === lockEntity.id));
});

test('an unparseable package manifest is recorded as a typed coverage gap, not silently skipped', () => {
  const file = 'apps/broken/package.json';
  const model = run({ [file]: '{ this is not valid json' });
  assert.deepEqual(model.entities, []);
  assert.deepEqual(model.coverageGaps, [{ kind: 'unparsed-automation-format', file, format: 'package.json' }]);
});

// ---------------------------------------------------------------------------
// Jenkinsfile: unparsed DSL format, still surfaces credential references.
// ---------------------------------------------------------------------------

test('a Jenkinsfile is recorded as an unparsed automation format while still surfacing credential references', () => {
  const file = 'Jenkinsfile';
  const text = [
    'node {',
    "  stage('Release') {",
    '    sh "curl -H \'Authorization: Bearer ${credentials(\'npm-token\')}\' https://registry.example.com/publish"',
    '  }',
    '}',
  ].join('\n');

  const model = run({ [file]: text });
  assertReferentialIntegrity(model);

  assert.ok(model.coverageGaps.some((g) => g.kind === 'unparsed-automation-format' && g.file === file && g.format === 'jenkinsfile'));
  assert.ok(model.initialFacts.some((f) => f.kind === 'credential-possession' && f.object === 'npm-token'));
});

// ---------------------------------------------------------------------------
// Dependency update automation (renovate/dependabot-style config).
// ---------------------------------------------------------------------------

test('scheduled dependency-update automation with automerge records the elevated capability and an unresolved scope gap', () => {
  const file = 'renovate.json';
  const text = JSON.stringify({ extends: ['config:base'], automerge: true });

  const model = run({ [file]: text });
  assertReferentialIntegrity(model);

  const identity = findEntity(model, (e) => e.kind === 'identity' && e.name === `dependency update bot identity ${file}`);
  assert.equal(identity.attributes.permissionScope, 'unknown');
  assert.ok(model.coverageGaps.some((g) => g.kind === 'unresolved-permission-scope' && g.file === file));
  assert.ok(model.initialFacts.some((f) => f.kind === 'capability' && f.action === 'auto-merge-dependency-update' && f.subject === identity.id));
});

// ---------------------------------------------------------------------------
// Release-tool config with nothing locally resolvable (all four gap kinds).
// ---------------------------------------------------------------------------

test('a release-tool config with no inline registry, credential, or permission info surfaces every unresolved dimension', () => {
  const file = '.releaserc.json';
  const text = JSON.stringify({ branches: ['main'], plugins: ['@semantic-release/npm'] });

  const model = run({ [file]: text });
  assertReferentialIntegrity(model);

  const gapKinds = new Set(model.coverageGaps.filter((g) => g.file === file).map((g) => g.kind));
  assert.ok(gapKinds.has('unresolved-permission-scope'));
  assert.ok(gapKinds.has('unresolved-identity'));
  assert.ok(gapKinds.has('unresolved-publication-target'));
  assert.ok(gapKinds.has('externally-configured-release-service'));
});

// ---------------------------------------------------------------------------
// Application auto-updater configuration: signature posture and update source.
// ---------------------------------------------------------------------------

test('an updater config with signature verification explicitly disabled records an absent control, not an unknown one', () => {
  const file = 'electron-builder.yml';
  const text = [
    'publish:',
    '  provider: generic',
    '  url: https://updates.example.com/',
    'verifyUpdateCodeSignature: false',
  ].join('\n');

  const model = run({ [file]: text });
  assertReferentialIntegrity(model);

  const signing = findEntity(model, (e) => e.kind === 'control' && e.attributes.controlType === 'signing');
  assert.equal(signing.attributes.controlState, 'absent');
  const capability = findEntity(model, (e) => e.kind === 'tool-capability' && e.attributes.capabilityKind === 'auto-update-execute');
  assert.ok(model.relations.some((r) => r.kind === 'protects' && r.from === signing.id && r.to === capability.id));
  const updateServer = findEntity(model, (e) => e.kind === 'service' && e.attributes.serviceKind === 'auto-update-endpoint');
  assert.ok(model.relations.some((r) => r.kind === 'retrieves-from' && r.from === capability.id && r.to === updateServer.id));
  assert.equal(model.coverageGaps.some((g) => g.file === file), false);
});

test('an updater config with no signature information at all leaves the signature posture explicitly unknown', () => {
  const file = 'app-update.yml';
  const text = ['provider: generic', 'url: https://updates.example.com/'].join('\n');

  const model = run({ [file]: text });
  const signing = findEntity(model, (e) => e.kind === 'control' && e.attributes.controlType === 'signing');
  assert.equal(signing.attributes.controlState, 'unknown');
  assert.ok(model.coverageGaps.some((g) => g.kind === 'unresolved-updater-signature-state' && g.file === file));
});

// ---------------------------------------------------------------------------
// .npmrc publication scope.
// ---------------------------------------------------------------------------

test('.npmrc with an auth token but no registry line leaves the publication target explicitly unresolved', () => {
  const file = 'packages/app/.npmrc';
  const model = run({ [file]: '_authToken=${NPM_TOKEN}\n' });
  const scope = findEntity(model, (e) => e.kind === 'permission-scope');
  assert.equal(scope.attributes.registry, 'unknown');
  assert.equal(scope.attributes.hasAuthToken, true);
  assert.ok(model.coverageGaps.some((g) => g.kind === 'unresolved-publication-target' && g.file === file));
  assert.ok(model.initialFacts.some((f) => f.kind === 'credential-possession' && f.subject === scope.id));
});

test('.npmrc with an explicit registry line resolves the publication target', () => {
  const file = '.npmrc';
  const model = run({ [file]: 'registry=https://registry.example.com/\n_authToken=${NPM_TOKEN}\n' });
  const scope = findEntity(model, (e) => e.kind === 'permission-scope');
  assert.equal(scope.attributes.registry, 'https://registry.example.com/');
  assert.equal(model.coverageGaps.some((g) => g.file === file), false);
});

// ---------------------------------------------------------------------------
// Dockerfile installer and publication-target flow.
// ---------------------------------------------------------------------------

test('a Dockerfile with a remote install pipe and a recognizable registry models both flows', () => {
  const file = 'Dockerfile';
  const text = [
    'FROM node:20-alpine',
    'RUN curl -fsSL https://get.example.com/install.sh | bash',
    'RUN npm ci',
    'LABEL registry=ghcr.io/example/app',
    'CMD ["node", "server.js"]',
  ].join('\n');

  const model = run({ [file]: text });
  assertReferentialIntegrity(model);

  const source = findEntity(model, (e) => e.kind === 'source' && e.attributes.sourceKind === 'network-fetch');
  const sink = findEntity(model, (e) => e.kind === 'sink' && e.attributes.sinkKind === 'shell');
  assert.ok(model.relations.some((r) => r.kind === 'flows-to' && r.from === source.id && r.to === sink.id));

  const image = findEntity(model, (e) => e.kind === 'asset' && e.attributes.assetKind === 'container-image');
  const registry = findEntity(model, (e) => e.kind === 'service' && e.attributes.serviceKind === 'container-registry');
  assert.ok(model.relations.some((r) => r.kind === 'publishes-to' && r.from === image.id && r.to === registry.id));
});

// ---------------------------------------------------------------------------
// Kind-vocabulary closure and determinism.
// ---------------------------------------------------------------------------

test('every produced kind belongs to the canonical security contracts vocabulary', () => {
  const model = run({
    '.github/workflows/release.yml': [
      'on:\n  push:\n    tags:\n      - v*',
      'permissions:\n  contents: write',
      'jobs:\n  release:\n    steps:\n      - run: npm publish',
    ].join('\n'),
    'package.json': JSON.stringify({ name: 'x', scripts: { postinstall: 'curl x | bash', publish: 'np' } }),
    'Jenkinsfile': "sh \"${credentials('id')}\"",
    'renovate.json': JSON.stringify({ automerge: true }),
    'electron-builder.yml': 'publish:\n  provider: generic\nverifyUpdateCodeSignature: false',
    '.npmrc': 'registry=https://registry.example.com/\n',
    'package-lock.json': '{}',
    'Dockerfile': 'FROM node\nRUN curl x | bash\nLABEL registry=ghcr.io/x',
  });

  for (const e of model.entities) assert.ok(ENTITY_KINDS.includes(e.kind), `unknown entity kind ${e.kind}`);
  for (const r of model.relations) assert.ok(RELATION_KINDS.includes(r.kind), `unknown relation kind ${r.kind}`);
  for (const f of model.initialFacts) assert.ok(FACT_KINDS.includes(f.kind), `unknown fact kind ${f.kind}`);
});

test('extraction is deterministic: identical input yields deeply-equal output on repeated calls', () => {
  const files = {
    '.github/workflows/release.yml': [
      'on:\n  push:\n    tags:\n      - v*',
      'permissions:\n  contents: write\n  id-token: write',
      'jobs:\n  release:\n    steps:\n      - run: npm publish\n        env:\n          T: ${{ secrets.NPM_TOKEN }}',
    ].join('\n'),
    '.github/workflows/fork-pr.yml': 'on:\n  pull_request_target:\njobs:\n  x:\n    steps:\n      - run: echo hi',
    'package.json': JSON.stringify({
      name: 'pkg', scripts: { postinstall: 'curl x | bash', publish: 'np' }, dependencies: { d: 'git+https://x/y.git' },
    }),
    'renovate.json': JSON.stringify({ automerge: true }),
    'Jenkinsfile': "sh \"${credentials('id')}\"",
  };

  const first = run(files);
  const second = run(files);
  assert.deepEqual(first, second);
});
