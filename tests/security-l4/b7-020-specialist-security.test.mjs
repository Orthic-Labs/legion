// B7-020 Part 1: specialist security packs (mobile, smart-contract,
// embedded-iot, ics-ot). Repository/configuration-backed lexical/model
// detectors only. Proves: every emitted candidate states its
// scope/hazards/assumptions/authorityLimits; parser presence alone never
// raises a pack's support tier or produces a clean/certified claim; the
// required domain rule categories are each covered; no pack imports a
// live-probe-capable builtin or calls fetch(); no rule/claim/hazard string
// asserts certification or regulatory compliance.

import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { runSecurityPack } from '../../providers/security/candidate-engine.mjs';
import { entity } from '../../providers/security/model-extractors/common.mjs';
import { extractMobile } from '../../providers/security/model-extractors/mobile.mjs';
import mobilePack from '../../providers/security/packs/mobile.mjs';
import smartContractPack from '../../providers/security/packs/smart-contract.mjs';
import embeddedIotPack from '../../providers/security/packs/embedded-iot.mjs';
import icsOtPack from '../../providers/security/packs/ics-ot.mjs';

const PACKS = [mobilePack, smartContractPack, embeddedIotPack, icsOtPack];

const registryPath = fileURLToPath(new URL('../../registry/rules/security/specialist.json', import.meta.url));
const registry = JSON.parse(readFileSync(registryPath, 'utf8'));

const PACK_FILES = {
  'security.mobile': fileURLToPath(new URL('../../providers/security/packs/mobile.mjs', import.meta.url)),
  'security.smart-contract': fileURLToPath(new URL('../../providers/security/packs/smart-contract.mjs', import.meta.url)),
  'security.embedded-iot': fileURLToPath(new URL('../../providers/security/packs/embedded-iot.mjs', import.meta.url)),
  'security.ics-ot': fileURLToPath(new URL('../../providers/security/packs/ics-ot.mjs', import.meta.url)),
};

const BINDING = {
  planDigest: 'sha256:plan', repositoryRevision: 'rev', dirtyPatchDigest: null,
  cortexGenerationId: 'gen', cortexManifestDigest: 'sha256:manifest', registryDigest: 'sha256:registry',
};

function planFor(pack, files) {
  return {
    seal: { digest: BINDING.planDigest },
    binding: {
      repositoryRevision: BINDING.repositoryRevision, dirtyPatchDigest: null,
      cortex: { generationId: BINDING.cortexGenerationId, manifestDigest: BINDING.cortexManifestDigest },
      registryDigest: BINDING.registryDigest,
    },
    providers: [{
      id: pack.id,
      benchmark: { requiredForCleanClaim: true },
      denominator: { pathDigest: 'sha256:denom', pathCount: files.length, paths: files },
    }],
  };
}

function baseModel(files, { extraEntities = [], extraRelations = [] } = {}) {
  const entities = [];
  const evidence = [];
  for (const file of files) {
    const evidenceRef = `ev:${file}`;
    entities.push(entity('repository-artifact', file, { path: file }, [evidenceRef]));
    evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Repository artifact' });
  }
  entities.push(...extraEntities);
  return {
    schemaVersion: 1, kind: 'security-surface-model', binding: BINDING, denominatorDigest: 'sha256:denom',
    complete: true, entities, relations: extraRelations, initialFacts: [], evidence, coverage: {}, coverageGaps: [],
  };
}

function run(pack, sourceByFile, options = {}) {
  const files = Object.keys(sourceByFile);
  const plan = planFor(pack, files);
  const model = options.model ?? baseModel(files, options);
  const projection = { files, sourceText: sourceByFile, auditFacts: options.auditFacts ?? {} };
  return runSecurityPack({ pack, root: '/repo', plan, projection, model, providerPlan: plan.providers[0] });
}

// Builds a full security-surface-model the way the real pipeline would:
// extractCommon-style repository artifacts plus the real extractMobile()
// output, so the mobile pack is exercised against genuine extractor entities
// rather than a hand-rolled substitute.
function mobileModel(sourceByFile) {
  const files = Object.keys(sourceByFile);
  const projection = { sourceText: sourceByFile, auditFacts: { packageManifests: [{ path: 'package.json', dependencies: ['react-native'], scripts: [] }] } };
  const extracted = extractMobile({ root: '/repo', plan: {}, projection, files, lensRegistry: null });
  const entities = [];
  const evidence = [...extracted.evidence];
  for (const file of files) {
    const evidenceRef = `ev:${file}`;
    entities.push(entity('repository-artifact', file, { path: file }, [evidenceRef]));
    evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Repository artifact' });
  }
  entities.push(...extracted.entities);
  return {
    schemaVersion: 1, kind: 'security-surface-model', binding: BINDING, denominatorDigest: 'sha256:denom',
    complete: true, entities, relations: extracted.relations, initialFacts: extracted.initialFacts, evidence,
    coverage: {}, coverageGaps: extracted.coverageGaps,
  };
}

function runMobile(sourceByFile) {
  const files = Object.keys(sourceByFile);
  const plan = planFor(mobilePack, files);
  const model = mobileModel(sourceByFile);
  const projection = { files, sourceText: sourceByFile, auditFacts: {} };
  return runSecurityPack({ pack: mobilePack, root: '/repo', plan, projection, model, providerPlan: plan.providers[0] });
}

// ---------------------------------------------------------------------------
// Registry <-> pack rule-id parity (both directions).
// ---------------------------------------------------------------------------

test('specialist.json registry and the four specialist packs are in exact rule-id parity', () => {
  assert.equal(registry.schemaVersion, 1);
  const registryIds = new Set(registry.rules.map((r) => r.id));
  const packIds = new Set(PACKS.flatMap((pack) => pack.rules.map((r) => r.id)));
  for (const id of packIds) assert.ok(registryIds.has(id), `registry is missing pack rule ${id}`);
  for (const id of registryIds) assert.ok(packIds.has(id), `registry has an orphan rule ${id} not exported by any specialist pack`);
  assert.equal(registryIds.size, packIds.size);
  for (const rule of registry.rules) {
    assert.equal(typeof rule.version, 'string');
    assert.equal(rule.tier, 'measured', `${rule.id} must be registered at the measured tier`);
    assert.ok(Array.isArray(rule.requiredControls));
    assert.ok(Array.isArray(rule.applicability) && rule.applicability.length > 0);
  }
});

// ---------------------------------------------------------------------------
// Support tier is a frozen constant — parser/file-type presence never
// raises it, and no pack claims certification.
// ---------------------------------------------------------------------------

test('every specialist pack is frozen at the measured support tier', () => {
  for (const pack of PACKS) assert.equal(pack.supportTier, 'measured');
});

test('parser-presence-only fixtures (domain file type, zero risky pattern) do not raise the tier or emit a clean/certified claim', () => {
  const fixtures = [
    [mobilePack, { 'android/app/src/main/AndroidManifest.xml': '<manifest></manifest>' }],
    [smartContractPack, { 'contracts/Empty.sol': 'pragma solidity ^0.8.0;\ncontract Empty {}' }],
    [embeddedIotPack, { 'firmware/main.c': 'int main(void) { return 0; }' }],
    [icsOtPack, { 'ot/topology.yaml': 'services:\n  app:\n    image: node' }],
  ];
  for (const [pack, source] of fixtures) {
    const result = run(pack, source);
    assert.equal(pack.supportTier, 'measured', `${pack.id} tier changed after a parser-only fixture`);
    assert.equal(result.candidates.length, 0, `${pack.id} must not fire on a parser-only fixture`);
    assert.equal(result.status, 'pass');
    assert.notEqual(result.status, 'certified');
  }
});

// ---------------------------------------------------------------------------
// mobile.mjs: entity-consuming rules (permissions, deep links, exported
// components, WebView bridge, backup, transport) exercised through the real
// extractMobile() output.
// ---------------------------------------------------------------------------

const dangerousManifest = `
  <manifest>
    <uses-permission android:name="android.permission.CAMERA" />
    <application android:allowBackup="true" android:usesCleartextTraffic="true">
      <activity android:exported="true">
        <intent-filter>
          <data android:scheme="myapp" />
        </intent-filter>
      </activity>
    </application>
  </manifest>
`;
const bridgeSource = '@ReactMethod\npublic void call() { addJavascriptInterface(obj, "Android"); }';

test('mobile pack flags a dangerous permission, deep link, exported component, backup, and cleartext from real extractor entities', () => {
  const result = runMobile({
    'android/app/src/main/AndroidManifest.xml': dangerousManifest,
    'android/app/src/main/java/Bridge.java': bridgeSource,
  });
  const byRule = (id) => result.candidates.filter((c) => c.ruleId === id);
  assert.ok(byRule('mobile.permission.dangerous-declared').length >= 1, 'dangerous permission');
  assert.ok(byRule('mobile.deep-link.entrypoint-unvalidated').length >= 1, 'deep link');
  assert.ok(byRule('mobile.exported-component.no-permission-gate').length >= 1, 'exported component');
  assert.ok(byRule('mobile.webview.js-bridge-exposed').length >= 1, 'webview bridge');
  assert.ok(byRule('mobile.backup.enabled-without-exclusion').length >= 1, 'backup');
  assert.ok(byRule('mobile.transport.cleartext-allowed').length >= 1, 'cleartext');
  for (const candidate of result.candidates) {
    assert.equal(candidate.verdict, 'UNADJUDICATED');
    assert.ok(candidate.evidenceRefs.length > 0, `${candidate.ruleId} must carry evidence`);
  }
});

test('mobile pack mitigation: stripped permission, verified app link, permission-gated component, allowlisted bridge, enforced backup produce no/downgraded candidates', () => {
  const mitigatedManifest = `
    <manifest>
      <uses-permission android:name="android.permission.CAMERA" tools:node="remove" />
      <application android:allowBackup="false">
        <activity android:exported="true" android:permission="com.app.PERMISSION_GATE">
          <intent-filter android:autoVerify="true">
            <data android:scheme="myapp" />
          </intent-filter>
        </activity>
      </application>
    </manifest>
  `;
  const mitigatedBridge = '@ReactMethod\npublic void call() { if (originWhitelist.contains(origin)) addJavascriptInterface(obj, "Android"); }';
  const result = runMobile({
    'android/app/src/main/AndroidManifest.xml': mitigatedManifest,
    'android/app/src/main/java/Bridge.java': mitigatedBridge,
  });
  assert.ok(!result.candidates.some((c) => c.ruleId === 'mobile.permission.dangerous-declared'), 'stripped permission must not fire');
  assert.ok(!result.candidates.some((c) => c.ruleId === 'mobile.exported-component.no-permission-gate'), 'permission-gated component must not fire');
  assert.ok(!result.candidates.some((c) => c.ruleId === 'mobile.backup.enabled-without-exclusion'), 'enforced backup must not fire');
  const deepLink = result.candidates.find((c) => c.ruleId === 'mobile.deep-link.entrypoint-unvalidated');
  assert.ok(deepLink, 'deep link still fires (verification is a downgrade signal, not a suppression)');
  assert.equal(deepLink.severityHint, 'medium');
  const bridge = result.candidates.find((c) => c.ruleId === 'mobile.webview.js-bridge-exposed');
  assert.ok(bridge, 'bridge still fires (allowlist is a downgrade signal, not a suppression)');
  assert.equal(bridge.severityHint, 'medium');
});

test('mobile bench regression fixture (no exported=true) yields zero candidates', () => {
  const result = run(mobilePack, { 'app.ts': '<activity android:name=".MainActivity" />' });
  assert.equal(result.candidates.length, 0);
});

// ---------------------------------------------------------------------------
// mobile.mjs: lexical-only rules (insecure storage, signing config).
// ---------------------------------------------------------------------------

test('mobile pack flags insecure sensitive-data storage and debug signing in release, clean by default', () => {
  const positive = run(mobilePack, {
    'auth.js': 'localStorage.setItem("authToken", token);',
  });
  assert.ok(positive.candidates.some((c) => c.ruleId === 'mobile.storage.insecure-sensitive-data'));

  const mitigatedStorage = run(mobilePack, {
    'auth.js': 'SecureStore.setItemAsync("authToken", token); // expo-secure-store',
  });
  assert.ok(!mitigatedStorage.candidates.some((c) => c.ruleId === 'mobile.storage.insecure-sensitive-data'));

  const signingPositive = run(mobilePack, {
    'app/build.gradle': 'android {\n  buildTypes {\n    release {\n      signingConfig signingConfigs.debug\n    }\n  }\n}',
  });
  assert.ok(signingPositive.candidates.some((c) => c.ruleId === 'mobile.signing.debug-config-in-release'));

  const signingClean = run(mobilePack, {
    'app/build.gradle': 'android {\n  buildTypes {\n    release {\n      signingConfig signingConfigs.release\n    }\n  }\n}',
  });
  assert.ok(!signingClean.candidates.some((c) => c.ruleId === 'mobile.signing.debug-config-in-release'));

  const clean = run(mobilePack, { 'neutral.mjs': 'export const value = 1;' });
  assert.equal(clean.candidates.length, 0);
});

// ---------------------------------------------------------------------------
// smart-contract.mjs: access control, reentrancy, oracle, upgradeability,
// signature/replay — one positive + one mitigated fixture each.
// ---------------------------------------------------------------------------

const smartContractFixtures = [
  {
    ruleId: 'smart-contract.access-control.tx-origin-authorization',
    positive: 'function withdraw() public { require(tx.origin == owner); payable(msg.sender).transfer(1); }',
    mitigated: 'function withdraw() public { require(msg.sender == owner); payable(msg.sender).transfer(1); }',
  },
  {
    ruleId: 'smart-contract.access-control.privileged-function-unprotected',
    positive: 'function mint(address to, uint amount) external { _mint(to, amount); }',
    mitigated: 'function mint(address to, uint amount) external onlyOwner { _mint(to, amount); }',
  },
  {
    ruleId: 'smart-contract.reentrancy.external-call-before-guard',
    positive: 'function withdraw() external { (bool ok, ) = msg.sender.call{value: balance}(""); }',
    mitigated: 'function withdraw() external nonReentrant { (bool ok, ) = msg.sender.call{value: balance}(""); }',
  },
  {
    ruleId: 'smart-contract.oracle.single-source-price-trust',
    positive: 'function price() public view returns (int) { return feed.latestAnswer(); }',
    mitigated: 'function price() public view returns (int) { (, int p,, uint updatedAt,) = feed.latestRoundData(); require(block.timestamp - updatedAt < heartbeat); return p; }',
  },
  {
    ruleId: 'smart-contract.upgradeability.unprotected-upgrade-authorization',
    positive: 'function _authorizeUpgrade(address newImpl) internal override {}',
    mitigated: 'function _authorizeUpgrade(address newImpl) internal override onlyOwner {}',
  },
  {
    ruleId: 'smart-contract.signature.replay-missing-nonce',
    positive: 'function claim(bytes32 h, uint8 v, bytes32 r, bytes32 s) external { address signer = ecrecover(h, v, r, s); }',
    mitigated: 'function claim(bytes32 h, uint8 v, bytes32 r, bytes32 s, uint nonce) external { require(!used[nonce]); address signer = ecrecover(h, v, r, s); }',
  },
];

test('smart-contract pack covers access-control, reentrancy, oracle, upgradeability, and signature/replay categories', () => {
  for (const fixture of smartContractFixtures) {
    const positive = run(smartContractPack, { 'Contract.sol': `pragma solidity ^0.8.0;\ncontract C {\n  ${fixture.positive}\n}` });
    const candidate = positive.candidates.find((c) => c.ruleId === fixture.ruleId);
    assert.ok(candidate, `${fixture.ruleId} did not fire on its positive fixture`);
    assert.equal(candidate.verdict, 'UNADJUDICATED');
    assert.ok(candidate.evidenceRefs.length > 0);

    const mitigated = run(smartContractPack, { 'Contract.sol': `pragma solidity ^0.8.0;\ncontract C {\n  ${fixture.mitigated}\n}` });
    assert.ok(!mitigated.candidates.some((c) => c.ruleId === fixture.ruleId), `${fixture.ruleId} still fired on its mitigated fixture`);
  }
});

test('smart-contract pack emits nothing for a non-Solidity file even with a risky-looking pattern', () => {
  const result = run(smartContractPack, { 'notes.md': 'require(tx.origin == owner);' });
  assert.equal(result.candidates.length, 0);
});

// ---------------------------------------------------------------------------
// embedded-iot.mjs: firmware update, debug interface, credentials, identity.
// ---------------------------------------------------------------------------

const embeddedFixtures = [
  {
    ruleId: 'embedded-iot.firmware.update-without-signature-verification',
    positive: 'void applyOta() { firmware_download(url); flash_image(buf); }',
    mitigated: 'void applyOta() { firmware_download(url); if (!verify_signature(buf, sha256)) return; flash_image(buf); }',
  },
  {
    ruleId: 'embedded-iot.debug-interface.enabled-in-production-build',
    positive: '#define DEBUG_SHELL_ENABLED 1',
    mitigated: '#ifdef DEBUG_BUILD\n#define DEBUG_SHELL_ENABLED 1\n#endif',
  },
  {
    ruleId: 'embedded-iot.credentials.hardcoded-secret',
    positive: 'char wifi_pass[] = "SuperSecretWifi123";',
    mitigated: 'char wifi_pass[] = getenv("WIFI_PASS");',
  },
  {
    ruleId: 'embedded-iot.identity.shared-static-device-key',
    positive: 'const char* DEVICE_SECRET "shared-across-every-unit-000";',
    mitigated: 'const char* DEVICE_SECRET secure_element_read(); // per-device provisioning via ATECC',
  },
];

test('embedded-iot pack covers firmware-update, debug-interface, credential, and identity categories', () => {
  for (const fixture of embeddedFixtures) {
    const positive = run(embeddedIotPack, { 'firmware/main.c': fixture.positive });
    const candidate = positive.candidates.find((c) => c.ruleId === fixture.ruleId);
    assert.ok(candidate, `${fixture.ruleId} did not fire on its positive fixture`);
    assert.ok(candidate.evidenceRefs.length > 0);

    const mitigated = run(embeddedIotPack, { 'firmware/main.c': fixture.mitigated });
    assert.ok(!mitigated.candidates.some((c) => c.ruleId === fixture.ruleId), `${fixture.ruleId} still fired on its mitigated fixture`);
  }
});

// ---------------------------------------------------------------------------
// ics-ot.mjs: authorization, segmentation, update-policy.
// ---------------------------------------------------------------------------

const icsFixtures = [
  {
    ruleId: 'ics-ot.authorization.unauthenticated-write-command',
    positive: 'function setPoint(v) { plc.writeRegister(40001, v); }',
    mitigated: 'function setPoint(v) { if (!isAuthorized(user)) return; plc.writeRegister(40001, v); }',
  },
  {
    ruleId: 'ics-ot.segmentation.ot-bridged-to-corporate-network',
    positive: '// scada gateway bridges to corporate network for reporting',
    mitigated: '// scada gateway bridges to corporate network for reporting, behind a firewall DMZ',
  },
  {
    ruleId: 'ics-ot.update-policy.unsigned-plc-firmware-push',
    positive: '// plc firmware push tool: deploy new logic to controller',
    mitigated: '// plc firmware push tool: deploy new logic to controller after signature verify',
  },
];

test('ics-ot pack covers authorization, segmentation, and update-policy categories', () => {
  for (const fixture of icsFixtures) {
    const positive = run(icsOtPack, { 'ot/control.js': fixture.positive });
    const candidate = positive.candidates.find((c) => c.ruleId === fixture.ruleId);
    assert.ok(candidate, `${fixture.ruleId} did not fire on its positive fixture`);
    assert.ok(candidate.evidenceRefs.length > 0);

    const mitigated = run(icsOtPack, { 'ot/control.js': fixture.mitigated });
    assert.ok(!mitigated.candidates.some((c) => c.ruleId === fixture.ruleId), `${fixture.ruleId} still fired on its mitigated fixture`);
  }
});

// ---------------------------------------------------------------------------
// Cross-cutting: scope/hazards/assumptions/authorityLimits are present and
// non-empty on every candidate every specialist pack emits.
// ---------------------------------------------------------------------------

const ALL_POSITIVE_FIXTURES = [
  [mobilePack, { 'auth.js': 'localStorage.setItem("authToken", token);' }],
  [smartContractPack, { 'C.sol': 'pragma solidity ^0.8.0;\ncontract C { function withdraw() public { require(tx.origin == owner); } }' }],
  [embeddedIotPack, { 'firmware/main.c': 'char wifi_pass[] = "SuperSecretWifi123";' }],
  [icsOtPack, { 'ot/control.js': 'function setPoint(v) { plc.writeRegister(40001, v); }' }],
];

test('every specialist candidate states a non-empty static/runtime scope, hazards, assumptions, and authority limits', () => {
  let total = 0;
  for (const [pack, source] of ALL_POSITIVE_FIXTURES) {
    const result = run(pack, source);
    assert.ok(result.candidates.length > 0, `${pack.id} fixture produced no candidates to check`);
    for (const candidate of result.candidates) {
      total += 1;
      const meta = candidate.detectorMetadata;
      assert.ok(meta.scope && typeof meta.scope.static === 'boolean' && typeof meta.scope.runtime === 'boolean', `${candidate.ruleId} missing scope.static/runtime`);
      assert.ok(typeof meta.scope.description === 'string' && meta.scope.description.length > 0, `${candidate.ruleId} missing scope.description`);
      assert.ok(Array.isArray(meta.hazards) && meta.hazards.length > 0, `${candidate.ruleId} missing non-empty hazards`);
      assert.ok(Array.isArray(meta.assumptions) && meta.assumptions.length > 0, `${candidate.ruleId} missing non-empty assumptions`);
      assert.ok(Array.isArray(meta.authorityLimits) && meta.authorityLimits.length > 0, `${candidate.ruleId} missing non-empty authorityLimits`);
    }
  }
  assert.ok(total >= ALL_POSITIVE_FIXTURES.length);
});

// ---------------------------------------------------------------------------
// No offensive/live capability; no certification/compliance claim language.
// ---------------------------------------------------------------------------

const FORBIDDEN_IMPORTS = ['node:http', 'node:https', 'node:net', 'node:dgram', 'node:child_process', 'node:serialport', 'serialport', 'usb'];

test('no specialist pack imports a live-probe-capable builtin, a serial/USB library, or calls fetch(', () => {
  for (const [name, path] of Object.entries(PACK_FILES)) {
    const source = readFileSync(path, 'utf8');
    for (const forbidden of FORBIDDEN_IMPORTS) {
      assert.ok(!source.includes(`'${forbidden}'`) && !source.includes(`"${forbidden}"`), `${name} must not import ${forbidden}`);
    }
    assert.ok(!/\bfetch\s*\(/.test(source), `${name} must not call fetch(`);
  }
});

test('no rule, claim, or detectorMetadata string in any specialist pack asserts certification or regulatory compliance', () => {
  const forbidden = /\bcertif|\bcomplian/i;
  for (const [pack, source] of ALL_POSITIVE_FIXTURES) {
    const result = run(pack, source);
    for (const candidate of result.candidates) {
      assert.ok(!forbidden.test(candidate.claim), `${candidate.ruleId} claim uses certification/compliance language`);
      const meta = candidate.detectorMetadata;
      for (const field of [meta.hazards, meta.assumptions, meta.authorityLimits]) {
        for (const str of field) assert.ok(!forbidden.test(str), `${candidate.ruleId} metadata uses certification/compliance language: ${str}`);
      }
    }
  }
  for (const rule of registry.rules) {
    assert.ok(!forbidden.test(rule.id), `registry rule id ${rule.id} uses certification/compliance language`);
  }
});

// ---------------------------------------------------------------------------
// variantStrategies shape.
// ---------------------------------------------------------------------------

test('every specialist pack declares a variantStrategy with rootCause/enumerate for every rule', () => {
  for (const pack of PACKS) {
    for (const rule of pack.rules) {
      const strategy = pack.variantStrategies[rule.id];
      assert.ok(strategy, `${pack.id} missing variant strategy for ${rule.id}`);
      assert.equal(typeof strategy.rootCause, 'function');
      assert.equal(typeof strategy.enumerate, 'function');
    }
  }
});

