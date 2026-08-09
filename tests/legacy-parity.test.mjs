import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { sourceSliceQualification } from '../lib/qualification/source-slice.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const legacySourceRoot = resolve(root, '..', '..', '..');
const LEGACY_TREE = '52a90cf0^';
const LEGACY_PATHS = [
  ['tools/skills/audit/', ''],
  ['tools/skills/audit-fix/', 'audit-fix/'],
  ['tools/skills/audit-visual/', 'audit-visual/'],
  ['tools/skills/_audit/', '_audit/'],
];

// Frozen from root commit 52a90cf0^ after translating audit skill paths into
// the standalone Legion checkout. This keeps legacy parity testable offline.
const LEGACY_BLOBS = [
  ['_audit/capability-aliases.json', '12649b2258e87d7d3d0db37526cc81c0774b4a53'],
  ['_audit/compatibility-matrix.json', 'aae0fcf603dfa72d1a8dad2dce24dacbe646ba02'],
  ['_audit/evals.schema.json', '68152f45dd4dae375ac6d87a314c2c8e79619ff3'],
  ['_audit/golden/skill-discovery.json', 'e9f7b97a668fe10ed8b2a488e4c1e2eebabb0af3'],
  ['_audit/MAINTAINERS.md', 'fd56c300c3fca47165ff2b710a27a17176570703'],
  ['_audit/migrate_evals.py', '64396ab189c3ab9a9b97f5a0388fb4c8e0bccb25'],
  ['_audit/model-eval-runs/20260508-232250-model-evals.json', '5fbc2e5a0d12d6efb413ae586e4ad5a284aa1c03'],
  ['_audit/model-eval-runs/20260508-232255-model-evals.json', '3f80e5598a9ecaafddd79e1a838a7014d931de5e'],
  ['_audit/model-eval-runs/20260508-232310-model-evals.json', '0a35313718726f98c892b49059a85ba0dcd3440d'],
  ['_audit/model-eval-runs/20260508-232416-model-evals.json', 'aa6b71bdd757b346ef5fe4579d10f7fe180df8b7'],
  ['_audit/model-eval-runs/20260508-232559-model-evals.json', '54b01fc601f1ed0f3a41c8d79899a569ff9bff6d'],
  ['_audit/model-eval-runs/20260508-232607-model-evals.json', '01b348103c3e182929264a10448d8305b95b6fff'],
  ['_audit/priority_snapshot.py', '50df85c6c22ea56e24b4280bc75f6a17eb852326'],
  ['_audit/README.md', 'b7d9495ca84184375461e5dfebb77ba708de1417'],
  ['_audit/review-checklist.md', '4ecb5988f9ea661b6063c5b5af33fd49c9b7c70f'],
  ['_audit/run_evals.py', '0996ee0fe2cb57942c3a1f1ae1a2be8f3625b2be'],
  ['_audit/security_scan_skills.py', '579bde140406847a56e10d21c482ed298b68e086'],
  ['_audit/seed_skill_evals.py', '6cfa79db357daa045ed0a3599c7270c05de289d7'],
  ['_audit/snapshots/20260508-231603-discovery.json', 'd3a3988385251169383f8bb8ebb1df584d5b432b'],
  ['_audit/snapshots/20260508-231603-skill-priority.json', '8e79d222d8db09eb93d9a4139b458e14e95f4221'],
  ['_audit/snapshots/20260508-231939-post-remediation-discovery.json', 'df0350cfc86310e201e541bdca5a0ea78b5ab9d6'],
  ['_audit/snapshots/20260508-231939-post-remediation-priority.json', 'ba6d0ffcfad35cb8a691ac65939f06d8e23f5427'],
  ['_audit/test_audit_harness.py', 'bf26f793abff0f5628cec54f47db51f88d412f28'],
  ['_audit/test_skill_regression_contracts.py', '041d328c0def45cb7ef06569e4c509cb59ea4695'],
  ['_audit/validate_skills.py', '6446688d92a61441ff5cf087832e5a2fbb3eaa40'],
  ['_selfcheck/clean.html', '86c5ef8d8ad5010775a45217d4bbf5886cacc798'],
  ['_selfcheck/perf.html', '1a19f8e2fc7012e0252f8e60f9efc79ab66f6178'],
  ['adapters/cortex-projection.mjs', '57cbb7f0e85331b0b0ce433501ca7c2ff742450b'],
  ['adapters/ecosystem-manifests.mjs', '016b559207f798d7f7be71264470ea130b8f34b3'],
  ['adapters/security-adjudication.mjs', '8a540a4517c442ef0a99b81a1e99b8e011746552'],
  ['audit_provider.py', '52b46d1404f44f292aaa02711a152266c0898c3c'],
  ['audit_store.py', '9ddcdbb2e04bf55628ff6dee29814c8a261ff1a3'],
  ['audit-complete.mjs', '565ba0defefe84d22f039115e61a33915f675cd0'],
  ['audit-finalize.mjs', 'f162fa29caa0724ac7aa269985c0e84b2186bd63'],
  ['audit-fix/SKILL.md', '3140c40d63ad7fd0f960fae372808c804bae81ea'],
  ['audit-plan.mjs', 'a3b5887755e4ca1a450677a07c9e4c166d9ad669'],
  ['audit-run.mjs', '60c4ea8a99da433ff3f00eb942f04415f8508cca'],
  ['audit-runtime.mjs', '5bac6f1b98cbb2d01f60956a763f1e234e998c30'],
  ['audit-verify.mjs', '0f4d282c174d902283caa97e69ffe1db6372746b'],
  ['audit-visual/evals/evals.json', 'c3ee69880e22494afef92ab4a79d65d4ecd9d550'],
  ['audit-visual/references/craft-tests.md', '31a4a72f421c95eef4bd6188236050cc16f40f68'],
  ['audit-visual/references/design-slop.md', '1276af258c17dd03afa3d26984c3b2be0889cacd'],
  ['audit-visual/references/manual.md', '9984dd835dbce1f9075b6be1a0bce3d5d552b19e'],
  ['audit-visual/references/motion-standards.md', '4d0d1314eec1216e18b420047e33b97d1f6dd24b'],
  ['audit-visual/references/native-feedback.md', 'b8d22dc6b5dfec2ea97bb3227b2c5d3d8985231d'],
  ['audit-visual/references/performance.md', 'ed85c9746fc28e3a7428b03cd75c0e3495b78f3f'],
  ['audit-visual/references/platform-fidelity.md', 'f5a56d0e6a56f1ac2c3b3e4f25908d6c4a92035b'],
  ['audit-visual/references/specialist-lenses.md', 'bdcbc2ee124efbfb96799ef5d44feaab6911d5ad'],
  ['audit-visual/references/surfaces.md', '8c526afe661a787ccd0387d3799c0f5991fc2e3b'],
  ['audit-visual/references/typography.md', '0cdf8e5d62b83965bb248941e5580250c70061ff'],
  ['audit-visual/references/ui-ux-checklist.md', '92c594e290dc3fc53b1dfa06c34f0ab0d0ae7c32'],
  ['audit-visual/references/visual-qa-capture.md', '7de43fc92462d651ac32f933040bd51c722bf2e2'],
  ['audit-visual/references/website-conversion-standards.md', '7b5b8801a56fd868ee5ac95d956d9a5372c41623'],
  ['audit-visual/references/website-regression-gotchas.md', 'd2d54ad75bfbf51c298c94991102a59b75c0e186'],
  ['audit-visual/SKILL.md', '197c0007fd30d436568d7bc09d9d61cced64b3d4'],
  ['bench/detectors/dead-code.mjs', '576a899c13e45bd2b5bd8d4166f0ef8e1d8aa73b'],
  ['bench/detectors/deps-cve.mjs', 'bb27d404a1776944842aa32dc527d8ac25b7d44d'],
  ['bench/detectors/drift.mjs', '054cb6b893c31deabc18109e3acc16b5563d7b4f'],
  ['bench/detectors/duplication.mjs', 'b50926567400d518c470a8cca013c0df56e97a34'],
  ['bench/detectors/secrets.mjs', '581680f6492bdbc0d0bdd9b21c579dbca6086bf7'],
  ['bench/detectors/types.mjs', 'b5abe1db656f4e4f8ce494cb912a8c29ceccedd6'],
  ['bench/fixtures/001-hardcoded-secret/app.js', '2f809dee995f39ded7909aa2aeb5166fa362afe6'],
  ['bench/fixtures/002-negative-apikey-label/app.js', '4bb508bd4841de934060910cd572a9c305dd0e6a'],
  ['bench/fixtures/003-vulnerable-dep/package.json', '0464be150a56ed77e57ef5f71de162d9ddd12b43'],
  ['bench/fixtures/004-negative-dep-latest/package.json', 'f0af07e046c62ac10e6089770e3cfafef4780ac3'],
  ['bench/fixtures/005-dead-code/app.js', '82fe874bb4a27429b20e36cca703627054fd3ee7'],
  ['bench/fixtures/006-negative-reachable/app.js', 'd7791265eab7d752c6fe85e47fa6f22f03f16106'],
  ['bench/fixtures/007-duplicated-logic/app.js', '743d533f7476ae35db71f4f7774c88034a7dafce'],
  ['bench/fixtures/008-negative-similar-shape/app.js', '2b5ca8d966c9d5b2b532b313ffccc4d8f4ab2712'],
  ['bench/fixtures/009-type-error/app.ts', '02d260445cd451dcce4fd403bb7ec42f0a6571ec'],
  ['bench/fixtures/010-negative-commented-credential/app.js', '15f150a1cfab04afd1648fb00eed9555b4327f39'],
  ['bench/fixtures/011-doc-drift/client.js', '9df387bde6c541cc79237e09d1c85cc72b96ca83'],
  ['bench/fixtures/011-doc-drift/README.md', '096772fdc2f36ac3d3b3415b68b3da7fdad46962'],
  ['bench/fixtures/012-negative-doc-matches/client.js', 'a7ed98e6c1f421a6c6261ca731c0fdebd6810901'],
  ['bench/fixtures/012-negative-doc-matches/README.md', '9382d426eb0244fec6ddec386e36b6c31953d576'],
  ['bench/fixtures/013-negative-type-ok/app.ts', 'db17729c84932aa8a4c3735add882a56a523d7ee'],
  ['bench/manifest.json', '9afb8cbf3e5c08d17a0e8bf508017ffe6c8e310b'],
  ['bench/precision-recall.mjs', '7055c9a60d6626a7a74fbc31e8cfbfc055167469'],
  ['bench/real-scan.mjs', '9cf72d0da63a937e89d71637a566cae2108c9f7f'],
  ['bench/run-bench.mjs', '362db778b852819909bf428ab93cf44ffdb5dff8'],
  ['bench/run-provider-selection-benchmark.mjs', '3094ad494aee26ea28c400c5ed0359baf4a6497e'],
  ['collect-facts.mjs', 'd3e9b9cf93fd80df1a336e7051a6f854fa574a51'],
  ['evals/evals.json', '6e862d44595060d7b63d0ac79725f0ab598c98f5'],
  ['evals/ground_truth/labeled_samples.json', 'd4d58e1993f6dfb76d6da2a1efae3ebaea0f0930'],
  ['manifest.json', 'c2c0768e2d0c51620f8a3b2d1c377a8918e37199'],
  ['providers/accessibility-suite.mjs', '0d0b057b5059d7abe017294f8ce42a722d96330b'],
  ['providers/data-suite.mjs', 'c6b686da5ba3ff2faae93137b9db714774588bcd'],
  ['providers/framework-suite.mjs', '8ba4cdcf8beb63ac767823cea285efacddda90eb'],
  ['providers/generic-source-suite.mjs', '3f74da275cd91dbd925aeae59127b28b14a8995d'],
  ['providers/infrastructure-suite.mjs', '9ae3d54c50a03f26a7dd48488030a12a4e7ad921'],
  ['providers/native-family-runner.mjs', 'd5d7c2aec516bdc97a708ca9e5f48e36d426422b'],
  ['providers/security-suite.mjs', '786aa4df5992ff1cd44757e4fd080ce9b9e97156'],
  ['providers/visual-core.mjs', 'd92ead1b4b2f0807f242b7e161e693577aa9b755'],
  ['references/a11y-checklist.md', 'da1fa2993033e7e3f4bfef98d6738165fdf7a4bc'],
  ['references/coverage-and-trajectory.md', 'a1be11079494fa9b1235229e1007f9415efe5ad5'],
  ['references/desktop-tauri-checklist.md', 'bac6f495982c3f06acfe6632ce303dc78999f37e'],
  ['references/engine-interface.md', '97aded7b0ee169ada7b05dc119b3a2f03eadfe87'],
  ['references/lens-cues.md', '5c680ae5aaf92b43faa7c5eace6784ddcd5469ee'],
  ['references/lens-routing.md', '8c202a2a534194a9e6839e6355ce5da47d3fa2a6'],
  ['references/manual.md', '42c0234f255399ddcb9ff22fbb3a7232236a7d6f'],
  ['references/migration-safety.md', '9dd573becbf2fb9429f43e0ca38fbb5e5cb06a2e'],
  ['references/performance-checklist.md', 'eaafbfd12710aa0e2f32d6e7bfb1312f536d0111'],
  ['references/ponytail-lens.md', '37aea3d0eef8664f5f37c35030b7503db68a3deb'],
  ['references/provider-architecture.md', '937b4cc9d613e38303b29dcb5df2481b9e3ad565'],
  ['references/security-checklist.md', '0158b1c96ded7849a8bb19eed941107d55d7149f'],
  ['references/sqlite-local-first.md', '27a44786e186d723394d4f67e943d6d7dc5ca280'],
  ['registry/provider-registry-complete.mjs', '3ef6198679a5a86d112b449970dd1831e069ff3b'],
  ['registry/provider-registry.mjs', '3275c50400a70efeb83481a24e304ad4b3552a9c'],
  ['registry/providers-runtime.json', 'caf380d412c7abfa6d49d25a6d1621a793bada82'],
  ['registry/providers.json', '4111e8d4310ea96c6eca37de50251f82c04a93f8'],
  ['render-report.mjs', '93e76a3ac9d378667507e00787cc5b2df10a0da5'],
  ['schemas/provider-result-v1.schema.json', '83c902256917a8f322356faf419afcf00b275f1a'],
  ['schemas/security-verdict-v1.schema.json', '43bc48499dde40117409531ecc5708ddfe2bd57a'],
  ['scripts/generate-manifest.mjs', '54a6ee41821671df9b4ba5dd38f5585e5d4aaa49'],
  ['scripts/normalize-provider-result.mjs', '2974faa2bac7f16e9dae5af5cd3e53ad34fecae5'],
  ['scripts/report-to-sarif.mjs', 'f5853f9cf315da80f2cfb5bafd2cf9434bed53a8'],
  ['scripts/self-test.mjs', '5af5018ae0135a6a8a9dc4b8189a3e4567305cc4'],
  ['security-pipeline.mjs', '79b0aec9def7a289d105adfde8ccb1bbb38b9926'],
  ['SKILL.md', '5142555452604a8d635ddcb506862b0e2b4cb582'],
  ['tests/accessibility-suite.test.mjs', '7cf492ea83a9b1ba66519b94dbb63b8b17da26ab'],
  ['tests/audit-finalize.test.mjs', '469cdbb044f2a45293981c133f3998913bb9c29e'],
  ['tests/decomposition-report.test.mjs', 'ae24d8e406129ca42abb54559592760c62a78e10'],
  ['tests/end-to-end-provider.test.mjs', 'd1d2c37eaf7269c03206e19a15fa4da112443fe1'],
  ['tests/framework-suite.test.mjs', 'a0fd3a4ef805d8bc40db4b002a9b6795861f04fa'],
  ['tests/generic-source-suite.test.mjs', '2c39d3856c61740bbf6efa07dd10294f6de8a22f'],
  ['tests/native-family-runner.test.mjs', 'c185bb3502ac243366ea6c66f1e785f58489351f'],
  ['tests/provider-architecture.test.mjs', 'e54e2d9b0184a56984b5c1e974c6116ee6629f31'],
  ['tests/provider-denominator-signature.test.mjs', '4856b93ee22bb1d453c00c10d71a20eb5346dbf7'],
  ['tests/prune-runs.test.mjs', '70bfcc0b1529caa7c3fc39c708b983a77770dabc'],
  ['tests/run-audit-conformance-tests.mjs', '199b77ccfccd55f277daf9b4b8d8cb30d3719a90'],
  ['tests/security-candidate-aggregation.test.mjs', '3595b72fe9a072d2c4975aae4b25e879bee276dd'],
  ['tests/security-pipeline.test.mjs', '1e6b34731ca334e6a0240d01455413563eb0443e'],
  ['tests/security-suite.test.mjs', '59d31fd88386bfee39833a5bf08df43997ec0704'],
  ['tests/visual-core.test.mjs', 'b3608fb2b1b6df4e65bac1df4815735c6a9d271d'],
  ['UPGRADE-PLAN.md', '7f3da60c7eaed71f3d45c5f920e0d77d20bf94b0'],
];

function gitBlobOid(file) {
  return execFileSync('git', ['hash-object', file], { cwd: root, encoding: 'utf8' }).trim();
}

function derivedLegacyBlobs() {
  const output = execFileSync('git', [
    '-C', legacySourceRoot, 'ls-tree', '-r', LEGACY_TREE, '--',
    'tools/skills/audit', 'tools/skills/audit-fix', 'tools/skills/audit-visual', 'tools/skills/_audit',
  ], { encoding: 'utf8' });
  return output.trim().split('\n').map((line) => {
    const match = /^(?:\d+) blob ([0-9a-f]{40})\t(.+)$/.exec(line);
    assert.ok(match, `unexpected legacy tree line: ${line}`);
    const [, oid, source] = match;
    const prefix = LEGACY_PATHS.find(([legacyPath]) => source.startsWith(legacyPath));
    assert.ok(prefix, `unexpected legacy source path: ${source}`);
    return [`${prefix[1]}${source.slice(prefix[0].length)}`, oid];
  }).sort(([left], [right]) => left.localeCompare(right));
}

function legacyRecords() {
  return LEGACY_BLOBS.map(([path, legacyBlob]) => {
    const file = join(root, path);
    const currentBlob = existsSync(file) ? gitBlobOid(file) : null;
    return { path, legacyBlob, currentBlob, status: currentBlob ? 'mapped' : 'blocked' };
  });
}

test('all 135 legacy paths remain in standalone Legion', () => {
  if (existsSync(join(legacySourceRoot, '.git'))) {
    assert.deepEqual(LEGACY_BLOBS, derivedLegacyBlobs(), 'embedded legacy mappings must match 52a90cf0^');
  }
  const records = legacyRecords();
  assert.equal(records.length, 135);
  assert.ok(LEGACY_BLOBS.every(([, oid]) => /^[0-9a-f]{40}$/.test(oid)), 'legacy OIDs are full Git blob IDs');
  assert.deepEqual(records.filter((record) => !record.currentBlob).map((record) => record.path), []);
  // Re-baselined 2026-08-09 (105/30 -> 104/31): `_audit/capability-aliases.json` legitimately
  // evolved when the retired skills it aliased were removed (/justdoit -> /alchemist,
  // /test-author -> /audit contract-tests). Every path still exists; only byte-parity moved.
  assert.equal(records.filter((record) => record.currentBlob === record.legacyBlob).length, 104);
  assert.equal(records.filter((record) => record.currentBlob !== record.legacyBlob).length, 31);
});

test('source completion reports legacy mappings without source blockers', () => {
  const records = legacyRecords();
  const receipt = sourceSliceQualification({
    book: 0,
    expectedTaskCount: 1,
    tasks: [{ id: 'S1-001', status: 'implemented', mapping: 'legacy parity' }],
    sourceRecords: records,
  });
  assert.deepEqual(receipt.sourceCompletion, { total: 135, mapped: 135, blocked: 0, missing: 0 });
});

test('source qualification fails closed for blocked tasks or source records', () => {
  const externalBlocker = { id: 'hardware-proof', kind: 'external-hardware' };
  const blockedTask = sourceSliceQualification({
    book: 0,
    expectedTaskCount: 1,
    tasks: [{ id: 'S1-blocked-task', status: 'blocked' }],
    blockers: [externalBlocker],
  });
  assert.equal(blockedTask.decision, 'BLOCKED');
  assert.deepEqual(blockedTask.externalGates, ['hardware-proof']);

  const blockedSource = sourceSliceQualification({
    book: 0,
    expectedTaskCount: 1,
    tasks: [{ id: 'S1-blocked-source', status: 'implemented' }],
    sourceRecords: [{ path: 'missing.mjs', currentBlob: null, status: 'blocked' }],
    blockers: [externalBlocker],
  });
  assert.equal(blockedSource.decision, 'BLOCKED');
  assert.deepEqual(blockedSource.sourceCompletion, { total: 1, mapped: 0, blocked: 1, missing: 1 });
  assert.deepEqual(blockedSource.externalGates, ['hardware-proof']);
});

test('source qualification rejects malformed, missing, mismatched, or escaping records', () => {
  const repositoryRoot = mkdtempSync(join(tmpdir(), 'legion-source-records-'));
  const externalBlocker = { id: 'hardware-proof', kind: 'external-hardware' };
  writeFileSync(join(repositoryRoot, 'claimed.mjs'), 'export const claimed = true;\n');
  const cases = [
    [{ path: 'claimed.mjs', status: 'mapped', currentBlob: 'not-a-git-object' }, 'current-blob-oid-invalid'],
    [{ path: 'absent.mjs', status: 'mapped', currentBlob: '0000000000000000000000000000000000000000' }, 'source-path-not-found'],
    [{ path: 'claimed.mjs', status: 'mapped', currentBlob: '0000000000000000000000000000000000000000' }, 'current-blob-oid-mismatch'],
    [{ path: '../outside.mjs', status: 'mapped', currentBlob: '0000000000000000000000000000000000000000' }, 'source-path-outside-root'],
  ];
  try {
    for (const [record, reason] of cases) {
      const receipt = sourceSliceQualification({
        book: 0,
        expectedTaskCount: 1,
        tasks: [{ id: `S1-${reason}`, status: 'implemented' }],
        sourceRecords: [record],
        blockers: [externalBlocker],
        root: repositoryRoot,
      });
      assert.equal(receipt.decision, 'BLOCKED', reason);
      assert.equal(receipt.sourceCompletion.mapped, 0, reason);
      assert.equal(receipt.sourceCompletion.blocked, 1, reason);
      assert.ok(receipt.sourceBlockers.some((blocker) => blocker.reason === reason), reason);
      assert.deepEqual(receipt.externalGates, ['hardware-proof'], reason);
    }
  } finally {
    rmSync(repositoryRoot, { recursive: true, force: true });
  }
});
