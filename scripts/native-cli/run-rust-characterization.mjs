#!/usr/bin/env node
/**
 * Native characterization gate. By default this is a current-tree gate and
 * requires build evidence binding the exact executable, source tree, and
 * frozen manifest. --diagnostic deliberately produces non-qualifying output.
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { brotliDecompressSync } from 'node:zlib';
import {
  DEFAULT_MAX_OUTPUT_BYTES,
  DEFAULT_TIMEOUT_MS,
  evaluateParityRow,
  createSandbox,
  developerExecutablePath,
  loadManifest,
  removeSandbox,
  resolveEvidencePath,
  runBounded,
  sha256,
  snapshotSandbox,
  sourceIdentity,
  summarizeResults,
  validateExecutableProvenance,
  validateNormalization,
} from './gate.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIXTURE_INDEX = resolve(ROOT, 'tests', 'native-cli-characterization', 'fixtures.json');
const NODE_BASELINES = resolve(ROOT, 'tests', 'native-cli-characterization', 'node-baselines.br.json');
const OUT_DIR = resolve(ROOT, 'dist', 'native-cli', 'rust-characterization');

const frozen = JSON.parse(readFileSync(NODE_BASELINES, 'utf8'));
const baselines = JSON.parse(brotliDecompressSync(Buffer.from(frozen.payload, frozen.encoding === 'brotli-base64' ? 'base64' : 'utf8')));
function readBaseline(id) { return baselines[id] ?? null; }

function semanticOracle(fixture, observation) {
  const expect = fixture.rustExpect ?? {};
  const mismatches = [];
  if (expect.exitCode !== undefined && observation.exitCode !== expect.exitCode) mismatches.push(`expected native exit ${expect.exitCode}, got ${observation.exitCode}`);
  for (const needle of expect.stdoutIncludes ?? []) if (!observation.stdout.includes(needle)) mismatches.push(`native stdout missing: ${needle}`);
  for (const needle of expect.stderrIncludes ?? []) if (!observation.stderr.includes(needle)) mismatches.push(`native stderr missing: ${needle}`);
  if (expect.kind) {
    try { if (JSON.parse(observation.stdout).kind !== expect.kind) mismatches.push(`expected native kind ${expect.kind}`); }
    catch { mismatches.push('native stdout is not JSON'); }
  }
  return mismatches;
}

function main() {
  const diagnostic = process.argv.includes('--diagnostic');
  const manifest = loadManifest(FIXTURE_INDEX);
  const source = sourceIdentity(ROOT);
  const executable = developerExecutablePath(process.env);
  const provenance = diagnostic ? { mode: 'diagnostic-developer', executable, evidenceRole: 'diagnostic-developer-capture' } : validateExecutableProvenance({
    executable,
    evidencePath: resolveEvidencePath(process.env, ROOT),
    manifestSha256: manifest.manifestSha256,
    source,
    mode: 'current-tree',
  });
  mkdirSync(OUT_DIR, { recursive: true });
  const results = [];
  for (const { fixture, id, fixtureSha256 } of manifest.rows) {
    validateNormalization(fixture);
    const baseline = readBaseline(id);
    const sandbox = createSandbox(ROOT, fixture);
    try {
      const before = snapshotSandbox(sandbox);
      const observation = runBounded(executable, fixture.argv, {
        cwd: sandbox.cwd,
        env: sandbox.env,
        timeoutMs: fixture.timeoutMs ?? DEFAULT_TIMEOUT_MS,
        maxOutputBytes: fixture.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES,
      });
      const after = snapshotSandbox(sandbox);
      const record = {
        schemaVersion: 2,
        kind: 'legion-rust-characterization-row',
        id,
        fixtureSha256,
        manifestSha256: manifest.manifestSha256,
        source,
        executable: provenance.executable ?? executable,
        executableSha256: diagnostic ? sha256(readFileSync(executable)) : provenance.executableSha256,
        argv: fixture.argv,
        cwd: fixture.cwd ?? '.',
        sandboxRoots: sandbox.tempRoots,
        exitCode: observation.exitCode,
        stdoutSha256: sha256(observation.stdout),
        stderrSha256: sha256(observation.stderr),
        stdout: observation.stdout,
        stderr: observation.stderr,
        error: observation.error,
        signal: observation.signal,
        timedOut: observation.timedOut,
        outputLimitExceeded: observation.outputLimitExceeded,
        filesystem: { before: before.value, after: after.value, beforeSha256: before.sha256, afterSha256: after.sha256 },
        mismatch: [],
        status: 'blocked',
      };
      Object.assign(record, evaluateParityRow({ fixture, record, baseline,
        manifestSha256: manifest.manifestSha256, fixtureSha256,
        tempRoots: [...sandbox.tempRoots, ...(baseline?.sandboxRoots ?? [])] }));
      if (record.status === 'matched' || record.status === 'mismatched') {
        record.mismatch.push(...semanticOracle(fixture, observation));
        record.status = record.mismatch.length ? 'mismatched' : 'matched';
      }
      writeFileSync(resolve(OUT_DIR, `${id}.json`), `${JSON.stringify(record, null, 2)}\n`);
      results.push({ id, fixtureSha256, status: record.status, comparison: record.comparison, mismatch: record.mismatch });
    } finally { removeSandbox(sandbox); }
  }
  const summary = {
    schemaVersion: 2,
    kind: 'legion-rust-characterization',
    evidenceRole: diagnostic ? 'diagnostic-developer-capture' : 'current-tree-qualifying-parity',
    qualifying: false,
    manifest: { sha256: manifest.manifestSha256, rowCount: manifest.rowCount, rowIds: manifest.rowIds },
    source,
    executable,
    provenance,
    ...summarizeResults(results, { rowIds: manifest.rowIds, rowCount: manifest.rowCount }),
  };
  summary.qualifying = !diagnostic && summary.qualifying;
  writeFileSync(resolve(OUT_DIR, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
  console.log(JSON.stringify(summary, null, 2));
  if (!diagnostic && !summary.qualifying) process.exitCode = 1;
}

if (resolve(process.argv[1] ?? '') === fileURLToPath(import.meta.url)) main();
