#!/usr/bin/env node
/**
 * Installed parity gate. The executable is intentionally not overrideable: only
 * the installer-owned stable current path can qualify installed behavior.
 */
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { brotliDecompressSync } from 'node:zlib';
import {
  DEFAULT_MAX_OUTPUT_BYTES,
  DEFAULT_TIMEOUT_MS,
  evaluateParityRow,
  createSandbox,
  installedExecutablePath,
  loadManifest,
  removeSandbox,
  resolveEvidencePath,
  runBounded,
  sha256,
  snapshotSandbox,
  sourceIdentity,
  summarizeResults,
  validateExecutableProvenance,
  validateInstalledSkillLinks,
  validateNormalization,
} from './gate.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIXTURE_INDEX = resolve(ROOT, 'tests', 'native-cli-characterization', 'fixtures.json');
const NODE_BASELINES = resolve(ROOT, 'tests', 'native-cli-characterization', 'node-baselines.br.json');
const OUT_DIR = resolve(ROOT, 'dist', 'native-cli', 'installed-parity');

const frozen = JSON.parse(readFileSync(NODE_BASELINES, 'utf8'));
const baselines = JSON.parse(brotliDecompressSync(Buffer.from(frozen.payload, frozen.encoding === 'brotli-base64' ? 'base64' : 'utf8')));
function readBaseline(id) { return baselines[id] ?? null; }

function main() {
  const manifest = loadManifest(FIXTURE_INDEX);
  const source = sourceIdentity(ROOT);
  const stable = installedExecutablePath(process.env);
  const installedPluginRoot = realpathSync.native(resolve(stable.currentRoot, 'plugin'));
  const provenance = validateExecutableProvenance({
    executable: stable.executable,
    evidencePath: resolveEvidencePath(process.env, ROOT),
    manifestSha256: manifest.manifestSha256,
    source,
    mode: 'installed',
  });
  mkdirSync(OUT_DIR, { recursive: true });
  const results = [];
  for (const { fixture, id, fixtureSha256 } of manifest.rows) {
    validateNormalization(fixture);
    const baseline = readBaseline(id);
    const sandbox = createSandbox(ROOT, fixture);
    try {
      const before = snapshotSandbox(sandbox);
      const observation = runBounded(stable.executable, fixture.argv, {
        cwd: sandbox.cwd,
        env: sandbox.env,
        timeoutMs: fixture.timeoutMs ?? DEFAULT_TIMEOUT_MS,
        maxOutputBytes: fixture.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES,
      });
      const after = snapshotSandbox(sandbox);
      const record = {
        schemaVersion: 2,
        kind: 'legion-installed-parity-row',
        id,
        fixtureSha256,
        manifestSha256: manifest.manifestSha256,
        source,
        executable: stable.executable,
        executableSha256: provenance.executableSha256,
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
        tempRoots: [ROOT, resolve(stable.currentRoot, 'plugin'), installedPluginRoot, `\\\\?\\${installedPluginRoot}`, ...sandbox.tempRoots, ...(baseline?.sandboxRoots ?? [])] }));
      if (id === 'harness-install-codex') {
        const installedRootProblems = validateInstalledSkillLinks(record.filesystem, resolve(installedPluginRoot, 'skills'), ROOT);
        record.installedRootAssertion = { requiredRoot: resolve(installedPluginRoot, 'skills'), forbiddenRoot: ROOT, problems: installedRootProblems };
        if (installedRootProblems.length) {
          record.status = 'mismatched';
          record.mismatch.push(...installedRootProblems);
        }
      }
      writeFileSync(resolve(OUT_DIR, `${id}.json`), `${JSON.stringify(record, null, 2)}\n`);
      results.push({ id, fixtureSha256, status: record.status, comparison: record.comparison, mismatch: record.mismatch });
    } finally { removeSandbox(sandbox); }
  }
  const summary = {
    schemaVersion: 2,
    kind: 'legion-installed-parity',
    evidenceRole: 'installed-current-qualifying-parity',
    qualifying: false,
    manifest: { sha256: manifest.manifestSha256, rowCount: manifest.rowCount, rowIds: manifest.rowIds },
    source,
    executable: stable.executable,
    provenance,
    ...summarizeResults(results, { rowIds: manifest.rowIds, rowCount: manifest.rowCount }),
  };
  writeFileSync(resolve(OUT_DIR, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
  console.log(JSON.stringify(summary, null, 2));
  if (!summary.qualifying) process.exitCode = 1;
}

if (resolve(process.argv[1] ?? '') === fileURLToPath(import.meta.url)) main();
