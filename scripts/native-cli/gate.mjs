import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve } from 'node:path';

export const DEFAULT_TIMEOUT_MS = 30_000;
export const DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
const SHA256 = /^[a-f0-9]{64}$/i;
const REVISION = /^[a-f0-9]{40,64}$/i;
const ALLOWED_NORMALIZATION_KEYS = new Set(['lineEndings', 'stackFrames', 'trailingWhitespace', 'timestamps', 'tempRoots']);
const NATIVE_ORACLE_KEYS = new Set(['exitCode', 'stdoutIncludes', 'stderrIncludes', 'kind', 'stdoutSha256', 'stderrSha256']);

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function sha256File(path) {
  return sha256(readFileSync(path));
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonical(value));
}

export function fixtureDigest(fixture) {
  return sha256(canonicalJson(fixture));
}

export function loadManifest(manifestPath) {
  const bytes = readFileSync(manifestPath);
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); } catch (error) { throw new Error(`manifest is invalid JSON: ${error.message}`); }
  if (!value || value.schemaVersion !== 1 || !Array.isArray(value.fixtures) || value.fixtures.length === 0) {
    throw new Error('manifest must be schemaVersion 1 with a non-empty fixtures array');
  }
  const seen = new Set();
  const rows = value.fixtures.map((fixture, index) => {
    if (!fixture || typeof fixture !== 'object' || typeof fixture.id !== 'string' || !fixture.id) throw new Error(`manifest row ${index} has no id`);
    if (seen.has(fixture.id)) throw new Error(`manifest row id is duplicated: ${fixture.id}`);
    seen.add(fixture.id);
    if (!Array.isArray(fixture.argv) || fixture.argv.some((arg) => typeof arg !== 'string')) throw new Error(`manifest row ${fixture.id} has invalid argv`);
    return { fixture, id: fixture.id, fixtureSha256: fixtureDigest(fixture) };
  });
  return {
    value,
    path: resolve(manifestPath),
    manifestSha256: sha256(bytes),
    rowCount: rows.length,
    rowIds: rows.map(({ id }) => id),
    rows,
  };
}

export function identityOfManifest(manifest) {
  return { manifestSha256: manifest.manifestSha256, rowCount: manifest.rowCount, rowIds: [...manifest.rowIds] };
}

function git(root, args) {
  try { return execFileSync('git', args, { cwd: root, encoding: 'utf8', windowsHide: true }); } catch { return ''; }
}

export function sourceIdentity(root) {
  const sourceRevision = git(root, ['rev-parse', 'HEAD']).trim().toLowerCase();
  if (!REVISION.test(sourceRevision)) throw new Error(`cannot determine current source revision for ${root}`);
  const paths = git(root, ['ls-files', '-z', '--cached', '--others', '--exclude-standard']).split('\0').filter(Boolean).sort();
  const digest = createHash('sha256');
  for (const path of paths) {
    const full = resolve(root, path);
    if (!existsSync(full) || !lstatSync(full).isFile() || lstatSync(full).isSymbolicLink()) continue;
    digest.update(path.replaceAll('\\', '/'));
    digest.update('\0');
    digest.update(readFileSync(full));
    digest.update('\0');
  }
  return { sourceRevision, sourceTreeSha256: digest.digest('hex') };
}

function stableRoot(path) {
  return resolve(path);
}

export function installedExecutablePath(env = process.env) {
  if (!env.LOCALAPPDATA) throw new Error('LOCALAPPDATA is required for installed qualification');
  const root = stableRoot(join(env.LOCALAPPDATA, 'Orthic Labs', 'Legion'));
  const current = stableRoot(join(root, 'current'));
  const executable = stableRoot(join(current, 'bin', 'legion.exe'));
  if (!existsSync(executable) || !lstatSync(executable).isFile() || lstatSync(executable).isSymbolicLink()) throw new Error(`stable installed executable is missing or unsafe: ${executable}`);
  return { installRoot: root, currentRoot: current, executable };
}

export function developerExecutablePath(env = process.env) {
  const candidate = env.LEGION_EXE;
  if (!candidate || !isAbsolute(candidate)) throw new Error('LEGION_EXE must be an absolute executable path for developer characterization');
  const path = resolve(candidate);
  if (!existsSync(path) || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) throw new Error(`developer executable is missing or unsafe: ${path}`);
  return path;
}

function getField(value, paths) {
  for (const path of paths) {
    let current = value;
    for (const part of path.split('.')) current = current?.[part];
    if (typeof current === 'string' && current) return current;
  }
  return null;
}

export function readEvidence(path) {
  if (!path || !existsSync(path) || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) throw new Error(`qualification evidence is missing or unsafe: ${path ?? '<unset>'}`);
  let value;
  try { value = JSON.parse(readFileSync(path, 'utf8')); } catch (error) { throw new Error(`qualification evidence is invalid JSON: ${error.message}`); }
  return { path: resolve(path), value, sha256: sha256File(path) };
}

export function validateExecutableProvenance({ executable, evidencePath, manifestSha256, source, mode = 'current-tree' }) {
  const evidence = readEvidence(evidencePath);
  const value = evidence.value;
  if (!['pass', 'qualified', 'verified'].includes(String(value.status ?? '').toLowerCase())) throw new Error('qualification evidence does not report a completed status');
  const sourceRevision = getField(value, ['sourceRevision', 'source_revision', 'build.sourceRevision']);
  const sourceTreeSha256 = getField(value, ['sourceTreeSha256', 'sourceTreeDigest', 'build.sourceTreeSha256']);
  const recordedManifest = getField(value, ['manifestSha256', 'manifest.sha256', 'behaviorManifestSha256', 'build.manifestSha256']);
  const recordedExecutable = getField(value, ['executableSha256', 'installedExecutableSha256', 'executable.sha256', 'build.executableSha256']);
  const recordedPath = getField(value, ['installedExecutable', 'executable.path', 'build.executablePath']);
  if (!sourceRevision || !REVISION.test(sourceRevision)) throw new Error('qualification evidence is missing a valid source revision');
  if (!sourceTreeSha256 || !SHA256.test(sourceTreeSha256)) throw new Error('qualification evidence is missing sourceTreeSha256');
  if (!recordedManifest || recordedManifest.toLowerCase() !== manifestSha256.toLowerCase()) throw new Error('qualification evidence manifest SHA-256 does not match frozen manifest');
  if (!recordedExecutable || !SHA256.test(recordedExecutable)) throw new Error('qualification evidence is missing executableSha256');
  const actualExecutable = sha256File(executable);
  if (recordedExecutable.toLowerCase() !== actualExecutable) throw new Error('qualification evidence executable SHA-256 does not match executable');
  const normalizedExecutable = resolve(executable);
  if (mode === 'installed') {
    const stable = installedExecutablePath({ LOCALAPPDATA: process.env.LOCALAPPDATA });
    if (normalizedExecutable !== stable.executable) throw new Error('installed qualification executable is not the installer-owned stable current executable');
    if (!recordedPath || resolve(recordedPath) !== normalizedExecutable) throw new Error('qualification evidence does not name the stable current executable');
    if (value.origin !== 'installed' && value.activation?.status?.origin !== 'installed') throw new Error('qualification evidence does not prove installed origin');
  } else if (recordedPath && resolve(recordedPath) !== normalizedExecutable) {
    throw new Error('qualification evidence executable path does not match requested executable');
  }
  if (source.sourceRevision && sourceRevision.toLowerCase() !== source.sourceRevision.toLowerCase()) throw new Error('qualification evidence source revision is not the current tree');
  if (source.sourceTreeSha256 && sourceTreeSha256.toLowerCase() !== source.sourceTreeSha256.toLowerCase()) throw new Error('qualification evidence source tree hash is not the current tree');
  return {
    path: evidence.path,
    receiptSha256: evidence.sha256,
    sourceRevision: sourceRevision.toLowerCase(),
    sourceTreeSha256: sourceTreeSha256.toLowerCase(),
    manifestSha256: recordedManifest.toLowerCase(),
    executableSha256: actualExecutable,
    executable: normalizedExecutable,
    mode,
  };
}

function normalizeText(value, normalization = {}, tempRoots = []) {
  if (!normalization || typeof normalization !== 'object') return String(value ?? '');
  for (const key of Object.keys(normalization)) if (!ALLOWED_NORMALIZATION_KEYS.has(key)) throw new Error(`unsupported normalization field: ${key}`);
  let text = String(value ?? '');
  if (normalization.lineEndings === true) text = text.replaceAll('\r\n', '\n').replaceAll('\r', '\n');
  if (normalization.trailingWhitespace === true) text = text.split('\n').map((line) => line.replace(/[ \t]+$/u, '')).join('\n');
  if (normalization.stackFrames === true) text = text.split('\n').filter((line) => !/^\s+at\s/u.test(line)).join('\n');
  if (normalization.timestamps === true) text = text.replace(/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z\b/gu, '<TIMESTAMP>');
  if (normalization.tempRoots === true) {
    for (const root of tempRoots.filter(Boolean).sort((a, b) => b.length - a.length)) {
      text = text.split(root).join('<TEMP_ROOT>');
      const jsonEscapedRoot = JSON.stringify(root).slice(1, -1);
      text = text.split(jsonEscapedRoot).join('<TEMP_ROOT>');
    }
  }
  return text;
}

function normalizeEvidenceValue(value, normalization, tempRoots) {
  if (typeof value === 'string') return normalizeText(value, normalization, tempRoots);
  if (Array.isArray(value)) return value.map((item) => normalizeEvidenceValue(item, normalization, tempRoots));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, normalizeEvidenceValue(item, normalization, tempRoots)]));
  }
  return value;
}

export function compareObservations(expected, actual, { fixture = {}, tempRoots = [] } = {}) {
  const mismatches = [];
  const baselineProblems = observationProblems(expected, 'baseline');
  const actualProblems = observationProblems(actual, 'native');
  if (baselineProblems.length) mismatches.push(...baselineProblems);
  if (actualProblems.length) mismatches.push(...actualProblems);
  if (baselineProblems.length || actualProblems.length) return mismatches;
  if (actual.exitCode !== expected.exitCode) mismatches.push(`exit ${actual.exitCode} != baseline ${expected.exitCode}`);
  const normalization = fixture.normalization ?? fixture.normalize ?? {};
  const expectedStdout = normalizeText(expected.stdout, normalization, tempRoots);
  const actualStdout = normalizeText(actual.stdout, normalization, tempRoots);
  const expectedStderr = normalizeText(expected.stderr, normalization, tempRoots);
  const actualStderr = normalizeText(actual.stderr, normalization, tempRoots);
  if (expectedStdout !== actualStdout) mismatches.push('stdout differs from baseline');
  if (expectedStderr !== actualStderr) mismatches.push('stderr differs from baseline');
  const expectedBefore = normalizeEvidenceValue(expected.filesystem.before, normalization, tempRoots);
  const actualBefore = normalizeEvidenceValue(actual.filesystem.before, normalization, tempRoots);
  const expectedAfter = normalizeEvidenceValue(expected.filesystem.after, normalization, tempRoots);
  const actualAfter = normalizeEvidenceValue(actual.filesystem.after, normalization, tempRoots);
  if (canonicalJson(expectedBefore) !== canonicalJson(actualBefore)) mismatches.push('filesystem mutation differs from baseline');
  if (canonicalJson(expectedAfter) !== canonicalJson(actualAfter)) mismatches.push('filesystem mutation differs from baseline');
  return mismatches;
}

function normalizedWindowsPath(value) {
  return String(value ?? '').replace(/^\\\\\?\\/u, '').replaceAll('/', '\\').toLowerCase();
}

export function validateInstalledSkillLinks(filesystem, installedSkillsRoot, forbiddenRoot) {
  const entries = filesystem?.after?.cwd;
  if (!Array.isArray(entries)) return ['installed filesystem evidence has no cwd inventory'];
  const links = entries.filter((entry) => entry?.type === 'symlink' && /^\.agents\/skills\/[^/]+$/u.test(String(entry.path ?? '')));
  if (links.length === 0) return ['installed harness created no skill links'];
  const required = `${normalizedWindowsPath(installedSkillsRoot)}\\`;
  const forbidden = `${normalizedWindowsPath(forbiddenRoot)}\\`;
  const problems = [];
  for (const link of links) {
    const target = normalizedWindowsPath(link.target);
    if (!target.startsWith(required)) problems.push(`${link.path} does not target installed plugin skills`);
    if (target.startsWith(forbidden)) problems.push(`${link.path} targets development checkout`);
  }
  return problems;
}

/** Classify one whole manifest row. captureOnly describes how the reference
 * was recorded; it is NOT authority to stop comparing that reference. */
export function evaluateParityRow({ fixture, record, baseline, manifestSha256, fixtureSha256, tempRoots = [] }) {
  const problems = observationProblems(record, 'native');
  if (problems.length) return { status: 'blocked', comparison: 'invalid-observation', mismatch: problems };
  if (fixture.rust === false) {
    return { status: 'blocked', comparison: 'unsupported-native-row', mismatch: ['manifest row has no asserted native implementation'] };
  }
  if (fixture.nativeOnly === true) {
    const mismatch = [];
    try { mismatch.push(...assertNativeOracle(fixture, record)); }
    catch (error) { mismatch.push(error.message); }
    // Native-only behavior cannot inherit a Node mutation oracle. Until a
    // specific mutation oracle is supplied, only read-only native rows qualify.
    if (canonicalJson(record.filesystem.before) !== canonicalJson(record.filesystem.after)) mismatch.push('native-only row has unasserted filesystem mutations');
    return { status: mismatch.length ? 'blocked' : 'matched', comparison: 'native-oracle', mismatch };
  }
  if (!baseline) return { status: 'unmatched', comparison: 'node-parity', mismatch: ['Node baseline row is missing'] };
  if (baseline.manifestSha256 !== manifestSha256 || baseline.fixtureSha256 !== fixtureSha256 || baseline.id !== fixture.id) {
    return { status: 'unmatched', comparison: 'node-parity', mismatch: ['Node baseline identity does not match frozen manifest row'] };
  }
  const mismatch = compareObservations(baseline, record, { fixture, tempRoots });
  return { status: mismatch.length ? 'mismatched' : 'matched', comparison: 'node-parity', mismatch };
}

function validExitCode(value) {
  return Number.isInteger(value) && value >= 0 && value <= 255;
}

function validStringList(value) {
  return Array.isArray(value) && value.length > 0 && value.every((item) => typeof item === 'string' && item.length > 0);
}

function validDigest(value) {
  return typeof value === 'string' && SHA256.test(value);
}

function observationProblems(observation, label, { requireEvidence = true } = {}) {
  const problems = [];
  if (!observation || typeof observation !== 'object' || Array.isArray(observation)) return [`${label} observation is not an object`];
  if (!validExitCode(observation.exitCode)) problems.push(`${label} observation has no valid integer exitCode`);
  if (typeof observation.stdout !== 'string' || typeof observation.stderr !== 'string') problems.push(`${label} observation streams are missing or not strings`);
  if (requireEvidence) {
    if (observation.error !== null) problems.push(`${label} observation reports an error`);
    if (observation.signal !== null) problems.push(`${label} observation reports a signal`);
    if (observation.timedOut !== false) problems.push(`${label} observation timed out or has invalid timeout state`);
    if (observation.outputLimitExceeded !== false) problems.push(`${label} observation exceeded the output limit or has invalid limit state`);
    if (!Array.isArray(observation.mismatch) || observation.mismatch.length !== 0) problems.push(`${label} observation reports a mismatch`);
    if (!observation.filesystem || typeof observation.filesystem !== 'object' || Array.isArray(observation.filesystem)) problems.push(`${label} filesystem evidence is missing`);
    else {
      if (!Object.hasOwn(observation.filesystem, 'before') || observation.filesystem.before === undefined || observation.filesystem.before === null || typeof observation.filesystem.before !== 'object') problems.push(`${label} filesystem before evidence is missing or invalid`);
      if (!Object.hasOwn(observation.filesystem, 'after') || observation.filesystem.after === undefined || observation.filesystem.after === null || typeof observation.filesystem.after !== 'object') problems.push(`${label} filesystem after evidence is missing or invalid`);
    }
  } else {
    if (observation.error !== undefined && observation.error !== null && observation.error !== '') problems.push(`${label} observation reports an error`);
    if (observation.signal !== undefined && observation.signal !== null) problems.push(`${label} observation reports a signal`);
    if (observation.timedOut !== undefined && observation.timedOut !== false) problems.push(`${label} observation timed out or has invalid timeout state`);
    if (observation.outputLimitExceeded !== undefined && observation.outputLimitExceeded !== false) problems.push(`${label} observation exceeded the output limit or has invalid limit state`);
  }
  return problems;
}

export function assertNativeOracle(fixture, observation) {
  const oracle = fixture.nativeOracle;
  if (!oracle || typeof oracle !== 'object' || Array.isArray(oracle)) throw new Error(`row ${fixture.id} has no valid native behavior oracle object`);
  const unknown = Object.keys(oracle).filter((key) => !NATIVE_ORACLE_KEYS.has(key));
  if (unknown.length) throw new Error(`row ${fixture.id} native oracle has unknown assertion fields: ${unknown.join(', ')}`);
  if (!validExitCode(oracle.exitCode)) throw new Error(`row ${fixture.id} native oracle requires a valid integer exitCode`);
  if (oracle.stdoutIncludes !== undefined && !validStringList(oracle.stdoutIncludes)) throw new Error(`row ${fixture.id} native oracle stdoutIncludes must be a non-empty string array`);
  if (oracle.stderrIncludes !== undefined && !validStringList(oracle.stderrIncludes)) throw new Error(`row ${fixture.id} native oracle stderrIncludes must be a non-empty string array`);
  if (oracle.kind !== undefined && (typeof oracle.kind !== 'string' || oracle.kind.length === 0)) throw new Error(`row ${fixture.id} native oracle kind must be a non-empty string`);
  if (oracle.stdoutSha256 !== undefined && !validDigest(oracle.stdoutSha256)) throw new Error(`row ${fixture.id} native oracle stdoutSha256 is invalid`);
  if (oracle.stderrSha256 !== undefined && !validDigest(oracle.stderrSha256)) throw new Error(`row ${fixture.id} native oracle stderrSha256 is invalid`);
  const observationIssues = observationProblems(observation, 'native', { requireEvidence: false });
  if (observationIssues.length) throw new Error(observationIssues.join('; '));
  const mismatches = [];
  if (observation.exitCode !== oracle.exitCode) mismatches.push(`exit ${observation.exitCode} != native oracle ${oracle.exitCode}`);
  if (oracle.stdoutIncludes?.some((needle) => !observation.stdout.includes(needle))) mismatches.push('stdout native oracle assertion failed');
  if (oracle.stderrIncludes?.some((needle) => !observation.stderr.includes(needle))) mismatches.push('stderr native oracle assertion failed');
  if (oracle.kind) {
    try { if (JSON.parse(observation.stdout).kind !== oracle.kind) mismatches.push(`stdout kind != native oracle ${oracle.kind}`); }
    catch { mismatches.push('native oracle requires JSON stdout'); }
  }
  if (oracle.stdoutSha256 && sha256(observation.stdout) !== oracle.stdoutSha256) mismatches.push('stdout SHA-256 != native oracle');
  if (oracle.stderrSha256 && sha256(observation.stderr) !== oracle.stderrSha256) mismatches.push('stderr SHA-256 != native oracle');
  return mismatches;
}

function resultHasIssue(result) {
  return (Array.isArray(result?.mismatch) && result.mismatch.length > 0)
    || (typeof result?.mismatch === 'string' && result.mismatch.length > 0)
    || (result?.error !== null && result?.error !== undefined && result.error !== '');
}

export function summarizeResults(results, identity = {}) {
  const expectedIds = Array.isArray(identity.rowIds) ? identity.rowIds : (Array.isArray(identity.manifest?.rowIds) ? identity.manifest.rowIds : null);
  const expectedCount = Number.isInteger(identity.rowCount) ? identity.rowCount : (Number.isInteger(identity.manifest?.rowCount) ? identity.manifest.rowCount : null);
  const resultIds = results.map((result) => result?.id);
  const invalidIds = resultIds.filter((id) => typeof id !== 'string' || id.length === 0);
  const duplicateIds = [...new Set(resultIds.filter((id, index) => typeof id === 'string' && id.length > 0 && resultIds.indexOf(id) !== index))];
  const resultIdSet = new Set(resultIds);
  const missingIds = expectedIds ? expectedIds.filter((id) => !resultIdSet.has(id)) : [];
  const unexpectedIds = expectedIds ? [...new Set(resultIds.filter((id) => !expectedIds.includes(id)))] : [];
  const expectedIdsUnique = expectedIds ? expectedIds.every((id) => typeof id === 'string' && id.length > 0) && new Set(expectedIds).size === expectedIds.length : true;
  const coverageValid = invalidIds.length === 0 && duplicateIds.length === 0 && expectedIdsUnique && (expectedCount === null || expectedCount === results.length) && (!expectedIds || (missingIds.length === 0 && unexpectedIds.length === 0 && expectedIds.length === results.length));
  const normalizedResults = results.map((result) => {
    if (result?.status !== 'matched' || !resultHasIssue(result)) return result;
    const mismatch = Array.isArray(result.mismatch) && result.mismatch.length ? [...result.mismatch] : ['matched row contains an error or invalid mismatch state'];
    return { ...result, status: 'mismatched', mismatch };
  });
  const counts = {
    total: normalizedResults.length,
    matched: normalizedResults.filter((result) => result.status === 'matched').length,
    mismatched: normalizedResults.filter((result) => result.status === 'mismatched').length,
    blocked: normalizedResults.filter((result) => result.status === 'blocked').length,
    unmatched: normalizedResults.filter((result) => result.status === 'unmatched').length,
    skipped: normalizedResults.filter((result) => result.status === 'skipped').length,
  };
  return {
    ...identity,
    ...counts,
    duplicateIds,
    invalidIds,
    missingIds,
    unexpectedIds,
    coverageValid,
    qualifying: coverageValid && counts.total > 0 && counts.matched === counts.total && counts.mismatched === 0 && counts.blocked === 0 && counts.unmatched === 0 && counts.skipped === 0,
    results: normalizedResults,
  };
}

export function inventoryClosure(counts = {}) {
  const blockingKeys = [
    'rustStubs',
    'rustPartial',
    'rustDivergent',
    'rustUnknown',
    'uncharacterizedNodeCommands',
  ];
  const blockers = Object.fromEntries(blockingKeys.map((key) => [key, Number(counts[key] ?? 0)]));
  return {
    ok: Object.values(blockers).every((count) => Number.isInteger(count) && count === 0),
    blockers,
  };
}

export function snapshotRoot(root, label, maxFiles = 2000, maxBytes = 32 * 1024 * 1024, maxDepth = 16) {
  const records = [];
  let bytes = 0;
  let rootStat;
  try { rootStat = lstatSync(root); } catch (error) { throw new Error(`filesystem snapshot root vanished at ${label}: ${error.message}`); }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new Error(`filesystem snapshot root is not a directory at ${label}`);
  function walk(current, depth = 0) {
    if (depth > maxDepth) throw new Error(`filesystem snapshot depth limit exceeded at ${label}/${relative(root, current)}`);
    let entries;
    try { entries = readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name)); }
    catch (error) { throw new Error(`filesystem snapshot directory vanished at ${label}/${relative(root, current)}: ${error.message}`); }
    for (const entry of entries) {
      if (records.length >= maxFiles) throw new Error(`filesystem snapshot file bound exceeded at ${label}`);
      const path = join(current, entry.name);
      const rel = relative(root, path).replaceAll('\\', '/');
      let observed;
      try { observed = lstatSync(path); } catch (error) { throw new Error(`filesystem snapshot entry vanished at ${label}/${rel}: ${error.message}`); }
      const describedType = entry.isSymbolicLink() ? 'symlink' : entry.isDirectory() ? 'directory' : entry.isFile() ? 'file' : 'other';
      const actualType = observed.isSymbolicLink() ? 'symlink' : observed.isDirectory() ? 'directory' : observed.isFile() ? 'file' : 'other';
      if (describedType !== actualType) throw new Error(`filesystem snapshot entry type changed at ${label}/${rel}`);
      if (actualType === 'directory') {
        records.push({ path: rel, type: 'directory' });
        walk(path, depth + 1);
      } else if (actualType === 'symlink') {
        records.push({ path: rel, type: 'symlink', target: readlinkSafe(path) });
      } else if (actualType === 'file') {
        const size = observed.size;
        if (bytes + size > maxBytes) throw new Error(`filesystem snapshot output limit exceeded at ${label}/${rel}`);
        bytes += size;
        let digest;
        try { digest = sha256File(path); } catch (error) { throw new Error(`filesystem snapshot file vanished at ${label}/${rel}: ${error.message}`); }
        records.push({ path: rel, type: 'file', size, sha256: digest });
      } else {
        records.push({ path: rel, type: 'other' });
      }
    }
  }
  walk(root);
  return records;
}

function readlinkSafe(path) { try { return readlinkSync(path); } catch { return null; } }

export function snapshotSandbox(sandbox) {
  const roots = [
    ['cwd', sandbox.cwd], ['home', sandbox.home], ['localAppData', sandbox.localAppData], ['state', sandbox.stateRoot],
  ];
  const value = Object.fromEntries(roots.map(([label, root]) => [label, snapshotRoot(root, label)]));
  return { value, sha256: sha256(canonicalJson(value)) };
}

function copyFixture(source, destination) {
  if (!existsSync(source) || !lstatSync(source).isDirectory()) return;
  cpSync(source, destination, { recursive: true, force: true, filter: (path) => !/[\\/]\.git(?:[\\/]|$)/u.test(path) && !/[\\/](?:node_modules|target|dist)(?:[\\/]|$)/u.test(path) });
}

export function createSandbox(root, fixture) {
  const base = mkdtempSync(join(tmpdir(), 'legion-native-cli-gate-'));
  const cwd = join(base, 'cwd');
  const home = join(base, 'home');
  const localAppData = join(base, 'local-app-data');
  const stateRoot = join(base, 'state');
  for (const path of [cwd, home, localAppData, stateRoot]) mkdirSync(path, { recursive: true });
  const fixtureCwd = resolve(root, fixture.cwd ?? '.');
  if (fixture.cwd && fixture.cwd !== '.') copyFixture(fixtureCwd, cwd);
  const env = {
    ...process.env,
    ...(fixture.env ?? {}),
    HOME: home,
    USERPROFILE: home,
    LOCALAPPDATA: localAppData,
    APPDATA: join(home, 'AppData', 'Roaming'),
    XDG_CONFIG_HOME: join(home, '.config'),
    XDG_DATA_HOME: join(home, '.local', 'share'),
    XDG_STATE_HOME: join(home, '.local', 'state'),
    LEGION_STATE_ROOT: stateRoot,
    ARCANE_STATE_ROOT: stateRoot,
    ARCANE_KEY_DIR: join(stateRoot, 'keys'),
    LEGION_INSTALL_EVENT_LOG: join(stateRoot, 'install-events.jsonl'),
    TEMP: join(base, 'temp'),
    TMP: join(base, 'temp'),
  };
  delete env.LEGION_EXE;
  mkdirSync(env.TEMP, { recursive: true });
  return { base, cwd, home, localAppData, stateRoot, env, tempRoots: [base, cwd, home, localAppData, stateRoot] };
}

export function runBounded(command, args, { cwd, env, timeoutMs = DEFAULT_TIMEOUT_MS, maxOutputBytes = DEFAULT_MAX_OUTPUT_BYTES } = {}) {
  const result = spawnSync(command, args, { cwd, env, encoding: 'utf8', windowsHide: true, timeout: timeoutMs, maxBuffer: Math.max(maxOutputBytes + 1, 64 * 1024), stdio: ['ignore', 'pipe', 'pipe'] });
  const stdout = String(result.stdout ?? '');
  const stderr = String(result.stderr ?? '');
  const outputBytes = Buffer.byteLength(stdout) + Buffer.byteLength(stderr);
  const timedOut = result.error?.code === 'ETIMEDOUT' || result.signal === 'SIGTERM';
  let error = result.error?.message ?? null;
  const outputLimitExceeded = outputBytes > maxOutputBytes || result.error?.code === 'ENOBUFS';
  if (outputLimitExceeded) error = `output limit exceeded (${maxOutputBytes} bytes)`;
  else if (timedOut) error = `timeout exceeded (${timeoutMs} ms)`;
  return { exitCode: Number.isInteger(result.status) ? result.status : null, stdout, stderr, error, signal: result.signal ?? null, outputBytes, timedOut: timedOut && !outputLimitExceeded, outputLimitExceeded };
}

export function removeSandbox(sandbox) { if (sandbox?.base) rmSync(sandbox.base, { recursive: true, force: true }); }

export function validateNormalization(fixture) {
  const normalization = fixture.normalization ?? fixture.normalize ?? {};
  for (const key of Object.keys(normalization)) if (!ALLOWED_NORMALIZATION_KEYS.has(key)) throw new Error(`row ${fixture.id} uses unsupported normalization: ${key}`);
}

export function resolveEvidencePath(env = process.env, root) {
  const explicit = env.LEGION_NATIVE_BUILD_EVIDENCE;
  if (explicit) return resolve(explicit);
  return resolve(root, 'dist', 'local-windows', 'local-verification.json');
}

export function hashManifestPath(path) { return sha256File(path); }
