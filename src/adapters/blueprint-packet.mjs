/**
 * Membrane packet boundary for Blueprint repository evidence.
 *
 * Blueprint owns repository truth. Build a run-scoped graph under `.audit/`,
 * pin its generation with `blueprint graph status --json`, then project that
 * exact generation with `blueprint graph audit-projection`. This module validates the
 * Membrane packet schema (`membrane.blueprint-packet.v1`), binds each
 * projection to the exact pinned generation, & exposes typed degradation that
 * preserves Membrane/Blueprint error codes instead of collapsing them. Output
 * defaults under Audit's `.audit/` root & never escapes the
 * audited repository. It never walks files or derives repository semantic
 * truth locally; the git collector below is execution provenance only.
 */

import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, readlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { consumeMembranePacket } from '../packages/context/lib/context.mjs';

export const BLUEPRINT_ERROR_CODES = Object.freeze({
  transportUnavailable: 'membrane-blueprint-transport-unavailable',
  oneShotTimeout: 'membrane-blueprint-one-shot-timeout',
  oneShotCancelled: 'membrane-blueprint-one-shot-cancelled',
  graphStale: 'membrane-blueprint-graph-stale',
  graphBuildFailed: 'membrane-blueprint-graph-build-failed',
  packetInvalid: 'membrane-blueprint-packet-invalid',
  generationMismatch: 'membrane-blueprint-generation-mismatch',
  outputOutsideAuditBoundary: 'membrane-blueprint-output-outside-audit-boundary',
});

const DEFAULT_ONE_SHOT_TIMEOUT_MS = 120_000;
const MAX_ONE_SHOT_TIMEOUT_MS = 300_000;

/** Resident transport may report these states when Hub is off or enrollment
 * only governs its watcher. Direct Blueprint consumers must then use one-shot. */
export function shouldUseBlueprintOneShot(value) {
  const reason = String(value?.reason ?? value?.error?.code ?? value?.code ?? '').toLowerCase();
  return reason.includes('unavailable')
    || reason.includes('transport')
    || reason.includes('hub_inactive')
    || reason.includes('hub-inactive')
    || reason.includes('not_enrolled')
    || reason.includes('not-enrolled')
    || reason.includes('not configured')
    || reason.includes('not_configured')
    || reason.includes('not-configured')
    || reason.includes('project is not enrolled')
    || reason.includes('project_not_enrolled');
}

/** Audit-owned output defaults under the only permitted audit write boundary. */
export const DEFAULT_OUT_DIR = join('.audit', 'blueprint');

export function unavailablePacket(reason = 'membrane-transport-unavailable') {
  return { schema: 'legion.context-result.v1', status: 'unavailable', reason };
}

export function consumeBlueprintPacket(packet) {
  return consumeMembranePacket(packet);
}

export async function requestBlueprintPacket({ transport, request }) {
  if (typeof transport !== 'function') return unavailablePacket();
  let raw;
  try {
    raw = await transport({ operation: 'membrane_context', ...request });
  } catch (error) {
    // Transport failure & malformed packets degrade distinctly; never collapse them.
    return unavailablePacket(error?.code === 'MEMBRANE_UNAVAILABLE' ? 'membrane-unavailable' : 'membrane-transport-failed');
  }
  // Context unavailable envelopes are intentionally not packet-schema values;
  // preserve their typed reason so caller can select one-shot access.
  if (raw?.status === 'unavailable') return unavailablePacket(raw.reason ?? 'membrane-unavailable');
  try {
    return consumeBlueprintPacket(raw);
  } catch {
    return unavailablePacket('membrane-packet-invalid');
  }
}

/**
 * Classify one untracked path without following links: regular files hash by
 * content, symlinks (& Windows junctions, which surface as symlinks) hash by
 * their link text alone, & directories are represented explicitly instead of
 * being read as bytes.
 */
export function describeUntrackedEntry(absolutePath) {
  let stats;
  try { stats = lstatSync(absolutePath); } catch { return { kind: 'unreadable' }; }
  if (stats.isSymbolicLink()) {
    let target = null;
    try { target = readlinkSync(absolutePath); } catch { /* keep null */ }
    return { kind: 'symlink', target };
  }
  if (stats.isFile()) {
    try {
      return { kind: 'file', contentDigest: `sha256:${createHash('sha256').update(readFileSync(absolutePath)).digest('hex')}` };
    } catch { return { kind: 'unreadable' }; }
  }
  // Directories & junction-like reparse points are represented explicitly,
  // never read as bytes.
  return { kind: stats.isDirectory() ? 'directory' : 'other' };
}

/** Git binding is execution provenance, not repository semantic truth. */
export function collectRepositoryBinding(rootInput) {
  const root = resolve(rootInput);
  const git = (args, encoding = 'utf8') => {
    const result = spawnSync('git', args, { cwd: root, encoding, windowsHide: true, maxBuffer: 32 * 1024 * 1024 });
    if (result.status !== 0) throw new Error(`git ${args.join(' ')} failed`);
    return result.stdout;
  };
  const revision = String(git(['rev-parse', 'HEAD'])).trim();
  const status = git(['status', '--porcelain=v1', '-z', '--untracked-files=normal'], 'buffer');
  const patch = git(['diff', '--binary', 'HEAD', '--'], 'buffer');
  const untracked = String(git(['ls-files', '--others', '--exclude-standard', '-z'])).split('\0').filter(Boolean).sort();
  const digest = createHash('sha256');
  digest.update('status\0'); digest.update(status); digest.update('patch\0'); digest.update(patch);
  for (const path of untracked) {
    digest.update('untracked\0'); digest.update(path); digest.update('\0');
    digest.update(JSON.stringify(describeUntrackedEntry(join(root, path))));
    digest.update('\0');
  }
  return { repositoryRevision: revision, dirty: status.length > 0, dirtyPatchDigest: `sha256:${digest.digest('hex')}` };
}

/**
 * Audit owns everything written under its output root inside the audited
 * repository. Refuse absolute paths & traversal escaping the repository root,
 * & refuse collapsing output onto the repository root itself. All resolution
 * goes through node:path so Windows drive letters & separators stay intact.
 */
export function enforceAuditOutputBoundary(rootInput, outDir = DEFAULT_OUT_DIR) {
  const root = resolve(rootInput);
  const resolvedOutDir = isAbsolute(outDir) ? resolve(outDir) : resolve(root, outDir);
  if (resolvedOutDir === root || !resolvedOutDir.startsWith(root + sep)) {
    return { ok: false, code: BLUEPRINT_ERROR_CODES.outputOutsideAuditBoundary, outDir: resolvedOutDir };
  }
  return { ok: true, outDir: resolvedOutDir };
}

function boundedTimeout(timeoutMs) {
  const requested = Number(timeoutMs ?? DEFAULT_ONE_SHOT_TIMEOUT_MS);
  if (!Number.isFinite(requested) || requested < 1) return DEFAULT_ONE_SHOT_TIMEOUT_MS;
  return Math.min(Math.floor(requested), MAX_ONE_SHOT_TIMEOUT_MS);
}

function resolveBlueprintInvocation(blueprintBin) {
  let executable = blueprintBin;
  const explicitPath = isAbsolute(executable) || /[\\/]/.test(executable);
  if (process.platform === 'win32' && !explicitPath) {
    const located = spawnSync('where.exe', [executable], { encoding: 'utf8', windowsHide: true, maxBuffer: 1024 * 1024 });
    if (located.status === 0 && located.stdout) {
      const candidates = String(located.stdout).split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
      executable = candidates.find((candidate) => /\.(?:cmd|bat)$/i.test(candidate)) ?? candidates[0] ?? executable;
    }
  }
  if (process.platform !== 'win32' || !existsSync(executable)) {
    return { executable, prefix: [] };
  }
  if (!/\.(?:cmd|bat)$/i.test(executable)) {
    // Windows cannot launch extensionless shebang files directly. Support
    // test/dev Blueprint node shims while leaving arbitrary real executables
    // untouched.
    try {
      const header = readFileSync(executable, 'utf8').slice(0, 256);
      if (/^#![^\r\n]*\bnode(?:\.exe)?\b/i.test(header)) {
        return { executable: process.execPath, prefix: [executable] };
      }
    } catch { /* preserve arbitrary executable unchanged */ }
    return { executable, prefix: [] };
  }
  // Windows command wrappers cannot be launched with shell:false. Resolve
  // Blueprint's checked-in wrapper to node + script so child argv remains
  // explicit & shell-free.
  let wrapper;
  try { wrapper = readFileSync(executable, 'utf8'); } catch { return { executable, prefix: [] }; }
  const script = wrapper.match(/node(?:\.exe)?\s+"([^"]+\.mjs)"/i)?.[1];
  return script ? { executable: process.execPath, prefix: [script] } : { executable, prefix: [] };
}

function runBlueprintCli(root, blueprintBin, args, maxBuffer, options = {}) {
  if (options.signal?.aborted) return { error: Object.assign(new Error('Blueprint one-shot cancelled'), { code: 'ABORT_ERR' }) };
  const invocation = resolveBlueprintInvocation(blueprintBin);
  const result = spawnSync(invocation.executable, [...invocation.prefix, ...args], {
    cwd: root,
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer,
    timeout: boundedTimeout(options.timeoutMs),
    killSignal: 'SIGTERM',
  });
  return result;
}

function blueprintCliOutDir(root, absoluteOutDir) {
  return relative(root, absoluteOutDir).replaceAll('\\', '/');
}

/**
 * Preserve Blueprint/Membrane's own exact degradation code whenever it emits
 * one; fall back to a canonical code only where the CLI produced no
 * structured reason.
 */
export function classifyBlueprintFailure(result, fallbackCode) {
  if (result?.error?.code === 'ETIMEDOUT') return BLUEPRINT_ERROR_CODES.oneShotTimeout;
  if (result?.error?.code === 'ABORT_ERR') return BLUEPRINT_ERROR_CODES.oneShotCancelled;
  if (result?.signal === 'SIGTERM' && result?.status === null) return BLUEPRINT_ERROR_CODES.oneShotTimeout;
  for (const stream of [result?.stdout, result?.stderr]) {
    if (typeof stream !== 'string' || !stream.trim()) continue;
    try {
      const payload = JSON.parse(stream);
      const reason = typeof payload?.reason === 'string'
        ? payload.reason
        : typeof payload?.error?.code === 'string' ? payload.error.code : null;
      if (reason) return reason;
    } catch { /* stream is not structured degradation */ }
  }
  if (result?.error) return BLUEPRINT_ERROR_CODES.transportUnavailable;
  return fallbackCode;
}

function pinnedGenerationFromStatus(payload) {
  const stale = payload?.stale === true || payload?.generation?.stale === true
    || payload?.state === 'stale' || payload?.status === 'stale';
  if (stale) {
    return { ok: false, code: typeof payload?.reason === 'string' ? payload.reason : BLUEPRINT_ERROR_CODES.graphStale };
  }
  const id = typeof payload?.generation?.id === 'string' && payload.generation.id.length > 0 ? payload.generation.id
    : typeof payload?.generationId === 'string' && payload.generationId.length > 0 ? payload.generationId
      : typeof payload?.manifest?.generationId === 'string' && payload.manifest.generationId.length > 0 ? payload.manifest.generationId : null;
  return id ? { ok: true, generationId: id } : { ok: false, code: BLUEPRINT_ERROR_CODES.packetInvalid };
}

/** Build a fresh graph into this audit run's output directory. */
export function buildRunScopedGraph(rootInput, options = {}) {
  const root = resolve(rootInput);
  const blueprintBin = options.blueprintBin ?? process.env.BLUEPRINT_BIN ?? 'blueprint';
  const boundary = enforceAuditOutputBoundary(root, options.outDir ?? DEFAULT_OUT_DIR);
  if (!boundary.ok) return { ok: false, code: boundary.code };
  const result = runBlueprintCli(root, blueprintBin, ['graph', 'build', '--out', blueprintCliOutDir(root, boundary.outDir)], 128 * 1024 * 1024, options);
  if (result.error || result.status !== 0) {
    return { ok: false, code: classifyBlueprintFailure(result, BLUEPRINT_ERROR_CODES.graphBuildFailed) };
  }
  return { ok: true, outDir: boundary.outDir };
}

/** Pin the generated Blueprint generation (`blueprint graph status --json`). */
export function readBlueprintGraphStatus(rootInput, options = {}) {
  const root = resolve(rootInput);
  const blueprintBin = options.blueprintBin ?? process.env.BLUEPRINT_BIN ?? 'blueprint';
  const boundary = enforceAuditOutputBoundary(root, options.outDir ?? DEFAULT_OUT_DIR);
  if (!boundary.ok) return { ok: false, code: boundary.code };
  const result = runBlueprintCli(root, blueprintBin, ['graph', 'status', '--out', blueprintCliOutDir(root, boundary.outDir), '--json'], 32 * 1024 * 1024, options);
  if (result.error || result.status !== 0) {
    return { ok: false, code: classifyBlueprintFailure(result, BLUEPRINT_ERROR_CODES.graphBuildFailed) };
  }
  try {
    return pinnedGenerationFromStatus(JSON.parse(result.stdout));
  } catch {
    return { ok: false, code: BLUEPRINT_ERROR_CODES.packetInvalid };
  }
}

function invokeBlueprintProjection(rootInput, options = {}) {
  const root = resolve(rootInput);
  const blueprintBin = options.blueprintBin ?? process.env.BLUEPRINT_BIN ?? 'blueprint';
  const boundary = enforceAuditOutputBoundary(root, options.outDir ?? DEFAULT_OUT_DIR);
  if (!boundary.ok) return unavailablePacket(boundary.code);
  const built = buildRunScopedGraph(root, { blueprintBin, outDir: boundary.outDir, timeoutMs: options.timeoutMs, signal: options.signal });
  if (!built.ok) return unavailablePacket(built.code);
  const status = readBlueprintGraphStatus(root, { blueprintBin, outDir: boundary.outDir, timeoutMs: options.timeoutMs, signal: options.signal });
  if (!status.ok) return unavailablePacket(status.code);
  const result = runBlueprintCli(root, blueprintBin, [
    'graph', 'audit-projection', '--out', blueprintCliOutDir(root, boundary.outDir),
    '--expected-generation', status.generationId, '--json',
  ], 128 * 1024 * 1024, options);
  if (result.error || result.status !== 0) return unavailablePacket(classifyBlueprintFailure(result, BLUEPRINT_ERROR_CODES.transportUnavailable));
  try {
    const packet = consumeBlueprintPacket(JSON.parse(result.stdout));
    const pinned = status.generationId;
    if (pinned !== null && packet.generationId != null && packet.generationId !== pinned) {
      return unavailablePacket(BLUEPRINT_ERROR_CODES.generationMismatch);
    }
    const files = [...new Set((packet.files ?? []).map((path) => String(path).replaceAll('\\', '/')).filter(Boolean))].sort();
    const fileSetDigest = `sha256:${createHash('sha256').update(JSON.stringify(files)).digest('hex')}`;
    return {
      ...packet,
      generationId: packet.generationId ?? pinned,
      files,
      fileCount: files.length,
      fileSetDigest,
    };
  } catch {
    return unavailablePacket(BLUEPRINT_ERROR_CODES.packetInvalid);
  }
}

/**
 * Synchronous Audit callers can inject resident Hub transport when its host
 * provides a synchronous bridge. Async bridges are handled by MembraneAdapter;
 * they never get mistaken for a packet or silently bypass validation.
 */
function invokeResidentOrOneShot(rootInput, options = {}) {
  const transport = options.transport ?? options.residentTransport;
  if (typeof transport !== 'function') return invokeBlueprintProjection(rootInput, options);
  let raw;
  try {
    raw = transport({ operation: 'membrane_context', root: resolve(rootInput), ...(options.request ?? {}) });
  } catch (error) {
    const unavailable = unavailablePacket(error?.code === 'MEMBRANE_UNAVAILABLE' ? 'membrane-unavailable' : 'membrane-transport-failed');
    return shouldUseBlueprintOneShot(unavailable) ? invokeBlueprintProjection(rootInput, options) : unavailable;
  }
  if (raw && typeof raw.then === 'function') {
    return invokeBlueprintProjection(rootInput, options);
  }
  if (raw?.status === 'unavailable') {
    const unavailable = unavailablePacket(raw.reason ?? 'membrane-unavailable');
    return shouldUseBlueprintOneShot(unavailable) ? invokeBlueprintProjection(rootInput, options) : unavailable;
  }
  try {
    return consumeBlueprintPacket(raw);
  } catch {
    return unavailablePacket('membrane-packet-invalid');
  }
}

export function readBlueprintManifestBinding(rootInput, options = {}) {
  const packet = invokeResidentOrOneShot(rootInput, options);
  if (packet.status !== 'ready' || packet.state !== 'ready') {
    return { state: 'unproven', reason: packet.reason ?? 'membrane-blueprint-transport-unavailable' };
  }
  return {
    state: 'ready',
    generationId: packet.generationId ?? null,
    manifestDigest: packet.manifestDigest ?? null,
    sourceObservation: packet.sourceObservation ?? null,
  };
}

export function readBlueprintPacket(rootInput, options = {}) {
  return invokeResidentOrOneShot(rootInput, options);
}
