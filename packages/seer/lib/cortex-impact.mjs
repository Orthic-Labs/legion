import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function normalizePath(value) {
  const path = String(value ?? '').replaceAll('\\', '/').replace(/^\.\//, '');
  if (!path || path.startsWith('/') || /^[A-Za-z]:\//.test(path) || path.split('/').includes('..')) throw new TypeError('changed path must be repository-relative');
  return path;
}

function findCortexScript(repoRoot) {
  for (let cursor = resolve(repoRoot); ; cursor = dirname(cursor)) {
    for (const name of ['cortex.mjs', 'blueprint.mjs']) {
      const candidate = join(cursor, 'cortex', 'scripts', name);
      if (existsSync(candidate)) return candidate;
    }
    const parent = dirname(cursor);
    if (parent === cursor) return null;
  }
}

function defaultRun(repoRoot, args) {
  const script = findCortexScript(repoRoot);
  if (!script) return { status: null, stdout: '', stderr: 'cortex executable unavailable' };
  const result = spawnSync(process.execPath, [script, ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    windowsHide: true,
    shell: false,
    timeout: 120_000,
    maxBuffer: 32 * 1024 * 1024,
  });
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? result.error?.message ?? '' };
}

function parsed(result, label) {
  if (result?.status !== 0) return { error: `${label}:${String(result?.stderr ?? '').trim() || 'failed'}` };
  try { return { value: JSON.parse(result.stdout) }; }
  catch { return { error: `${label}:invalid-json` }; }
}

export async function traceDiffBlastRadius({ repoRoot, changedPaths, outDir = '.agent', depth = 3, budget = 2000, run = defaultRun }) {
  const paths = [...new Set((changedPaths ?? []).map(normalizePath))].sort();
  if (!paths.length) throw new TypeError('at least one changed path is required');
  const traces = [];
  for (const path of paths) {
    const resolvedNode = parsed(await run(repoRoot, ['graph', 'resolve', '--node', path, '--out', outDir]), 'resolve');
    const nodeId = resolvedNode.value?.id ?? resolvedNode.value?.nodeId ?? null;
    if (resolvedNode.error || !nodeId) {
      traces.push({ path, state: 'unproven', reason: resolvedNode.error ?? 'resolve:missing-node-id' });
      continue;
    }
    const impact = parsed(await run(repoRoot, ['graph', 'impact', '--node', nodeId, '--depth', String(depth), '--budget', String(budget), '--json', '--out', outDir]), 'impact');
    if (impact.error) traces.push({ path, nodeId, state: 'unproven', reason: impact.error });
    else traces.push({ path, nodeId, state: 'ready', impact: impact.value });
  }
  const payload = {
    schemaVersion: 1,
    kind: 'seer-cortex-diff-blast-radius',
    state: traces.every(({ state }) => state === 'ready') ? 'ready' : 'unproven',
    changedPaths: paths,
    traces,
  };
  return Object.freeze({ ...payload, digest: `sha256:${createHash('sha256').update(canonical(payload)).digest('hex')}` });
}
