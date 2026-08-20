import { createHash } from 'node:crypto';

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

function unavailable() {
  return { status: null, stdout: '', stderr: 'Membrane Blueprint packet transport unavailable' };
}

function parsed(result, label) {
  if (result?.status !== 0) return { error: `${label}:${String(result?.stderr ?? '').trim() || 'failed'}` };
  try { return { value: JSON.parse(result.stdout) }; } catch { return { error: `${label}:invalid-json` }; }
}

/** Read-only impact consumer. Repository semantics remain in Blueprint. */
export async function traceDiffBlastRadius({ changedPaths, run = unavailable, packet = null, depth = 3, budget = 2000 } = {}) {
  const paths = [...new Set((changedPaths ?? []).map(normalizePath))].sort();
  if (!paths.length) throw new TypeError('at least one changed path is required');
  if (packet?.status === 'unavailable') return { schemaVersion: 1, kind: 'oracle-blueprint-impact', state: 'unproven', changedPaths: paths, traces: [], reason: packet.reason };
  const traces = [];
  for (const path of paths) {
    const resolvedNode = parsed(await run(null, ['blueprint', 'resolve', '--node', path]), 'resolve');
    const nodeId = resolvedNode.value?.id ?? resolvedNode.value?.nodeId ?? null;
    if (resolvedNode.error || !nodeId) { traces.push({ path, state: 'unproven', reason: resolvedNode.error ?? 'resolve:missing-node-id' }); continue; }
    const impact = parsed(await run(null, ['blueprint', 'impact', '--node', nodeId, '--depth', String(depth), '--budget', String(budget)]), 'impact');
    if (impact.error) traces.push({ path, nodeId, state: 'unproven', reason: impact.error });
    else traces.push({ path, nodeId, state: 'ready', impact: impact.value });
  }
  const payload = { schemaVersion: 1, kind: 'oracle-blueprint-impact', state: traces.every(({ state }) => state === 'ready') ? 'ready' : 'unproven', changedPaths: paths, traces };
  return Object.freeze({ ...payload, digest: `sha256:${createHash('sha256').update(canonical(payload)).digest('hex')}` });
}
