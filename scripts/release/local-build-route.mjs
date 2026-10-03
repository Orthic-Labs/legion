import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export function buildRoute(inventory, now = Date.now()) {
  if (!inventory || !Array.isArray(inventory.inFlight) || !Array.isArray(inventory.recent)) {
    return { route: 'github', reason: 'build inventory unavailable' };
  }
  const active = inventory.inFlight.find(job => !['SUCCEEDED', 'FAILED', 'CANCELLED'].includes(job.state));
  if (active) return { route: 'github', reason: 'another build is queued or running', request: active.id };
  const cutoff = now - 30 * 60_000;
  for (const job of inventory.recent) {
    const timestamps = [job.terminalAt, job.completedAt, job.lastOutputAt, job.startedAt, job.submittedAt]
      .map(value => Date.parse(value)).filter(Number.isFinite);
    const started = Date.parse(job.startedAt);
    if (Number.isFinite(started) && Number.isFinite(job.elapsedMs)) timestamps.push(started + job.elapsedMs);
    if (!timestamps.length) return { route: 'github', reason: 'build activity timestamp unavailable', request: job.id };
    if (Math.max(...timestamps) >= cutoff) {
      return { route: 'github', reason: 'another build was processed within past 30 minutes', request: job.id };
    }
  }
  return { route: 'local', reason: 'no queued, running, or processed builds within past 30 minutes' };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = spawnSync('rightkit.cmd', ['list'], { encoding: 'utf8', shell: true, windowsHide: true, timeout: 15_000 });
  let inventory;
  if (!result.error && result.status === 0) {
    try { inventory = JSON.parse(result.stdout); } catch { /* Fail closed to CI. */ }
  }
  const decision = buildRoute(inventory);
  console.log(JSON.stringify({ ...decision, observedAt: new Date().toISOString(), lookbackMinutes: 30 }));
  if (decision.route !== 'local') {
    console.error('LOCAL_BUILD_REFUSED: use Windows unsigned GitHub CI; do not queue or retry locally.');
    process.exitCode = 3;
  }
}
