// External process runner per SNIP-PROCESS-01: executable allowlist, exact
// args, sanitized environment, cwd, timeout, output cap, abort signal, and
// raw-output artifacts. Shell execution is forbidden.

import { spawn } from 'node:child_process';

const DEFAULT_ALLOWED = new Set([
  'node', 'npm', 'npx', 'git', 'tsc', 'eslint', 'python3', 'python', 'ruff',
  'cargo', 'go', 'dotnet', 'opengrep', 'semgrep', 'ast-grep', 'sg', 'osv-scanner',
  'gitleaks', 'syft', 'trivy', 'hadolint', 'actionlint', 'shellcheck', 'swift',
  'clang', 'gcc', 'cmake', 'mvn', 'gradle', 'php', 'composer', 'ruby', 'bundle',
]);

export function pickEnvironment(env, environmentKeys) {
  const picked = {};
  for (const key of environmentKeys ?? ['PATH', 'HOME']) {
    if (env[key] !== undefined) picked[key] = env[key];
  }
  return picked;
}

function collectBounded(stream, maxBytes, onCap) {
  return new Promise((resolve) => {
    const chunks = [];
    let total = 0;
    let capped = false;
    stream.on('data', (chunk) => {
      if (capped) return;
      total += chunk.length;
      if (total > maxBytes) {
        capped = true;
        stream.destroy();
        if (onCap) onCap();
        resolve({ capped: true, text: Buffer.concat(chunks).toString('utf8').slice(0, maxBytes) });
        return;
      }
      chunks.push(chunk);
    });
    stream.on('end', () => resolve({ capped: false, text: Buffer.concat(chunks).toString('utf8') }));
    stream.on('error', () => resolve({ capped: false, text: Buffer.concat(chunks).toString('utf8') }));
  });
}

function waitForChild(child) {
  return new Promise((resolve) => {
    child.on('error', (error) => resolve({ error }));
    child.on('close', (code, signal) => resolve({ code, signal }));
  });
}

export function blocked(spec, reason) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-execution-result',
    provider: spec?.provider ?? null,
    command: { executable: spec?.executable ?? null, args: spec?.args ?? [], cwd: spec?.cwd ?? null },
    startedAt: null,
    completedAt: null,
    durationMs: null,
    spawnStatus: 'blocked',
    exitCode: null,
    signal: null,
    timedOut: false,
    stdoutArtifact: null,
    stderrArtifact: null,
    environmentKeys: spec?.environmentKeys ?? [],
    sandboxReceipt: null,
    tool: null,
    providerResult: {
      provider: spec?.provider ?? null,
      status: 'blocked',
      complete: false,
      coverageGaps: [{ kind: 'execution-blocked', reason }],
    },
  };
}

export async function runExternal(spec, host) {
  const allowed = host.allowedExecutables ?? DEFAULT_ALLOWED;
  if (!allowed.has(spec.executable)) {
    return blocked(spec, 'executable-not-allowlisted');
  }
  if (spec.shell === true) throw new Error('shell execution is forbidden');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), spec.timeoutMs ?? 120000);
  const startedAt = host.clock.now();
  let capped = false;
  const killOnCap = () => {
    capped = true;
    controller.abort();
  };
  const child = spawn(spec.executable, spec.args ?? [], {
    cwd: spec.cwd,
    env: pickEnvironment(host.env ?? {}, spec.environmentKeys ?? ['PATH', 'HOME']),
    shell: false,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    signal: controller.signal,
  });
  const stdout = collectBounded(child.stdout, spec.maxOutputBytes ?? 8388608, killOnCap);
  const stderr = collectBounded(child.stderr, spec.maxOutputBytes ?? 8388608, killOnCap);
  const result = await waitForChild(child);
  clearTimeout(timer);
  const completedAt = host.clock.now();
  const stdoutResult = await stdout;
  const stderrResult = await stderr;
  const timedOut = Boolean(result.error?.name === 'AbortError') || controller.signal.aborted;
  const spawnStatus = result.error
    ? (timedOut ? 'timeout' : 'error')
    : result.code === null ? 'signaled' : 'completed';
  return {
    schemaVersion: 1,
    kind: 'nemesis-execution-result',
    provider: spec.provider ?? null,
    command: { executable: spec.executable, args: spec.args ?? [], cwd: spec.cwd },
    startedAt,
    completedAt,
    durationMs: completedAt - startedAt,
    spawnStatus,
    exitCode: result.code,
    signal: result.signal ?? null,
    timedOut,
    stdoutArtifact: { path: `raw/${spec.provider ?? 'process'}.stdout`, digest: null },
    stderrArtifact: { path: `raw/${spec.provider ?? 'process'}.stderr`, digest: null },
    environmentKeys: spec.environmentKeys ?? [],
    sandboxReceipt: host.capabilities?.networkSandbox?.receipt ?? null,
    tool: { name: spec.executable, version: null, executableDigest: null },
    providerResult: null,
    _outputLimitHit: stdoutResult.capped || stderrResult.capped || capped,
  };
}
