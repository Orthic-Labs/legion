import { existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));

function version() {
  return JSON.parse(readFileSync(resolve(ROOT, 'release', 'version.json'), 'utf8')).version;
}

export function resolveNativeCli() {
  const candidates = [
    process.env.LEGION_EXE,
    resolve(ROOT, 'dist', 'native', 'windows-x86_64', `legion-${version()}`, 'bin', 'legion.exe'),
    process.env.LOCALAPPDATA && resolve(process.env.LOCALAPPDATA, 'Orthic Labs', 'Legion', 'current', 'bin', 'legion.exe'),
  ].filter(Boolean);
  return candidates.find((candidate) => existsSync(candidate)) ?? null;
}

/** Run product CLI tests against staged/native executable selected by LEGION_EXE or release roots. */
export function runNativeCli(args = [], { cwd = ROOT, env = {} } = {}) {
  const executable = resolveNativeCli();
  if (!executable) throw new Error('native legion.exe unavailable; set LEGION_EXE to staged executable');
  const result = spawnSync(executable, args, {
    cwd, encoding: 'utf8', env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 8 * 1024 * 1024,
  });
  return { executable, status: result.status ?? 3, exitCode: result.status ?? 3, stdout: result.stdout ?? '', stderr: result.stderr ?? '', error: result.error ?? null };
}

export { ROOT as nativeCliRoot };
