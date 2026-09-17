import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));

function version() {
  return JSON.parse(readFileSync(resolve(ROOT, 'release', 'version.json'), 'utf8')).version;
}

/**
 * Resolve only installer-owned stable current. Product tests must never bind a
 * development checkout or staged repository executable.
 */
export function resolveNativeCli(env = process.env) {
  if (env.LEGION_TEST_NATIVE_CLI_PATH) {
    const path = resolve(env.LEGION_TEST_NATIVE_CLI_PATH);
    if (!existsSync(path) || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) {
      throw new Error('LEGION_TEST_NATIVE_CLI_PATH must name a regular native executable');
    }
    return path;
  }
  if (!env.LOCALAPPDATA) return null;
  const path = resolve(env.LOCALAPPDATA, 'Orthic Labs', 'Legion', 'current', 'bin', 'legion.exe');
  if (!existsSync(path) || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) return null;
  return path;
}

/** Run product CLI tests against the explicitly selected native executable. */
export function runNativeCli(args = [], { cwd = ROOT, env = {} } = {}) {
  const executable = resolveNativeCli({ ...process.env, ...env });
  if (!executable) throw new Error('installed stable legion.exe unavailable; run the local unsigned installer');
  const result = spawnSync(executable, args, {
    cwd, encoding: 'utf8', env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 8 * 1024 * 1024, windowsHide: true,
  });
  return { executable, status: result.status ?? 3, exitCode: result.status ?? 3, stdout: result.stdout ?? '', stderr: result.stderr ?? '', error: result.error ?? null };
}

export { ROOT as nativeCliRoot, version };
