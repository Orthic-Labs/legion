import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { lstat, readdir, readFile, readlink } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';
import { promisify } from 'node:util';
import { digest } from './binding.mjs';

const execFileAsync = promisify(execFile);

// Git is the source of truth for repository membership & ignore rules. These
// names keep a non-Git checkout from walking Legion's own runtime state.
const FALLBACK_DIRECTORY_EXCLUSIONS = new Set([
  '.agent', '.audit', '.git', '.legion', 'dist', 'node_modules',
]);
const FALLBACK_PATH_EXCLUSIONS = new Set([
  'engine/target',
  'src/lib/review/cache',
  'src/lib/review/shadow_log',
  'src/lib/research-core/runs',
]);

function normalizeName(name) {
  return String(name).replaceAll('\\', '/');
}

function parseGitFileList(output) {
  const text = Buffer.isBuffer(output) ? output.toString('utf8') : String(output ?? '');
  return [...new Set(text.split('\0').filter(Boolean).map(normalizeName))].sort();
}

function isGitUnavailable(error) {
  if (error?.code === 'ENOENT') return true;
  const stderr = Buffer.isBuffer(error?.stderr) ? error.stderr.toString('utf8') : String(error?.stderr ?? '');
  return (error?.code === 128 || error?.status === 128)
    && /not a git repository|outside of a git work tree/i.test(stderr);
}

async function gitFiles(root) {
  try {
    const { stdout } = await execFileAsync(
      'git',
      ['ls-files', '--cached', '--others', '--exclude-standard', '-z', '--', '.'],
      { cwd: root, encoding: 'buffer', windowsHide: true, maxBuffer: 256 * 1024 * 1024 },
    );
    return parseGitFileList(stdout);
  } catch (error) {
    if (isGitUnavailable(error)) return null;
    throw error;
  }
}

function fallbackPath(root, current, name) {
  return normalizeName(relative(root, join(current, name)));
}

async function files(root, current = root, output = []) {
  for (const entry of await readdir(current, { withFileTypes: true })) {
    const pathName = fallbackPath(root, current, entry.name);
    if (entry.isDirectory() && (
      FALLBACK_DIRECTORY_EXCLUSIONS.has(entry.name)
      || FALLBACK_PATH_EXCLUSIONS.has(pathName)
    )) continue;
    const path = join(current, entry.name);
    if (entry.isDirectory()) await files(root, path, output);
    else if (entry.isFile()) output.push(relative(root, path).replaceAll('\\', '/'));
  }
  return output;
}

async function hashRepositoryEntry(hash, absoluteRoot, name, gitBacked) {
  const path = join(absoluteRoot, name);
  let entry;
  try {
    entry = await lstat(path);
  } catch (error) {
    if (gitBacked && error?.code === 'ENOENT') {
      hash.update('missing\0');
      return;
    }
    throw error;
  }

  if (entry.isSymbolicLink()) {
    hash.update('symlink\0');
    hash.update(await readlink(path, 'utf8'));
    return;
  }
  if (!entry.isFile()) {
    hash.update(`non-file:${entry.isDirectory() ? 'directory' : 'other'}\0`);
    return;
  }
  try {
    hash.update(await readFile(path));
  } catch (error) {
    if (gitBacked && error?.code === 'ENOENT') {
      hash.update('missing\0');
      return;
    }
    throw error;
  }
}

export async function bindRepository(root, { revision = null, sourceRevision = revision, blueprintDigest = null, skillRegistryDigest = null, familyRegistryDigest = null, providerRegistryDigest = null, configDigest = null } = {}) {
  const absoluteRoot = resolve(root);
  const gitNames = await gitFiles(absoluteRoot);
  const gitBacked = gitNames !== null;
  const names = gitBacked ? gitNames : (await files(absoluteRoot)).sort();
  const hash = createHash('sha256');
  for (const name of names) {
    hash.update(`${name}\0`);
    await hashRepositoryEntry(hash, absoluteRoot, name, gitBacked);
  }
  const dirtyOverlayDigest=`sha256:${hash.digest('hex')}`;const authorities={blueprintDigest,skillRegistryDigest,familyRegistryDigest,providerRegistryDigest,configDigest};
  return Object.freeze({ schemaVersion: 1, root: absoluteRoot, repositoryRevision: revision,sourceRevision,dirtyOverlayDigest,fileCount:names.length,...authorities,digest:digest({revision,sourceRevision,dirtyOverlayDigest,names,authorities}) });
}
