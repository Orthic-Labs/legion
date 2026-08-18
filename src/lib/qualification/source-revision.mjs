import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Content-based source revision. Hashes the tracked SOURCE tree (qualification
// evidence, architecture notes, and the lockfile excluded) plus any dirty
// non-excluded working files. Two checkouts with identical source bytes produce
// the identical revision regardless of git history — so a commit that only
// touches qualification/ (e.g. sealing a book receipt) does not change the
// revision, and receipts survive their own commit.
const EXCLUDED = (path) => path.startsWith('qualification/') || path === 'architecture.md' || path === 'pnpm-lock.yaml';

function sourceRevision(root, { includeDirty }) {
  const hash = createHash('sha256');
  // Tracked source content, stable order: path NUL blob-sha NUL. Uses git's own
  // blob identity (content hash) so we avoid re-reading every tracked file.
  const tracked = execFileSync('git', ['ls-tree', '-r', 'HEAD', '--format=%(objectname) %(path)'], { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
    .split(/\r?\n/).filter(Boolean)
    .map((line) => { const space = line.indexOf(' '); return [line.slice(space + 1).replaceAll('\\', '/'), line.slice(0, space)]; })
    .filter(([path]) => !EXCLUDED(path))
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  for (const [path, blob] of tracked) { hash.update(path); hash.update('\0'); hash.update(blob); hash.update('\0'); }
  // Dirty overlay: modified + untracked non-excluded files, hashed by content.
  const dirty = includeDirty ? execFileSync('git', ['ls-files', '-m', '-o', '--exclude-standard'], { cwd: root, encoding: 'utf8' })
    .split(/\r?\n/).filter(Boolean)
    .map((path) => path.replaceAll('\\', '/'))
    .filter((path) => !EXCLUDED(path))
    .sort() : [];
  for (const name of dirty) { hash.update('dirty:'); hash.update(name); hash.update('\0'); try { hash.update(readFileSync(resolve(root, name))); } catch { hash.update('unreadable'); } hash.update('\0'); }
  const digest = `content.sha256:${hash.digest('hex')}`;
  return dirty.length ? `${digest}+dirty` : digest;
}

export function currentSourceRevision(root) {
  return sourceRevision(root, { includeDirty: true });
}

// Qualification receipts are committed artifacts. Seal them to tracked HEAD,
// never to unrelated working-copy bytes that cannot exist in a clean checkout.
export function committedSourceRevision(root) {
  return sourceRevision(root, { includeDirty: false });
}
