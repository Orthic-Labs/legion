/**
 * open-for-review.mjs — Open artifact in OS viewer for the operator's review.
 *
 * Behavioral contract (CLAUDE.md):
 *   Whenever Claude tells the operator to review an artifact, Claude MUST call this
 *   helper FIRST so the artifact actually appears on screen. "Here's the file
 *   at <path>" without opening it = friction, every time. This eliminates that.
 *
 * Rules:
 *   - single file path  → open that file in OS-associated app
 *   - multiple paths    → open the common parent directory
 *   - directory path    → open the directory
 *   - missing path      → log a clear error, return false (never throw)
 *
 * Cross-platform: Windows `start ""`, macOS `open`, Linux `xdg-open`.
 *
 * Usage from Claude in a Bash call:
 *   node src/lib/open-for-review.mjs <path>
 *   node src/lib/open-for-review.mjs <path1> <path2> ...
 *
 * Usage from any pipeline script:
 *   import { openForReview } from '../../lib/open-for-review.mjs';
 *   openForReview(filePath);
 *   openForReview([p1, p2, p3]);
 */

import { existsSync, statSync } from 'node:fs';
import { dirname, resolve }     from 'node:path';
import { spawn }                from 'node:child_process';

function commonParentDir(paths) {
  if (paths.length === 0) return null;
  if (paths.length === 1) return dirname(resolve(paths[0]));
  const parts = paths.map(p => resolve(p).split(/[\\/]/));
  const min   = Math.min(...parts.map(p => p.length));
  const common = [];
  for (let i = 0; i < min; i++) {
    const seg = parts[0][i];
    if (parts.every(p => p[i] === seg)) common.push(seg);
    else break;
  }
  return common.join('/') || dirname(resolve(paths[0]));
}

function openOne(target) {
  return new Promise((resolve) => {
    let cmd, args;
    if (process.platform === 'win32') {
      cmd  = 'cmd';
      args = ['/c', 'start', '""', target];
    } else if (process.platform === 'darwin') {
      cmd  = 'open';
      args = [target];
    } else {
      cmd  = 'xdg-open';
      args = [target];
    }
    const p = spawn(cmd, args, { stdio: 'ignore', detached: true, windowsHide: false });
    p.on('error', () => resolve(false));
    p.unref();
    setTimeout(() => resolve(true), 50);
  });
}

/**
 * Open one path or a list. Returns {ok, opened} where opened is the resolved
 * target that was actually launched (file or dir).
 */
export async function openForReview(pathOrPaths) {
  const list = Array.isArray(pathOrPaths) ? pathOrPaths : [pathOrPaths];
  const real = list.filter(Boolean).map(String);
  if (real.length === 0) {
    console.error('[open-for-review] no path provided');
    return { ok: false, opened: null };
  }

  // Filter to existing paths.
  const existing = real.filter(p => existsSync(p));
  if (existing.length === 0) {
    console.error(`[open-for-review] none of the paths exist: ${real.join(', ')}`);
    return { ok: false, opened: null };
  }

  let target;
  if (existing.length === 1) {
    const p  = existing[0];
    target   = p;          // file or dir — OS handles either
  } else {
    target = commonParentDir(existing);
  }

  // If single path is a directory, open it directly. If single file, open file.
  // Both cases land on the same `openOne(target)` call.
  const ok = await openOne(target);
  if (ok) console.log(`[open-for-review] opened: ${target}`);
  else    console.error(`[open-for-review] could not open: ${target}`);
  return { ok, opened: target };
}

// CLI entry — Claude calls this from Bash.
const _argv1 = process.argv[1] ? process.argv[1].replace(/\\/g, '/') : '';
if (_argv1 && (
    import.meta.url === `file:///${_argv1}` ||
    import.meta.url === `file://${_argv1}` ||
    import.meta.url.endsWith('/' + (_argv1.split('/').pop() || ''))
)) {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.error('usage: node open-for-review.mjs <path> [<path> ...]');
    process.exit(2);
  }
  await openForReview(args);
}
