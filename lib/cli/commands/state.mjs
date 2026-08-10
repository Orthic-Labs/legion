// `legion state snapshot|verify` — the mechanical machine-state boundary.
//
// Built after the HeardRight escape (2026-08-10): an intermediate test wrote a
// fake `two/cpu_only` route into the app's REAL app-data directory; the final
// source was clean (mock persister), every test was green, Seer passed the
// audit, and the shipped build loaded CPU instead of DML. The doctrine rule in
// doctrine/bundles/seer-assurance.md names the failure; this command is the
// enforcement — prose asks an auditor to remember, a snapshot/verify pair
// fails the run.
//
// Usage (wrap any test run):
//   legion state snapshot --path <dir-or-file> [--path ...] --out .cache/state-before.json
//   <run tests>
//   legion state verify --snapshot .cache/state-before.json
//
// verify exits nonzero listing every path that changed, appeared, or vanished
// under the snapshotted surface. Any delta under a production path caused by a
// test run is a defect (or the test run touched state it must not own) — the
// caller decides which, but it cannot happen silently.
//
// Deliberately dumb: no daemon, no watch mode, no allowlist logic. Hashes are
// sha256 of file bytes; directories are walked fully. A tool this small has
// nothing to be wrong about.

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { parseArgs } from 'node:util';

import { EXIT, LegionError } from '../../errors.mjs';

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

/** Walk a file or directory into {relativePath: {sha256, size}} entries. */
function collect(root) {
  const entries = {};
  const rootResolved = resolve(root);
  let rootStat;
  try {
    rootStat = statSync(rootResolved);
  } catch {
    return entries; // absent surface is a valid observation: {} — appearing later IS a delta.
  }
  if (rootStat.isFile()) {
    entries['.'] = { sha256: sha256(rootResolved), size: rootStat.size };
    return entries;
  }
  const walk = (dir, prefix) => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      const rel = prefix ? `${prefix}/${name}` : name;
      let st;
      try { st = statSync(full); } catch { continue; } // vanished mid-walk: racing writer, skip
      if (st.isDirectory()) walk(full, rel);
      else if (st.isFile()) {
        try { entries[rel] = { sha256: sha256(full), size: st.size }; } catch { /* unreadable: not observable */ }
      }
    }
  };
  walk(rootResolved, '');
  return entries;
}

export async function runState(argv, { stdout, stderr, env, cwd }) {
  const [sub, ...rest] = argv;
  if (sub === 'snapshot') return stateSnapshot(rest, { stdout, cwd });
  if (sub === 'verify') return stateVerify(rest, { stdout, stderr, cwd });
  throw new LegionError(`state requires a subcommand: snapshot|verify (got ${sub ?? '<none>'})`, { code: 'USAGE', exitCode: EXIT.USAGE });
}

function stateSnapshot(argv, { stdout, cwd }) {
  const { values } = parseArgs({ args: argv, strict: true, allowPositionals: false, options: { path: { type: 'string', multiple: true }, out: { type: 'string' } } });
  const paths = values.path ?? [];
  if (paths.length === 0 || !values.out) {
    throw new LegionError('state snapshot requires --path <file-or-dir> (repeatable) and --out <snapshot.json>', { code: 'USAGE', exitCode: EXIT.USAGE });
  }
  const surfaces = {};
  for (const p of paths) surfaces[resolve(cwd, p)] = collect(resolve(cwd, p));
  const snapshot = { schema: 'legion-state-snapshot.v1', takenAt: new Date().toISOString(), surfaces };
  const out = resolve(cwd, values.out);
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, `${JSON.stringify(snapshot, null, 2)}\n`);
  const fileCount = Object.values(surfaces).reduce((n, s) => n + Object.keys(s).length, 0);
  stdout.write(`${JSON.stringify({ kind: 'legion-state-snapshot', surfaces: paths.length, files: fileCount, out })}\n`);
  return { exitCode: EXIT.PASS };
}

function stateVerify(argv, { stdout, stderr, cwd }) {
  const { values } = parseArgs({ args: argv, strict: true, allowPositionals: false, options: { snapshot: { type: 'string' } } });
  if (!values.snapshot) {
    throw new LegionError('state verify requires --snapshot <snapshot.json>', { code: 'USAGE', exitCode: EXIT.USAGE });
  }
  let snapshot;
  try {
    snapshot = JSON.parse(readFileSync(resolve(cwd, values.snapshot), 'utf8'));
  } catch (err) {
    throw new LegionError(`state verify cannot read snapshot: ${err.message}`, { code: 'USAGE', exitCode: EXIT.USAGE });
  }
  if (snapshot?.schema !== 'legion-state-snapshot.v1') {
    throw new LegionError('snapshot schema must be legion-state-snapshot.v1', { code: 'USAGE', exitCode: EXIT.USAGE });
  }

  const deltas = [];
  for (const [surface, before] of Object.entries(snapshot.surfaces)) {
    const after = collect(surface);
    for (const [rel, entry] of Object.entries(before)) {
      if (!(rel in after)) deltas.push({ surface, path: rel, change: 'deleted' });
      else if (after[rel].sha256 !== entry.sha256) deltas.push({ surface, path: rel, change: 'modified' });
    }
    for (const rel of Object.keys(after)) {
      if (!(rel in before)) deltas.push({ surface, path: rel, change: 'created' });
    }
  }

  if (deltas.length === 0) {
    stdout.write(`${JSON.stringify({ kind: 'legion-state-verify', verdict: 'clean', deltas: [] })}\n`);
    return { exitCode: EXIT.PASS };
  }
  stderr.write(`STATE BOUNDARY BREACH: ${deltas.length} delta(s) under snapshotted production state\n`);
  for (const d of deltas.slice(0, 20)) stderr.write(`  ${d.change}: ${d.surface} :: ${d.path}\n`);
  stdout.write(`${JSON.stringify({ kind: 'legion-state-verify', verdict: 'breach', deltas })}\n`);
  return { exitCode: EXIT.POLICY_FAIL };
}
