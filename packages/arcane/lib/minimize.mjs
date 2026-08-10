// Minimize commit gate — Arcane's, now that it lives here.
//
// This is a receipt-gated effect check: it binds a review to the exact staged
// tree, mints a receipt over it, and refuses the commit when the receipt does
// not describe what is actually being committed. That is Arcane's discipline
// (hash-bound receipts gating an effect), and it was implemented outside Arcane
// in a separate language with none of Arcane's guarantees.
//
// Ported from tools/lib/minimize/minimize_gate.py. Behaviour is intentionally
// identical — the Python version is the spec, and its tests are the parity
// check. Four properties it carries, each of which was earned by a real failure:
//
//   1. POSIX ERE only. `git grep -E` runs against libc's regex engine; macOS and
//      BSD do not understand \s or \b (only GNU glibc does). Using them matched
//      nothing on Mac while matching on Windows — a check that is a silent no-op
//      on one platform and looks healthy on the other.
//   2. Package-scoped. Apps consume published packages, never each other's
//      internals, so a name shared across two packages is not a duplicate anyone
//      could have reused.
//   3. Language-scoped. A Python `def evaluate` and a JS `function evaluate` are
//      not a duplicate; no commit can reuse one from the other.
//   4. Underscore-private names are skipped. `_helper` is module-private by
//      convention in both languages, so "you could have reused it" is false by
//      construction.

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

export const RUNGS = ['NOT_BUILD', 'REUSE', 'STDLIB', 'NATIVE', 'INSTALLED_DEP', 'ONE_LINE', 'MIN_CUSTOM'];
export const REVIEW_SCHEMA = 'minimize-commit-review.v1';
export const RECEIPT_SCHEMA = 'minimize-commit-receipt.v1';

export class MinimizeError extends Error {
  constructor(message) {
    super(message);
    this.name = 'MinimizeError';
  }
}

const ADDED_DECL_RE = /^\+\s*(?:export\s+)?(?:async\s+)?(?:function|class|def)\s+([A-Za-z_$][\w$]*)|^\+\s*(?:export\s+)?(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\()/;

// Names too ubiquitous to mean duplication (every adapter has a `main`).
const COMMON_NAMES = new Set([
  'main', 'handle', 'create', 'resolve', 'render', 'update', 'delete', 'insert',
  'execute', 'process', 'convert', 'collect', 'compare', 'extract', 'cleanup',
]);
const SOURCE_SUFFIXES = new Set(['.mjs', '.js', '.cjs', '.ts', '.tsx', '.py', '.rs']);
const LANGUAGE_FAMILIES = [
  ['*.mjs', '*.js', '*.cjs', '*.ts', '*.tsx'],
  ['*.py'],
  ['*.rs'],
];
const OWNER_MANIFESTS = new Set(['package.json', 'Cargo.toml', 'pyproject.toml', 'go.mod', 'deno.json']);
// See property 1 above: POSIX character classes, never \s or \b.
const DECL_SEARCH = '(export[[:space:]]+)?(async[[:space:]]+)?(function|class|def|const|let)[[:space:]]+{name}([^A-Za-z0-9_$]|$)';

function git(...args) {
  const result = spawnSync('git', args, { encoding: 'utf8', windowsHide: true, maxBuffer: 64 * 1024 * 1024 });
  if (result.status !== 0) throw new MinimizeError((result.stderr || '').trim() || `git ${args.join(' ')} failed`);
  return result.stdout.trim();
}

/** git that tolerates the "no match" exit status (git grep returns 1). */
function gitOptional(...args) {
  const result = spawnSync('git', args, { encoding: 'utf8', windowsHide: true, maxBuffer: 64 * 1024 * 1024 });
  return result.status === 0 || result.status === 1 ? (result.stdout ?? '') : '';
}

export function stagedTree() {
  return git('write-tree');
}

export function stagedFiles(env = process.env) {
  const base = env.MINIMIZE_BASE_REF;
  const args = ['diff', '--cached'];
  if (base) args.push(base);
  args.push('--name-only', '--diff-filter=ACMR');
  return git(...args).split('\n').filter(Boolean);
}

export function stagedAddedFiles() {
  return git('diff', '--cached', '--name-only', '--diff-filter=A').split('\n').filter(Boolean);
}

/** Dependency names ADDED to any staged manifest, read from the diff itself. */
export function stagedNewDependencies() {
  const found = new Set();
  for (const name of stagedFiles()) {
    const base = name.split('/').pop();
    if (!['package.json', 'pyproject.toml', 'Cargo.toml'].includes(base)) continue;
    for (const line of gitOptional('diff', '--cached', '-U0', '--', name).split('\n')) {
      if (!line.startsWith('+') || line.startsWith('+++')) continue;
      const match = line.match(/^\+\s*"([^"]+)"\s*:\s*"/) ?? line.match(/^\+\s*([A-Za-z0-9_-]+)\s*=\s*["{]/);
      if (match) found.add(match[1]);
    }
  }
  return [...found].sort();
}

function suffixOf(path) {
  const base = path.split('/').pop() ?? '';
  const dot = base.lastIndexOf('.');
  return dot <= 0 ? '' : base.slice(dot);
}

export function languageFamily(path) {
  const suffix = `*${suffixOf(path)}`;
  return LANGUAGE_FAMILIES.find((family) => family.includes(suffix)) ?? [];
}

/**
 * Repo-relative directory of the nearest package manifest above `path`, or ""
 * for the repository root. Searched at HEAD, not on disk, so the boundary is the
 * one the commit is actually measured against.
 */
export function ownerRoot(path) {
  let current = path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '.';
  for (;;) {
    const listing = gitOptional('ls-tree', '--name-only', 'HEAD', current === '.' ? 'HEAD:' : `${current}/`);
    const names = new Set(listing.split('\n').filter(Boolean).map((row) => row.split('/').pop()));
    if ([...OWNER_MANIFESTS].some((manifest) => names.has(manifest))) return current === '.' ? '' : current;
    if (current === '.') return '';
    current = current.includes('/') ? current.slice(0, current.lastIndexOf('/')) : '.';
  }
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Symbols this commit declares that HEAD already declared somewhere else. */
export function reuseFindings() {
  const changed = stagedFiles().filter((name) => SOURCE_SUFFIXES.has(suffixOf(name)));
  const findings = [];
  const seen = new Set();
  for (const path of changed) {
    for (const line of gitOptional('diff', '--cached', '-U0', '--', path).split('\n')) {
      const match = ADDED_DECL_RE.exec(line);
      if (!match) continue;
      const symbol = match[1] || match[2];
      if (!symbol || symbol.startsWith('_') || seen.has(symbol) || COMMON_NAMES.has(symbol) || symbol.length < 6) continue;
      seen.add(symbol);
      const family = languageFamily(path);
      if (family.length === 0) continue;
      const owner = ownerRoot(path);
      const scope = family.map((glob) => (owner ? `${owner}/${glob}` : glob));
      const pattern = DECL_SEARCH.replace('{name}', escapeRegex(symbol));
      // `git grep -l <rev>` prints "HEAD:<path>"; keep the path half only.
      const hits = gitOptional('grep', '-l', '-E', pattern, 'HEAD', '--', ...scope)
        .split('\n')
        .filter(Boolean)
        .map((row) => row.slice(row.indexOf(':') + 1));
      const elsewhere = [...new Set(hits.filter((hit) => hit !== path && ownerRoot(hit) === owner))].sort();
      if (elsewhere.length > 0) {
        findings.push({
          rung: 'REUSE',
          symbol,
          added_in: path,
          already_defined_in: elsewhere.slice(0, 5),
          detail: `'${symbol}' is added in ${path} but HEAD already defines it in ${elsewhere[0]}`,
          status: 'open',
        });
      }
    }
  }
  return findings;
}

export function buildReview() {
  const findings = reuseFindings();
  return {
    schema: REVIEW_SCHEMA,
    candidate_tree: stagedTree(),
    scope_files: stagedFiles(),
    selected_rung: 'REUSE',
    rung_checks: [
      { rung: 'NOT_BUILD', verdict: 'REJECTED', evidence: 'staged change is requested' },
      {
        rung: 'REUSE',
        verdict: findings.length === 0 ? 'REJECTED' : 'OPEN',
        evidence: `searched HEAD for every declaration this commit adds; ${findings.length} already defined elsewhere`,
      },
    ],
    new_files: stagedAddedFiles(),
    new_dependencies: stagedNewDependencies(),
    findings,
    verdict: 'CLEAN',
  };
}

export function validateReview(review) {
  if (review?.schema !== REVIEW_SCHEMA) throw new MinimizeError(`review schema must be ${REVIEW_SCHEMA}`);
  if (review.candidate_tree !== stagedTree()) throw new MinimizeError('stale review: candidate_tree mismatch');
  const declared = [...(review.scope_files ?? [])].sort();
  const actual = [...stagedFiles()].sort();
  if (JSON.stringify(declared) !== JSON.stringify(actual)) throw new MinimizeError('stale review: scope_files mismatch');
  if (review.verdict !== 'CLEAN') throw new MinimizeError('review verdict must be CLEAN');

  const open = (review.findings ?? []).filter((row) => !['resolved', 'waived'].includes(row?.status));
  if (open.length > 0) {
    const detail = open.slice(0, 3).map((row) => String(row.detail || row.symbol || 'unnamed finding')).join('; ');
    throw new MinimizeError(
      `open finding blocks commit receipt: ${detail}. `
      + "Reuse the existing definition, or set that finding's status to 'waived' with a reason if the duplicate is deliberate.",
    );
  }
  // A waiver is the governed party excusing itself, so it must at least cost a
  // stated reason and leave a trace. The policy bundle reserves waivers to Sage
  // (waiverAuthority), but that cannot be enforced until authority bindings carry
  // a real sessionId/agentId — an authority-bound waiver would be unsatisfiable
  // today, a dead end rather than a control.
  const unexplained = (review.findings ?? []).filter(
    (row) => row?.status === 'waived' && !String(row?.waiver_reason ?? '').trim(),
  );
  if (unexplained.length > 0) {
    const names = unexplained.slice(0, 3).map((row) => String(row.symbol ?? 'unnamed finding')).join(', ');
    throw new MinimizeError(
      `waived finding needs a waiver_reason: ${names}. `
      + 'A waiver with no stated reason is indistinguishable from silently deleting the finding.',
    );
  }
  return review;
}

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

export function buildReceipt(reviewPath, { policyPath, validatorPath }) {
  const review = validateReview(readJson(reviewPath));
  return {
    schema: RECEIPT_SCHEMA,
    candidate_tree: review.candidate_tree,
    scope_files: review.scope_files,
    review: resolve(reviewPath),
    review_sha256: sha256File(reviewPath),
    policy_sha256: sha256File(policyPath),
    validator_sha256: sha256File(validatorPath),
    // Carried on purpose: a CLEAN verdict reached by waiving findings is a
    // different fact from one reached with none, and the receipt is the only
    // place a later reader can tell them apart.
    waivers: (review.findings ?? [])
      .filter((row) => row?.status === 'waived')
      .map((row) => ({ symbol: row.symbol ?? null, reason: row.waiver_reason ?? null })),
    verdict: 'CLEAN',
  };
}

export function verifyReceipt(receipt, { policyPath, validatorPath }) {
  if (receipt?.schema !== RECEIPT_SCHEMA) throw new MinimizeError('commit receipt schema mismatch');
  if (receipt.candidate_tree !== stagedTree()) throw new MinimizeError('stale commit receipt: candidate_tree mismatch');
  const declared = [...(receipt.scope_files ?? [])].sort();
  const actual = [...stagedFiles()].sort();
  if (JSON.stringify(declared) !== JSON.stringify(actual)) throw new MinimizeError('stale commit receipt: scope_files mismatch');
  if (receipt.policy_sha256 !== sha256File(policyPath)) throw new MinimizeError('stale commit receipt: policy_sha256 mismatch');
  if (receipt.validator_sha256 !== sha256File(validatorPath)) throw new MinimizeError('stale commit receipt: validator_sha256 mismatch');
  if (receipt.verdict !== 'CLEAN') throw new MinimizeError('commit receipt verdict must be CLEAN');
  return receipt;
}

// --- decision domain -------------------------------------------------------
//
// The other half of the gate: a Minimize *decision* records which rung of the
// ladder a change selected and why every cheaper rung was rejected. The dispatch
// validator loads this to refuse a dispatch whose Minimize authority is missing,
// invalid, or stale — so it has to move with the commit half, or minimize ends
// up living in two languages in two places, which is the state this port exists
// to end.

export const DECISION_SCHEMA = 'minimize-decision.v1';
export const DECISION_RECEIPT_SCHEMA = 'minimize-decision-receipt.v1';

export function validateDecision(value, newFiles = [], newDependencies = []) {
  if (value?.schema !== DECISION_SCHEMA) throw new MinimizeError(`decision schema must be ${DECISION_SCHEMA}`);
  const selected = value.selected_rung;
  if (!RUNGS.includes(selected)) throw new MinimizeError(`selected_rung must be one of: ${RUNGS.join(', ')}`);
  const prior = value.prior_rungs;
  if (!Array.isArray(prior)) throw new MinimizeError('prior_rungs must be a list');

  const required = RUNGS.slice(0, RUNGS.indexOf(selected));
  const observed = prior.filter((row) => row && typeof row === 'object').map((row) => row.rung);
  if (JSON.stringify(observed) !== JSON.stringify(required)) {
    const missing = required.find((rung) => !observed.includes(rung)) ?? 'ordered prior rung';
    throw new MinimizeError(`missing or unordered prior rung: ${missing}`);
  }
  for (const row of prior) {
    if (row?.verdict !== 'REJECTED' || !String(row?.evidence ?? '').trim()) {
      throw new MinimizeError(`prior rung ${row?.rung} needs REJECTED verdict and evidence`);
    }
  }
  for (const key of ['decision_id', 'state_a', 'state_b']) {
    if (!String(value[key] ?? '').trim()) throw new MinimizeError(`${key} is required`);
  }
  const allowedFiles = new Set(value.allowed_new_files ?? []);
  const allowedDeps = new Set(value.allowed_new_dependencies ?? []);
  const deniedFiles = [...new Set(newFiles)].filter((name) => !allowedFiles.has(name)).sort();
  const deniedDeps = [...new Set(newDependencies)].filter((name) => !allowedDeps.has(name)).sort();
  if (deniedFiles.length > 0) throw new MinimizeError(`new file not allowed by decision: ${deniedFiles.join(', ')}`);
  if (deniedDeps.length > 0) throw new MinimizeError(`new dependency not allowed by decision: ${deniedDeps.join(', ')}`);
  return value;
}

export function decisionReceipt(sourcePath, { policyPath, validatorPath }) {
  const value = validateDecision(readJson(sourcePath));
  return {
    schema: DECISION_RECEIPT_SCHEMA,
    decision: canonicalLocator(sourcePath),
    decision_sha256: sha256File(sourcePath),
    policy_sha256: sha256File(policyPath),
    validator_sha256: sha256File(validatorPath),
    decision_id: value.decision_id,
    selected_rung: value.selected_rung,
  };
}

export function verifyDecision(sourcePath, receiptPath, paths) {
  const expected = decisionReceipt(sourcePath, paths);
  const actual = readJson(receiptPath);
  for (const key of ['decision_sha256', 'policy_sha256', 'validator_sha256', 'decision_id', 'selected_rung']) {
    if (actual[key] !== expected[key]) throw new MinimizeError(`stale decision receipt: ${key} mismatch`);
  }
  return actual;
}

/** Repo-relative path when inside a repo, else absolute — matches the Python locator. */
export function canonicalLocator(path) {
  const resolved = resolve(path);
  const result = spawnSync('git', ['-C', dirname(resolved), 'rev-parse', '--show-toplevel'], {
    encoding: 'utf8', windowsHide: true,
  });
  if (result.status !== 0) return resolved;
  const root = result.stdout.trim();
  const normalized = resolved.replace(/\\/g, '/');
  const rootNormalized = root.replace(/\\/g, '/');
  return normalized.startsWith(`${rootNormalized}/`) ? normalized.slice(rootNormalized.length + 1) : resolved;
}

export function readJson(path) {
  try {
    const value = JSON.parse(readFileSync(path, 'utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('not an object');
    return value;
  } catch (error) {
    throw new MinimizeError(`cannot read ${path}: ${error.message}`);
  }
}

/** Deep key-sorted, matching Python's json.dump(..., sort_keys=True) byte for byte. */
function sortKeysDeep(value) {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortKeysDeep(value[key])]));
  }
  return value;
}

export function writeJson(path, value) {
  mkdirSync(dirname(resolve(path)), { recursive: true });
  writeFileSync(path, `${JSON.stringify(sortKeysDeep(value), null, 2)}\n`, 'utf8');
}

export function fileExists(path) {
  return existsSync(path);
}
