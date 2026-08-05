#!/usr/bin/env node
// collect-facts.mjs — deterministic scanner runner for the audit skill (P1: required checks).
//
// Detects the repo's stack(s), runs every applicable required scanner, and writes
//   <out>/facts.json  +  <out>/<check>.log   (secret-redacted)
// Scanners run in a bounded PARALLEL pool; the `build` check runs SEQUENTIALLY, alone,
// after the pool drains (CLAUDE.md: builds/installs are serial).
//
// Proof model: every check records its literal command + exit code + log path, so a human
// or CI can RE-RUN any line and get the same result. The agent never asserts a deterministic
// result it didn't run — absent tools are reported as `skipped`, never silently "clean".
//
// Usage:
//   node collect-facts.mjs <root> [--out <dir>] [--skip a,b] [--only a,b] [--json]
//
// ponytail: minimum mechanism — spawn the standard CLIs, normalize what they emit, skip
//           loudly when absent. No hashing subsystem (proof is re-run, not sha256).

import { spawn } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, mkdirSync, writeFileSync, chmodSync, unlinkSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { cpus } from 'node:os';
import { pathToFileURL } from 'node:url';

const args = process.argv.slice(2);
// Root = the first bare positional. Tokens consumed as a value-taking flag's argument are NOT
// positionals — without this, `collect-facts.mjs --only apple_platform` silently set root to
// "apple_platform", so every check that reads tracked files saw an empty repo and skipped.
const VALUE_FLAGS = new Set(['--base', '--base-commit', '--dir', '--only', '--out', '--skip', '--type']);
const root = (() => {
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) { if (VALUE_FLAGS.has(args[i])) i++; continue; }
    return args[i];
  }
  return process.cwd();
})();
const flag = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const has  = (name) => args.includes(name);
const skip = new Set((flag('--skip') || '').split(',').filter(Boolean));
const only = new Set((flag('--only') || '').split(',').filter(Boolean));
const scopeType = flag('--type') || 'all';
const scopeDir = cleanPath(flag('--dir'));
const scopeBase = gitRef(flag('--base'));
const scopeBaseCommit = gitRef(flag('--base-commit'));
const ts   = new Date().toISOString().replace(/[:.]/g, '-');
const outDir = flag('--out') || join(root, '.audit', ts);
const CONCURRENCY = Math.max(1, Math.min(cpus().length - 1, 4));

// ---------- helpers ----------
function run(command, { cwd = root, timeoutMs = 180000 } = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(command, { cwd, shell: true });   // shell:true for cross-platform npm/npx/.cmd
    let out = '', err = ''; const CAP = 5 * 1024 * 1024;
    child.stdout.on('data', d => { if (out.length < CAP) out += d; });
    child.stderr.on('data', d => { if (err.length < CAP) err += d; });
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.on('close', code => { clearTimeout(timer); resolve({ code, stdout: out, stderr: err, duration_ms: Date.now() - started }); });
    child.on('error', e => { clearTimeout(timer); resolve({ code: -1, stdout: out, stderr: String(e), duration_ms: Date.now() - started, spawn_error: true }); });
  });
}

// Tool presence via ENOENT (reliable on Windows + macOS; exit codes are not — cmd.exe
// returns 1/9009, bash returns 127). Only for real binaries (gitleaks, mypy, semgrep…),
// NOT pkg-manager .cmd shims (npm/pnpm) which ENOENT under shell:false even when present.
function which(bin) {
  return new Promise((resolve) => {
    const c = spawn(bin, ['--version'], { shell: false });
    c.on('error', (e) => resolve(e.code !== 'ENOENT'));
    c.on('close', () => resolve(true));
    setTimeout(() => { try { c.kill('SIGKILL'); } catch {} }, 10000).unref();
  });
}
// npx-resolved tools (tsc, eslint) are "present" iff the package is a dependency — deterministic.
function hasDep(d, name) {
  const p = d.pkg || {};
  return !!((p.dependencies && p.dependencies[name]) || (p.devDependencies && p.devDependencies[name]));
}
// Post-hoc missing-tool signal for shell-invoked commands (pkg managers, npx).
function looksMissing(r) {
  return /is not recognized|command not found|ENOENT|could not determine executable|npm error code ENOENT|npx canceled|missing packages|no YES option/i.test((r.stderr || '') + (r.stdout || ''));
}

function fileExists(...p) { return existsSync(join(root, ...p)); }
function pkgJson() { try { return JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')); } catch { return null; } }
function decompositionReviewLoc() {
  // No silent defaults: a configured-but-invalid value is surfaced as `ignored`, never dropped.
  const ignored = [];
  const valid = (n) => Number.isInteger(n) && n >= 100;
  const rawEnv = process.env.CORTEX_DECOMPOSITION_REVIEW_LOC;
  if (rawEnv !== undefined && rawEnv !== '') {
    const fromEnv = Number(rawEnv);
    if (valid(fromEnv)) return { value: fromEnv, source: 'cortex-config', ignored };
    ignored.push({ source: 'CORTEX_DECOMPOSITION_REVIEW_LOC', value: rawEnv, reason: 'must be an integer >= 100' });
  }
  try {
    const config = JSON.parse(readFileSync(join(root, '.agent', 'config.json'), 'utf8'));
    const configured = config?.hygiene?.decompositionReviewLoc;
    if (configured !== undefined && configured !== null) {
      if (valid(Number(configured))) return { value: Number(configured), source: '.agent/config.json', ignored };
      ignored.push({ source: '.agent/config.json hygiene.decompositionReviewLoc', value: configured, reason: 'must be an integer >= 100' });
    }
  } catch {}
  for (const item of ignored) console.error(`[decomposition] ignoring configured review threshold from ${item.source} (${JSON.stringify(item.value)}): ${item.reason}; using workspace default 400`);
  return { value: 400, source: 'workspace-default', ignored };
}
function isGeneratedOrVendoredPath(file) {
  const f = cleanPath(file);
  return (
    f.startsWith('vendor/') ||
    f.startsWith('qwik/') ||
    f.startsWith('dist/') ||
    f.startsWith('src-tauri/gen/') ||
    f.startsWith('src/generated/') ||
    f.includes('/src/generated/') ||
    f.includes('/drizzle/')
  );
}

// Classify a tracked code file by what it IS, so ship-quality gates (decompose floor) apply to
// RUNTIME code first. Tests stay in scope for secrets/correctness, but a 2000-line test file is not
// the same architecture debt as a 2000-line runtime god-file. Conservative: only clearly-test and
// clearly-config classify as non-runtime; anything ambiguous stays `runtime` (safer to flag than skip).
function classifyFile(file) {
  const p = '/' + cleanPath(file).toLowerCase();
  const base = p.split('/').pop();
  if (/(?:^|\/)(?:tests?|specs?|__tests__|__mocks__|e2e|fixtures?|__fixtures__|cypress|playwright|\.storybook)\//.test(p)
      || /\.(test|spec|stories|bench|e2e|cy)\.[a-z0-9]+$/.test(base)
      || /_test\.[a-z0-9]+$/.test(base) || /^test_.*\.py$/.test(base) || base === 'conftest.py') return 'test';
  if (/(?:^|\/)\.github\//.test(p)
      || /\.config\.[a-z0-9]+$/.test(base) || /\.(setup|teardown)\.[a-z0-9]+$/.test(base)
      || base === 'dockerfile' || base === 'makefile') return 'tooling';
  return 'runtime';
}

function cleanPath(p) {
  return p ? String(p).replace(/\\/g, '/').replace(/^\.\/+/, '').replace(/\/+$/, '') : null;
}

// Memoized `git ls-files` — several grep-style checks walk the tracked set; run it once.
let _tracked = null;
async function trackedFiles() {
  if (!_tracked) _tracked = (await run('git ls-files')).stdout.split('\n').filter(Boolean).map(cleanPath);
  return _tracked;
}

function gitRef(ref) {
  if (!ref) return null;
  const s = String(ref);
  if (!/^[A-Za-z0-9][A-Za-z0-9._/@-]*$/.test(s)) throw new Error(`Unsafe git ref: ${s}`);
  return s;
}

function inScope(file, dir) {
  const f = cleanPath(file);
  const d = cleanPath(dir);
  return !d || f === d || f.startsWith(d + '/');
}

async function changedFiles(d) {
  if (!d.git) return [];
  // `local` = ALL local changes (what /commit guards): working tree (tracked) ∪ untracked ∪
  // committed-but-unpushed. Distinct from `all`, which means whole-repo (no diff scope).
  if (scopeType === 'local') {
    const out = [
      (await run('git diff --name-only HEAD')).stdout || '',                  // staged + unstaged (tracked)
      (await run('git ls-files --others --exclude-standard')).stdout || '',   // new untracked files
    ];
    const up = await run('git rev-parse --abbrev-ref --symbolic-full-name @{u}');
    if (up.code === 0 && (up.stdout || '').trim()) {
      out.push((await run('git diff --name-only @{u}..HEAD')).stdout || '');   // committed but not pushed
    }
    return [...new Set(out.join('\n').split('\n').map(cleanPath).filter(Boolean))]
      .filter(f => !f.startsWith('.audit/') && !isGeneratedOrVendoredPath(f))   // never sweep the audit's own output / vendored
      .filter(f => inScope(f, scopeDir));
  }
  let cmd = null;
  if (scopeBaseCommit) cmd = `git diff --name-only ${scopeBaseCommit}`;
  else if (scopeBase) cmd = `git diff --name-only ${scopeBase}...HEAD`;
  else if (scopeType === 'uncommitted') cmd = 'git diff --name-only';
  else if (scopeType === 'committed') cmd = 'git diff --name-only HEAD~1..HEAD';
  if (!cmd) return [];   // `all` (whole-repo) or unknown → no diff scope
  const r = await run(cmd);
  return (r.stdout || '').split('\n').map(cleanPath).filter(Boolean).filter(f => inScope(f, scopeDir));
}

async function scopeFor(d) {
  const scoped = !!(scopeDir || scopeBase || scopeBaseCommit || scopeType !== 'all');
  return {
    mode: scoped ? 'diff' : 'whole-repo',
    type: scopeType,
    base: scopeBase || null,
    base_commit: scopeBaseCommit || null,
    dir: scopeDir || null,
    changed_files: await changedFiles(d),
  };
}

function redact(text) {
  if (!text) return text;
  return String(text)
    .replace(/\bsk-[A-Za-z0-9]{16,}\b/g, '<REDACTED:openai>')
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, '<REDACTED:aws>')
    .replace(/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, '<REDACTED:github>')
    .replace(/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, '<REDACTED:slack>')
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '<REDACTED:privkey>')
    .replace(/\b[A-Za-z0-9+/]{60,}={0,2}\b/g, '<REDACTED:b64>');
}
function redactGitleaks(jsonText) {
  try {
    const arr = JSON.parse(jsonText);
    for (const f of arr) { if (f.Secret) f.Secret = '<REDACTED>'; if (f.Match) f.Match = '<REDACTED>'; }
    return JSON.stringify(arr, null, 2);
  } catch { return redact(jsonText); }
}

async function pool(items, worker) {
  const out = []; let i = 0;
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, items.length || 1) }, async () => {
    while (i < items.length) { const idx = i++; out[idx] = await worker(items[idx], idx); }
  }));
  return out;
}

// ---------- stack detection ----------
// Walk up for .git — audits are often scoped to a subtree (e.g. <repo>/tauri-app-next) whose repo
// root is a parent; git commands run fine from the subdir (and scope themselves to it).
function inGitWorktree() {
  let dir = root;
  for (let i = 0; i < 12; i++) {
    if (existsSync(join(dir, '.git'))) return true;
    const parent = join(dir, '..');
    if (parent === dir) break;
    dir = parent;
  }
  return false;
}

function detect() {
  const pkg = pkgJson();
  const pkgMgr = fileExists('pnpm-lock.yaml') ? 'pnpm' : fileExists('yarn.lock') ? 'yarn' : 'npm';
  // Tauri apps keep Cargo.toml under src-tauri/ — a root-only check misses the whole Rust tree
  // (clippy/build/cargo-audit would silently skip every Right Suite app).
  const rustDir = fileExists('Cargo.toml') ? '.' : (fileExists('src-tauri', 'Cargo.toml') ? 'src-tauri' : null);
  return {
    git:   inGitWorktree(),
    node:  !!pkg,
    pkg, pkgMgr,
    ts:    fileExists('tsconfig.json'),
    py:    fileExists('pyproject.toml') || fileExists('setup.py') || fileExists('requirements.txt'),
    rust:  rustDir !== null,
    rustDir,
    // Swift signal — a Tauri workspace has no Swift, but the shared iOS packages (RightKitSwift) +
    // iOS app repos do. SPM manifest or an Xcode project/workspace at root is the cheap marker; the
    // swift_lint check falls back to a `git ls-files *.swift` scan for nested-only sources.
    swift: (() => { try { return fileExists('Package.swift') || readdirSync(root).some(n => /\.(xcodeproj|xcworkspace)$/.test(n)); } catch { return false; } })(),
    tauri: fileExists('src-tauri', 'tauri.conf.json'),
    buildScript: !!(pkg && pkg.scripts && pkg.scripts.build),
    eslint: ['.eslintrc', '.eslintrc.js', '.eslintrc.cjs', '.eslintrc.json', '.eslintrc.yml', 'eslint.config.js', 'eslint.config.mjs', 'eslint.config.cjs'].some(f => fileExists(f)) || !!(pkg && pkg.eslintConfig),
    biome: ['biome.json', 'biome.jsonc'].some(f => fileExists(f)),
    workflows: fileExists('.github', 'workflows'),
    dockerfile: fileExists('Dockerfile'),
  };
}

// ---------- check definitions (P1: required six) ----------
const ALL_CHECK_NAMES = [];   // full registry, unaffected by --only/--skip (manifest-drift denominator)
function buildChecks(d) {
  const list = [];
  const add = (c) => { ALL_CHECK_NAMES.push(c.check); if (only.size && !only.has(c.check)) return; if (skip.has(c.check)) { list.push({ ...c, _forceSkip: true }); return; } list.push(c); };

  add({ check: 'repo', tool: 'git', required: d.git, parallel: true,
        run: async () => {
          if (!d.git) return { status: 'unproven', skip_reason: 'not a git repo' };
          const sha = (await run('git rev-parse HEAD')).stdout.trim();
          const files = (await run('git ls-files')).stdout.split('\n').filter(Boolean).length;
          return { status: 'ran', command: 'git rev-parse HEAD; git ls-files', exit_code: 0, meta: { commit: sha, tracked_files: files }, log: '' };
        } });

  // Size is a deterministic REVIEW TRIGGER, never proof that decomposition is correct. Cortex
  // enriches these candidates with graph metrics; Audit/Architect must inspect responsibilities,
  // state, callers, dependencies, and tests before emitting a decomposition finding or plan.
  add({ check: 'decomposition', tool: 'loc', required: false, parallel: true,
        run: async () => {
          if (!d.git) return { status: 'unproven', skip_reason: 'not a git repo' };
          const CODE = /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rs|java|rb|php|c|cc|cpp|h|hpp|cs|swift|kt|scala|sh|sql)$/;
          const reviewThreshold = decompositionReviewLoc();
          const FILE_REVIEW_LOC = reviewThreshold.value;
          const files = (await run('git ls-files')).stdout.split('\n').filter((f) => CODE.test(f) && !isGeneratedOrVendoredPath(f));
          // ONE read pass: per-file LOC (for oversized) + include!/mod-stitch count (gaming signal).
          const oversized = [];
          const locByFile = new Map();
          let includeStitchCount = 0;
          for (const f of files) {
            try {
              const txt = readFileSync(join(root, f), 'utf8');
              const loc = txt.split('\n').length;
              locByFile.set(f, loc);
              if (loc > FILE_REVIEW_LOC) oversized.push({ file: f, loc, bytes: Buffer.byteLength(txt, 'utf8'), class: classifyFile(f) });
              includeStitchCount += (txt.match(/^\s*include!\s*\(/gm) || []).length;
            } catch { /* unreadable/binary — skip */ }
          }
          oversized.sort((a, b) => b.loc - a.loc);
          // Mechanical-split detection — a module chopped into `partNN`/`*_parts/` files stitched by
          // include!/mod+pub use can evade a per-file review trigger (many small parts = one huge logical module
          // hidden). Group part-files by their containing dir and reconstruct the logical-unit LOC.
          // Conservative: requires part-naming or a `*_parts/` dir, never flags ordinary barrels/mods.
          const groups = new Map();
          for (const f of files) {
            const segs = f.split(/[\\/]/);
            const base = segs[segs.length - 1] || '';
            const parent = segs[segs.length - 2] || '';
            const isPartsDir = /(?:_parts|^parts)$/i.test(parent);
            const isPartFile = /^part[._-]?\d+\.[a-z0-9]+$/i.test(base);
            if (!isPartsDir && !isPartFile) continue;
            const dir = segs.slice(0, -1).join('/');
            if (!groups.has(dir)) groups.set(dir, []);
            groups.get(dir).push(f);
          }
          const mechanical_splits = [];
          for (const [dir, gfiles] of groups) {
            if (gfiles.length < 2) continue; // a lone part-named file isn't a split
            const logical_loc = gfiles.reduce((s, f) => s + (locByFile.get(f) || 0), 0);
            if (logical_loc <= FILE_REVIEW_LOC) continue; // review only reconstructed units above the trigger
            // runtime if ANY part is runtime (conservative); else test/tooling
            const cls = gfiles.some((f) => classifyFile(f) === 'runtime') ? 'runtime'
                      : (gfiles.some((f) => classifyFile(f) === 'test') ? 'test' : 'tooling');
            // `files` is a display slice; `part_files` is the full list so graph enrichment can
            // aggregate symbols/relationships across every part, not just the first 6.
            mechanical_splits.push({ dir, parts: gfiles.length, logical_loc, files: gfiles.slice(0, 6), part_files: gfiles, class: cls });
          }
          mechanical_splits.sort((a, b) => b.logical_loc - a.logical_loc);
          // Runtime candidates must be assessed by the architecture lens; size alone blocks nothing.
          const all = [...oversized, ...mechanical_splits];
          const by_class = { runtime: all.filter((x) => x.class === 'runtime').length,
                             test: all.filter((x) => x.class === 'test').length,
                             tooling: all.filter((x) => x.class === 'tooling').length };
          return {
            status: 'ran', command: `measure tracked code files (review trigger > ${FILE_REVIEW_LOC} LOC; reconstruct include-split units; class: runtime|test|tooling)`,
            exit_code: 0,
            findings_count: 0,
            candidate_count: oversized.length + mechanical_splits.length,
            meta: {
              threshold: FILE_REVIEW_LOC,
              thresholdKind: 'review-trigger',
              thresholdSource: reviewThreshold.source,
              ...(reviewThreshold.ignored?.length ? { thresholdIgnored: reviewThreshold.ignored } : {}),
              oversized,
              mechanical_splits,
              review_candidates: all,
              include_stitch_count: includeStitchCount,
              by_class,
              runtime_review_candidates: by_class.runtime,
            },
            log: '',
          };
        } });

  add({ check: 'secrets', tool: 'gitleaks', required: false, flag_if_absent: true, tier: 'supplemental', parallel: true,
        run: async () => {
          if (!(await which('gitleaks'))) return { status: 'unproven', skip_reason: 'gitleaks not installed', tool_absent: true };
          const rawPath = join(outDir, '_gitleaks.json');
          // git repos: `git` mode scans tracked history — fast, node_modules-free (dir mode ignores
          // .gitignore and reads node_modules: 10 GB / 4 min / 12k false positives on a real app).
          // ponytail: git-mode covers committed content; uncommitted working-tree secrets would need a
          //           scoped dir scan — add that only if pre-commit coverage ever matters.
          const cmd = d.git
            ? `gitleaks git . --report-format json --no-banner --report-path "${rawPath}"`
            : `gitleaks dir . --report-format json --no-banner --report-path "${rawPath}"`;
          const r = await run(cmd, { timeoutMs: 300000 });
          // gitleaks exit: 0 = no leaks, 1 = leaks found, >1 = error. Never call an error "ran".
          if (r.code > 1 || looksMissing(r)) return { status: 'error', command: cmd, exit_code: r.code, _rawLog: redact(r.stderr || r.stdout) };
          let findings = 0, raw = '[]';
          try { raw = readFileSync(rawPath, 'utf8'); findings = JSON.parse(raw).length; } catch { findings = null; }
          try { unlinkSync(rawPath); } catch {}
          // An unreadable/unparseable report is NOT a clean scan. Reporting 'ran'
          // with a null count defeats secrets_unscanned (which only trips on
          // status !== 'ran') and renders as zero findings downstream — a silent
          // false-clean on the highest-stakes check. Found by the AU20 bench.
          if (findings === null) return { status: 'error', command: cmd, exit_code: r.code, skip_reason: 'gitleaks report unreadable — scan not proven', _rawLog: redact(r.stderr || r.stdout) };
          return { status: 'ran', command: cmd, exit_code: r.code, findings_count: findings, _rawLog: redactGitleaks(raw), duration_ms: r.duration_ms };
        } });

  add({ check: 'deps_cve', tool: `${d.pkgMgr} audit`, required: d.node, parallel: true,
        run: async () => {
          if (!d.node) return { status: 'unproven', skip_reason: 'no package.json' };
          const cmd = `${d.pkgMgr} audit --json`;
          const r = await run(cmd);
          if (looksMissing(r)) return { status: 'error', command: cmd, exit_code: r.code, skip_reason: `${d.pkgMgr} not available`, _rawLog: redact(r.stderr || r.stdout) };
          if (/requires an existing lockfile|no lockfile|ENOLOCK/i.test((r.stderr || '') + (r.stdout || ''))) return { status: 'unproven', command: cmd, exit_code: r.code, skip_reason: `no lockfile for ${d.pkgMgr}` };
          let count = null; try { const j = JSON.parse(r.stdout); count = j?.metadata?.vulnerabilities?.total ?? (j?.metadata?.vulnerabilities && Object.values(j.metadata.vulnerabilities).reduce((a, b) => a + (typeof b === 'number' ? b : 0), 0)) ?? null; } catch {}
          // Same rule as secrets: no parseable count means the audit did not
          // complete, and 'ran' with null renders as 0 findings downstream.
          if (count === null) return { status: 'error', command: cmd, exit_code: r.code, skip_reason: `${d.pkgMgr} audit output unparseable — scan not proven`, _rawLog: redact(r.stdout || r.stderr) };
          return { status: 'ran', command: cmd, exit_code: r.code, findings_count: count, _rawLog: redact(r.stdout || r.stderr), duration_ms: r.duration_ms };
        } });

  // pip-audit — Python dependency CVEs (PyPI Advisory DB + OSV). The npm/cargo-audit sibling; without
  // it a Python tree ships with zero dep-CVE coverage while the report implies its deps were audited.
  add({ check: 'py_deps_cve', tool: 'pip-audit', required: false, flag_if_absent: true, parallel: true,
        run: async () => {
          if (!d.py) return { status: 'unproven', skip_reason: 'no Python project (pyproject/setup.py/requirements)' };
          if (!(await which('pip-audit'))) return { status: 'unproven', skip_reason: 'pip-audit not installed (`pipx install pip-audit`)', tool_absent: true };
          // A requirements file gives a deterministic set; else audit the active environment.
          const req = ['requirements.txt', 'requirements-dev.txt'].find(f => fileExists(f));
          const cmd = req ? `pip-audit -r ${req} -f json` : 'pip-audit -f json';
          const r = await run(cmd, { timeoutMs: 300000 });
          if (looksMissing(r)) return { status: 'unproven', skip_reason: 'pip-audit not resolvable', tool_absent: true };
          let count = null;
          try { const j = JSON.parse(r.stdout); const deps = Array.isArray(j) ? j : (j.dependencies || []); count = deps.reduce((a, dep) => a + ((dep.vulns || dep.vulnerabilities || []).length), 0); } catch {}
          return { status: 'ran', command: cmd, exit_code: r.code, findings_count: count, _rawLog: redact(r.stdout || r.stderr), duration_ms: r.duration_ms };
        } });

  add({ check: 'types', tool: d.ts ? 'tsc' : (d.py ? 'basedpyright|mypy' : null), required: d.ts || d.py, parallel: true,
        run: async () => {
          if (d.ts) {
            if (!hasDep(d, 'typescript')) return { status: 'unproven', skip_reason: 'tsconfig present but typescript not in dependencies', tool_absent: true };
            const cmd = 'npx --no-install tsc --noEmit';
            const r = await run(cmd);
            if (looksMissing(r)) return { status: 'unproven', skip_reason: 'tsc not resolvable via npx --no-install', tool_absent: true };
            const count = (r.stdout + r.stderr).split('\n').filter(l => /error TS\d+/.test(l)).length;
            return { status: 'ran', command: cmd, exit_code: r.code, findings_count: count, _rawLog: redact(r.stdout + r.stderr), duration_ms: r.duration_ms };
          }
          if (d.py) {
            // ruff lints but does NOT type-check. Prefer basedpyright (tsc-parity strict inference);
            // fall back to mypy. This is the Python half of the `types` gate — without it a Python tree
            // ships untyped while the report implies types were checked.
            if (await which('basedpyright')) {
              const cmd = 'basedpyright --outputjson'; const r = await run(cmd);
              let count = null; try { count = JSON.parse(r.stdout)?.summary?.errorCount ?? null; } catch {}
              return { status: 'ran', command: cmd, exit_code: r.code, findings_count: count, _rawLog: redact(r.stdout + r.stderr), duration_ms: r.duration_ms };
            }
            if (await which('mypy')) {
              const cmd = 'mypy .'; const r = await run(cmd);
              return { status: 'ran', command: cmd, exit_code: r.code, _rawLog: redact(r.stdout + r.stderr), duration_ms: r.duration_ms };
            }
            return { status: 'unproven', skip_reason: 'no Python type checker (basedpyright/mypy) installed', tool_absent: true };
          }
          return { status: 'unproven', skip_reason: 'no typed stack detected' };
        } });

  add({ check: 'lint', tool: d.biome ? 'biome' : (d.eslint ? 'eslint' : (d.rust ? 'clippy' : (d.py ? 'ruff' : null))), required: d.eslint || d.biome, parallel: true,
        run: async () => {
          if (d.biome) {
            if (!hasDep(d, '@biomejs/biome')) return { status: 'unproven', skip_reason: 'biome config present but @biomejs/biome not in dependencies', tool_absent: true };
            // --max-diagnostics lifts biome's default 20-diagnostic cap so findings_count is the true
            // total (the clean bar is 0 either way, but a truncated "20" misrepresents a dirty repo).
            const cmd = 'npx --no-install biome lint . --reporter=json --max-diagnostics=1000';
            const r = await run(cmd);
            if (looksMissing(r)) return { status: 'unproven', skip_reason: 'biome not resolvable via npx --no-install', tool_absent: true };
            let count = null;
            try { count = (JSON.parse(r.stdout || '{}').diagnostics || []).length; } catch {}
            return { status: 'ran', command: cmd, exit_code: r.code, findings_count: count, _rawLog: redact(r.stdout || r.stderr), duration_ms: r.duration_ms };
          }
          if (d.eslint) {
            if (!hasDep(d, 'eslint')) return { status: 'unproven', skip_reason: 'eslint config present but eslint not in dependencies', tool_absent: true };
            const cmd = 'npx --no-install eslint . -f json'; const r = await run(cmd);
            if (looksMissing(r)) return { status: 'unproven', skip_reason: 'eslint not resolvable via npx --no-install', tool_absent: true };
            let count = null; try { count = JSON.parse(r.stdout).reduce((a, f) => a + (f.errorCount || 0) + (f.warningCount || 0), 0); } catch {}
            return { status: 'ran', command: cmd, exit_code: r.code, findings_count: count, _rawLog: redact(r.stdout || r.stderr), duration_ms: r.duration_ms };
          }
          if (d.py && (await which('ruff'))) {
            const cmd = 'ruff check . --output-format json'; const r = await run(cmd);
            let count = null; try { count = JSON.parse(r.stdout).length; } catch {}
            return { status: 'ran', command: cmd, exit_code: r.code, findings_count: count, _rawLog: redact(r.stdout || r.stderr), duration_ms: r.duration_ms };
          }
          if (d.rust && (await which('cargo'))) {
            // -D warnings promotes EVERY lint — clippy AND rustc's own (dead_code, unused_imports,
            // unused_variables) — to an error, so the bar is literally "0 warnings" (exit ≠ 0 on any).
            // --all-targets also lints tests/examples/benches (default clippy skips them). JSON is
            // counted per real diagnostic: `--message-format short` double-counts the "generated N
            // warnings" summary lines. Only diagnostics with a source span are counted (drops the
            // "aborting due to…" tail). Warm-cache clippy can under-report — `cargo clean` once if a
            // Rust lint gate must be trusted absolutely.
            const cmd = 'cargo clippy --all-targets --message-format=json -- -D warnings';
            const r = await run(cmd, { timeoutMs: 600000, cwd: join(root, d.rustDir) });
            let count = 0;
            for (const line of (r.stdout || '').split('\n')) {
              if (!line.trim()) continue;
              try {
                const m = JSON.parse(line);
                if (m.reason === 'compiler-message' && Array.isArray(m.message?.spans) && m.message.spans.length
                    && /^(warning|error)/.test(m.message.level || '')) count++;
              } catch {}
            }
            return { status: 'ran', command: cmd, exit_code: r.code, findings_count: count, _rawLog: redact(r.stdout + r.stderr), duration_ms: r.duration_ms };
          }
          if (d.py)   return { status: 'unproven', skip_reason: 'ruff not installed', tool_absent: true };
          if (d.rust) return { status: 'unproven', skip_reason: 'cargo/clippy not installed', tool_absent: true };
          return { status: 'unproven', skip_reason: 'no configured linter (biome/eslint/ruff/clippy)' };
        } });

  // ---- optional (P2) — skip freely when the tool is absent ----
  add({ check: 'dead_code', tool: 'knip', required: false, parallel: true,
        run: async () => {
          if (!d.node) return { status: 'unproven', skip_reason: 'no package.json' };
          const cmd = 'npx --no-install knip --reporter json'; const r = await run(cmd);
          if (looksMissing(r)) return { status: 'unproven', skip_reason: 'knip not installed (add as dep or `npm i -g knip`)', tool_absent: true };
          let count = null; try { const j = JSON.parse(r.stdout); count = (j.files?.length || 0) + (Array.isArray(j.issues) ? j.issues.length : Object.keys(j.issues || {}).length); } catch {}
          return { status: 'ran', command: cmd, exit_code: r.code, findings_count: count, _rawLog: redact(r.stdout || r.stderr), duration_ms: r.duration_ms };
        } });

  add({ check: 'duplication', tool: 'jscpd', required: false, parallel: true,
        run: async () => {
          const rep = join(outDir, '_jscpd');
          const cmd = `npx --no-install jscpd . --reporters json --output "${rep}" --min-lines 20 --ignore "**/*.md,**/node_modules/**,**/dist/**,**/.git/**,**/.audit/**,**/.agent/**,**/.cache/**,**/.sampleapp/**,**/.tools/**,**/_mockups/**,**/eval/**,**/reference/**,**/docs/**,**/site/**,**/src-tauri/gen/**,**/vendor/**,**/qwik/**,**/benchmarks/article-quality/goldens/**,**/benchmarks/**/target/**,**/drizzle/meta/**,**/src/generated/**,**/pnpm-lock.yaml" --silent`;
          const r = await run(cmd);
          if (looksMissing(r)) return { status: 'unproven', skip_reason: 'jscpd not installed (`npm i -g jscpd`)', tool_absent: true };
          let count = null, summary = '';
          try { const j = JSON.parse(readFileSync(join(rep, 'jscpd-report.json'), 'utf8')); count = j.statistics?.total?.clones ?? (Array.isArray(j.duplicates) ? j.duplicates.length : null); summary = JSON.stringify(j.statistics?.total ?? {}, null, 2); } catch {}
          // Same rule as secrets/deps_cve: an absent or unparseable jscpd report
          // means no duplication scan happened, not that the repo is duplicate-free.
          if (count === null) return { status: 'error', command: cmd, exit_code: r.code, skip_reason: 'jscpd report unreadable — scan not proven', _rawLog: redact(r.stdout || r.stderr) };
          return { status: 'ran', command: cmd, exit_code: r.code, findings_count: count, _rawLog: redact(summary || r.stdout || r.stderr), duration_ms: r.duration_ms };
        } });

  add({ check: 'ci_lint', tool: 'actionlint', required: false, parallel: true,
        run: async () => {
          if (!d.workflows) return { status: 'unproven', skip_reason: 'no .github/workflows' };
          if (!(await which('actionlint'))) return { status: 'unproven', skip_reason: 'actionlint not installed', tool_absent: true };
          const cmd = 'actionlint -format "{{json .}}"'; const r = await run(cmd);
          let count = null; try { count = JSON.parse(r.stdout || '[]').length; } catch {}
          return { status: 'ran', command: cmd, exit_code: r.code, findings_count: count, _rawLog: redact(r.stdout || r.stderr), duration_ms: r.duration_ms };
        } });

  add({ check: 'docker', tool: 'hadolint', required: false, parallel: true,
        run: async () => {
          if (!d.dockerfile) return { status: 'unproven', skip_reason: 'no Dockerfile' };
          if (!(await which('hadolint'))) return { status: 'unproven', skip_reason: 'hadolint not installed', tool_absent: true };
          const cmd = 'hadolint --format json Dockerfile'; const r = await run(cmd);
          let count = null; try { count = JSON.parse(r.stdout || '[]').length; } catch {}
          return { status: 'ran', command: cmd, exit_code: r.code, findings_count: count, _rawLog: redact(r.stdout || r.stderr), duration_ms: r.duration_ms };
        } });

  add({ check: 'sast', tool: 'semgrep', required: false, tier: 'supplemental', parallel: true,
        run: async () => {
          if (!(await which('semgrep'))) return { status: 'unproven', skip_reason: 'semgrep not installed', tool_absent: true };
          const cmd = 'semgrep --config auto --json --quiet --exclude vendor --exclude qwik --exclude .audit --exclude .agent --exclude dist'; const r = await run(cmd, { timeoutMs: 300000 });
          let count = null; try { count = (JSON.parse(r.stdout).results || []).length; } catch {}
          return { status: 'ran', command: cmd, exit_code: r.code, findings_count: count, _rawLog: redact(r.stdout || r.stderr), duration_ms: r.duration_ms };
        } });

  // swift_lint — Swift idiom + style (the eslint/clippy sibling for Apple-platform code). Gates on a
  // real `.swift` in the tree, not just a root marker, so nested SPM/Xcode sources are covered. macOS
  // tool — skips cleanly on Windows/Linux where swiftlint isn't installed.
  add({ check: 'swift_lint', tool: 'swiftlint', required: false, tier: 'supplemental', parallel: true,
        run: async () => {
          if (!d.git) return { status: 'unproven', skip_reason: 'needs git ls-files' };
          const swiftFiles = (await trackedFiles()).filter(f => f.endsWith('.swift') && !isGeneratedOrVendoredPath(f));
          if (!swiftFiles.length) return { status: 'unproven', skip_reason: 'no .swift sources' };
          if (!(await which('swiftlint'))) return { status: 'unproven', skip_reason: 'swiftlint not installed (`brew install swiftlint`)', tool_absent: true };
          const cmd = 'swiftlint lint --quiet --reporter json';
          const r = await run(cmd, { timeoutMs: 300000 });
          let count = null; try { count = JSON.parse(r.stdout || '[]').length; } catch {}
          return { status: 'ran', command: cmd, exit_code: r.code, findings_count: count, _rawLog: redact(r.stdout || r.stderr), duration_ms: r.duration_ms };
        } });

  // js_licenses — copyleft license exposure in the JS dependency tree (GPL/AGPL/SSPL shipped inside a
  // proprietary product). cargo-deny covers the Rust side; this is the npm half. Counts copyleft deps
  // as the finding, not total deps.
  add({ check: 'js_licenses', tool: 'license-checker', required: false, tier: 'supplemental', parallel: true,
        run: async () => {
          if (!d.node) return { status: 'unproven', skip_reason: 'no package.json' };
          const cmd = 'npx --no-install license-checker --json --production';
          const r = await run(cmd);
          if (looksMissing(r)) return { status: 'unproven', skip_reason: 'license-checker not installed (`npm i -D license-checker`)', tool_absent: true };
          let flagged = null, total = null;
          try {
            const j = JSON.parse(r.stdout);
            const COPYLEFT = /\b(GPL|AGPL|LGPL|SSPL|CC-BY-SA|EUPL|OSL|CPAL)\b/i;
            const pkgs = Object.entries(j).filter(([, v]) => v && v.licenses);
            total = pkgs.length;
            flagged = pkgs.filter(([, v]) => COPYLEFT.test(String(v.licenses))).length;
          } catch {}
          return { status: 'ran', command: cmd, exit_code: r.code, findings_count: flagged, meta: { total_deps: total, copyleft: flagged }, _rawLog: redact(r.stdout || r.stderr), duration_ms: r.duration_ms };
        } });

  // cargo audit — RUSTSEC advisories. The pnpm/npm-audit sibling; without it a Rust/Tauri tree
  // ships with zero CVE coverage while the report claims deps were audited.
  add({ check: 'cargo_audit', tool: 'cargo-audit', required: false, flag_if_absent: true, tier: 'supplemental', parallel: true,
        run: async () => {
          if (!d.rust) return { status: 'unproven', skip_reason: 'no Cargo.toml' };
          const lockDir = fileExists(d.rustDir, 'Cargo.lock') ? d.rustDir : null;
          if (!lockDir) return { status: 'unproven', skip_reason: 'no Cargo.lock' };
          if (!(await which('cargo-audit'))) return { status: 'unproven', skip_reason: 'cargo-audit not installed (`cargo install cargo-audit`)', tool_absent: true };
          const cmd = 'cargo audit --json';
          const r = await run(cmd, { timeoutMs: 300000, cwd: join(root, lockDir) });
          let count = null; try { count = JSON.parse(r.stdout)?.vulnerabilities?.count ?? null; } catch {}
          return { status: 'ran', command: `${cmd}  (cwd: ${lockDir})`, exit_code: r.code, findings_count: count, _rawLog: redact(r.stdout || r.stderr), duration_ms: r.duration_ms };
        } });

  // cargo-deny — supply-chain POLICY beyond advisories: license compliance + banned/duplicate crates +
  // multiple advisory sources. Complements cargo-audit (RUSTSEC-only); catches GPL creep and duplicate
  // dependency-version bloat that cargo-audit is blind to.
  add({ check: 'cargo_deny', tool: 'cargo-deny', required: false, tier: 'supplemental', parallel: true,
        run: async () => {
          if (!d.rust) return { status: 'unproven', skip_reason: 'no Cargo.toml' };
          if (!(await which('cargo-deny'))) return { status: 'unproven', skip_reason: 'cargo-deny not installed (`cargo install cargo-deny`)', tool_absent: true };
          // JSON diagnostics stream on stderr, one object per line; count error/warning-level ones.
          const cmd = 'cargo deny --format json check';
          const r = await run(cmd, { timeoutMs: 300000, cwd: join(root, d.rustDir) });
          let count = 0;
          for (const line of (((r.stderr || '') + '\n' + (r.stdout || '')).split('\n'))) {
            if (!line.trim()) continue;
            try { const j = JSON.parse(line); if (j.type === 'diagnostic' && /error|warning/i.test(j.fields?.severity || j.fields?.level || '')) count++; } catch {}
          }
          return { status: 'ran', command: `${cmd}  (cwd: ${d.rustDir})`, exit_code: r.code, findings_count: count || null, _rawLog: redact(r.stdout + r.stderr), duration_ms: r.duration_ms };
        } });

  // cargo-machete — unused Rust dependencies (declared in Cargo.toml, never imported). The knip sibling
  // for the Rust side of a Tauri tree. Stable toolchain (no nightly, unlike cargo-udeps → CI-safe).
  add({ check: 'cargo_unused_deps', tool: 'cargo-machete', required: false, parallel: true,
        run: async () => {
          if (!d.rust) return { status: 'unproven', skip_reason: 'no Cargo.toml' };
          if (!(await which('cargo-machete'))) return { status: 'unproven', skip_reason: 'cargo-machete not installed (`cargo install cargo-machete`)', tool_absent: true };
          const cmd = 'cargo machete --with-metadata';
          const r = await run(cmd, { timeoutMs: 180000, cwd: join(root, d.rustDir) });
          // No JSON output; unused crates print one per indented line under each crate header. Parse
          // failure → null (still `ran`), never a fabricated 0.
          const count = (r.stdout || '').split('\n').filter(l => /^\s+\S/.test(l) && !/Analyzing|If you|cargo-machete|found the following/i.test(l)).length || null;
          return { status: 'ran', command: `${cmd}  (cwd: ${d.rustDir})`, exit_code: r.code, findings_count: count, _rawLog: redact(r.stdout + r.stderr), duration_ms: r.duration_ms };
        } });

  // cargo-geiger — counts `unsafe` usage across the dependency tree. Heavy (full compile) and brittle on
  // some workspaces, so it only runs when explicitly installed (skips clean otherwise). Relevant where
  // raw FFI/unsafe lives (e.g. the macOS CGEventTap / IOKit hotkey taps in fn_hotkey.rs).
  add({ check: 'cargo_unsafe', tool: 'cargo-geiger', required: false, parallel: true,
        run: async () => {
          if (!d.rust) return { status: 'unproven', skip_reason: 'no Cargo.toml' };
          if (!(await which('cargo-geiger'))) return { status: 'unproven', skip_reason: 'cargo-geiger not installed (`cargo install cargo-geiger`)', tool_absent: true };
          const cmd = 'cargo geiger --output-format Json --quiet';
          const r = await run(cmd, { timeoutMs: 600000, cwd: join(root, d.rustDir) });
          let count = null;
          try {
            const j = JSON.parse(r.stdout);
            count = (j.packages || []).reduce((a, p) => {
              const u = p.unsafety?.used; if (!u) return a;
              return a + Object.values(u).reduce((s, cat) => s + (cat?.unsafe_ || 0), 0);
            }, 0);
          } catch {}
          return { status: 'ran', command: `${cmd}  (cwd: ${d.rustDir})`, exit_code: r.code, findings_count: count, _rawLog: redact(r.stdout + r.stderr), duration_ms: r.duration_ms };
        } });

  // vendored dependency trees — the root lockfile audit does NOT see vendor/* trees; enumerate
  // them so the report can say "unscanned tree" instead of implying coverage.
  add({ check: 'vendored_deps', tool: 'fs', required: false, parallel: true,
        run: async () => {
          if (!d.git) return { status: 'unproven', skip_reason: 'needs git ls-files' };
          const tracked = await trackedFiles();
          const seen = new Map();
          for (const m of tracked.filter(f => /(^|\/)vendor\/.*\/(package\.json|Cargo\.toml)$/.test(f) && !f.includes('node_modules/'))) {
            const dir = m.replace(/\/(package\.json|Cargo\.toml)$/, '');
            if (seen.has(dir)) continue;
            const has_lockfile = tracked.some(f => f.startsWith(dir + '/') && /(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.lock)$/.test(f));
            seen.set(dir, { dir, manifest: m, has_lockfile });
          }
          const trees = [...seen.values()];
          return { status: 'ran', command: 'git ls-files → vendor/**/{package.json,Cargo.toml} (each tree is OUTSIDE root deps_cve/cargo_audit coverage)',
                   exit_code: 0, findings_count: trees.length, meta: { trees },
                   _rawLog: trees.map(t => `${t.dir}  lockfile=${t.has_lockfile}`).join('\n'), duration_ms: 0 };
        } });

  // dep pinning — unpinned git deps bypass the registry, minimumReleaseAge, and audit tooling.
  add({ check: 'dep_pinning', tool: 'grep', required: false, parallel: true,
        run: async () => {
          if (!d.git) return { status: 'unproven', skip_reason: 'needs git ls-files' };
          const tracked = await trackedFiles();
          const offenders = [];
          for (const f of tracked.filter(f => /(^|\/)package\.json$/.test(f) && !f.includes('node_modules/') && !isGeneratedOrVendoredPath(f))) {
            try {
              const p = JSON.parse(readFileSync(join(root, f), 'utf8'));
              for (const sect of ['dependencies', 'devDependencies', 'optionalDependencies']) {
                for (const [name, spec] of Object.entries(p[sect] || {})) {
                  if (typeof spec !== 'string') continue;
                  if (/^(git\+|github:|git:\/\/|https?:\/\/.*\.git)/.test(spec) && !/#[0-9a-f]{7,40}$/i.test(spec) && !/#(semver:)?v?\d/.test(spec))
                    offenders.push({ file: f, dep: name, spec, kind: 'npm-git-unpinned' });
                }
              }
            } catch {}
          }
          for (const f of tracked.filter(f => /(^|\/)Cargo\.toml$/.test(f) && !isGeneratedOrVendoredPath(f))) {
            try {
              const txt = readFileSync(join(root, f), 'utf8');
              for (const m of txt.matchAll(/^\s*([\w-]+)\s*=\s*\{[^}]*\bgit\s*=\s*"[^"]+"[^}]*\}/gm)) {
                if (!/\b(rev|tag)\s*=/.test(m[0])) offenders.push({ file: f, dep: m[1], kind: 'cargo-git-unpinned' });
              }
            } catch {}
          }
          return { status: 'ran', command: 'scan tracked package.json/Cargo.toml for git deps without a commit/tag pin',
                   exit_code: 0, findings_count: offenders.length, meta: { offenders },
                   _rawLog: offenders.map(o => `${o.file}: ${o.dep} (${o.kind})`).join('\n'), duration_ms: 0 };
        } });

  // tool coverage — what the configured linters/compilers are told to IGNORE. A lint that skips
  // half the repo reports clean; the exclusions are facts the lenses must see. Heuristic on flat
  // eslint configs (textual `ignores:` read) — marked as such, lens verifies before flagging.
  add({ check: 'tool_coverage', tool: 'fs', required: false, parallel: true,
        run: async () => {
          const cov = { heuristic: true };
          try { if (fileExists('.eslintignore')) cov.eslintignore = readFileSync(join(root, '.eslintignore'), 'utf8').split('\n').map(s => s.trim()).filter(s => s && !s.startsWith('#')); } catch {}
          for (const f of ['eslint.config.js', 'eslint.config.mjs', 'eslint.config.cjs', 'eslint.config.ts']) {
            if (!fileExists(f)) continue;
            try {
              const m = [...readFileSync(join(root, f), 'utf8').matchAll(/ignores\s*:\s*\[([^\]]*)\]/g)];
              if (m.length) cov.eslint_flat_ignores = m.flatMap(x => x[1].split(',').map(s => s.replace(/['"`\s]/g, '')).filter(Boolean));
            } catch {}
            break;
          }
          try {
            if (d.ts) {
              const t = JSON.parse(readFileSync(join(root, 'tsconfig.json'), 'utf8').replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '').replace(/,\s*([}\]])/g, '$1'));
              cov.tsconfig = { include: t.include ?? null, exclude: t.exclude ?? null };
            }
          } catch {}
          let code_dirs = [];
          if (d.git) {
            const CODE = /\.(ts|tsx|js|jsx|mjs|cjs|py|rs)$/;
            code_dirs = [...new Set((await trackedFiles()).filter(f => CODE.test(f) && !isGeneratedOrVendoredPath(f)).map(f => f.includes('/') ? f.split('/')[0] : '.'))].sort();
          }
          cov.top_level_code_dirs = code_dirs;
          return { status: 'ran', command: 'read .eslintignore / eslint flat-config ignores / tsconfig include+exclude; list top-level code dirs',
                   exit_code: 0, findings_count: null, meta: cov,
                   _rawLog: JSON.stringify(cov, null, 2), duration_ms: 0 };
        } });

  // contract mirror — Tauri IPC surface diff: registered handlers vs frontend invoke() callers.
  // knip cannot see across the Rust↔JS boundary; this is the only check that does.
  add({ check: 'contract_mirror', tool: 'grep', required: false, parallel: true,
        run: async () => {
          if (!d.tauri || !d.git) return { status: 'unproven', skip_reason: d.tauri ? 'needs git ls-files' : 'no src-tauri/tauri.conf.json' };
          const tracked = await trackedFiles();
          const handlers = new Set(), invokes = new Set();
          for (const f of tracked.filter(f => f.startsWith('src-tauri/') && f.endsWith('.rs') && !isGeneratedOrVendoredPath(f))) {
            try {
              const txt = readFileSync(join(root, f), 'utf8');
              for (const m of txt.matchAll(/generate_handler!\s*\[([\s\S]*?)\]/g))
                for (const raw of m[1].split(',')) {
                  const name = raw.trim().split('::').pop();
                  if (name && /^[a-z_][a-z0-9_]*$/i.test(name)) handlers.add(name);
                }
            } catch {}
          }
          for (const f of tracked.filter(f => !f.startsWith('src-tauri/') && /\.(ts|tsx|js|jsx|mjs|svelte|vue)$/.test(f) && !isGeneratedOrVendoredPath(f) && classifyFile(f) !== 'test')) {
            try {
              const txt = readFileSync(join(root, f), 'utf8');
              for (const m of txt.matchAll(/\binvoke(?:<[^>]*>)?\s*\(\s*['"`]([\w-]+)['"`]/g)) invokes.add(m[1]);
            } catch {}
          }
          const uncalled = [...handlers].filter(h => !invokes.has(h)).sort();
          const unregistered = [...invokes].filter(i => !handlers.has(i)).sort();
          return { status: 'ran', command: 'diff generate_handler![] names vs frontend invoke("...") literals (wrapper-indirected calls need lens verification)',
                   exit_code: 0, findings_count: uncalled.length + unregistered.length,
                   meta: { handlers: handlers.size, invokes: invokes.size, uncalled_handlers: uncalled, unregistered_invokes: unregistered },
                   _rawLog: `uncalled handlers (${uncalled.length}): ${uncalled.join(', ')}\nunregistered invokes (${unregistered.length}): ${unregistered.join(', ')}`, duration_ms: 0 };
        } });

  // tauri_capabilities — Tauri v2 permission SURFACE. contract_mirror diffs which commands exist;
  // this reads what the capability files GRANT and flags broad/dangerous grants (allow-all/default on
  // fs·shell·http·process, shell execute/spawn, wide `**` fs scopes) plus the count of exposed
  // #[tauri::command] handlers the frontend can invoke. Review trigger, not verdict — the security lens
  // decides. Nothing else in the audit reads capabilities/*.json.
  add({ check: 'tauri_capabilities', tool: 'fs', required: false, parallel: true,
        run: async () => {
          if (!d.tauri) return { status: 'unproven', skip_reason: 'no src-tauri/tauri.conf.json' };
          const capDir = join(root, 'src-tauri', 'capabilities');
          const perms = [];      // { file, permission }
          const broad = [];      // flagged grants for the security lens to review
          let capFiles = 0, unparseable = 0;
          const flagOf = (p) => {
            const id = typeof p === 'string' ? p : (p && (p.identifier || p.permission)) || '';
            const scope = typeof p === 'object' && p ? p : null;
            if (/:(allow-all|default)$/.test(id) && /^(fs|shell|http|process|core|os):/.test(id)) return `broad grant: ${id}`;
            if (/^shell:allow-(execute|spawn|stdin-write)/.test(id)) return `shell execution: ${id}`;
            if (/^(fs|http):/.test(id) && scope && JSON.stringify(scope.allow ?? scope).includes('**')) return `wide scope: ${id}`;
            return null;
          };
          try {
            for (const f of readdirSync(capDir).filter(n => /\.(json|toml)$/.test(n))) {
              capFiles++;
              if (!f.endsWith('.json')) continue;   // toml capabilities are counted, not deep-parsed
              try {
                const j = JSON.parse(readFileSync(join(capDir, f), 'utf8'));
                for (const p of (j.permissions || [])) {
                  const id = typeof p === 'string' ? p : (p.identifier || p.permission || JSON.stringify(p));
                  perms.push({ file: f, permission: id });
                  const flag = flagOf(p);
                  if (flag) broad.push({ file: f, flag });
                }
              } catch { unparseable++; }
            }
          } catch { return { status: 'unproven', skip_reason: 'no src-tauri/capabilities/ directory' }; }
          // Exposed custom commands — every #[tauri::command] reachable from the frontend.
          let exposed = 0;
          if (d.git) {
            for (const f of (await trackedFiles()).filter(x => x.startsWith('src-tauri/') && x.endsWith('.rs') && !isGeneratedOrVendoredPath(x))) {
              try { exposed += (readFileSync(join(root, f), 'utf8').match(/#\[tauri::command\]/g) || []).length; } catch {}
            }
          }
          return {
            status: 'ran',
            command: 'parse src-tauri/capabilities/*.json permissions + count #[tauri::command] handlers',
            exit_code: 0,
            findings_count: broad.length,
            meta: { capability_files: capFiles, unparseable_capability_files: unparseable, total_permissions: perms.length, exposed_commands: exposed, broad_grants: broad },
            _rawLog: JSON.stringify({ broad_grants: broad, permissions: perms }, null, 2), duration_ms: 0,
          };
        } });

  // apple_platform — Info.plist / entitlements / XcodeGen consistency for Apple-platform targets.
  // Deliberately NOT a "flag every capability" scanner: a keyboard extension needs Full Access to do
  // anything useful, and a mic app needs the mic. Declared capabilities are INVENTORY (meta) so the
  // security lens can reason about them with context. Only genuine mismatches are findings:
  //   1. a permission-gated API is called but its usage-description key is missing  -> crash on first use
  //   2. ATS is weakened (arbitrary loads / insecure HTTP exception domains)
  //   3. a debug entitlement (get-task-allow) is committed
  // Pure text parsing, so it runs on Windows/Linux as well as macOS.
  add({ check: 'apple_platform', tool: 'fs', required: false, parallel: true,
        run: async () => {
          const tracked = d.git ? await trackedFiles() : [];
          const swiftFiles = tracked.filter(f => f.endsWith('.swift') && !isGeneratedOrVendoredPath(f));
          const plists = tracked.filter(f => /(^|\/)Info\.plist$/.test(f) && !isGeneratedOrVendoredPath(f));
          const ents = tracked.filter(f => f.endsWith('.entitlements') && !isGeneratedOrVendoredPath(f));
          const projYml = tracked.filter(f => /(^|\/)project\.yml$/.test(f));
          if (!swiftFiles.length || (!plists.length && !projYml.length)) {
            return { status: 'unproven', skip_reason: 'no Apple-platform target (needs .swift + Info.plist/project.yml)' };
          }
          const read = (f) => { try { return readFileSync(join(root, f), 'utf8'); } catch { return ''; } };
          // Usage-description keys may live in Info.plist OR be injected by XcodeGen from project.yml.
          const declaredBlob = [...plists, ...projYml].map(read).join('\n');
          const entBlob = ents.map(read).join('\n');
          const codeBlob = swiftFiles.map(read).join('\n');

          // Gate on real API symbols, not bare imports — `import AVFoundation` for playback alone
          // does not require a microphone string, and flagging it would be noise.
          // `keys` = ANY one declared key satisfies the requirement (per-era/per-scope variants).
          const NEEDS = [
            { keys: ['NSMicrophoneUsageDescription'],       api: /AVAudioRecorder|AVAudioEngine|installTap|requestRecordPermission|AVAudioSession.*record|AVCaptureDevice\.(?:default|requestAccess)\(\s*for:\s*\.audio/ },
            { keys: ['NSSpeechRecognitionUsageDescription'], api: /SFSpeechRecognizer|SFSpeechAudioBuffer/ },
            { keys: ['NSCameraUsageDescription'],           api: /UIImagePickerController|AVCaptureDevice\.(?:default|requestAccess)\(\s*for:\s*\.video|AVCaptureDevice\.default\(\s*\.builtIn/ },
            { keys: ['NSPhotoLibraryUsageDescription'],     api: /PHPhotoLibrary|PHAsset\b/ },
            // Add-only save APIs need the Add key (the full-library key also covers them).
            { keys: ['NSPhotoLibraryAddUsageDescription', 'NSPhotoLibraryUsageDescription'], api: /UIImageWriteToSavedPhotosAlbum|creationRequestForAsset/ },
            { keys: ['NSLocationWhenInUseUsageDescription'], api: /CLLocationManager/ },
            { keys: ['NSContactsUsageDescription'],         api: /CNContactStore/ },
            // iOS 17 split EventKit into full-access / write-only keys; legacy-only is a
            // separate finding below because it is DENIED (not prompted) on modern OSes.
            { keys: ['NSCalendarsFullAccessUsageDescription', 'NSCalendarsWriteOnlyAccessUsageDescription', 'NSRemindersFullAccessUsageDescription', 'NSCalendarsUsageDescription', 'NSRemindersUsageDescription'], api: /EKEventStore/ },
            { keys: ['NSBluetoothAlwaysUsageDescription'],  api: /CBCentralManager|CBPeripheralManager/ },
            // Bonjour/multicast/nearby APIs trigger the iOS 14+ local-network prompt.
            { keys: ['NSLocalNetworkUsageDescription'],     api: /NWBrowser|NWListener|NetServiceBrowser|MCNearbyService/ },
          ];
          const missingUsage = NEEDS
            .filter(n => n.api.test(codeBlob) && !n.keys.some(k => declaredBlob.includes(k)))
            .map(n => ({ missing_key: n.keys[0], accepted_keys: n.keys, reason: 'API is called but no usage description declared — crashes on first access' }));
          // iOS 17+ EventKit: the legacy calendars key ALONE no longer grants access — the
          // request is denied outright. Fires only when EventKit is actually used.
          if (/EKEventStore/.test(codeBlob)
              && declaredBlob.includes('NSCalendarsUsageDescription')
              && !/NSCalendarsFullAccessUsageDescription|NSCalendarsWriteOnlyAccessUsageDescription|NSRemindersFullAccessUsageDescription/.test(declaredBlob)) {
            missingUsage.push({
              missing_key: 'NSCalendarsFullAccessUsageDescription',
              accepted_keys: ['NSCalendarsFullAccessUsageDescription', 'NSCalendarsWriteOnlyAccessUsageDescription'],
              reason: 'legacy NSCalendarsUsageDescription alone is denied on iOS 17+ — EventKit requires the full-access or write-only key',
            });
          }

          // ATS weakening. NSAllowsArbitraryLoads sits above its <true/> sibling in the plist XML.
          const atsArbitrary = /<key>NSAllowsArbitraryLoads<\/key>\s*<true\s*\/>/.test(declaredBlob)
            || /NSAllowsArbitraryLoads\s*:\s*(true|YES)/i.test(declaredBlob);
          const atsInsecureHttp = /<key>NSExceptionAllowsInsecureHTTPLoads<\/key>\s*<true\s*\/>/.test(declaredBlob)
            || /NSExceptionAllowsInsecureHTTPLoads\s*:\s*(true|YES)/i.test(declaredBlob);
          const debugEnt = /<key>get-task-allow<\/key>\s*<true\s*\/>/.test(entBlob);

          const atsFindings = [];
          if (atsArbitrary)    atsFindings.push({ issue: 'NSAllowsArbitraryLoads is true — ATS disabled app-wide' });
          if (atsInsecureHttp) atsFindings.push({ issue: 'NSExceptionAllowsInsecureHTTPLoads is true — cleartext HTTP permitted for an exception domain' });
          if (debugEnt)        atsFindings.push({ issue: 'get-task-allow entitlement is committed — debug entitlement in a tracked entitlements file' });

          // ---- Inventory (context for the security lens; NOT findings) ----
          const declaredUsage = [...new Set((declaredBlob.match(/NS[A-Za-z]+UsageDescription/g) || []))].sort();
          // Per-file key map: the blob union above cannot see PER-TARGET gaps (one target's
          // declaration masks another target's missing key). The lens reasons target-by-target
          // from this — plists and project.yml name their targets by path.
          const declaredUsageByFile = {};
          for (const f of [...plists, ...projYml]) {
            const ks = [...new Set((read(f).match(/NS[A-Za-z]+UsageDescription/g) || []))].sort();
            if (ks.length) declaredUsageByFile[f] = ks;
          }
          const entitlements = [...new Set((entBlob.match(/com\.apple\.[a-z0-9.\-]+/gi) || []))].sort();
          // A keyboard extension with Full Access is a normal, required product decision. Report the
          // state plus whether the target actually has egress-capable symbols, so a privacy claim
          // ("we don't send your data anywhere") is checkable instead of taken on faith.
          const openAccess = /RequestsOpenAccess\s*:\s*(true|YES)/i.test(declaredBlob)
            || /<key>RequestsOpenAccess<\/key>\s*<true\s*\/>/.test(declaredBlob);
          // Keyboard-extension targets often compile SHARED sources (XcodeGen
          // `sources: [SampleAppKeyboard, Shared]`). A filename heuristic alone misses those,
          // so an egress-capable shared client reads as "zero network symbols in the keyboard
          // target" — a false privacy pass. Resolve the keyboard target's source dirs from
          // project.yml (indentation scan, no YAML dep) and union with the filename match.
          const kbSourceDirs = [];
          for (const y of projYml) {
            const text = read(y);
            if (!/keyboard/i.test(text)) continue;
            const base = y.replace(/project\.yml$/, '');
            const lines = text.split(/\r?\n/);
            const tIdx = lines.findIndex(l => /^targets:\s*$/.test(l));
            if (tIdx < 0) continue;
            let childIndent = -1;
            for (let i = tIdx + 1; i < lines.length; i++) {
              const line = lines[i];
              if (!line.trim() || /^\s*#/.test(line)) continue;
              const indent = line.match(/^\s*/)[0].length;
              if (indent === 0) break; // left the targets: mapping
              const key = line.match(/^\s*([A-Za-z0-9_.\- ]+):\s*$/);
              if (childIndent < 0) childIndent = indent;
              if (indent !== childIndent || !key) continue;
              let end = lines.length;
              for (let j = i + 1; j < lines.length; j++) {
                if (!lines[j].trim()) continue;
                if (lines[j].match(/^\s*/)[0].length <= childIndent) { end = j; break; }
              }
              const bl = lines.slice(i, end);
              if (!bl.some(l => /keyboard-service/.test(l)) && !/keyboard/i.test(key[1])) continue;
              for (let j = 0; j < bl.length; j++) {
                const flow = bl[j].match(/^\s*sources:\s*\[([^\]]*)\]/);
                if (flow) {
                  for (const item of flow[1].split(',')) {
                    const p = item.trim().replace(/^["']|["']$/g, '');
                    if (p) kbSourceDirs.push(base + p);
                  }
                  break;
                }
                const sm = bl[j].match(/^(\s*)sources:\s*$/);
                if (!sm) continue;
                for (let k = j + 1; k < bl.length; k++) {
                  if (!bl[k].trim()) continue;
                  if (bl[k].match(/^\s*/)[0].length <= sm[1].length) break;
                  const item = bl[k].match(/^\s*-\s+(?:path:\s*)?["']?([^"'#\s]+)/);
                  if (item) kbSourceDirs.push(base + item[1]);
                }
                break;
              }
            }
          }
          const kbTargetFiles = swiftFiles.filter(f =>
            kbSourceDirs.some(dir => f === dir || f.startsWith(dir.replace(/\/?$/, '/'))));
          const kbFiles = [...new Set([...swiftFiles.filter(f => /keyboard/i.test(f)), ...kbTargetFiles])];
          const NET = /URLSession|NWConnection|NSURLConnection|Alamofire|CFStream|\.dataTask\(/;
          const kbNetwork = kbFiles.filter(f => NET.test(read(f)));

          const findings = [...missingUsage, ...atsFindings];
          return {
            status: 'ran',
            command: 'parse Info.plist/project.yml usage descriptions + *.entitlements vs called Apple APIs',
            exit_code: findings.length ? 1 : 0,
            findings_count: findings.length,
            meta: {
              swift_files: swiftFiles.length, info_plists: plists.length, entitlements_files: ents.length,
              declared_usage_descriptions: declaredUsage,
              declared_usage_by_file: declaredUsageByFile,
              entitlements,
              missing_usage_descriptions: missingUsage,
              ats_findings: atsFindings,
              keyboard_requests_open_access: openAccess,
              keyboard_source_dirs: kbSourceDirs,
              keyboard_files: kbFiles.length,
              keyboard_files_with_network_symbols: kbNetwork,
            },
            _rawLog: JSON.stringify({ findings, declared_usage: declaredUsage, entitlements, open_access: openAccess, keyboard_network: kbNetwork }, null, 2),
            duration_ms: 0,
          };
        } });

  // react_hooks — config COVERAGE, not a scanner: a React project WITHOUT eslint-plugin-react-hooks
  // ships conditional-hook and stale-dependency bugs that static lint would catch. Flags the gap.
  add({ check: 'react_hooks', tool: 'fs', required: false, parallel: true,
        run: async () => {
          if (!d.node || !hasDep(d, 'react')) return { status: 'unproven', skip_reason: 'not a React project' };
          const present = hasDep(d, 'eslint-plugin-react-hooks');
          return {
            status: 'ran',
            command: 'check package.json: react present ⇒ eslint-plugin-react-hooks configured?',
            exit_code: 0,
            findings_count: present ? 0 : 1,
            meta: { react: true, eslint_plugin_react_hooks: present,
                    note: present ? 'react-hooks lint configured' : 'React app has NO eslint-plugin-react-hooks — hook-rule bugs (conditional hooks, stale deps) ship unlinted' },
            duration_ms: 0,
          };
        } });

  // negative space — flag the ABSENCE of expected things, not just bad code present (GLM's lens).
  add({ check: 'negative_space', tool: 'fs', required: false, parallel: true,
        run: async () => {
          const missing = [];
          const need = (label, ok) => { if (!ok) missing.push(label); };
          need('README', fileExists('README.md') || fileExists('README') || fileExists('readme.md'));
          need('LICENSE', fileExists('LICENSE') || fileExists('LICENSE.md') || fileExists('LICENSE.txt'));
          need('.gitignore', fileExists('.gitignore'));
          need('CI', d.workflows || fileExists('.gitlab-ci.yml') || fileExists('azure-pipelines.yml') || fileExists('.circleci'));
          if (d.node) need('lockfile', fileExists('package-lock.json') || fileExists('pnpm-lock.yaml') || fileExists('yarn.lock'));
          need('tests', fileExists('test') || fileExists('tests') || fileExists('__tests__') || fileExists('spec') || !!(d.pkg?.scripts?.test));
          // ponytail: root-level presence heuristic; nested-monorepo tests may live per-package — refine if it false-flags.
          const meta = { missing };
          if (d.git) {
            const tracked = await trackedFiles();
            // test-coverage SHAPE: tests-exist is not tests-everywhere. Per top-level dir,
            // code-vs-test file counts — skew relative to surface criticality is a lens signal.
            const CODE = /\.(ts|tsx|js|jsx|mjs|cjs|py|rs|go|java|rb|swift|kt)$/;
            const skew = {};
            for (const f of tracked) {
              if (!CODE.test(f) || isGeneratedOrVendoredPath(f)) continue;
              const top = f.includes('/') ? f.split('/')[0] : '.';
              skew[top] = skew[top] || { code: 0, test: 0 };
              skew[top][classifyFile(f) === 'test' ? 'test' : 'code']++;
            }
            meta.test_skew = skew;
            // tracked large binaries: bloat + silently degrade every grep-backed scanner.
            const large = [];
            for (const f of tracked) { try { const s = statSync(join(root, f)); if (s.size > 5 * 1024 * 1024) large.push({ file: f, mb: +(s.size / 1048576).toFixed(1) }); } catch {} }
            meta.large_tracked_files = large.sort((a, b) => b.mb - a.mb).slice(0, 20);
            // CI gates that don't gate: a green check from continue-on-error / `|| true` is advisory, not enforcement.
            const advisory = [];
            for (const f of tracked.filter(f => f.startsWith('.github/workflows/'))) {
              try {
                readFileSync(join(root, f), 'utf8').split('\n').forEach((l, i) => {
                  if (/continue-on-error:\s*true/.test(l) || /\|\|\s*true\s*$/.test(l)) advisory.push(`${f}:${i + 1}`);
                });
              } catch {}
            }
            meta.ci_advisory_gates = advisory;
            // Rust unsafe inventory — sites per file; the lens asks whether any test exercises their failure paths.
            if (d.rust) {
              const unsafe_sites = {};
              for (const f of tracked.filter(f => f.endsWith('.rs') && !isGeneratedOrVendoredPath(f) && classifyFile(f) !== 'test')) {
                try { const n = (readFileSync(join(root, f), 'utf8').match(/\bunsafe\b/g) || []).length; if (n) unsafe_sites[f] = n; } catch {}
              }
              meta.unsafe_sites = unsafe_sites;
            }
          }
          return { status: 'ran', command: '(fs presence checks + test-skew / large-binary / CI-advisory / unsafe inventory)', exit_code: 0, findings_count: missing.length, meta, _rawLog: missing.length ? 'Missing: ' + missing.join(', ') : 'none missing', duration_ms: 0 };
        } });

  // outdated — beyond CVEs: how far behind latest (EOL / stale majors).
  add({ check: 'outdated', tool: `${d.pkgMgr} outdated`, required: false, tier: 'supplemental', parallel: true,
        run: async () => {
          if (!d.node) return { status: 'unproven', skip_reason: 'no package.json' };
          const cmd = `${d.pkgMgr} outdated --json`; const r = await run(cmd);
          if (looksMissing(r)) return { status: 'unproven', skip_reason: `${d.pkgMgr} not available`, tool_absent: true };
          let total = null, majors = 0;
          try {
            const entries = Object.entries(JSON.parse(r.stdout || '{}'));
            total = entries.length;
            for (const [, v] of entries) { const c = Number((v.current || '').split('.')[0]), l = Number((v.latest || '').split('.')[0]); if (c && l && l > c) majors++; }
          } catch {}
          return { status: 'ran', command: cmd, exit_code: r.code, findings_count: total, meta: { majors_behind: majors }, _rawLog: redact(r.stdout || r.stderr), duration_ms: r.duration_ms };
        } });

  // cargo outdated — the Rust/Tauri sibling of `outdated`. Without it a Cargo tree reports zero
  // stale crates while the report implies deps were checked for how far behind latest they are.
  add({ check: 'cargo_outdated', tool: 'cargo-outdated', required: false, tier: 'supplemental', parallel: true,
        run: async () => {
          if (!d.rust) return { status: 'unproven', skip_reason: 'no Cargo.toml' };
          const lockDir = fileExists(d.rustDir, 'Cargo.lock') ? d.rustDir : null;
          if (!lockDir) return { status: 'unproven', skip_reason: 'no Cargo.lock' };
          if (!(await which('cargo-outdated'))) return { status: 'unproven', skip_reason: 'cargo-outdated not installed (`cargo install cargo-outdated`)', tool_absent: true };
          const cmd = 'cargo outdated --format json --root-deps-only';
          const r = await run(cmd, { timeoutMs: 300000, cwd: join(root, lockDir) });
          let total = null, majors = 0;
          try {
            const deps = (JSON.parse(r.stdout || '{}').dependencies || []).filter(x => x.latest && x.latest !== '---' && x.latest !== x.project);
            total = deps.length;
            for (const x of deps) { const c = Number((x.project || '').split('.')[0]), l = Number((x.latest || '').split('.')[0]); if (c && l && l > c) majors++; }
          } catch {}
          return { status: 'ran', command: `${cmd}  (cwd: ${lockDir})`, exit_code: r.code, findings_count: total, meta: { majors_behind: majors }, _rawLog: redact(r.stdout || r.stderr), duration_ms: r.duration_ms };
        } });

  // binary pins — the third "outdated" sibling: bundled binaries fetched by build/packaging
  // scripts via hardcoded URL + SHA256 literals (the package.ps1 Ensure-* pattern). Invisible to
  // `outdated`/`cargo_outdated`/Dependabot/Renovate because a .ps1/.sh/.mjs script is not a
  // recognized package manifest, and skip-if-present fetch logic means a pin is NEVER re-evaluated
  // once downloaded. Pinning is correct (integrity, reproducibility) — the gap is cadence: nothing
  // ever asks "is this pin stale?". Inventory every pin, extract its version, and (network
  // permitting) resolve upstream latest for GitHub-hosted artifacts. Non-resolvable pins are
  // findings too (MANUAL-CHECK), never silently "clean".
  add({ check: 'binary_pins', tool: 'grep+github-api', required: false, parallel: true,
        run: async () => {
          const started = Date.now();
          if (!d.git) return { status: 'unproven', skip_reason: 'needs git ls-files' };
          const tracked = await trackedFiles();
          const scriptRe = /\.(ps1|psm1|sh|bash|zsh|mjs|cjs|js|py|rb)$|(^|\/)(dockerfile[^/]*|justfile|makefile)$/i;
          const urlRe = /https?:\/\/[^\s"'`<>\\)\]}]+\.(?:zip|tar\.gz|tar\.xz|tar\.bz2|tgz|txz|7z|exe|msi|dmg|pkg|AppImage|deb|rpm|dll|so|dylib|wasm|jar)\b[^\s"'`<>\\)\]}]*/gi;
          const shaRe = /\b[0-9a-fA-F]{64}\b/;
          const pins = [];
          for (const f of tracked.filter(f => scriptRe.test(f) && !f.includes('node_modules/') && !isGeneratedOrVendoredPath(f))) {
            let lines;
            try { lines = readFileSync(join(root, f), 'utf8').split('\n'); } catch { continue; }
            if (lines.length > 8000) continue;
            for (let i = 0; i < lines.length; i++) {
              for (const m of lines[i].matchAll(urlRe)) {
                let url = m[0];
                // expand $Var / ${Var} from a same-file literal assignment (the ps1 idiom) so the
                // pinned version inside a variable is still comparable
                for (const vm of [...url.matchAll(/\$\{?([A-Za-z_]\w*)\}?/g)]) {
                  const re = new RegExp(`\\$\\{?${vm[1]}\\}?\\s*=\\s*['"]([^'"]+)['"]`);
                  const def = lines.map(l => l.match(re)).find(Boolean);
                  if (def) url = url.replace(vm[0], def[1]);
                }
                // a 64-hex literal within ±10 lines (excluding the URL itself) = a deliberate integrity
                // pin (±10 spans the package.ps1 env-override if/else idiom between URL and SHA vars)
                const near = lines.slice(Math.max(0, i - 10), i + 11).join('\n').replace(url, '');
                const sha256_pinned = shaRe.test(near);
                const version = url.match(/\d+\.\d+(?:\.\d+){0,2}/)?.[0] ?? null;
                const gh = url.match(/github\.com\/([\w.-]+)\/([\w.-]+)\/(?:releases\/(?:latest\/)?download|archive)\//i);
                // a releases/latest/download URL is ROLLING — it grabbed whatever was latest at
                // fetch time; with skip-if-present the local copy is frozen at an unknown version
                const rolling = /\/releases\/latest\/download\//i.test(url);
                const npm = url.match(/registry\.npmjs\.org\/((?:@[\w.-]+\/)?[\w.-]+)\/-\//);
                pins.push({ file: f, line: i + 1, url, version, sha256_pinned, rolling, github: gh ? `${gh[1]}/${gh[2]}` : null, npm: npm ? npm[1] : null, latest: null, stale: null });
              }
            }
          }
          // resolve upstream latest for GitHub-hosted pins (best-effort, one call per repo;
          // offline-safe: a failed/absent lookup leaves latest=null → MANUAL-CHECK, never clean)
          if (pins.length && !process.env.AUDIT_OFFLINE) {
            const repos = [...new Set(pins.map(p => p.github).filter(Boolean))];
            const npmPkgs = [...new Set(pins.map(p => p.npm).filter(Boolean))];
            const latestBy = new Map();
            await Promise.all([
              ...repos.map(async (repo) => {
                try {
                  const res = await fetch(`https://api.github.com/repos/${repo}/releases/latest`,
                    { signal: AbortSignal.timeout(8000), headers: { 'User-Agent': 'audit-binary-pins', Accept: 'application/vnd.github+json' } });
                  if (res.ok) latestBy.set('gh:' + repo, (await res.json()).tag_name || null);
                } catch {}
              }),
              ...npmPkgs.map(async (pkg) => {
                try {
                  const res = await fetch(`https://registry.npmjs.org/${pkg}/latest`,
                    { signal: AbortSignal.timeout(8000), headers: { 'User-Agent': 'audit-binary-pins' } });
                  if (res.ok) latestBy.set('npm:' + pkg, (await res.json()).version || null);
                } catch {}
              }),
            ]);
            for (const p of pins) {
              const tag = (p.github && latestBy.get('gh:' + p.github)) || (p.npm && latestBy.get('npm:' + p.npm)) || null;
              if (!tag) continue;
              p.latest = tag;
              if (p.rolling) continue; // frozen-at-unknown-version → stays MANUAL-CHECK, latest shown for the user
              const lv = tag.match(/\d+\.\d+(?:\.\d+){0,2}/)?.[0] ?? null;
              let dec = p.url; try { dec = decodeURIComponent(p.url); } catch {}
              if (lv && p.version) p.stale = lv !== p.version;
              else p.stale = !dec.includes(tag); // dot-less/encoded tags (e.g. chromium%2F7920): pinned URL contains the latest tag ⇔ current
            }
          }
          const stale = pins.filter(p => p.stale === true).length;
          const unpinned = pins.filter(p => !p.sha256_pinned).length;
          const manual = pins.filter(p => p.sha256_pinned && p.stale === null).length;
          return { status: 'ran',
                   command: 'scan tracked build/packaging scripts for hardcoded artifact-download URLs (64-hex within ±10 lines = integrity pin); resolve github releases/latest per repo (AUDIT_OFFLINE=1 skips network)',
                   exit_code: 0, findings_count: stale + unpinned + manual,
                   meta: { pins, stale, no_integrity_pin: unpinned, manual_check_upstream: manual },
                   _rawLog: pins.map(p => `${p.file}:${p.line}  v=${p.version ?? '?'}  sha256=${p.sha256_pinned ? 'yes' : 'NO'}  latest=${p.latest ?? 'unresolved'}  ${p.stale === true ? 'STALE' : p.stale === false ? 'current' : p.sha256_pinned ? 'MANUAL-CHECK' : 'NO-INTEGRITY-PIN'}  ${p.url}`).join('\n') || 'no binary pins found',
                   duration_ms: Date.now() - started };
        } });

  // debt markers — ponytail: shortcuts + TODO/FIXME/HACK/XXX, with rot flags.
  add({ check: 'debt_markers', tool: 'git grep', required: false, parallel: true,
        run: async () => {
          if (!d.git) return { status: 'unproven', skip_reason: 'debt-marker scan needs a git repo' };
          const cmd = 'git grep -nIE "(ponytail:|\\b(TODO|FIXME|HACK|XXX)\\b)" -- . ":(exclude)*lock.yaml" ":(exclude)*lock.yml" ":(exclude)*lock.json" ":(exclude)vendor/**" ":(exclude)qwik/**"';
          const r = await run(cmd);
          const lines = (r.stdout || '').split('\n').filter(Boolean);
          const pony = lines.filter(l => /ponytail:/.test(l));
          const ponyNoTrigger = pony.filter(l => !/upgrade|ceiling|\bif\b/i.test(l)).length;
          const todos = lines.filter(l => /\b(TODO|FIXME|HACK|XXX)\b/.test(l)).length;
          return { status: 'ran', command: cmd, exit_code: 0, findings_count: lines.length, meta: { ponytail: pony.length, ponytail_no_trigger: ponyNoTrigger, todo_fixme: todos }, _rawLog: redact(r.stdout), duration_ms: r.duration_ms };
        } });

  // SEQUENTIAL — runs alone, after the pool.
  add({ check: 'build', tool: '<project build>', required: d.buildScript || d.rust, parallel: false,
        run: async () => {
          const cmd = d.buildScript ? `${d.pkgMgr} run build` : d.rust ? 'cargo build' : null;
          if (!cmd) return { status: 'unproven', skip_reason: 'no build script / Cargo.toml' };
          const r = await run(cmd, { timeoutMs: 600000, cwd: d.buildScript ? root : join(root, d.rustDir) });
          const warns = (r.stdout + r.stderr).split('\n').filter(l => /\bwarn(ing)?\b/i.test(l)).length;
          return { status: r.code === 0 ? 'ran' : 'error', command: cmd, exit_code: r.code, findings_count: warns, _rawLog: redact(r.stdout + r.stderr), duration_ms: r.duration_ms };
        } });

  return list;
}

// ---------- execute ----------
async function execOne(c) {
  if (c._forceSkip) return { check: c.check, tool: c.tool, status: 'skipped', skip_reason: 'skipped via --skip', required: !!c.required };
  let res;
  try { res = await c.run(); }
  catch (e) { res = { status: 'error', exit_code: -1, _rawLog: String(e) }; }
  // persist redacted log
  let logRel = '';
  if (res._rawLog != null && res._rawLog !== '') {
    logRel = `${c.check}.log`;
    const logPath = join(outDir, logRel);
    writeFileSync(logPath, res._rawLog, 'utf8');
    try { chmodSync(logPath, 0o600); } catch {}   // best-effort (Windows ACLs differ)
  }
  delete res._rawLog;
  return {
    check: c.check, tool: c.tool ?? null, required: !!c.required,
    tier: c.tier ?? 'core',
    flag_if_absent: !!c.flag_if_absent, parallel: c.parallel !== false,
    command: res.command ?? null, exit_code: res.exit_code ?? null,
    status: res.status, skip_reason: res.skip_reason ?? null,
    findings_count: res.findings_count ?? null, candidate_count: res.candidate_count ?? null,
    duration_ms: res.duration_ms ?? null,
    meta: res.meta ?? null, log: logRel, tool_absent: !!res.tool_absent,
  };
}

async function doctor(d, checks) {
  const rows = [];
  for (const c of checks) {
    let ready = 'configured';
    let reason = null;
    if (c._forceSkip) { ready = 'skipped'; reason = 'skipped by --skip'; }
    else if (c.check === 'secrets') ready = await which('gitleaks') ? 'ready' : 'missing-tool';
    else if (c.check === 'sast') ready = await which('semgrep') ? 'ready' : 'missing-tool';
    else if (c.check === 'ci_lint') ready = await which('actionlint') ? 'ready' : 'missing-tool';
    else if (c.check === 'docker') ready = await which('hadolint') ? 'ready' : 'missing-tool';
    else if (c.check === 'cargo_audit') ready = !d.rust ? 'not-configured' : (await which('cargo-audit') ? 'ready' : 'missing-tool');
    else if (c.check === 'cargo_deny') ready = !d.rust ? 'not-configured' : (await which('cargo-deny') ? 'ready' : 'missing-tool');
    else if (c.check === 'cargo_unused_deps') ready = !d.rust ? 'not-configured' : (await which('cargo-machete') ? 'ready' : 'missing-tool');
    else if (c.check === 'cargo_unsafe') ready = !d.rust ? 'not-configured' : (await which('cargo-geiger') ? 'ready' : 'missing-tool');
    else if (c.check === 'py_deps_cve') ready = !d.py ? 'not-configured' : (await which('pip-audit') ? 'ready' : 'missing-tool');
    else if (c.check === 'tauri_capabilities') ready = d.tauri ? 'ready' : 'not-configured';
    else if (c.check === 'apple_platform') ready = (await trackedFiles()).some(f => f.endsWith('.swift')) ? 'ready' : 'not-configured';
    else if (c.check === 'react_hooks') ready = (d.node && hasDep(d, 'react')) ? 'ready' : 'not-configured';
    // Mirror the check's own gate: swift_lint runs on ANY tracked .swift, not just a root marker.
    // Gating the doctor on the root-only d.swift flag reported 'not-configured' for repos whose
    // Swift lives in a subdir (e.g. sampleapp/ios-native/), while the check itself still ran.
    else if (c.check === 'swift_lint') ready = !(d.swift || (await trackedFiles()).some(f => f.endsWith('.swift')))
      ? 'not-configured' : (await which('swiftlint') ? 'ready' : 'missing-tool');
    else if (c.check === 'js_licenses') ready = d.node ? (hasDep(d, 'license-checker') ? 'ready' : 'missing-dep') : 'not-configured';
    else if (c.check === 'cargo_outdated') ready = !d.rust ? 'not-configured' : (await which('cargo-outdated') ? 'ready' : 'missing-tool');
    else if (c.check === 'dead_code') ready = hasDep(d, 'knip') ? 'ready' : 'missing-dep';
    else if (c.check === 'duplication') ready = hasDep(d, 'jscpd') ? 'ready' : 'missing-dep';
    else if (c.check === 'types') ready = (d.ts && hasDep(d, 'typescript')) ? 'ready' : (d.py ? ((await which('basedpyright')) || (await which('mypy')) ? 'ready' : 'missing-tool') : 'not-configured');
    else if (c.check === 'lint') ready = d.biome || d.eslint || d.py || d.rust ? 'ready' : 'not-configured';
    else if (c.check === 'build') ready = d.buildScript || d.rust ? 'ready' : 'not-configured';
    rows.push({ check: c.check, tool: c.tool || null, required: !!c.required, ready, reason });
  }
  const payload = { kind: 'audit-doctor', workspace: root, generated_at: new Date().toISOString(), stack: { node: d.node, ts: d.ts, py: d.py, rust: d.rust, swift: d.swift, tauri: d.tauri, pkgMgr: d.pkgMgr, git: d.git }, checks: rows };
  if (has('--json')) {
    console.log(JSON.stringify(payload, null, 2));
  } else {
    const pad = (s, n) => String(s).padEnd(n);
    console.log(`${pad('check', 14)} ${pad('ready', 16)} required tool`);
    for (const r of rows) console.log(`${pad(r.check, 14)} ${pad(r.ready, 16)} ${String(r.required).padEnd(8)} ${r.tool || ''}`);
  }
}

// Keep only the newest `keep` timestamped run dirs under the audit root (including
// the current one just created). A run dir matches the exact shape produced by
// `new Date().toISOString().replace(/[:.]/g,'-')` — nothing else is eligible, so the
// persistent stores and backups are safe. ISO timestamps sort lexically = by time.
const RUN_DIR_RE = /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z$/;
function pruneOldRuns(auditRoot, currentTs, keep) {
  let entries;
  try {
    entries = readdirSync(auditRoot, { withFileTypes: true });
  } catch {
    return;
  }
  const runs = entries
    .filter((e) => e.isDirectory() && RUN_DIR_RE.test(e.name))
    .map((e) => e.name)
    .sort()            // ascending (oldest first)
    .reverse();        // newest first
  for (const name of runs.slice(Math.max(keep, 1))) {
    if (name === currentTs) continue; // never delete the run we just started
    try { rmSync(join(auditRoot, name), { recursive: true, force: true }); } catch { /* best effort */ }
  }
}

async function main() {
  const d = detect();
  const checks = buildChecks(d);
  if (has('--doctor')) {
    await doctor(d, checks);
    process.exit(0);
  }

  mkdirSync(outDir, { recursive: true });
  // One current audit reflecting current repo state: prune older timestamped run
  // dirs so `.audit/` doesn't accumulate forever (same cache-with-no-GC trap the
  // Cortex generations had). ONLY the `<ts>` run dirs are pruned — the persistent
  // typed stores (`.audit/audit/`, `.audit/architect/`) and any non-timestamp entry
  // are never touched. Skipped when the caller passed an explicit --out.
  if (!flag('--out')) pruneOldRuns(join(root, '.audit'), ts, 1);
  const parallelChecks = checks.filter(c => c.parallel !== false);
  const serialChecks   = checks.filter(c => c.parallel === false);

  const parallelResults = await pool(parallelChecks, execOne);
  const serialResults = [];
  for (const c of serialChecks) serialResults.push(await execOne(c));   // build, alone

  const results = [...parallelResults, ...serialResults];

  // Separate execution status from verdict: ran means completed, not passed.
  for (const r of results) {
    r.execution_status = r.status; // ran|error|skipped|missing
    if (r.status === 'ran') {
      r.verdict = (r.exit_code && r.exit_code > 0) || (r.findings_count && r.findings_count > 0) ? 'fail' : 'pass';
    } else {
      r.verdict = 'unproven';
    }
  }

  // D2: required + applicable but status!=ran => incomplete
  const incomplete = results.some(r => r.required && r.status !== 'ran');
  // secrets absent => loud flag (not a silent pass)
  const secrets_unscanned = results.some(r => r.check === 'secrets' && r.status !== 'ran');
  const scope = await scopeFor(d);

  // manifest drift selfcheck — manifest.json is a hand-synced documentation mirror of this file's
  // check set; prove it matches instead of trusting the hand-sync (the audit's own doc-drift rule).
  let manifest_drift = null;
  try {
    const mf = JSON.parse(readFileSync(join(import.meta.dirname, 'manifest.json'), 'utf8'));
    const declared = new Set(mf.checks.map(c => c.check));
    const runtimeSet = new Set(ALL_CHECK_NAMES);
    const missing_from_manifest = [...runtimeSet].filter(c => !declared.has(c));
    const stale_in_manifest = [...declared].filter(c => !runtimeSet.has(c) && c !== 'runtime');   // `runtime` lives in audit-runtime.mjs
    if (missing_from_manifest.length || stale_in_manifest.length) manifest_drift = { missing_from_manifest, stale_in_manifest };
  } catch {}

  const facts = {
    kind: 'audit-facts', generated_at: new Date().toISOString(),
    workspace: root, out_dir: outDir,
    stack: { node: d.node, ts: d.ts, py: d.py, rust: d.rust, pkgMgr: d.pkgMgr, git: d.git },
    concurrency: CONCURRENCY, incomplete, secrets_unscanned, manifest_drift,
    scope,
    decomposition: results.find(r => r.check === 'decomposition')?.meta || null,
    checks: results,
    detectionOwner: 'cortex',
    detectionDisagreement: (() => {
      const skipped = results.filter((r) => r.status === 'skipped' && r.skip_reason);
      return skipped.length ? skipped.map((r) => ({ check: r.check, reason: r.skip_reason, note: 'toolchain absent per local detect(); Cortex projection decides provider applicability' })) : [];
    })(),
  };
  const factsPath = join(outDir, 'facts.json');
  writeFileSync(factsPath, JSON.stringify(facts, null, 2), 'utf8');

  // live one-line summary table
  const pad = (s, n) => String(s).padEnd(n);
  console.log(`\ncollect-facts → ${factsPath}   (concurrency ${CONCURRENCY})`);
  console.log(`${pad('check', 12)} ${pad('status', 9)} ${pad('exit', 5)} ${pad('findings', 9)} tool`);
  for (const r of results) console.log(`${pad(r.check, 12)} ${pad(r.status, 9)} ${pad(r.exit_code ?? '-', 5)} ${pad(r.findings_count ?? '-', 9)} ${r.tool ?? ''}${r.tool_absent ? '  (absent)' : ''}`);
  console.log(`\nincomplete=${incomplete}  secrets_unscanned=${secrets_unscanned}`);
  if (manifest_drift) console.log(`WARNING manifest.json drift — missing: [${manifest_drift.missing_from_manifest.join(', ')}]  stale: [${manifest_drift.stale_in_manifest.join(', ')}]`);
  if (has('--json')) console.log('\n' + JSON.stringify(facts));
  process.exit(0);
}

// Run only when invoked directly (node collect-facts.mjs …), not when imported by
// a test — importing must not spawn the whole scanner suite.
//
// Match by basename instead of `pathToFileURL(process.argv[1]).href === import.meta.url`:
// the URL form normalizes differently on macOS Node 22 (extra slashes, percent-encoding
// in special paths) and silently fails the comparison, so the script exits 0 with no
// output when invoked as `node <abs-path>/collect-facts.mjs`. The basename check is
// equivalent for the only intended direct-invocation form and robust across platforms.
export { pruneOldRuns, RUN_DIR_RE };
if (process.argv[1] && process.argv[1].endsWith('collect-facts.mjs')) {
  main();
}
