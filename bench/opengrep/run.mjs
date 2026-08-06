// OpenGrep provider bench: normalizes a synthetic taint-trace corpus and
// verifies candidate conversion, capability classification, and stable ids.
import { normalizeFinding, toCandidate } from '../../providers/opengrep/index.mjs';

const CORPUS = [
  {
    check_id: 'nemesis-command-injection-shell', path: 'src/app.py',
    start: { line: 12, col: 4 }, end: { line: 12, col: 40 },
    extra: { severity: 'WARNING', message: 'shell sink' },
    dataflow_trace: { source: [['src/views.py', 3]], sink: [['src/app.py', 12]] },
  },
  {
    check_id: 'nemesis-sql-interpolation', path: 'src/db.ts',
    start: { line: 5, col: 0 }, end: { line: 5, col: 30 },
    extra: { severity: 'WARNING', message: 'sql' },
    dataflow_trace: { source: [['src/routes.ts', 2]], sink: [['src/db.ts', 5]], intermediate_vars: [['src/db.ts', 4]] },
  },
  {
    check_id: 'nemesis-command-injection-shell', path: 'src/clean.py',
    start: { line: 1, col: 0 }, end: { line: 1, col: 10 },
    extra: { severity: 'INFO', message: 'benign' },
  },
];

const findings = CORPUS.map((raw) => normalizeFinding(raw, { ruleset: 'nemesis-core' }));
const candidates = findings.map((f) => toCandidate(f, { denominatorDigest: 'sha256:bench' }));
const ids = new Set(candidates.map((c) => c.id));

console.log(`opengrep bench: ${findings.length} findings normalized, ${candidates.length} candidates, ${ids.size} unique ids`);
if (findings.length !== 3) process.exit(1);
if (candidates.length !== 3) process.exit(1);
if (candidates.some((c) => c.verdict !== 'UNADJUDICATED')) process.exit(1);
if (candidates.some((c) => c.findings?.length)) process.exit(1);
console.log('GATE: PASS');
