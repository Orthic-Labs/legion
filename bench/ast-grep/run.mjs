// ast-grep provider bench: normalizes a synthetic match stream and reports
// stable-fingerprint and normalization metrics. Requires no ast-grep install
// (pure normalization path); the adapter qualification is covered by the
// structural tests.
import { normalizeStream } from '../../providers/ast-grep/index.mjs';

const SYNTHETIC_LINES = [
  { file: 'src/a.ts', line: 3, column: 0, endLine: 3, endColumn: 30, ruleId: 'no-inner-html', severity: 'error', message: 'raw html', structuralDigest: 'sha256:s1' },
  { file: 'src/b.ts', line: 12, column: 0, endLine: 12, endColumn: 20, ruleId: 'no-console-error-leak', severity: 'warning', message: 'console error', structuralDigest: 'sha256:s2' },
  { file: 'src/c.tsx', line: 1, column: 0, endLine: 1, endColumn: 40, ruleId: 'no-inner-html', severity: 'error', message: 'raw html', structuralDigest: 'sha256:s3' },
];

const matches = normalizeStream(SYNTHETIC_LINES, { ruleId: 'no-inner-html', severity: 'error' });
const fingerprints = new Set(matches.map((match) => match.fingerprint));

console.log(`ast-grep bench: ${matches.length} matches normalized, ${fingerprints.size} unique fingerprints`);
if (matches.length !== 3) process.exit(1);
if (fingerprints.size !== 3) process.exit(1);
console.log('GATE: PASS');
