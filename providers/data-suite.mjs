#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const DATA_EXTENSIONS = new Set(['sql', 'ts', 'tsx', 'js', 'mjs', 'cjs', 'py', 'php', 'rb', 'go', 'rs', 'java', 'kt', 'cs']);

function read(root, path) { try { return readFileSync(join(root, path), 'utf8'); } catch { return ''; } }
function lineAt(text, index) { return text.slice(0, index).split('\n').length; }
function severityHint(level) { return level === 'error' ? 'high' : level === 'warning' ? 'medium' : 'low'; }
function candidate(ruleId, level, message, file, line) {
  return {
    id: `sha256:${createHash('sha256').update(`${ruleId}\0${file}\0${line}`).digest('hex')}`,
    ruleId, severityHint: severityHint(level), claim: message, file, line,
  };
}
function scan(root, files, rule) {
  const candidates = [];
  for (const file of files) {
    const ext = basename(file).split('.').at(-1)?.toLowerCase();
    if (!DATA_EXTENSIONS.has(ext)) continue;
    const text = read(root, file);
    for (const pattern of rule.patterns) {
      pattern.lastIndex = 0;
      for (const match of text.matchAll(pattern)) candidates.push(candidate(rule.id, rule.level, rule.message, file, lineAt(text, match.index ?? 0)));
    }
  }
  return candidates;
}

const RULES = Object.freeze([
  { id: 'data.sql-interpolation', level: 'error', message: 'SQL text appears to interpolate or concatenate variable input.', patterns: [/(?:SELECT|INSERT|UPDATE|DELETE|ALTER|DROP)[^\n;]*(?:\$\{|\+\s*(?:req|request|input|user|params|query)|format\s*\(|f['"])/gi] },
  { id: 'data.destructive-migration', level: 'warning', message: 'Migration contains a destructive DROP operation; require backup, rollback, and compatibility evidence.', patterns: [/\bDROP\s+(?:TABLE|COLUMN|DATABASE|INDEX)\b/gi] },
  { id: 'data.not-null-migration', level: 'warning', message: 'Migration adds NOT NULL without a visible default/backfill sequence.', patterns: [/\bADD\s+(?:COLUMN\s+)?[A-Za-z0-9_"`]+[^;\n]*\bNOT\s+NULL\b(?![^;\n]*\bDEFAULT\b)/gi] },
  { id: 'data.sqlite-foreign-keys-off', level: 'error', message: 'SQLite foreign-key enforcement is disabled.', patterns: [/PRAGMA\s+foreign_keys\s*=\s*(?:OFF|0)/gi] },
  { id: 'data.sqlite-no-busy-timeout', level: 'note', message: 'SQLite connection is configured without a visible busy timeout; assess lock contention.', patterns: [/sqlite(?:3)?[\s\S]{0,200}(?:connect|open)\s*\((?![\s\S]{0,300}(?:busy_timeout|timeout))/gi] },
  { id: 'data.redis-keys', level: 'warning', message: 'Redis KEYS can block the server; use bounded SCAN for production paths.', patterns: [/\.(?:keys|KEYS)\s*\(\s*['"][^'"]*['"]\s*\)/g] },
  { id: 'data.redis-unbounded-value', level: 'note', message: 'Redis write has no visible expiration; verify retention and invalidation.', patterns: [/\.(?:set|hset)\s*\([^\n;]+\)(?![^\n;]*(?:expire|ttl|ex\s*:|px\s*:))/gi] },
  { id: 'data.mongo-javascript', level: 'error', message: 'MongoDB server-side JavaScript evaluation is used.', patterns: [/\$(?:where|function)\b|mapReduce\s*\(/gi] },
  { id: 'data.transaction-missing', level: 'note', message: 'Multiple adjacent write operations have no visible transaction boundary.', patterns: [/(?:insert|update|delete|save)\s*\([\s\S]{0,500}(?:insert|update|delete|save)\s*\((?![\s\S]{0,700}(?:transaction|beginTransaction|BEGIN\b))/gi] },
]);

export function runDataSuite({ root, files }) {
  const candidates = RULES.flatMap((rule) => scan(root, files, rule));
  return {
    schemaVersion: 1,
    provider: 'data.internal-suite',
    providerVersion: '1.0.0',
    ownerProvider: 'data.internal-suite',
    phase: 'runtime',
    role: 'candidate-generator',
    status: candidates.length ? 'candidates' : 'pass',
    complete: true, applicable: true, required: true,
    coverage: { pathCount: files.length, rules: RULES.length },
    candidates, findings: [], receipts: [], coverageGaps: [], degradation: [],
  };
}

function main() {
  const [rootArg, planPath, outPath] = process.argv.slice(2);
  if (!rootArg || !planPath) throw new Error('usage: data-suite.mjs <root> <plan.json> [out.json]');
  const root = resolve(rootArg); const plan = JSON.parse(readFileSync(resolve(planPath), 'utf8'));
  const files = [...new Set((plan.coverageFamilies ?? []).flatMap((family) => family.denominator?.paths ?? []))].sort();
  const result = runDataSuite({ root, files });
  if (outPath) writeFileSync(resolve(outPath), `${JSON.stringify(result, null, 2)}\n`); else console.log(JSON.stringify(result, null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
