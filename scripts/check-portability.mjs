#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PATTERNS = Object.freeze({
  'developer-workspace': new RegExp(String.raw`D:[/\\]Clau` + String.raw`de|/Volumes/D/[Cc]lau` + 'de', 'gi'),
  'developer-home': new RegExp(String.raw`C:[/\\]Users[/\\](?:Adri` + String.raw`an|AD` + String.raw`RDS)|/Users/(?:Adri` + String.raw`an|adri` + String.raw`an|AD` + String.raw`RDS)`, 'gi'),
  'developer-username': new RegExp(String.raw`(?<![A-Za-z0-9])AD` + String.raw`RDS(?![A-Za-z0-9])`, 'gi'),
});

function recursiveFiles(root, cursor = root, output = []) {
  for (const entry of readdirSync(cursor)) {
    if (['.git', '.audit', 'node_modules', 'target'].includes(entry)) continue;
    const absolute = resolve(cursor, entry);
    const stat = statSync(absolute);
    if (stat.isDirectory()) recursiveFiles(root, absolute, output);
    else if (stat.isFile()) output.push(relative(root, absolute).replaceAll('\\', '/'));
  }
  return output;
}

function trackedFiles(root) {
  try {
    return execFileSync('git', ['ls-files', '-z'], { cwd: root, stdio: ['ignore', 'pipe', 'ignore'] })
      .toString().split('\0').filter(Boolean)
      .filter((path) => {
        const absolute = resolve(root, path);
        return existsSync(absolute) && statSync(absolute).isFile();
      });
  } catch {
    return recursiveFiles(root);
  }
}

function text(path) {
  const bytes = readFileSync(path);
  if (bytes.includes(0)) return null;
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { return null; }
}

function count(content, pattern) {
  pattern.lastIndex = 0;
  return [...content.matchAll(pattern)].length;
}

export function portabilityReport(root = ROOT) {
  const files = trackedFiles(root);
  const allowlistPath = 'src/config/portability-allowlist.json';
  const allowlist = JSON.parse(readFileSync(resolve(root, allowlistPath), 'utf8'));
  const issues = [];
  if (allowlist.schemaVersion !== 1 || !Array.isArray(allowlist.rules)) {
    issues.push({ path: allowlistPath, reason: 'invalid portability allowlist' });
  }
  const fileSet = new Set(files);
  for (const rule of allowlist.rules ?? []) {
    if (!fileSet.has(rule.path)) {
      issues.push({ path: rule.path, reason: 'portability allowlist path does not exist' });
      continue;
    }
    if (!rule.reason || !rule.class || !Array.isArray(rule.patterns) || rule.patterns.length === 0) {
      issues.push({ path: rule.path, reason: 'portability allowlist rule lacks classification, reason, or patterns' });
      continue;
    }
    const content = text(resolve(root, rule.path));
    for (const id of rule.patterns) {
      if (!PATTERNS[id]) {
        issues.push({ path: rule.path, pattern: id, reason: 'unknown portability pattern in allowlist' });
        continue;
      }
      const expected = rule.occurrences?.[id];
      const observed = content === null ? 0 : count(content, PATTERNS[id]);
      if (!Number.isInteger(expected) || expected < 1 || observed !== expected) {
        issues.push({ path: rule.path, pattern: id, reason: `allowlisted occurrence count differs: expected ${expected ?? '<missing>'}, found ${observed}` });
      }
    }
  }
  for (const path of files) {
    const content = text(resolve(root, path));
    if (content === null) continue;
    for (const [id, pattern] of Object.entries(PATTERNS)) {
      const observed = count(content, pattern);
      if (!observed) continue;
      const rule = (allowlist.rules ?? []).find((candidate) => candidate.path === path && candidate.patterns?.includes(id));
      if (!rule) issues.push({ path, pattern: id, reason: `unclassified developer-local value (${observed} occurrence${observed === 1 ? '' : 's'})` });
    }
  }
  return { schemaVersion: 1, kind: 'legion-portability-report', status: issues.length ? 'fail' : 'pass', filesScanned: files.length, issues };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const report = portabilityReport();
  if (process.argv.includes('--json')) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else if (report.status === 'pass') process.stdout.write(`portability: PASS (${report.filesScanned} tracked files)\n`);
  else for (const issue of report.issues) process.stderr.write(`${issue.path}: ${issue.reason}${issue.pattern ? ` [${issue.pattern}]` : ''}\n`);
  process.exitCode = report.status === 'pass' ? 0 : 1;
}
