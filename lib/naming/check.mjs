import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { resolve, relative } from 'node:path';
import { canonicalAuthorityIds, loadNamingRegistry } from './registry.mjs';

const TOKENS = Object.freeze(['seer', 'nemesis', 'forge', 'sentinel', 'sorcerer']);
const SKIP_PREFIXES = Object.freeze(['.git/', '.agent/', 'node_modules/']);

function recursiveFiles(root, cursor = root, output = []) {
  for (const entry of readdirSync(cursor)) {
    const path = resolve(cursor, entry);
    const rel = relative(root, path).replaceAll('\\', '/');
    if (SKIP_PREFIXES.some((prefix) => `${rel}/`.startsWith(prefix))) continue;
    const stat = statSync(path);
    if (stat.isDirectory()) recursiveFiles(root, path, output);
    else if (stat.isFile()) output.push(rel);
  }
  return output;
}

function repositoryFiles(root) {
  try {
    return execFileSync('git', ['ls-files', '-co', '--exclude-standard', '-z'], { cwd: root })
      .toString().split('\0').filter(Boolean).filter((path) => existsSync(resolve(root, path)))
      .filter((path) => !SKIP_PREFIXES.some((prefix) => path.startsWith(prefix)));
  } catch {
    return recursiveFiles(root);
  }
}

function text(path) {
  const bytes = readFileSync(path);
  if (bytes.includes(0)) return null;
  return bytes.toString('utf8');
}

function ruleAllows(rules, path, token) {
  return rules.some((rule) => (rule.path === path || (rule.pathPrefix && path.startsWith(rule.pathPrefix))) && rule.tokens.includes(token));
}

function occurrences(content, token) {
  const pattern = new RegExp(`(?<![A-Za-z0-9])${token}(?![A-Za-z0-9])`, 'ig');
  const found = [];
  for (const match of content.matchAll(pattern)) {
    const line = content.slice(0, match.index).split('\n').length;
    found.push(line);
  }
  return found;
}

function semanticIssues(root, registry) {
  const issues = [];
  const expected = ['alchemist', 'arcane', 'oracle', 'sage'];
  if (JSON.stringify(canonicalAuthorityIds(registry)) !== JSON.stringify(expected)) issues.push({ path: 'config/naming-registry.json', reason: 'canonical authority set mismatch' });
  const packageJson = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
  for (const id of ['legion', ...expected, 'covenant']) if (!packageJson.keywords.includes(id)) issues.push({ path: 'package.json', reason: `missing canonical keyword ${id}` });
  for (const path of ['.claude-plugin/plugin.json', '.codex-plugin/plugin.json']) {
    const manifest = JSON.parse(readFileSync(resolve(root, path), 'utf8'));
    for (const display of ['Legion', 'Sage', 'Alchemist', 'Oracle', 'Arcane']) if (!manifest.description.includes(display)) issues.push({ path, reason: `description missing ${display}` });
  }
  if (!existsSync(resolve(root, 'packages/oracle/index.mjs'))) issues.push({ path: 'packages/oracle/index.mjs', reason: 'canonical Oracle package missing' });
  if (existsSync(resolve(root, 'packages/seer'))) issues.push({ path: 'packages/seer', reason: 'legacy assurance package still exists' });
  if (existsSync(resolve(root, 'registry/rules/opengrep/nemesis-core.yml'))) issues.push({ path: 'registry/rules/opengrep/nemesis-core.yml', reason: 'legacy product filename still exists' });
  return issues;
}

export function checkCanonicalNames({ root }) {
  const registry = loadNamingRegistry(resolve(root, 'config/naming-registry.json'));
  const allowlist = JSON.parse(readFileSync(resolve(root, 'config/naming-legacy-allowlist.json'), 'utf8'));
  const issues = semanticIssues(root, registry);
  for (const path of repositoryFiles(root)) {
    const content = text(resolve(root, path));
    if (content === null) continue;
    for (const token of TOKENS) {
      const lines = occurrences(content, token);
      if (lines.length && !ruleAllows(allowlist.rules, path, token)) issues.push({ path, line: lines[0], token, reason: 'unclassified legacy token' });
      const pathHit = occurrences(path, token).length > 0;
      if (pathHit && !ruleAllows(allowlist.rules, path, token)) issues.push({ path, token, reason: 'unclassified legacy filename' });
    }
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: 'legion-naming-contract-report',
    status: issues.length ? 'fail' : 'pass',
    canonicalAuthorities: canonicalAuthorityIds(registry),
    deprecatedAliases: Object.values(registry.authorities).flatMap(({ aliases = [] }) => aliases.map(({ id }) => id)).sort(),
    unclassified: issues,
  });
}
