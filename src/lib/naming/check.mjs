import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { resolve, relative } from 'node:path';
import { canonicalAuthorityIds, loadNamingRegistry } from './registry.mjs';
import { AUTHORITY_ID } from '../../packages/contracts/enums.mjs';
import { ROSTER_ROLE_IDS } from '../roster/index.mjs';

const TOKENS = Object.freeze(['seer', 'nemesis', 'forge', 'sentinel', 'sorcerer']);
const SKIP_PREFIXES = Object.freeze(['.git/', '.agent/', '.audit/', 'node_modules/']);
const ACTIVE_SOURCE = /\.(?:cjs|js|json|jsx|md|mjs|py|sh|toml|ts|tsx|ya?ml)$/i;

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
    return execFileSync('git', ['ls-files', '-co', '--exclude-standard', '-z'], { cwd: root, stdio: ['ignore', 'pipe', 'ignore'] })
      // Keep only real files: nested checkout entries may resolve to directories
      // on disk, and reading those as files throws EISDIR.
      .toString().split('\0').filter(Boolean)
      .filter((path) => { const p = resolve(root, path); return existsSync(p) && statSync(p).isFile(); })
      .filter((path) => !SKIP_PREFIXES.some((prefix) => path.startsWith(prefix)));
  } catch {
    return recursiveFiles(root);
  }
}

function text(path) {
  const bytes = readFileSync(path);
  if (bytes.includes(0)) return null;
  try {
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const controls = [...bytes].filter((byte) => byte < 32 && ![0, 9, 10, 13].includes(byte)).length;
    return controls / Math.max(bytes.length, 1) > 0.01 ? null : decoded;
  } catch { return null; }
}

function matchingRule(rules, path, token) {
  return rules.find((rule) => (rule.path === path || (rule.pathPrefix && path.startsWith(rule.pathPrefix))) && rule.tokens.includes(token));
}

function allowlistIssues(root, rules, files) {
  const issues = [];
  for (const [index, rule] of rules.entries()) {
    const rulePath = `src/config/naming-legacy-allowlist.json#rules[${index}]`;
    if ((!rule.path && !rule.pathPrefix) || !Array.isArray(rule.tokens) || rule.tokens.length === 0 || !rule.class || !rule.reason) {
      issues.push({ path: rulePath, reason: 'legacy allowlist rule lacks target, tokens, class, or reason' });
      continue;
    }
    const candidates = files.filter((path) => rule.path === path || (rule.pathPrefix && path.startsWith(rule.pathPrefix)));
    if (candidates.length === 0) {
      issues.push({ path: rule.path ?? rule.pathPrefix, reason: 'legacy allowlist target does not exist or matches no files' });
      continue;
    }
    for (const token of rule.tokens) {
      if (!TOKENS.includes(token)) {
        issues.push({ path: rulePath, token, reason: 'legacy allowlist names unknown token' });
        continue;
      }
      let observed = 0;
      for (const path of candidates) {
        observed += occurrences(path, token).length;
        const content = text(resolve(root, path));
        if (content !== null) observed += occurrences(content, token).length;
      }
      if (observed === 0) issues.push({ path: rule.path ?? rule.pathPrefix, token, reason: 'legacy allowlist token exemption is unused' });
    }
  }
  return issues;
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
  if (JSON.stringify(canonicalAuthorityIds(registry)) !== JSON.stringify(expected)) issues.push({ path: 'src/config/naming-registry.json', reason: 'canonical authority set mismatch' });
  const runtimeExpected = [...new Set([registry.product.id, ...expected, ...Object.keys(registry.actors)])].sort();
  if (JSON.stringify([...AUTHORITY_ID].sort()) !== JSON.stringify(runtimeExpected)) issues.push({ path: 'src/packages/contracts/enums.mjs', reason: 'runtime authority set differs from naming registry' });
  for (const [id, seat] of Object.entries(registry.seats)) if (seat.authority !== false || AUTHORITY_ID.includes(id)) issues.push({ path: 'src/config/naming-registry.json', reason: `advisory seat '${id}' must not be an authority` });
  if (JSON.stringify([...ROSTER_ROLE_IDS].sort()) !== JSON.stringify(['alchemist', 'oracle', 'sage'])) issues.push({ path: 'src/lib/roster/index.mjs', reason: 'runtime roster differs from naming registry' });
  const readme = readFileSync(resolve(root, 'README.md'), 'utf8');
  for (const display of ['Legion', 'Sage', 'Alchemist', 'Oracle', 'Arcane', 'Covenant']) {
    if (!readme.includes(`| **${display}** |`)) issues.push({ path: 'README.md', reason: `authority table missing ${display}` });
  }
  const packageJson = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
  for (const id of ['legion', ...expected, 'covenant']) if (!packageJson.keywords.includes(id)) issues.push({ path: 'package.json', reason: `missing canonical keyword ${id}` });
  if (!packageJson.files.includes('src/packages/oracle/')) issues.push({ path: 'package.json', reason: 'published files omit canonical Oracle package' });
  if (packageJson.files.includes('packages/seer/')) issues.push({ path: 'package.json', reason: 'published files retain legacy assurance package' });
  const packageManifest = JSON.parse(readFileSync(resolve(root, 'MANIFEST.package.json'), 'utf8'));
  if (!packageManifest.allowlistedTopLevel.includes('src/packages/oracle/')) issues.push({ path: 'MANIFEST.package.json', reason: 'package manifest omits canonical Oracle package' });
  if (packageManifest.allowlistedTopLevel.includes('packages/seer/')) issues.push({ path: 'MANIFEST.package.json', reason: 'package manifest retains legacy assurance package' });
  for (const path of ['.claude-plugin/plugin.json', '.codex-plugin/plugin.json']) {
    const manifest = JSON.parse(readFileSync(resolve(root, path), 'utf8'));
    for (const display of ['Legion', 'Sage', 'Alchemist', 'Oracle', 'Arcane']) if (!manifest.description.includes(display)) issues.push({ path, reason: `description missing ${display}` });
  }
  if (!existsSync(resolve(root, 'src/packages/oracle/index.mjs'))) issues.push({ path: 'src/packages/oracle/index.mjs', reason: 'canonical Oracle package missing' });
  if (existsSync(resolve(root, 'packages/seer'))) issues.push({ path: 'packages/seer', reason: 'legacy assurance package still exists' });
  if (existsSync(resolve(root, 'registry/rules/opengrep/nemesis-core.yml'))) issues.push({ path: 'registry/rules/opengrep/nemesis-core.yml', reason: 'legacy product filename still exists' });
  for (const { path, declaration, valuePattern = /['"]([^'"]+)['"]/g, expected: values } of [
    { path: 'src/packages/arcane/lib/architecture-event-store.mjs', declaration: /const ACTOR_ROLES\s*=\s*new Set\((\[[^\]]+\])\)/, expected: ['alchemist', 'covenant', 'host', 'legion', 'oracle', 'sage', 'worker'] },
    { path: 'src/packages/arcane/lib/authority-binding-store.mjs', declaration: /const MAP\s*=\s*(\{[^}]+\})/, valuePattern: /:\s*['"]([^'"]+)['"]/g, expected: ['alchemist', 'legion', 'oracle', 'sage'] },
  ]) {
    const source = readFileSync(resolve(root, path), 'utf8');
    const literal = declaration.exec(source)?.[1] ?? '';
    const observed = [...new Set([...literal.matchAll(valuePattern)].map((match) => match[1]))].sort();
    if (JSON.stringify(observed) !== JSON.stringify([...values].sort())) issues.push({ path, reason: 'runtime authority registry differs from canonical set' });
  }
  return issues;
}

export function checkCanonicalNames({ root }) {
  const registry = loadNamingRegistry(resolve(root, 'src/config/naming-registry.json'));
  const allowlist = JSON.parse(readFileSync(resolve(root, 'src/config/naming-legacy-allowlist.json'), 'utf8'));
  const files = repositoryFiles(root);
  const issues = [...semanticIssues(root, registry), ...allowlistIssues(root, allowlist.rules, files)];
  for (const path of files) {
    for (const token of TOKENS) {
      const pathHit = occurrences(path, token).length > 0;
      if (pathHit && !matchingRule(allowlist.rules, path, token)) issues.push({ path, token, reason: 'unclassified legacy filename' });
    }
    const content = text(resolve(root, path));
    if (content === null) {
      if (ACTIVE_SOURCE.test(path)) issues.push({ path, reason: 'active source cannot be decoded for naming scan' });
      continue;
    }
    for (const token of TOKENS) {
      const lines = occurrences(content, token);
      const rule = matchingRule(allowlist.rules, path, token);
      const exactCount = rule?.occurrences?.[token];
      if (lines.length && !rule) issues.push({ path, line: lines[0], token, reason: 'unclassified legacy token' });
      else if (lines.length && rule.path && rule.class !== 'R5' && !Number.isInteger(exactCount)) issues.push({ path, line: lines[0], token, reason: 'active exact-path allowlist lacks occurrence count' });
      else if (Number.isInteger(exactCount) && lines.length !== exactCount) issues.push({ path, line: lines[0], token, reason: `legacy token occurrence count differs: expected ${exactCount}, found ${lines.length}` });
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
