// Dependency-closure validation.
//
// Every packaged semantic bundle owns one typed dependency declaration. A
// declaration classifies package resources, host capabilities, project overlays,
// and historical evidence before a host projects or invokes that bundle.
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve, relative, dirname, isAbsolute, sep } from 'node:path';
import { commandCapabilityMap, loadCapabilityRegistry as loadRegistry } from '../capabilities/registry.mjs';
import { parseSkillFrontmatter } from './skill-frontmatter.mjs';

export { loadCapabilityRegistry } from '../capabilities/registry.mjs';

export const DEPENDENCY_CLASSES = Object.freeze([
  'PACKAGE_INTERNAL', 'HOST_CAPABILITY', 'PROJECT_OVERLAY', 'HISTORICAL_EVIDENCE',
]);

export const DEPENDENCY_DECLARATION = 'dependencies.json';

// Placeholder roots that stand in for something the consuming project supplies. These are the only
// unresolvable path prefixes a packaged document may contain.
const OVERLAY_PREFIX = /^(?:<project-overlay>|<workspace>|<studio-workspace-root>|<CURRENT_WORKSPACE>|<package-root>|<audit-skill-dir>|<[a-z][a-z0-9-]*>)/i;
const UNRESOLVED_MARKER = /\b(?:TODO|FIXME|XXX)\b\s*:?\s*(?:no in-package|not available|missing|unresolved)/i;
const SCRIPT_REFERENCE = /`(?:scripts\/|\.{1,2}\/)[A-Za-z0-9._\-/]+\.(?:mjs|js|py|sh|ps1|vbs)`/g;
const PLACEHOLDER = /(?:^|\/)(?:xxx|yyy|foo|bar|example|placeholder)\.[a-z0-9]+$/i;
const DOCUMENT = /\.(?:md|mdx|txt)$/i;
const INLINE_CODE = /`([^`\r\n]+)`/g;
const FENCED_CODE = /```[^\r\n]*\r?\n([\s\S]*?)```/g;
const COMMAND_START = /^(?:[$>]\s*)?([A-Za-z0-9][A-Za-z0-9._-]*)\b/;
const HOST_CAPABILITY_DIRECTIVE = /\bREQUIRES_HOST_CAPABILITY:\s*([a-z][a-z0-9-]*)/gi;

function dependencyError(path, detail) {
  throw new Error(`${path}: ${detail}`);
}

/** Parse the one canonical typed dependency declaration for a semantic bundle. */
export function parseDependencyDeclaration(text, { path = DEPENDENCY_DECLARATION } = {}) {
  let document;
  try { document = JSON.parse(text); } catch { dependencyError(path, 'dependency declaration is not valid JSON'); }
  if (!document || typeof document !== 'object' || Array.isArray(document)) dependencyError(path, 'dependency declaration must be an object');
  const allowed = new Set(['schemaVersion', 'kind', 'resources']);
  for (const key of Object.keys(document)) if (!allowed.has(key)) dependencyError(path, `unknown dependency declaration field ${key}`);
  if (document.schemaVersion !== 1 || document.kind !== 'legion-skill-dependencies') {
    dependencyError(path, 'dependency declaration has an unsupported schema');
  }
  if (!Array.isArray(document.resources)) dependencyError(path, 'dependency declaration resources must be an array');
  return document;
}

function loadDependencyDeclaration(skillRoot) {
  const path = join(skillRoot, DEPENDENCY_DECLARATION);
  if (!existsSync(path)) return { path, document: null, error: 'missing dependency declaration' };
  try {
    return { path, document: parseDependencyDeclaration(readFileSync(path, 'utf8'), { path }) };
  } catch (error) {
    return { path, document: null, error: error.message };
  }
}

// Classify one typed resource entry from a canonical dependency declaration or route table.
export function classifyResource(entry, { packageRoot, skillRoot, capabilities }) {
  if (typeof entry === 'string') {
    return { ok: false, code: 'untyped-resource', detail: `resource is a bare string, not a typed entry: ${entry}` };
  }
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    return { ok: false, code: 'invalid-resource', detail: `resource is not an object: ${JSON.stringify(entry)}` };
  }
  const { class: klass } = entry;
  if (!DEPENDENCY_CLASSES.includes(klass)) {
    return { ok: false, code: 'unknown-class', detail: `resource declares no known dependency class: ${JSON.stringify(entry)}` };
  }
  if (klass === 'PACKAGE_INTERNAL') {
    if (!entry.path || typeof entry.path !== 'string') return { ok: false, code: 'invalid-resource', detail: 'PACKAGE_INTERNAL declares no path' };
    const target = resolve(skillRoot, entry.path);
    const contained = relative(resolve(packageRoot), target);
    if (contained === '..' || contained.startsWith(`..${sep}`) || isAbsolute(contained)) {
      return { ok: false, code: 'escapes-package', detail: `PACKAGE_INTERNAL escapes the package: ${entry.path}` };
    }
    if (!existsSync(target)) {
      return { ok: false, code: 'missing-internal', detail: `PACKAGE_INTERNAL does not exist: ${entry.path}` };
    }
    return { ok: true };
  }
  if (klass === 'HOST_CAPABILITY') {
    if (!entry.capability || typeof entry.capability !== 'string') return { ok: false, code: 'invalid-resource', detail: 'HOST_CAPABILITY names no capability' };
    if (!capabilities[entry.capability]) {
      return { ok: false, code: 'undeclared-capability', detail: `HOST_CAPABILITY is absent from the registry: ${entry.capability}` };
    }
    return { ok: true };
  }
  if (klass === 'PROJECT_OVERLAY') {
    if (entry.optional !== true) {
      return { ok: false, code: 'mandatory-overlay', detail: `PROJECT_OVERLAY must be optional: ${entry.path ?? '(no path)'}` };
    }
    if (!entry.absent) {
      return { ok: false, code: 'undeclared-degradation', detail: `PROJECT_OVERLAY states no behaviour when absent: ${entry.path ?? '(no path)'}` };
    }
    if (entry.path && (typeof entry.path !== 'string' || !OVERLAY_PREFIX.test(entry.path))) {
      return { ok: false, code: 'concrete-overlay-path', detail: `PROJECT_OVERLAY must use a placeholder root, not a concrete path: ${entry.path}` };
    }
    return { ok: true };
  }
  return { ok: true }; // HISTORICAL_EVIDENCE is inert by definition.
}

// Scan a packaged text file for references that resolve into no class at all.
export function scanPackagedText(text, { path, skillRoot, packageRoot }) {
  const findings = [];
  if (UNRESOLVED_MARKER.test(text)) {
    findings.push({ code: 'unresolved-marker', path, detail: 'packaged text ships an unresolved TODO in place of a real reference' });
  }
  if (DOCUMENT.test(path)) {
    for (const match of text.matchAll(SCRIPT_REFERENCE)) {
      const reference = match[0].slice(1, -1);
      if (PLACEHOLDER.test(reference)) continue;
      const candidates = [resolve(packageRoot, reference)];
      for (let dir = resolve(skillRoot, dirname(path)); ; dir = dirname(dir)) {
        candidates.push(resolve(dir, reference));
        if (dir === skillRoot || !dir.startsWith(skillRoot)) break;
      }
      if (!candidates.some((candidate) => existsSync(candidate))) {
        findings.push({ code: 'dangling-script', path, detail: `document promises a script that does not exist: ${reference}` });
      }
    }
  }
  return findings;
}

function codeSnippets(text) {
  const snippets = [];
  for (const match of text.matchAll(FENCED_CODE)) snippets.push(match[1]);
  for (const match of text.matchAll(INLINE_CODE)) snippets.push(match[1]);
  return snippets;
}

/** Reject use of a registry-owned executable command without its host requirement. */
export function scanHostCommandReferences(text, { path, commandCapabilities, hostRequirements }) {
  const findings = [];
  const seen = new Set();
  for (const snippet of codeSnippets(text)) {
    for (const line of snippet.split(/\r?\n/)) {
      const command = COMMAND_START.exec(line.trim())?.[1]?.toLowerCase();
      const capability = command && commandCapabilities.get(command);
      if (!capability || hostRequirements.has(capability)) continue;
      const key = `${command}:${capability}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        code: 'undeclared-host-command', path,
        detail: `command ${command} requires declared host capability ${capability}`,
      });
    }
  }
  for (const match of text.matchAll(HOST_CAPABILITY_DIRECTIVE)) {
    const capability = match[1];
    if (hostRequirements.has(capability)) continue;
    findings.push({
      code: 'undeclared-host-capability', path,
      detail: `REQUIRES_HOST_CAPABILITY ${capability} is absent from dependencies.json and hostRequirements`,
    });
  }
  return findings;
}

function sameMembers(left, right) {
  return left.size === right.size && [...left].every((value) => right.has(value));
}

function verifyBundleDependencies({ packageRoot, manifest, capabilities, commandCapabilities }) {
  const findings = [];
  const skillRoot = resolve(packageRoot, 'skills', manifest.id);
  const declaration = loadDependencyDeclaration(skillRoot);
  const relativePath = `skills/${manifest.id}/${DEPENDENCY_DECLARATION}`;
  if (!declaration.document) {
    findings.push({
      code: declaration.error === 'missing dependency declaration' ? 'missing-dependency-declaration' : 'invalid-dependency-declaration',
      bundleId: manifest.id,
      path: relativePath,
      detail: declaration.error,
    });
    return { findings, declarationCount: 0, typedResourceCount: 0 };
  }

  const declared = new Set();
  for (const [index, entry] of declaration.document.resources.entries()) {
    const result = classifyResource(entry, { packageRoot, skillRoot, capabilities });
    if (!result.ok) {
      findings.push({ bundleId: manifest.id, path: `${DEPENDENCY_DECLARATION}#resources.${index}`, code: result.code, detail: result.detail });
    }
    if (entry?.class === 'HOST_CAPABILITY' && typeof entry.capability === 'string') {
      if (declared.has(entry.capability)) {
        findings.push({
          bundleId: manifest.id, path: `${DEPENDENCY_DECLARATION}#resources.${index}`, code: 'duplicate-host-capability',
          detail: `HOST_CAPABILITY is declared more than once: ${entry.capability}`,
        });
      }
      declared.add(entry.capability);
    }
  }

  const skillPath = join(skillRoot, 'SKILL.md');
  try {
    const frontmatter = parseSkillFrontmatter(readFileSync(skillPath, 'utf8'), { path: `skills/${manifest.id}/SKILL.md` });
    const required = new Set(frontmatter.hostRequirements);
    if (!sameMembers(declared, required)) {
      findings.push({
        bundleId: manifest.id, path: 'SKILL.md', code: 'host-requirement-mismatch',
        detail: `SKILL.md hostRequirements (${[...required].sort().join(', ') || 'none'}) do not match dependencies.json HOST_CAPABILITY entries (${[...declared].sort().join(', ') || 'none'})`,
      });
    }
    for (const finding of scanHostCommandReferences(readFileSync(skillPath, 'utf8'), {
      path: 'SKILL.md', commandCapabilities, hostRequirements: required,
    })) findings.push({ bundleId: manifest.id, ...finding });
  } catch (error) {
    findings.push({ bundleId: manifest.id, path: 'SKILL.md', code: 'invalid-skill-frontmatter', detail: error.message });
  }
  return {
    findings,
    declarationCount: 1,
    typedResourceCount: declaration.document.resources.length,
  };
}

// Validate that every capability alias points at a skill this package actually ships.
export function verifyCapabilityAliases(packageRoot) {
  const findings = [];
  const path = resolve(packageRoot, 'src/config/capability-aliases.json');
  if (!existsSync(path)) return findings;
  for (const [alias, target] of Object.entries(JSON.parse(readFileSync(path, 'utf8')).aliases ?? {})) {
    if (!target.startsWith('/')) continue;
    const skill = target.slice(1).split(/\s+/, 1)[0];
    if (!existsSync(resolve(packageRoot, 'skills', skill, 'SKILL.md'))) {
      findings.push({
        code: 'dangling-alias', bundleId: null, path: 'src/config/capability-aliases.json',
        detail: `alias ${alias} routes to a skill this package does not ship: ${target}`,
      });
    }
  }
  return findings;
}

// Validate that every manifest's declared consumers actually exist.
export function verifyManifestConsumers(packageRoot, manifests) {
  const findings = [];
  for (const manifest of Object.values(manifests)) {
    for (const consumer of manifest.parity?.consumers ?? []) {
      if (!existsSync(resolve(packageRoot, consumer))) {
        findings.push({
          code: 'stale-consumer', bundleId: manifest.id, path: consumer,
          detail: `manifest declares a consumer that no longer exists: ${consumer}`,
        });
      }
    }
  }
  return findings;
}

/** Every semantic SKILL.md participates in closure; no unmanifested bundle may bypass it. */
function semanticBundleIds(packageRoot) {
  const skillsRoot = resolve(packageRoot, 'skills');
  if (!existsSync(skillsRoot)) return [];
  return readdirSync(skillsRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && existsSync(join(skillsRoot, entry.name, 'SKILL.md')))
    .map((entry) => entry.name)
    .sort();
}

export function verifyManifestCoverage(packageRoot, manifests) {
  const findings = [];
  const skillsRoot = resolve(packageRoot, 'skills');
  const declared = new Set(Object.keys(manifests));
  for (const id of semanticBundleIds(packageRoot)) {
    if (!declared.has(id)) {
      findings.push({
        code: 'missing-skill-manifest', bundleId: id, path: `skills/${id}/SKILL.md`,
        detail: 'semantic bundle has no manifest and cannot enter dependency closure',
      });
    }
  }
  for (const manifest of Object.values(manifests)) {
    if (!existsSync(join(skillsRoot, manifest.id, 'SKILL.md'))) {
      findings.push({
        code: 'missing-skill-entry', bundleId: manifest.id, path: `skills/${manifest.id}/SKILL.md`,
        detail: 'manifest declares a semantic bundle whose SKILL.md is absent',
      });
    }
  }
  return findings;
}

function verifyRouteResources(text, { packageRoot, skillRoot, capabilities, manifest }) {
  const findings = [];
  let document;
  try { document = JSON.parse(text); } catch {
    return [{ bundleId: manifest.id, path: 'references/route-resources.json', code: 'invalid-resource-document', detail: 'route resource table is not valid JSON' }];
  }
  for (const [section, table] of Object.entries(document)) {
    if (!table || typeof table !== 'object' || Array.isArray(table)) continue;
    for (const [key, entries] of Object.entries(table)) {
      if (!Array.isArray(entries)) continue;
      for (const entry of entries) {
        const result = classifyResource(entry, { packageRoot, skillRoot, capabilities });
        if (!result.ok) {
          findings.push({ bundleId: manifest.id, path: `references/route-resources.json#${section}.${key}`, code: result.code, detail: result.detail });
        }
      }
    }
  }
  return findings;
}

export function verifyDependencyClosure({ packageRoot, manifests }) {
  const registry = loadRegistry(packageRoot);
  const capabilities = registry.capabilities ?? {};
  const commandCapabilities = commandCapabilityMap(registry);
  const findings = [
    ...verifyManifestConsumers(packageRoot, manifests),
    ...verifyManifestCoverage(packageRoot, manifests),
    ...verifyCapabilityAliases(packageRoot),
  ];
  let declarationCount = 0;
  let typedResourceCount = 0;

  for (const manifest of Object.values(manifests)) {
    const skillRoot = resolve(packageRoot, 'skills', manifest.id);
    if (!existsSync(skillRoot)) continue;
    const declaration = verifyBundleDependencies({ packageRoot, manifest, capabilities, commandCapabilities });
    findings.push(...declaration.findings);
    declarationCount += declaration.declarationCount;
    typedResourceCount += declaration.typedResourceCount;
    for (const file of allFiles(skillRoot)) {
      const relativePath = relative(skillRoot, file).replaceAll('\\', '/');
      if (!/\.(?:md|mdx|txt|json|ya?ml|mjs|js|py|sh|ps1|vbs)$/i.test(relativePath)) continue;
      const text = readFileSync(file, 'utf8');
      for (const finding of scanPackagedText(text, { path: relativePath, skillRoot, packageRoot })) {
        findings.push({ bundleId: manifest.id, ...finding });
      }
      if (relativePath.endsWith('route-resources.json')) {
        findings.push(...verifyRouteResources(text, { packageRoot, skillRoot, capabilities, manifest }));
      }
    }
  }
  return {
    ok: findings.length === 0,
    findings,
    summary: {
      semanticBundles: semanticBundleIds(packageRoot).length,
      dependencyDeclarations: declarationCount,
      typedResources: typedResourceCount,
    },
  };
}

function allFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? allFiles(path) : (statSync(path).isFile() ? [path] : []);
  });
}
