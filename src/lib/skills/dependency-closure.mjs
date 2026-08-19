// Dependency-closure validation.
//
// The package boundary is not a style rule: every reference a packaged skill makes must resolve
// into exactly one declared class. Prose alone cannot enforce that, so this module classifies
// references mechanically and rejects anything that resolves nowhere.
//
//   PACKAGE_INTERNAL   — ships here; must exist on disk.
//   HOST_CAPABILITY    — provided by the embedding host; must be declared in the capability registry.
//   PROJECT_OVERLAY    — supplied by the consuming project; must be optional and marked as such.
//   HISTORICAL_EVIDENCE— a record of a past run; never resolved as a live path.
//
// Anything else is a leak: a private path, a dangling script, or a silent assumption about the
// author's own machine.

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve, relative, dirname } from 'node:path';

export const DEPENDENCY_CLASSES = Object.freeze([
  'PACKAGE_INTERNAL', 'HOST_CAPABILITY', 'PROJECT_OVERLAY', 'HISTORICAL_EVIDENCE',
]);

// Placeholder roots that stand in for something the consuming project supplies. These are the only
// unresolvable path prefixes a packaged document may contain.
const OVERLAY_PREFIX = /^(?:<project-overlay>|<workspace>|<studio-workspace-root>|<CURRENT_WORKSPACE>|<package-root>|<audit-skill-dir>|<[a-z][a-z0-9-]*>)/i;

// An unresolved marker is a promise the package never kept.
const UNRESOLVED_MARKER = /\b(?:TODO|FIXME|XXX)\b\s*:?\s*(?:no in-package|not available|missing|unresolved)/i;

const SCRIPT_REFERENCE = /`(?:scripts\/|\.{1,2}\/)[A-Za-z0-9._\-/]+\.(?:mjs|js|py|sh|ps1|vbs)`/g;


// `xxx` and `foo` are prose placeholders standing for "any script", not real references.
const PLACEHOLDER = /(?:^|\/)(?:xxx|yyy|foo|bar|example|placeholder)\.[a-z0-9]+$/i;
const DOCUMENT = /\.(?:md|mdx|txt)$/i;

export function loadCapabilityRegistry(packageRoot) {
  const path = resolve(packageRoot, 'src/registry/capabilities.json');
  if (!existsSync(path)) throw new Error(`capability registry is absent: ${path}`);
  const registry = JSON.parse(readFileSync(path, 'utf8'));
  if (registry.schemaVersion !== 1 || registry.kind !== 'legion-capability-registry') {
    throw new Error('capability registry is malformed');
  }
  for (const [name, entry] of Object.entries(registry.capabilities ?? {})) {
    if (!entry.degradation) throw new Error(`capability ${name} declares no degradation behaviour`);
  }
  return registry;
}

// Classify one typed resource entry from a route-resources table.
export function classifyResource(entry, { packageRoot, skillRoot, capabilities }) {
  if (typeof entry === 'string') {
    return { ok: false, code: 'untyped-resource', detail: `resource is a bare string, not a typed entry: ${entry}` };
  }
  const { class: klass } = entry;
  if (!DEPENDENCY_CLASSES.includes(klass)) {
    return { ok: false, code: 'unknown-class', detail: `resource declares no known dependency class: ${JSON.stringify(entry)}` };
  }
  if (klass === 'PACKAGE_INTERNAL') {
    if (!entry.path) return { ok: false, code: 'invalid-resource', detail: 'PACKAGE_INTERNAL declares no path' };
    const target = resolve(skillRoot, entry.path);
    if (!target.startsWith(`${resolve(packageRoot)}/`)) {
      return { ok: false, code: 'escapes-package', detail: `PACKAGE_INTERNAL escapes the package: ${entry.path}` };
    }
    if (!existsSync(target)) {
      return { ok: false, code: 'missing-internal', detail: `PACKAGE_INTERNAL does not exist: ${entry.path}` };
    }
    return { ok: true };
  }
  if (klass === 'HOST_CAPABILITY') {
    if (!entry.capability) return { ok: false, code: 'invalid-resource', detail: 'HOST_CAPABILITY names no capability' };
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
    if (entry.path && !OVERLAY_PREFIX.test(entry.path)) {
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
      // A relative script reference is read the way a reader would read it: against the document's
      // own directory, then each ancestor up to the bundle root, then the package root. Bundles
      // nest an engine root between the two, and a `scripts/x` reference from a sibling
      // `references/` directory means that engine root.
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

// Validate that every capability alias points at a skill this package actually ships. An alias to
// a removed skill is a routing dead end that no digest check would ever notice.
export function verifyCapabilityAliases(packageRoot) {
  const findings = [];
  const path = resolve(packageRoot, 'src/config/capability-aliases.json');
  if (!existsSync(path)) return findings;
  for (const [alias, target] of Object.entries(JSON.parse(readFileSync(path, 'utf8')).aliases ?? {})) {
    if (!target.startsWith('/')) continue; // hook: and tool: targets are host-resolved.
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

export function verifyDependencyClosure({ packageRoot, manifests }) {
  const registry = loadCapabilityRegistry(packageRoot);
  const capabilities = registry.capabilities ?? {};
  const findings = [...verifyManifestConsumers(packageRoot, manifests), ...verifyCapabilityAliases(packageRoot)];

  for (const manifest of Object.values(manifests)) {
    const skillRoot = resolve(packageRoot, 'skills', manifest.id);
    if (!existsSync(skillRoot)) continue;
    for (const file of allFiles(skillRoot)) {
      const relativePath = relative(skillRoot, file).replaceAll('\\', '/');
      if (!/\.(?:md|mdx|txt|json|ya?ml|mjs|js|py|sh|ps1|vbs)$/i.test(relativePath)) continue;
      const text = readFileSync(file, 'utf8');
      for (const finding of scanPackagedText(text, { path: relativePath, skillRoot, packageRoot })) {
        findings.push({ bundleId: manifest.id, ...finding });
      }
      if (relativePath.endsWith('route-resources.json')) {
        for (const [section, table] of Object.entries(JSON.parse(text))) {
          if (!table || typeof table !== 'object' || Array.isArray(table)) continue;
          for (const [key, entries] of Object.entries(table)) {
            if (!Array.isArray(entries)) continue;
            for (const entry of entries) {
              const result = classifyResource(entry, { packageRoot, skillRoot, capabilities });
              if (!result.ok) {
                findings.push({ bundleId: manifest.id, path: `${relativePath}#${section}.${key}`, code: result.code, detail: result.detail });
              }
            }
          }
        }
      }
    }
  }
  return { ok: findings.length === 0, findings };
}

function allFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? allFiles(path) : (statSync(path).isFile() ? [path] : []);
  });
}
