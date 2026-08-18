// Automation, package, update, and release extractor — B7-006.
//
// Reads only `projection.sourceText` for paths already present in the frozen
// denominator file list. Never touches the filesystem, network, or a child
// process, and never executes or renders any configuration it reads. Builds
// the release trust path — privileged trigger -> build/release step (sink)
// -> build/release identity -> published artifact — for CI/CD pipeline
// configuration, package manifests, release-tool configuration, dependency
// update automation, and application auto-updater configuration. Records
// caches, secret references, dependency install surfaces, code-signing
// posture, and publication targets along that path. Unparseable automation
// formats and release paths whose identity, permission scope, or
// publication target cannot be resolved from local text are recorded as
// typed coverage gaps, never silently dropped or defaulted.
//
// Only recognises standard config file locations and generic automation
// keys (triggers, permissions, secrets, publish/registry keywords) — no
// repository-host-specific product logic.

import { entity, fact, relation } from './common.mjs';
import {
  assertControlState,
  assertEntityKind,
  assertFactKind,
  assertRelationKind,
  stableId,
} from '../contracts.mjs';

// ---------------------------------------------------------------------------
// File classification. Generic locations only — no host-branded adapters.
// ---------------------------------------------------------------------------

const WORKFLOW_FILE = /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$|(^|\/)\.gitlab-ci\.ya?ml$|(^|\/)azure-pipelines\.ya?ml$|(^|\/)\.circleci\/config\.ya?ml$|(^|\/)bitbucket-pipelines\.ya?ml$/i;
const JENKINSFILE = /(^|\/)Jenkinsfile$/;
const PACKAGE_MANIFEST = /(^|\/)package\.json$/;
const RELEASE_CONFIG = /(^|\/)\.releaserc(\.[a-zA-Z0-9]+)?$|(^|\/)release\.config\.[cm]?js$|(^|\/)\.goreleaser\.ya?ml$/i;
const DEPENDENCY_UPDATE_CONFIG = /(^|\/)renovate\.json5?$|(^|\/)\.github\/renovate\.json5?$|(^|\/)\.github\/dependabot\.ya?ml$|(^|\/)\.dependabot\/config\.ya?ml$/i;
const UPDATER_CONFIG = /electron-builder\.(ya?ml|json5?|toml)$|(^|\/)app-update\.ya?ml$/i;
const NPM_CONFIG = /(^|\/)\.npmrc$/;
const LOCKFILE = /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$/;
const DOCKERFILE = /(^|\/)Dockerfile(\.[A-Za-z0-9._-]+)?$/;

// ---------------------------------------------------------------------------
// Typed constructors — every kind is asserted against the canonical
// contracts vocabulary before an entity/relation/fact is built.
// ---------------------------------------------------------------------------

function typedEntity(kind, name, attributes, evidenceRefs, options) {
  assertEntityKind(kind);
  return entity(kind, name, attributes, evidenceRefs, options);
}

function typedRelation(kind, from, to, evidenceRefs, attributes, options) {
  assertRelationKind(kind);
  return relation(kind, from, to, evidenceRefs, attributes, options);
}

function typedFact(kind, fields, evidenceRefs) {
  assertFactKind(kind);
  return fact(kind, fields, evidenceRefs);
}

// ---------------------------------------------------------------------------
// Extraction context: dedupes by content-derived id and finalizes sorted,
// deterministic arrays.
// ---------------------------------------------------------------------------

function makeContext() {
  return {
    entitiesById: new Map(),
    relationsById: new Map(),
    evidenceById: new Map(),
    factsById: new Map(),
    coverageGaps: [],
    addEntity(item) {
      this.entitiesById.set(item.id, item);
      return item;
    },
    addRelation(item) {
      this.relationsById.set(item.id, item);
      return item;
    },
    addFact(item) {
      this.factsById.set(item.id, item);
      return item;
    },
    addEvidence(file, description) {
      const id = stableId('automation-evidence', { file, description });
      if (!this.evidenceById.has(id)) {
        this.evidenceById.set(id, { id, kind: 'source-location', file, description });
      }
      return id;
    },
    addGap(gap) {
      this.coverageGaps.push(gap);
    },
    finalize() {
      const byId = (a, b) => a.id.localeCompare(b.id);
      return {
        entities: [...this.entitiesById.values()].sort(byId),
        relations: [...this.relationsById.values()].sort(byId),
        evidence: [...this.evidenceById.values()].sort(byId),
        initialFacts: [...this.factsById.values()].sort(byId),
        coverageGaps: this.coverageGaps,
      };
    },
  };
}

// ---------------------------------------------------------------------------
// Text-pattern detectors. Deliberately regex/text based — this repository
// has no YAML/TOML parser dependency and none is added here.
// ---------------------------------------------------------------------------

function looksLikeHostileTrigger(text) {
  return /\bpull_request_target\b/.test(text)
    || /\bworkflow_run\b/.test(text)
    || /\bissue_comment\b/.test(text);
}

function looksLikeReleaseTrigger(text) {
  return /\bpush\s*:\s*[\s\S]{0,80}\btags\s*:/.test(text)
    || /\brelease\s*:\s*[\s\S]{0,80}\btypes\s*:/.test(text)
    || /\bworkflow_dispatch\b/.test(text);
}

function looksLikeReleaseStep(text) {
  return /\bnpm publish\b/.test(text)
    || /\bdocker push\b/.test(text)
    || /docker\/build-push-action/.test(text)
    || /\bgoreleaser\b/.test(text)
    || /\bsemantic-release\b/.test(text)
    || /electron-builder\s+--publish/.test(text)
    || /\bgh release create\b/.test(text)
    || /actions\/create-release/.test(text)
    || /upload-artifact/.test(text);
}

function looksLikeSigning(text) {
  return /\bcodesign\b/i.test(text)
    || /\bnotarize\b/i.test(text)
    || /\bCSC_LINK\b/.test(text)
    || /\bWIN_CSC_LINK\b/.test(text)
    || /\bAPPLE_ID\b/.test(text)
    || /\bcosign\b/.test(text)
    || /\bsigstore\b/.test(text)
    || /gpg\s+--sign/.test(text)
    || /--provenance\b/.test(text)
    || /npm_config_provenance/.test(text);
}

function explicitlyDisabledSigning(text) {
  return /\bsign\s*:\s*false\b/.test(text)
    || /\bskipSign\s*:\s*true\b/.test(text)
    || /verifyUpdateCodeSignature\s*:\s*false/.test(text);
}

// Returns `null` when no `permissions:` key is present anywhere (scope truly
// unresolvable from this file), `[]` when the block resolves to an explicit
// deny, or a list of `{ scope, level }` pairs otherwise. Never guesses a
// default.
function detectPermissionScopes(text) {
  const index = text.search(/\bpermissions\s*:/);
  if (index === -1) return null;
  const window = text.slice(index, index + 400);
  if (/write-all/.test(window)) return [{ scope: 'all', level: 'write' }];
  if (/read-all/.test(window)) return [{ scope: 'all', level: 'read' }];
  const scopes = [];
  const scopeRe = /\b([a-z][a-z0-9-]*)\s*:\s*(write|read|none)\b/gi;
  let match = scopeRe.exec(window);
  while (match) {
    if (match[1].toLowerCase() !== 'permissions') {
      scopes.push({ scope: match[1].toLowerCase(), level: match[2].toLowerCase() });
    }
    match = scopeRe.exec(window);
  }
  return scopes;
}

function permissionScopeLabel(scopes) {
  if (scopes === null) return 'unknown';
  if (scopes.length === 0) return 'none';
  return [...new Set(scopes.map((s) => `${s.scope}:${s.level}`))].sort().join(',');
}

// Generic secret-reference conventions (templated `secrets.NAME`, upper-case
// TOKEN/SECRET/KEY-shaped env var names, Jenkins-style `credentials(id)`) —
// no host-specific secret store integration.
function detectSecretRefs(text) {
  const names = new Set();
  const secretsRe = /\bsecrets\.([A-Za-z0-9_]+)/g;
  let match = secretsRe.exec(text);
  while (match) {
    names.add(match[1]);
    match = secretsRe.exec(text);
  }
  const envRe = /\$\{?([A-Z][A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD|CREDENTIALS))\}?/g;
  match = envRe.exec(text);
  while (match) {
    names.add(match[1]);
    match = envRe.exec(text);
  }
  const credRe = /credentials\(\s*['"]([^'"]+)['"]\s*\)/g;
  match = credRe.exec(text);
  while (match) {
    names.add(match[1]);
    match = credRe.exec(text);
  }
  return [...names].sort();
}

function detectPublicationTarget(text) {
  if (/registry\.npmjs\.org/.test(text)) return 'npm-registry';
  if (/ghcr\.io/.test(text)) return 'container-registry';
  if (/\bdocker\.io\b|hub\.docker\.com/.test(text)) return 'container-registry';
  const npmrcMatch = text.match(/^\s*registry\s*=\s*(\S+)/m);
  if (npmrcMatch) return npmrcMatch[1];
  const providerMatch = text.match(/\bprovider\s*:\s*["']?([a-zA-Z0-9_-]+)["']?/);
  if (providerMatch) return `updater:${providerMatch[1]}`;
  if (/\bnpm publish\b/.test(text)) return 'npm-registry';
  if (/\bdocker push\b|docker\/build-push-action/.test(text)) return 'container-registry';
  return null;
}

// ---------------------------------------------------------------------------
// Release trust-path chain: trigger --executes--> sink --runs-as--> identity
// --publishes-to--> published artifact, with a principal assuming the
// identity and a granted publish capability. Unresolved identity, scope, or
// target are recorded as typed coverage gaps rather than defaulted.
// ---------------------------------------------------------------------------

function buildReleaseChain(ctx, {
  file, evidenceRef, sink, triggerLabel, triggerType, scopes, credentialRefs, publicationTarget, artifactLabel,
}) {
  const trigger = ctx.addEntity(typedEntity('entrypoint', triggerLabel, {
    entrypointType: triggerType, environment: 'ci',
  }, [evidenceRef]));
  const principal = ctx.addEntity(typedEntity('principal', `automation service principal ${file}`, {
    environment: 'ci',
  }, [evidenceRef]));
  const permissionScope = permissionScopeLabel(scopes);
  const sortedCredentials = [...new Set(credentialRefs ?? [])].sort();
  const identity = ctx.addEntity(typedEntity('identity', `release identity ${file}`, {
    environment: 'ci',
    permissionScope,
    credentialRefs: sortedCredentials,
  }, [evidenceRef]));
  const capability = ctx.addEntity(typedEntity('tool-capability', `publish capability ${file}`, {
    capabilityKind: 'package-publish',
  }, [evidenceRef]));
  const artifact = ctx.addEntity(typedEntity('asset', artifactLabel, {
    assetKind: 'published-artifact',
    publicationTarget: publicationTarget ?? 'unknown',
  }, [evidenceRef]));

  ctx.addRelation(typedRelation('executes', trigger.id, sink.id, [evidenceRef]));
  ctx.addRelation(typedRelation('assumes-role', principal.id, identity.id, [evidenceRef]));
  ctx.addRelation(typedRelation('runs-as', sink.id, identity.id, [evidenceRef]));
  ctx.addRelation(typedRelation('grants', identity.id, capability.id, [evidenceRef]));
  ctx.addRelation(typedRelation('publishes-to', identity.id, artifact.id, [evidenceRef]));

  if (permissionScope === 'unknown') ctx.addGap({ kind: 'unresolved-permission-scope', file });
  if (sortedCredentials.length === 0) ctx.addGap({ kind: 'unresolved-identity', file, entityId: identity.id });
  if (!publicationTarget) ctx.addGap({ kind: 'unresolved-publication-target', file });

  return {
    trigger, principal, identity, capability, artifact,
  };
}

// ---------------------------------------------------------------------------
// Per-category scanners.
// ---------------------------------------------------------------------------

function scanPipelineConfig(ctx, file, text) {
  const ev = ctx.addEvidence(file, 'Automation pipeline configuration');
  const step = ctx.addEntity(typedEntity('sink', `pipeline step ${file}`, { sinkKind: 'automation-step' }, [ev]));

  if (looksLikeHostileTrigger(text)) {
    const hostileTrigger = ctx.addEntity(typedEntity('entrypoint', `untrusted-content trigger ${file}`, {
      entrypointType: 'hostile-trigger', environment: 'ci',
    }, [ev]));
    const boundary = ctx.addEntity(typedEntity('trust-boundary', `fork/external-content boundary ${file}`, {
      boundaryType: 'untrusted-contribution',
    }, [ev]));
    ctx.addRelation(typedRelation('executes', hostileTrigger.id, step.id, [ev]));
    ctx.addRelation(typedRelation('crosses', hostileTrigger.id, boundary.id, [ev]));
    ctx.addFact(typedFact('attacker-position', {
      subject: 'actor:external-contributor',
      action: 'control-repository-content',
      object: file,
      environment: 'ci',
    }, [ev]));
  }

  if (looksLikeReleaseTrigger(text) && looksLikeReleaseStep(text)) {
    buildReleaseChain(ctx, {
      file,
      evidenceRef: ev,
      sink: step,
      triggerLabel: `release trigger ${file}`,
      triggerType: 'release-trigger',
      scopes: detectPermissionScopes(text),
      credentialRefs: detectSecretRefs(text),
      publicationTarget: detectPublicationTarget(text),
      artifactLabel: `published artifact ${file}`,
    });
  }

  if (/actions\/cache\b/.test(text) || /\bcache-dependency-path\b/.test(text) || /^\s*cache:\s*$/m.test(text)) {
    const cache = ctx.addEntity(typedEntity('data-store', `build cache ${file}`, { dataStoreKind: 'build-cache' }, [ev]));
    ctx.addRelation(typedRelation('stores', step.id, cache.id, [ev]));
  }

  for (const name of detectSecretRefs(text)) {
    ctx.addFact(typedFact('credential-possession', {
      subject: step.id, action: 'reference-secret', object: name, environment: 'ci',
    }, [ev]));
  }

  if (looksLikeSigning(text)) {
    const controlState = assertControlState(explicitlyDisabledSigning(text) ? 'absent' : 'present-unenforced');
    const signing = ctx.addEntity(typedEntity('control', `release signing ${file}`, {
      controlType: 'signing', controlState,
    }, [ev]));
    ctx.addRelation(typedRelation('protects', signing.id, step.id, [ev]));
  }

  if (/upload-artifact|download-artifact/.test(text)) {
    const buildOutput = ctx.addEntity(typedEntity('asset', `build output ${file}`, { assetKind: 'build-artifact' }, [ev]));
    ctx.addRelation(typedRelation('flows-to', buildOutput.id, step.id, [ev]));
  }
}

function scanJenkinsfile(ctx, file, text) {
  const ev = ctx.addEvidence(file, 'Jenkins pipeline (unparsed DSL)');
  ctx.addEntity(typedEntity('repository-artifact', `Jenkins pipeline ${file}`, { automationFormat: 'jenkinsfile' }, [ev]));
  for (const name of detectSecretRefs(text)) {
    ctx.addFact(typedFact('credential-possession', {
      subject: 'identity:jenkins-pipeline', action: 'reference-credential', object: name, environment: 'ci',
    }, [ev]));
  }
  // Groovy DSL is not structurally parsed by this extractor.
  ctx.addGap({ kind: 'unparsed-automation-format', file, format: 'jenkinsfile' });
}

function scanPackageManifest(ctx, file, text, files) {
  const ev = ctx.addEvidence(file, 'Package manifest');
  let pkg;
  try {
    pkg = JSON.parse(text);
  } catch {
    ctx.addGap({ kind: 'unparsed-automation-format', file, format: 'package.json' });
    return;
  }
  if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) {
    ctx.addGap({ kind: 'unparsed-automation-format', file, format: 'package.json' });
    return;
  }

  const manifestEntity = ctx.addEntity(typedEntity('repository-artifact', `package manifest ${file}`, {
    manifest: true,
    name: typeof pkg.name === 'string' ? pkg.name : 'unknown',
    private: pkg.private === true,
  }, [ev]));

  const scripts = pkg.scripts && typeof pkg.scripts === 'object' ? pkg.scripts : {};
  for (const key of ['preinstall', 'install', 'postinstall']) {
    const script = scripts[key];
    if (typeof script === 'string' && /\b(curl|wget)\b[\s\S]*\|\s*(sh|bash)\b/.test(script)) {
      const source = ctx.addEntity(typedEntity('source', `remote installer script ${file}#${key}`, {
        sourceKind: 'network-fetch',
      }, [ev]));
      const sink = ctx.addEntity(typedEntity('sink', `installer shell exec ${file}#${key}`, { sinkKind: 'shell' }, [ev]));
      ctx.addRelation(typedRelation('flows-to', source.id, sink.id, [ev]));
      ctx.addFact(typedFact('capability', {
        subject: sink.id, action: 'execute-remote-script', object: file, environment: 'install',
      }, [ev]));
    }
  }

  const publishScript = typeof scripts.publish === 'string' ? scripts.publish
    : (typeof scripts.release === 'string' ? scripts.release : null);
  if (publishScript || (pkg.publishConfig && typeof pkg.publishConfig === 'object')) {
    const publicationTarget = (pkg.publishConfig && typeof pkg.publishConfig.registry === 'string')
      ? pkg.publishConfig.registry
      : detectPublicationTarget(text);
    const step = ctx.addEntity(typedEntity('sink', `manual publish script ${file}`, { sinkKind: 'automation-step' }, [ev]));
    buildReleaseChain(ctx, {
      file,
      evidenceRef: ev,
      sink: step,
      triggerLabel: `manual publish invocation ${file}`,
      triggerType: 'manual-trigger',
      // A manifest alone never carries permission scope or literal
      // credentials — those live in the pipeline that invokes it.
      scopes: null,
      credentialRefs: [],
      publicationTarget,
      artifactLabel: `published package ${typeof pkg.name === 'string' ? pkg.name : file}`,
    });
  }

  for (const depField of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    const deps = pkg[depField];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, spec] of Object.entries(deps)) {
      if (typeof spec === 'string' && /^(git\+|https?:|github:)/.test(spec)) {
        const source = ctx.addEntity(typedEntity('source', `non-registry dependency ${name}`, {
          sourceKind: 'direct-url-dependency', spec,
        }, [ev]));
        ctx.addRelation(typedRelation('flows-to', source.id, manifestEntity.id, [ev]));
      }
    }
  }

  if (!files.some((f) => LOCKFILE.test(f))) {
    ctx.addGap({ kind: 'missing-dependency-lockfile', file });
  }
}

function scanReleaseConfig(ctx, file, text) {
  const ev = ctx.addEvidence(file, 'Release-tool configuration');
  const publicationTarget = detectPublicationTarget(text);
  const step = ctx.addEntity(typedEntity('sink', `release-config publish step ${file}`, { sinkKind: 'automation-step' }, [ev]));
  buildReleaseChain(ctx, {
    file,
    evidenceRef: ev,
    sink: step,
    triggerLabel: `release-config invocation ${file}`,
    triggerType: 'release-config-trigger',
    scopes: null,
    credentialRefs: detectSecretRefs(text),
    publicationTarget,
    artifactLabel: `published release artifact ${file}`,
  });
  if (!publicationTarget) {
    // The actual publish target/credentials are configured in a service
    // outside this repository (CI secret store, registry account, etc.).
    ctx.addGap({ kind: 'externally-configured-release-service', file });
  }
}

function scanDependencyUpdateConfig(ctx, file, text) {
  const ev = ctx.addEvidence(file, 'Dependency update automation configuration');
  const trigger = ctx.addEntity(typedEntity('entrypoint', `scheduled dependency update ${file}`, {
    entrypointType: 'scheduled-update', environment: 'ci',
  }, [ev]));
  const sink = ctx.addEntity(typedEntity('sink', `dependency update PR ${file}`, { sinkKind: 'dependency-update' }, [ev]));
  const principal = ctx.addEntity(typedEntity('principal', `dependency update bot principal ${file}`, {
    environment: 'ci',
  }, [ev]));
  const identity = ctx.addEntity(typedEntity('identity', `dependency update bot identity ${file}`, {
    environment: 'ci', permissionScope: 'unknown',
  }, [ev]));
  ctx.addRelation(typedRelation('executes', trigger.id, sink.id, [ev]));
  ctx.addRelation(typedRelation('assumes-role', principal.id, identity.id, [ev]));
  ctx.addRelation(typedRelation('runs-as', sink.id, identity.id, [ev]));
  // The bot's effective repository permission is granted by CI/host
  // configuration outside this file and cannot be resolved from it alone.
  ctx.addGap({ kind: 'unresolved-permission-scope', file });

  if (/"automerge"\s*:\s*true/.test(text) || /\bautomerge\s*:\s*true\b/.test(text)) {
    ctx.addFact(typedFact('capability', {
      subject: identity.id, action: 'auto-merge-dependency-update', object: 'repository', environment: 'ci',
    }, [ev]));
  }
}

function scanUpdaterConfig(ctx, file, text) {
  const ev = ctx.addEvidence(file, 'Application auto-update configuration');
  const publicationTarget = detectPublicationTarget(text);
  const updateServer = ctx.addEntity(typedEntity('service', `update server ${file}`, {
    serviceKind: 'auto-update-endpoint', endpoint: publicationTarget ?? 'unknown',
  }, [ev]));
  const capability = ctx.addEntity(typedEntity('tool-capability', `apply downloaded update ${file}`, {
    capabilityKind: 'auto-update-execute',
  }, [ev]));
  const identity = ctx.addEntity(typedEntity('identity', `installed application identity ${file}`, {
    environment: 'end-user-device',
  }, [ev]));
  ctx.addRelation(typedRelation('grants', identity.id, capability.id, [ev]));
  ctx.addRelation(typedRelation('retrieves-from', capability.id, updateServer.id, [ev]));

  let signatureState = 'unknown';
  if (/verifyUpdateCodeSignature\s*:\s*false/.test(text)) signatureState = 'absent';
  else if (/verifyUpdateCodeSignature\s*:\s*true/.test(text)) signatureState = 'enforced';
  else if (looksLikeSigning(text)) signatureState = 'present-unenforced';

  const signing = ctx.addEntity(typedEntity('control', `update signature verification ${file}`, {
    controlType: 'signing', controlState: assertControlState(signatureState),
  }, [ev]));
  ctx.addRelation(typedRelation('protects', signing.id, capability.id, [ev]));

  if (signatureState === 'unknown') {
    ctx.addGap({ kind: 'unresolved-updater-signature-state', file });
  }
  if (!publicationTarget) {
    ctx.addGap({ kind: 'unresolved-publication-target', file });
  }
}

function scanNpmrc(ctx, file, text) {
  const ev = ctx.addEvidence(file, 'npm registry configuration');
  const registryMatch = text.match(/^\s*registry\s*=\s*(\S+)/m);
  const hasAuthToken = /_authToken\s*=/.test(text);
  const scope = ctx.addEntity(typedEntity('permission-scope', `npm registry auth scope ${file}`, {
    registry: registryMatch ? registryMatch[1] : 'unknown',
    hasAuthToken,
  }, [ev]));
  if (hasAuthToken) {
    ctx.addFact(typedFact('credential-possession', {
      subject: scope.id, action: 'possess-registry-auth-token', object: file, environment: 'ci',
    }, [ev]));
  }
  if (!registryMatch) {
    ctx.addGap({ kind: 'unresolved-publication-target', file });
  }
}

function scanLockfile(ctx, file) {
  const ev = ctx.addEvidence(file, 'Dependency lockfile');
  const lock = ctx.addEntity(typedEntity('repository-artifact', `dependency lockfile ${file}`, { lockfile: true }, [ev]));
  ctx.addFact(typedFact('capability', {
    subject: lock.id, action: 'pin-dependency-resolution', object: file, environment: 'build',
  }, [ev]));
}

function scanDockerfile(ctx, file, text) {
  const ev = ctx.addEvidence(file, 'Container build configuration');
  if (/\b(curl|wget)\b[^\n]*\|\s*(sh|bash)\b/.test(text)) {
    const source = ctx.addEntity(typedEntity('source', `remote installer script ${file}`, {
      sourceKind: 'network-fetch',
    }, [ev]));
    const sink = ctx.addEntity(typedEntity('sink', `container build shell exec ${file}`, { sinkKind: 'shell' }, [ev]));
    ctx.addRelation(typedRelation('flows-to', source.id, sink.id, [ev]));
    ctx.addFact(typedFact('capability', {
      subject: sink.id, action: 'execute-remote-script', object: file, environment: 'build',
    }, [ev]));
  }
  const publicationTarget = detectPublicationTarget(text);
  if (/\bFROM\b/.test(text) && publicationTarget) {
    const image = ctx.addEntity(typedEntity('asset', `container image ${file}`, {
      assetKind: 'container-image', publicationTarget,
    }, [ev]));
    const registry = ctx.addEntity(typedEntity('service', `container registry ${publicationTarget}`, {
      serviceKind: 'container-registry',
    }, [ev]));
    ctx.addRelation(typedRelation('publishes-to', image.id, registry.id, [ev]));
  }
}

// ---------------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------------

export function extractAutomation({ root, plan, projection, files, lensRegistry }) {
  const ctx = makeContext();
  const fileList = files ?? [];

  for (const file of fileList) {
    const text = projection?.sourceText?.[file] ?? '';
    if (!text) continue;

    if (WORKFLOW_FILE.test(file)) {
      scanPipelineConfig(ctx, file, text);
    } else if (JENKINSFILE.test(file)) {
      scanJenkinsfile(ctx, file, text);
    } else if (PACKAGE_MANIFEST.test(file)) {
      scanPackageManifest(ctx, file, text, fileList);
    } else if (RELEASE_CONFIG.test(file)) {
      scanReleaseConfig(ctx, file, text);
    } else if (DEPENDENCY_UPDATE_CONFIG.test(file)) {
      scanDependencyUpdateConfig(ctx, file, text);
    } else if (UPDATER_CONFIG.test(file)) {
      scanUpdaterConfig(ctx, file, text);
    } else if (NPM_CONFIG.test(file)) {
      scanNpmrc(ctx, file, text);
    } else if (LOCKFILE.test(file)) {
      scanLockfile(ctx, file);
    } else if (DOCKERFILE.test(file)) {
      scanDockerfile(ctx, file, text);
    }
  }

  return ctx.finalize();
}
