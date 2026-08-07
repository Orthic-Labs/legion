import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

function sha256Bytes(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function normalizePath(value) {
  return String(value ?? '').replaceAll('\\', '/').replace(/^\.\//, '').replace(/\/+$/, '');
}

function parseJson(text, label) {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`${label} did not emit valid JSON: ${error.message}`);
  }
}

function graphGenerationId(payload) {
  return payload?.generationId
    ?? payload?.manifest?.generationId
    ?? payload?.generation?.id
    ?? null;
}

function graphManifestDigest(payload) {
  return payload?.manifestDigest
    ?? payload?.manifest?.manifestDigest
    ?? payload?.generation?.manifestDigest
    ?? null;
}

function cortexCandidates(root) {
  const candidates = [];
  if (process.env.CORTEX_BIN) candidates.push({ command: process.env.CORTEX_BIN, prefix: [] });
  candidates.push({ command: 'cortex', prefix: [] });
  candidates.push({ command: 'blueprint', prefix: [] });
  const localScript = join(root, 'cortex', 'scripts', 'blueprint.mjs');
  if (existsSync(localScript)) candidates.push({ command: process.execPath, prefix: [localScript] });
  return candidates;
}

function invokeCortex(root, args, options = {}) {
  let lastMissing = null;
  for (const candidate of cortexCandidates(root)) {
    const result = spawnSync(candidate.command, [...candidate.prefix, ...args], {
      cwd: root,
      encoding: 'utf8',
      windowsHide: true,
      timeout: options.timeoutMs ?? 120_000,
      shell: process.platform === 'win32' && !candidate.prefix.length,
      maxBuffer: options.maxBuffer ?? 128 * 1024 * 1024,
    });
    if (result.error?.code === 'ENOENT') {
      lastMissing = result.error;
      continue;
    }
    return {
      command: [candidate.command, ...candidate.prefix, ...args].join(' '),
      status: result.status,
      stdout: result.stdout ?? '',
      stderr: result.stderr ?? '',
      error: result.error ?? null,
    };
  }
  return {
    command: null,
    status: null,
    stdout: '',
    stderr: '',
    error: lastMissing ?? new Error('Cortex executable not found'),
  };
}

function git(root, args, options = {}) {
  const result = spawnSync('git', args, {
    cwd: root,
    encoding: options.encoding ?? 'utf8',
    windowsHide: true,
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${(result.stderr || result.error?.message || '').trim()}`);
  }
  return result.stdout;
}

export function collectRepositoryBinding(root) {
  const repositoryRevision = String(git(root, ['rev-parse', 'HEAD'])).trim();
  const status = git(root, ['status', '--porcelain=v1', '-z', '--untracked-files=normal'], { encoding: 'buffer' });
  const patch = git(root, ['diff', '--binary', 'HEAD', '--'], { encoding: 'buffer' });
  const untrackedRaw = git(root, ['ls-files', '--others', '--exclude-standard', '-z'], { encoding: 'buffer' });
  const untracked = untrackedRaw.toString('utf8').split('\0').filter(Boolean).sort();
  const digest = createHash('sha256');
  digest.update('status\0');
  digest.update(status);
  digest.update('patch\0');
  digest.update(patch);
  for (const path of untracked) {
    digest.update('untracked\0');
    digest.update(normalizePath(path));
    digest.update('\0');
    try { digest.update(readFileSync(join(root, path))); }
    catch (error) { digest.update(`UNREADABLE:${error.code ?? error.message}`); }
  }
  return {
    repositoryRevision,
    dirty: status.length > 0,
    dirtyPatchDigest: `sha256:${digest.digest('hex')}`,
  };
}

function readPackageManifest(root, path) {
  try {
    const parsed = JSON.parse(readFileSync(join(root, path), 'utf8'));
    const dependencies = new Set();
    for (const key of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
      for (const name of Object.keys(parsed[key] ?? {})) dependencies.add(name);
    }
    return {
      path,
      packageManager: parsed.packageManager ?? null,
      dependencies: [...dependencies].sort(),
      scripts: Object.keys(parsed.scripts ?? {}).sort(),
    };
  } catch (error) {
    return { path, dependencies: [], scripts: [], parseError: error.message };
  }
}

function readComposerManifest(root, path) {
  try {
    const parsed = JSON.parse(readFileSync(join(root, path), 'utf8'));
    const dependencies = new Set([
      ...Object.keys(parsed.require ?? {}),
      ...Object.keys(parsed['require-dev'] ?? {}),
    ]);
    return { path, dependencies: [...dependencies].sort(), scripts: Object.keys(parsed.scripts ?? {}).sort() };
  } catch (error) {
    return { path, dependencies: [], scripts: [], parseError: error.message };
  }
}

function deriveAuditFacts(root, files) {
  const packagePaths = files.filter((path) => basename(path) === 'package.json');
  const composerPaths = files.filter((path) => basename(path) === 'composer.json');
  const packageManifests = [
    ...packagePaths.map((path) => readPackageManifest(root, path)),
    ...composerPaths.map((path) => readComposerManifest(root, path)),
  ];
  const lockfileNames = new Set([
    'pnpm-lock.yaml', 'package-lock.json', 'yarn.lock', 'bun.lock', 'bun.lockb',
    'Cargo.lock', 'composer.lock', 'poetry.lock', 'uv.lock', 'Pipfile.lock',
    'go.sum', 'Gemfile.lock', 'Package.resolved', 'packages.lock.json',
    'gradle.lockfile', 'pubspec.lock', 'mix.lock',
  ]);
  const lockfiles = files.filter((path) => lockfileNames.has(basename(path)));
  const ciFiles = files.filter((path) => path.startsWith('.github/workflows/') || [
    '.gitlab-ci.yml', 'azure-pipelines.yml', '.circleci/config.yml',
  ].includes(path));
  const releaseFiles = files.filter((path) => /(^|\/)(tauri\.conf\.(json|json5)|Tauri\.toml|Dockerfile[^/]*|.*\.(entitlements|plist|wixproj|nsi|nsis|appxmanifest))$/i.test(path));
  const projectRoots = [...new Set(
    files
      .filter((path) => /(^|\/)(package\.json|composer\.json|Cargo\.toml|pyproject\.toml|go\.mod|Gemfile|Package\.swift|pubspec\.yaml|mix\.exs|pom\.xml|build\.gradle(?:\.kts)?|.*\.csproj)$/.test(path))
      .map((path) => normalizePath(dirname(path)) || '.'),
  )].sort();
  return {
    packageManifests, lockfiles, ciFiles, releaseFiles, projectRoots,
    toolchains: {},
    toolchainDiscovery: 'deferred-to-host-capabilities',
  };
}

function projectionFailure(reason, details = {}) {
  return {
    schemaVersion: 1,
    kind: 'audit-cortex-projection',
    state: 'unproven',
    reason,
    files: [],
    parsedExtensions: [],
    unsupportedExtensions: [],
    fileSetDigest: sha256Bytes(''),
    sourceFileCount: 0,
    ...details,
  };
}

export function projectCortexPayloads({ root, status, manifestBefore, generation, manifestAfter }) {
  if (status?.state !== 'fresh') {
    return projectionFailure(`cortex-${status?.state ?? 'unknown'}`, { status });
  }
  const beforeId = graphGenerationId(manifestBefore);
  const exportId = graphGenerationId(generation);
  const afterId = graphGenerationId(manifestAfter);
  if (!beforeId || beforeId !== exportId || beforeId !== afterId) {
    return projectionFailure('cortex-generation-changed', {
      observedGenerationIds: { before: beforeId, export: exportId, after: afterId },
    });
  }
  const envelope = manifestAfter?.manifest ? manifestAfter : { ...manifestAfter, manifest: manifestAfter };
  const graphManifest = envelope.manifest ?? {};
  const complete = envelope.complete ?? graphManifest.complete;
  if (complete !== true) return projectionFailure('cortex-generation-incomplete', { generationId: beforeId });

  const files = [...new Set([
    ...(generation?.files ?? []).map((file) => typeof file === 'string' ? file : file.path),
    ...(generation?.nodes ?? []).filter((node) => node.kind === 'file').map((node) => node.path ?? node.qualifiedName),
  ].map(normalizePath).filter(Boolean))].sort();
  const parsedExtensions = [...new Set(
    status?.capabilities?.parsedExtensions
      ?? status?.capabilities?.languageCoverage?.parsedExtensions
      ?? [],
  )].map((extension) => String(extension).toLowerCase()).sort();
  const unsupportedExtensions = [...new Set(status?.capabilities?.unsupportedExtensions ?? [])].sort();
  const parsedSet = new Set(parsedExtensions);
  const sourceFileCount = files.filter((path) => {
    const base = basename(path);
    const dot = base.lastIndexOf('.');
    return dot >= 0 && parsedSet.has(base.slice(dot + 1).toLowerCase());
  }).length;
  const sourceObservation = envelope.sourceObservation
    ?? graphManifest.sourceObservation
    ?? generation?.sourceObservation
    ?? null;
  return {
    schemaVersion: 1,
    kind: 'audit-cortex-projection',
    state: 'ready',
    root,
    generationId: beforeId,
    manifestDigest: graphManifestDigest(envelope) ?? graphManifestDigest(generation),
    provider: envelope.provider ?? graphManifest.provider ?? generation?.provider ?? null,
    providerComposition: envelope.providerComposition ?? graphManifest.providerComposition ?? null,
    sourceObservation,
    fileCount: files.length,
    sourceFileCount,
    files,
    fileSetDigest: sha256Bytes(files.join('\0')),
    parsedExtensions,
    unsupportedExtensions,
    counts: envelope.counts ?? graphManifest.counts ?? null,
    complete: true,
    auditFacts: deriveAuditFacts(root, files),
  };
}

export function readCortexProjection(rootInput, options = {}) {
  const root = resolve(rootInput);
  const outDir = options.outDir ?? '.agent';
  const statusResult = invokeCortex(root, ['graph', 'status', '--json', '--out', outDir]);
  if (statusResult.error || !statusResult.stdout.trim()) {
    return projectionFailure('cortex-unavailable', {
      command: statusResult.command,
      error: statusResult.error?.message ?? (statusResult.stderr.trim() || null),
    });
  }
  let status;
  try { status = parseJson(statusResult.stdout, 'cortex graph status'); }
  catch (error) { return projectionFailure('cortex-status-invalid', { error: error.message }); }
  if (status.state !== 'fresh') return projectionFailure(`cortex-${status.state ?? 'unknown'}`, { status });

  const manifestBeforeResult = invokeCortex(root, ['graph', 'manifest', '--out', outDir]);
  if (manifestBeforeResult.status !== 0) {
    return projectionFailure('cortex-manifest-unavailable', { error: manifestBeforeResult.stderr.trim() });
  }
  const exportResult = invokeCortex(root, ['graph', 'export', '--out', outDir], { timeoutMs: 240_000 });
  if (exportResult.status !== 0) {
    return projectionFailure('cortex-export-unavailable', { error: exportResult.stderr.trim() });
  }
  const manifestAfterResult = invokeCortex(root, ['graph', 'manifest', '--out', outDir]);
  if (manifestAfterResult.status !== 0) {
    return projectionFailure('cortex-manifest-unavailable-after-export', { error: manifestAfterResult.stderr.trim() });
  }
  try {
    return projectCortexPayloads({
      root,
      status,
      manifestBefore: parseJson(manifestBeforeResult.stdout, 'cortex graph manifest'),
      generation: parseJson(exportResult.stdout, 'cortex graph export'),
      manifestAfter: parseJson(manifestAfterResult.stdout, 'cortex graph manifest'),
    });
  } catch (error) {
    return projectionFailure('cortex-projection-failed', { error: error.message });
  }
}

export function readCortexManifestBinding(rootInput, options = {}) {
  const root = resolve(rootInput);
  const outDir = options.outDir ?? '.agent';
  const result = invokeCortex(root, ['graph', 'manifest', '--out', outDir]);
  if (result.status !== 0) return { state: 'unproven', reason: 'cortex-manifest-unavailable' };
  try {
    const payload = parseJson(result.stdout, 'cortex graph manifest');
    const manifest = payload.manifest ?? payload;
    return {
      state: 'ready',
      generationId: graphGenerationId(payload),
      manifestDigest: graphManifestDigest(payload),
      sourceObservation: payload.sourceObservation ?? manifest.sourceObservation ?? null,
    };
  } catch (error) {
    return { state: 'unproven', reason: 'cortex-manifest-invalid', error: error.message };
  }
}
