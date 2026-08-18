// Developer-machine extractor (B7-007): the local development/build-time
// surface distinct from a shipped native app's own runtime trust boundary
// (that is native-workspace.mjs). Extracts native process/file/network
// grants exercised at development or install time, local tool/plugin/hook
// authority, and editor/agent config discovery.
//
// Repository/config text and upstream package-manifest evidence only. No
// process execution, no hook invocation, no filesystem access beyond the
// frozen denominator text already supplied by the caller.

import { entity, relation, fact, controlEntity } from './common.mjs';
import { assertEntityKind, assertRelationKind, assertFactKind, stableId } from '../contracts.mjs';

function typedEntity(kind, name, attributes, evidenceRefs, opts) {
  assertEntityKind(kind);
  return entity(kind, name, attributes, evidenceRefs, opts);
}

function typedRelation(kind, from, to, evidenceRefs, attributes, opts) {
  assertRelationKind(kind);
  return relation(kind, from, to, evidenceRefs, attributes, opts);
}

function typedFact(kind, fields, evidenceRefs) {
  assertFactKind(kind);
  return fact(kind, fields, evidenceRefs);
}

function typedControlEntity(controlType, name, evidenceRefs, attributes) {
  assertEntityKind('control');
  return controlEntity(controlType, name, evidenceRefs, attributes);
}

const EDITOR_AGENT_CONFIG_PATTERN = /(^|\/)(\.vscode|\.idea|\.cursor|\.claude|\.github\/copilot|\.mcp\.json|mcp\.json|CLAUDE\.md|AGENTS\.md|\.husky|\.git\/hooks)(\/|$)/i;
const LIFECYCLE_HOOK_NAMES = new Set(['preinstall', 'postinstall', 'prepare']);
const FILESYSTEM_GRANT_PATTERN = /\bfs\.|filesystem|readFile|writeFile|readdir/i;
const PROCESS_GRANT_PATTERN = /\bexec\s*\(|\bspawn\s*\(|child_process|Bash\s*\(|shell\s*=\s*true/i;
const NETWORK_GRANT_PATTERN = /\bfetch\s*\(|\bhttp[s]?\b|axios|network/i;
const SANDBOX_BYPASS_PATTERN = /dangerouslySkipPermissions|--no-sandbox|bypassPermissions|trust\s*[:=]\s*(?:false|"?off"?|disabled)/i;

function lifecycleHookScripts(projection) {
  const manifests = projection?.auditFacts?.packageManifests ?? [];
  const found = [];
  for (const manifest of manifests) {
    for (const script of manifest.scripts ?? []) {
      if (LIFECYCLE_HOOK_NAMES.has(script)) found.push({ manifest: manifest.path, script });
    }
  }
  return found;
}

function grantKindsIn(text) {
  const kinds = [];
  if (FILESYSTEM_GRANT_PATTERN.test(text)) kinds.push('filesystem');
  if (PROCESS_GRANT_PATTERN.test(text)) kinds.push('process');
  if (NETWORK_GRANT_PATTERN.test(text)) kinds.push('network');
  return kinds;
}

export function extractDeveloperMachine({ root, plan, projection, files, lensRegistry }) {
  const entities = [];
  const relations = [];
  const evidence = [];
  const initialFacts = [];
  const coverageGaps = [];

  const sourceText = projection?.sourceText ?? {};
  const hookScripts = lifecycleHookScripts(projection);
  let sawDevMachineSignal = hookScripts.length > 0;

  for (const hook of hookScripts) {
    const evidenceRef = stableId('devmachine-lifecycle-hook-evidence', hook);
    const artifact = typedEntity('repository-artifact', `package manifest ${hook.manifest}`, { path: hook.manifest }, [evidenceRef]);
    const hookProcess = typedEntity(
      'process',
      `package lifecycle hook ${hook.manifest}:${hook.script}`,
      { environment: 'developer-machine', processKind: 'package-lifecycle-hook', script: hook.script },
      [evidenceRef],
    );
    entities.push(artifact, hookProcess);
    relations.push(typedRelation('executes', artifact.id, hookProcess.id, [evidenceRef]));
    evidence.push({ id: evidenceRef, kind: 'source-location', file: hook.manifest, description: `Package lifecycle hook ${hook.script}` });
    initialFacts.push(typedFact('code-execution', {
      subject: hookProcess.id, action: 'run-on-install', object: hook.manifest, scope: 'developer-machine',
    }, [evidenceRef]));
  }

  for (const file of files ?? []) {
    if (!EDITOR_AGENT_CONFIG_PATTERN.test(file)) continue;
    sawDevMachineSignal = true;

    const evidenceRef = stableId('devmachine-config-evidence', { file });
    const artifact = typedEntity(
      'repository-artifact',
      `editor/agent config ${file}`,
      { path: file, configKind: 'editor-agent-config' },
      [evidenceRef],
    );
    const loader = typedEntity(
      'entrypoint',
      `developer-machine config load ${file}`,
      { entrypointType: 'developer-machine-config-load' },
      [evidenceRef],
    );
    entities.push(artifact, loader);
    relations.push(typedRelation('loads', loader.id, artifact.id, [evidenceRef]));
    evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Editor/agent config discovery' });

    const text = sourceText[file];
    if (text === undefined) {
      coverageGaps.push({
        kind: 'missing-rendered-configuration',
        domain: 'developer-machine',
        file,
        reason: 'file matched an editor/agent config pattern but no source text was projected for it',
      });
      continue;
    }
    if (!text) continue;

    for (const grantKind of grantKindsIn(text)) {
      const grantRef = stableId('devmachine-grant-evidence', { file, grantKind });
      const scope = typedEntity(
        'permission-scope',
        `local tool grant ${grantKind} ${file}`,
        { file, grantKind },
        [grantRef],
      );
      entities.push(scope);
      relations.push(typedRelation('grants', artifact.id, scope.id, [grantRef]));
      evidence.push({ id: grantRef, kind: 'source-location', file, description: `Local ${grantKind} grant` });
    }

    if (SANDBOX_BYPASS_PATTERN.test(text)) {
      const bypassRef = stableId('devmachine-sandbox-bypass-evidence', { file });
      const control = typedControlEntity('local-sandbox', `local sandbox policy ${file}`, [bypassRef], {
        controlState: 'absent',
      });
      entities.push(control);
      evidence.push({ id: bypassRef, kind: 'source-location', file, description: 'Local sandbox/permission bypass' });
    }
  }

  if (!sawDevMachineSignal) {
    coverageGaps.push({
      kind: 'developer-machine-context-not-detected',
      domain: 'developer-machine',
      reason: 'no editor/agent config, plugin/hook discovery, or package lifecycle hook found in the denominator',
    });
  }

  return { entities, relations, evidence, initialFacts, coverageGaps };
}
