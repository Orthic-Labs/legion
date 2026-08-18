// Native-workspace extractor per Security Appendix §11.7: config discovery,
// .env loading, workspace trust, plugin/hook/tool/MCP discovery, process
// execution sinks, updater config, desktop boundaries, IPC, credential stores.

import { entity, relation } from './common.mjs';
import { stableId } from '../contracts.mjs';

export function extractNativeWorkspace({ root, plan, projection, files, lensRegistry }) {
  const entities = [];
  const relations = [];
  const evidence = [];
  const initialFacts = [];
  const coverageGaps = [];

  for (const file of files) {
    const text = projection.sourceText?.[file] ?? '';
    if (!text) continue;
    if (/\.env|config\.|plugin|hook|mcp|skill|extension|\.agent\//.test(file) || /\.env|loadConfig|plugin|hook|mcp/i.test(text)) {
      const evidenceRef = stableId('workspace-evidence', { file });
      const entrypoint = entity('entrypoint', `workspace config ${file}`, { entrypointType: 'workspace-open' }, [evidenceRef]);
      const artifact = entity('repository-artifact', `config artifact ${file}`, { trust: 'workspace-controlled' }, [evidenceRef]);
      entities.push(entrypoint, artifact);
      relations.push(relation('loads', entrypoint.id, artifact.id, [evidenceRef]));
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Workspace config' });
    }
    if (/(?:exec|spawn|child_process|Command::new|subprocess)/.test(text)) {
      const evidenceRef = stableId('exec-evidence', { file });
      const sink = entity('sink', `process execution ${file}`, { sinkKind: 'process' }, [evidenceRef]);
      entities.push(sink);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Process execution sink' });
    }
    if (/updater|autoUpdater|update/.test(text)) {
      const evidenceRef = stableId('updater-evidence', { file });
      const asset = entity('repository-artifact', `updater config ${file}`, { assetKind: 'updater' }, [evidenceRef]);
      entities.push(asset);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Updater config' });
    }
  }
  return { entities, relations, evidence, initialFacts, coverageGaps };
}
