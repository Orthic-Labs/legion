// AI-agent extractor per Security Appendix §11.8: model invocation sites,
// prompt templates, RAG sources, memory stores, tool definitions, approvals,
// validators, output sinks, budgets.

import { entity, relation } from './common.mjs';
import { stableId } from '../contracts.mjs';

export function extractAiAgent({ root, plan, projection, files, lensRegistry }) {
  const entities = [];
  const relations = [];
  const evidence = [];
  const initialFacts = [];
  const coverageGaps = [];

  for (const file of files) {
    const text = projection.sourceText?.[file] ?? '';
    if (!text) continue;
    if (/llm|model|openai|anthropic|claude|gpt|prompt|completion/i.test(text)) {
      const evidenceRef = stableId('model-evidence', { file });
      const process = entity('process', `model invocation ${file}`, { processKind: 'model-invocation', environment: 'agent' }, [evidenceRef]);
      entities.push(process);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Model invocation' });
    }
    if (/\b(?:tool|function_call|tools)\b/.test(text)) {
      const evidenceRef = stableId('tool-evidence', { file });
      const tool = entity('tool-capability', `tool ${file}`, { environment: 'agent' }, [evidenceRef]);
      entities.push(tool);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Tool capability' });
    }
    if (/approval|human_in_the_loop|requireApproval|confirm/i.test(text)) {
      const evidenceRef = stableId('approval-evidence', { file });
      const control = entity('control', `approval control ${file}`, { controlType: 'human-approval' }, [evidenceRef]);
      entities.push(control);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Approval control' });
    }
  }
  return { entities, relations, evidence, initialFacts, coverageGaps };
}
