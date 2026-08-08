// AI-agent extractor (B7-007): model invocation sites, agent tool
// definitions, MCP tool schemas, model outputs, memory/RAG stores, approval
// controls, and side-effect budgets. Hostile skill/document/repository/RAG
// content is modeled as untrusted input, never merged into a normal
// repository-artifact entity.
//
// Repository/config text only. No model call, no tool execution, no MCP
// connection, no network probe of any kind.

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

const MODEL_INVOCATION_PATTERN = /llm|model|openai|anthropic|claude|gpt|prompt|completion/i;
const TOOL_PATTERN = /\btool\b|function_call|\btools\b/i;
const MCP_PATTERN = /\bmcp\b|@modelcontextprotocol|inputSchema|tool_use/i;
const APPROVAL_PATTERN = /approval|human_in_the_loop|requireApproval|confirm/i;
const RAG_STORE_PATTERN = /\bvector\b|embedding|pinecone|chroma|weaviate|qdrant|faiss|milvus|retriever|\bRAG\b/i;
const MEMORY_STORE_PATTERN = /conversation_history|memory_store|session_memory|long[-_ ]?term memory|agent_memory/i;
const SIDE_EFFECT_BUDGET_PATTERN = /max_calls|max_steps|maxSteps|rate_limit|token_budget|spend_limit|\bquota\b|step_budget/i;
const UNTRUSTED_PATH_PATTERN = /(^|\/)(SKILL\.md|AGENTS\.md|\.claude\/skills\/|\/skills\/|\/prompts\/)/i;
const UNTRUSTED_TEXT_PATTERN = /retrieved[- ]?content|rag[- ]?context|search_result|document[- ]?content|untrusted/i;

export function extractAiAgent({ root, plan, projection, files, lensRegistry }) {
  const entities = [];
  const relations = [];
  const evidence = [];
  const initialFacts = [];
  const coverageGaps = [];

  const sourceText = projection?.sourceText ?? {};
  let sawAgentSignal = false;

  for (const file of files ?? []) {
    const text = sourceText[file];
    if (text === undefined || !text) continue;

    let invocationProcess = null;

    if (MODEL_INVOCATION_PATTERN.test(text)) {
      sawAgentSignal = true;
      const evidenceRef = stableId('model-evidence', { file });
      invocationProcess = typedEntity(
        'process',
        `model invocation ${file}`,
        { processKind: 'model-invocation', environment: 'agent' },
        [evidenceRef],
      );
      entities.push(invocationProcess);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Model invocation' });

      // Model output is a distinct entity/fact from tool authority below: it
      // is untrusted downstream data, never a capability grant.
      const outputRef = stableId('model-output-evidence', { file });
      const modelOutput = typedEntity(
        'source',
        `model output ${file}`,
        { sourceKind: 'model-output', trust: 'untrusted', file },
        [outputRef],
      );
      entities.push(modelOutput);
      evidence.push({ id: outputRef, kind: 'source-location', file, description: 'Model output' });
      relations.push(typedRelation('derives-from', modelOutput.id, invocationProcess.id, [outputRef]));
      initialFacts.push(typedFact('knowledge', {
        subject: modelOutput.id, action: 'produce', object: invocationProcess.id, scope: 'agent',
        attributes: { kind: 'model-output' },
      }, [outputRef]));
    }

    if (TOOL_PATTERN.test(text)) {
      sawAgentSignal = true;
      const evidenceRef = stableId('tool-evidence', { file });
      const tool = typedEntity(
        'tool-capability',
        `tool ${file}`,
        { environment: 'agent', mcp: MCP_PATTERN.test(text), file },
        [evidenceRef],
      );
      entities.push(tool);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Tool capability' });
      // Tool authority is a distinct entity/fact from model output above: it
      // is a capability grant, never a data value.
      initialFacts.push(typedFact('capability', {
        subject: invocationProcess ? invocationProcess.id : 'actor:agent',
        action: 'invoke', object: tool.id, scope: 'agent',
      }, [evidenceRef]));
      if (invocationProcess) relations.push(typedRelation('calls', invocationProcess.id, tool.id, [evidenceRef]));
    }

    if (APPROVAL_PATTERN.test(text)) {
      sawAgentSignal = true;
      const evidenceRef = stableId('approval-evidence', { file });
      const control = typedControlEntity('human-approval', `approval control ${file}`, [evidenceRef]);
      entities.push(control);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Approval control' });
    }

    if (RAG_STORE_PATTERN.test(text)) {
      sawAgentSignal = true;
      const evidenceRef = stableId('rag-store-evidence', { file });
      const store = typedEntity('data-store', `RAG store ${file}`, { environment: 'agent', storeKind: 'rag' }, [evidenceRef]);
      entities.push(store);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'RAG store' });
      if (invocationProcess) relations.push(typedRelation('retrieves-from', invocationProcess.id, store.id, [evidenceRef]));
    }

    if (MEMORY_STORE_PATTERN.test(text)) {
      sawAgentSignal = true;
      const evidenceRef = stableId('memory-store-evidence', { file });
      const store = typedEntity('data-store', `agent memory store ${file}`, { environment: 'agent', storeKind: 'memory' }, [evidenceRef]);
      entities.push(store);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Agent memory store' });
      if (invocationProcess) relations.push(typedRelation('stores', invocationProcess.id, store.id, [evidenceRef]));
    }

    if (SIDE_EFFECT_BUDGET_PATTERN.test(text)) {
      sawAgentSignal = true;
      const evidenceRef = stableId('side-effect-budget-evidence', { file });
      const control = typedControlEntity('side-effect-budget', `side-effect budget ${file}`, [evidenceRef]);
      entities.push(control);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Side-effect budget control' });
    }

    if (UNTRUSTED_PATH_PATTERN.test(file) || UNTRUSTED_TEXT_PATTERN.test(text)) {
      const evidenceRef = stableId('untrusted-content-evidence', { file });
      const untrusted = typedEntity(
        'source',
        `untrusted agent-context content ${file}`,
        { file, sourceKind: 'skill-or-document', trust: 'untrusted', hostile: 'possible' },
        [evidenceRef],
      );
      entities.push(untrusted);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Untrusted skill/document/retrieved content' });
      initialFacts.push(typedFact('attacker-position', {
        subject: 'actor:external', action: 'influence', object: untrusted.id, scope: 'agent-context',
        attributes: { vector: 'untrusted-content-injection' },
      }, [evidenceRef]));
    }
  }

  if (!sawAgentSignal) {
    coverageGaps.push({
      kind: 'ai-agent-context-not-detected',
      domain: 'ai-agent',
      reason: 'no model invocation, tool, MCP, memory, or RAG evidence found in the denominator',
    });
  }

  return { entities, relations, evidence, initialFacts, coverageGaps };
}
