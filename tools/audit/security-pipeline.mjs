#!/usr/bin/env node
import { randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createAdjudicationPacket, createSecurityCandidate, finalizeSecurityVerdict } from '../../src/adapters/security-adjudication.mjs';
import { deriveVariantQueries } from '../../src/providers/security-suite.mjs';

const SURVIVING = new Set(['TRUE_POSITIVE', 'LIKELY_TRUE_POSITIVE']);

function normalizeCandidate(candidate, contextId) {
  return createSecurityCandidate({
    id: candidate.id,
    provider: candidate.provider,
    contextId,
    claim: candidate.claim,
    allegedRootCause: candidate.allegedRootCause ?? candidate.ruleId ?? null,
    allegedTrigger: candidate.allegedTrigger ?? null,
    allegedImpact: candidate.allegedImpact ?? candidate.severityHint ?? null,
    evidence: candidate.evidence,
    generatedAt: candidate.generatedAt,
  });
}

export function prepareAdjudicationBundle(candidateReport, options = {}) {
  const generatorContextId = options.generatorContextId ?? randomUUID();
  const adjudicatorProvider = options.adjudicatorProvider ?? 'security.adjudication';
  const rawCandidates = candidateReport.candidates ?? [];
  if (options.adjudicatorContextId && rawCandidates.length > 1) {
    throw new Error('one adjudicatorContextId may only be supplied for a single candidate; each candidate requires a fresh context');
  }

  const packets = rawCandidates.map((raw) => {
    const candidate = normalizeCandidate(raw, generatorContextId);
    const contextId = options.adjudicatorContextId ?? randomUUID();
    if (contextId === generatorContextId) throw new Error(`candidate ${candidate.id} must be adjudicated in a fresh context`);
    return createAdjudicationPacket(candidate, { provider: adjudicatorProvider, contextId });
  });
  const contexts = packets.map((packet) => ({
    candidateId: packet.candidate.id,
    provider: packet.adjudicator.provider,
    contextId: packet.adjudicator.contextId,
  }));
  if (new Set(contexts.map((item) => item.contextId)).size !== contexts.length) {
    throw new Error('adjudication contexts must be unique per candidate');
  }

  return {
    schemaVersion: 1,
    kind: 'security-adjudication-bundle',
    generator: { provider: candidateReport.provider ?? 'security.internal-suite', contextId: generatorContextId },
    adjudicator: {
      provider: adjudicatorProvider,
      freshContextRequired: true,
      contextStrategy: 'one-context-per-candidate',
      contexts,
    },
    packets,
    requiredVerdictCandidateIds: packets.map((packet) => packet.candidate.id).sort(),
  };
}

export function finalizeAdjudicationBundle(bundle, submitted, variantReceipts = []) {
  const submittedById = new Map((submitted?.verdicts ?? []).map((verdict) => [verdict.candidateId, verdict]));
  const receiptsByFinding = new Map(variantReceipts.map((receipt) => [receipt.findingId, receipt]));
  const verdicts = [];
  const missingVerdicts = [];
  const invalidVerdicts = [];
  const missingVariantAnalysis = [];
  const contextIds = new Set();
  for (const packet of bundle.packets ?? []) {
    if (contextIds.has(packet.adjudicator?.contextId)) {
      invalidVerdicts.push({ candidateId: packet.candidate?.id ?? null, error: 'adjudicator context was reused across candidates' });
      continue;
    }
    contextIds.add(packet.adjudicator?.contextId);
    const input = submittedById.get(packet.candidate.id);
    if (!input) { missingVerdicts.push(packet.candidate.id); continue; }
    try {
      const verdict = finalizeSecurityVerdict(packet, input);
      verdicts.push(verdict);
      if (SURVIVING.has(verdict.verdict)) {
        const receipt = receiptsByFinding.get(verdict.candidateId);
        if (!receipt?.complete || receipt.ruleId !== packet.candidate.allegedRootCause) {
          missingVariantAnalysis.push({ candidateId: verdict.candidateId, requiredPlan: deriveVariantQueries({ id: verdict.candidateId, ruleId: packet.candidate.allegedRootCause, evidence: packet.candidate.evidence }) });
        }
      }
    } catch (error) {
      invalidVerdicts.push({ candidateId: packet.candidate.id, error: error.message });
    }
  }
  const unplannedVerdicts = [...submittedById.keys()].filter((id) => !(bundle.requiredVerdictCandidateIds ?? []).includes(id));
  const complete = !missingVerdicts.length && !invalidVerdicts.length && !unplannedVerdicts.length && !missingVariantAnalysis.length;
  return {
    schemaVersion: 1,
    kind: 'security-adjudication-result',
    complete,
    status: complete ? (verdicts.some((verdict) => SURVIVING.has(verdict.verdict)) ? 'findings' : 'pass') : 'unproven',
    verdicts,
    missingVerdicts,
    invalidVerdicts,
    unplannedVerdicts,
    missingVariantAnalysis,
  };
}

function arg(args, name) { const index = args.indexOf(name); return index >= 0 ? args[index + 1] : null; }

function main() {
  const args = process.argv.slice(2);
  const candidatesPath = arg(args, '--candidates');
  const bundlePath = arg(args, '--bundle');
  const verdictsPath = arg(args, '--verdicts');
  const variantsPath = arg(args, '--variants');
  const outPath = arg(args, '--out');
  if (candidatesPath) {
    const report = JSON.parse(readFileSync(resolve(candidatesPath), 'utf8'));
    const bundle = prepareAdjudicationBundle(report, { adjudicatorProvider: arg(args, '--provider') ?? 'security.adjudication' });
    if (outPath) writeFileSync(resolve(outPath), `${JSON.stringify(bundle, null, 2)}\n`);
    else console.log(JSON.stringify(bundle, null, 2));
    return;
  }
  if (!bundlePath || !verdictsPath) throw new Error('usage: security-pipeline.mjs --candidates candidates.json --out bundle.json OR --bundle bundle.json --verdicts verdicts.json [--variants variants.json] --out result.json');
  const bundle = JSON.parse(readFileSync(resolve(bundlePath), 'utf8'));
  const verdicts = JSON.parse(readFileSync(resolve(verdictsPath), 'utf8'));
  const variants = variantsPath ? JSON.parse(readFileSync(resolve(variantsPath), 'utf8')).receipts ?? [] : [];
  const result = finalizeAdjudicationBundle(bundle, verdicts, variants);
  if (outPath) writeFileSync(resolve(outPath), `${JSON.stringify(result, null, 2)}\n`);
  else console.log(JSON.stringify(result, null, 2));
  if (!result.complete) process.exitCode = 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
