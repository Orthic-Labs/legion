#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const LEVEL = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

// One canonical product identity for every machine output. No legacy
// bogusyogi-audit naming may survive.
const TOOL = Object.freeze({
  name: 'Nemesis',
  fullName: 'Orthic Labs Nemesis',
  organization: 'Orthic Labs',
  informationUri: 'https://github.com/Orthic-Labs/nemesis',
});

function locationFor(finding) {
  if (!finding?.file) return [];
  const line = Number(finding.line ?? 1);
  return [{
    physicalLocation: {
      artifactLocation: { uri: String(finding.file).replaceAll('\\', '/') },
      region: { startLine: Number.isFinite(line) && line > 0 ? line : 1 },
    },
  }];
}

export function reportToSarif(report) {
  const findings = report?.findings ?? [];
  const security = report?.security ?? {};
  const attackPaths = security?.attackPaths?.proven ?? [];
  const rules = new Map();
  const results = findings.map((finding) => {
    const ruleId = String(finding.ruleId ?? finding.category ?? finding.subtype ?? 'audit-finding');
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: ruleId.replaceAll(/[^A-Za-z0-9]+/g, '_'),
        shortDescription: { text: finding.category ? `Audit ${finding.category} finding` : 'Audit finding' },
        defaultConfiguration: { level: LEVEL[finding.severity] ?? 'warning' },
        properties: { category: finding.category ?? null },
      });
    }
    const properties = {
      severity: finding.severity ?? null,
      evidenceStrength: finding.evidence_strength ?? finding.evidenceStrength ?? null,
      judgment: finding.judgment ?? null,
      status: finding.status ?? null,
      tier: finding.tier ?? null,
      evidence: finding.evidence ?? null,
      action: finding.action ?? null,
      sources: finding.sources ?? [],
    };
    if (finding.candidateId) properties.candidateId = finding.candidateId;
    if (finding.rootCauseDigest || finding.rootCauseSignature) {
      properties.rootCauseDigest = finding.rootCauseDigest ?? finding.rootCauseSignature;
    }
    if (finding.variantReceiptId) properties.variantReceiptId = finding.variantReceiptId;
    if (finding.relatedAttackPathIds?.length) properties.relatedAttackPathIds = finding.relatedAttackPathIds;
    return {
      ruleId,
      level: LEVEL[finding.severity] ?? 'warning',
      message: { text: finding.title ? `${finding.title}${finding.detail ? ` — ${finding.detail}` : ''}` : String(finding.detail ?? 'Audit finding') },
      locations: locationFor(finding),
      // Stable semantic fingerprint, never presentation text. Based on the
      // finding's semantic identity so line moves do not create new findings.
      partialFingerprints: {
        'nemesisFinding/v1': String(finding.id ?? finding.candidateId ?? finding.ruleId),
        ...(finding.rootCauseDigest || finding.rootCauseSignature
          ? { 'nemesisRootCause/v1': String(finding.rootCauseDigest ?? finding.rootCauseSignature) }
          : {}),
      },
      properties,
    };
  });

  // Proven attack paths become separate SARIF results with ordered code flows
  // per Security Appendix §47. Partial/blocked/refuted paths are never emitted
  // as failing results.
  for (const path of attackPaths) {
    const ruleId = `security.attack-path.${path.objective?.id ?? 'proven-path'}`;
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: ruleId.replaceAll(/[^A-Za-z0-9]+/g, '_'),
        shortDescription: { text: 'Proven attack path' },
        defaultConfiguration: { level: LEVEL[path.severity] ?? 'error' },
        properties: { category: 'security-attack-path' },
      });
    }
    const threadFlow = (path.stepAssessments ?? []).map((step, index) => ({
      order: index,
      location: locationFor({ file: step.file, line: step.line })[0],
    })).filter((entry) => entry.location);
    results.push({
      ruleId,
      level: LEVEL[path.severity] ?? 'error',
      message: { text: `Proven attack path: ${path.objective?.id ?? ''} (${path.severity ?? 'unknown'})` },
      locations: threadFlow[0]?.location ? [threadFlow[0].location] : [],
      partialFingerprints: {
        'nemesisPath/v1': String(path.id ?? path.pathId),
      },
      codeFlows: threadFlow.length
        ? [{ threadFlows: [{ id: `path-${path.id ?? path.pathId}`, locations: threadFlow }] }]
        : undefined,
      properties: {
        pathId: path.id ?? path.pathId,
        constituentFindingIds: path.constituentFindingIds ?? [],
        start: path.start ?? null,
        objective: path.objective ?? null,
        proofDigest: path.proof?.digest ?? null,
      },
    });
  }
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          ...TOOL,
          semanticVersion: report?.tool?.version ?? report?.nemesisVersion ?? '0.0.0-dev',
          rules: [...rules.values()].sort((left, right) => left.id.localeCompare(right.id)),
        },
      },
      automationDetails: report?.commit ? { id: String(report.commit) } : undefined,
      results,
      properties: {
        auditStatus: report?.audit_status ?? report?.auditStatus ?? null,
        qualityGate: report?.quality_gate ?? report?.qualityGate ?? null,
        incomplete: Boolean(report?.incomplete),
        generatedAt: report?.generated_at ?? report?.generatedAt ?? null,
        planSeal: report?.plan?.seal?.digest ?? null,
        planSignature: report?.plan?.seal?.signature ?? null,
        cortexGeneration: report?.cortex?.generationId ?? null,
      },
    }],
  };
}

function arg(args, name) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : null;
}

async function main() {
  const args = process.argv.slice(2);
  const reportPath = arg(args, '--report');
  const outPath = arg(args, '--out');
  if (!reportPath || !outPath) {
    console.error('usage: report-to-sarif.mjs --report report.json --out report.sarif');
    process.exit(2);
  }
  const sarif = reportToSarif(JSON.parse(readFileSync(reportPath, 'utf8')));
  writeFileSync(outPath, `${JSON.stringify(sarif, null, 2)}\n`, 'utf8');
  console.log(outPath);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error.stack ?? error.message);
    process.exit(1);
  });
}
