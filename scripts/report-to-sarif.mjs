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
    return {
      ruleId,
      level: LEVEL[finding.severity] ?? 'warning',
      message: { text: finding.title ? `${finding.title}${finding.detail ? ` — ${finding.detail}` : ''}` : String(finding.detail ?? 'Audit finding') },
      locations: locationFor(finding),
      partialFingerprints: finding.id ? { auditFindingId: String(finding.id) } : undefined,
      properties: {
        severity: finding.severity ?? null,
        evidenceStrength: finding.evidence_strength ?? finding.evidenceStrength ?? null,
        judgment: finding.judgment ?? null,
        status: finding.status ?? null,
        tier: finding.tier ?? null,
        evidence: finding.evidence ?? null,
        action: finding.action ?? null,
        sources: finding.sources ?? [],
      },
    };
  });
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'operator-audit',
          informationUri: 'https://github.com/operator/claude',
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
