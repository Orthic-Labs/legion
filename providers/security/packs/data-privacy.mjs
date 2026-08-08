// Data-protection / privacy security pack: sensitive data in logs, PII
// collection, storage, transmission, retention, backups, export, tenant
// separation, and marketing/privacy-claim mismatches.
//
// Every candidate binds a data class (`detectorMetadata.dataClass`) and a
// lifecycle stage (`detectorMetadata.lifecycleStage`, one of
// collect/store/process/transmit/retain/export/delete). A high-impact
// privacy claim (this pack's base severity is 'high' or 'critical') is
// capped at 'medium' with an explicit uncertainty entry unless an *observed*
// sensitive-data classification is available — from
// `context.projection.auditFacts` data-privacy / claim-proof artifacts, or a
// model `data-store`/`asset` entity carrying a `dataClass` attribute. Those
// upstream artifacts are consumed defensively: absence degrades the claim,
// it never throws.
//
// Marketing/privacy-copy claims are cross-linked via
// `detectorMetadata.claimRefs` when a claim-proof/copy artifact is
// available; otherwise the absence itself is recorded as an uncertainty.
//
// Lexical (pattern-only) detection throughout; UNADJUDICATED candidates only.

import { digest } from '../contracts.mjs';

function findArtifact(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

function windowAround(text, index, matchLength, radius = 200) {
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + matchLength + radius);
  return text.slice(start, end);
}

function repoWideEvidenceRefs(context) {
  const refs = new Set();
  for (const file of context.files) {
    const artifact = findArtifact(context, file);
    for (const ref of artifact?.evidenceRefs ?? []) refs.add(ref);
  }
  return [...refs].sort();
}

const DATA_CLASS_PATTERNS = [
  ['financial', /credit[_-]?card|card[_-]?number|\bcvv\b|bank[_-]?account|\biban\b|routing[_-]?number/i],
  ['health', /diagnosis|health[_-]?record|medical[_-]?record|prescription/i],
  ['credential', /\bpassword\b|\bapi[_-]?key\b|\btoken\b|\bsecret\b/i],
  ['pii', /\bemail\b|\bphone\b|\baddress\b|\bssn\b|full[_-]?name|date[_-]?of[_-]?birth|\bdob\b/i],
];

function classifyDataClass(text) {
  for (const [cls, pattern] of DATA_CLASS_PATTERNS) {
    if (pattern.test(text)) return cls;
  }
  return 'unspecified-sensitive';
}

// Looks for an *observed* classification: a model data-store/asset entity
// carrying attributes.dataClass, or an upstream data-privacy audit-facts
// classification list. Falls back to null (lexical-only inference) rather
// than throwing when neither is present.
function observedClassification(context, file) {
  for (const e of context.model.entities ?? []) {
    if ((e.kind === 'data-store' || e.kind === 'asset') && e.attributes?.dataClass) {
      const related = context.relationsTo?.(e.id) ?? [];
      const touchesFile = related.some((r) => {
        const from = context.entityById?.get(r.from);
        return from?.kind === 'repository-artifact' && from.attributes?.path === file;
      });
      if (touchesFile || e.attributes?.file === file) {
        return { dataClass: e.attributes.dataClass, source: 'model-entity' };
      }
    }
  }
  const classifications = context.projection?.auditFacts?.dataPrivacy?.classifications ?? [];
  const hit = classifications.find((c) => c?.file === file);
  if (hit?.dataClass) return { dataClass: hit.dataClass, source: 'audit-facts' };
  return null;
}

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
function capSeverity(base, cap) {
  return SEVERITY_RANK[base] <= SEVERITY_RANK[cap] ? base : cap;
}

// Applies the "high-impact claim requires observed classification" gate.
// Returns { severityHint, dataClass, uncertainty[] }.
function classificationGate(context, file, lexicalText, baseSeverity) {
  const observed = observedClassification(context, file);
  const dataClass = observed?.dataClass ?? classifyDataClass(lexicalText);
  if (SEVERITY_RANK[baseSeverity] < SEVERITY_RANK.high) {
    return { severityHint: baseSeverity, dataClass, classificationObserved: Boolean(observed), uncertainty: [] };
  }
  if (observed) {
    return { severityHint: baseSeverity, dataClass, classificationObserved: true, uncertainty: [] };
  }
  return {
    severityHint: capSeverity(baseSeverity, 'medium'),
    dataClass,
    classificationObserved: false,
    uncertainty: ['No observed sensitive-data classification (a data-privacy audit-facts artifact or a model data-store/asset entity carrying a data class) was available; the data class is lexically inferred and this claim is capped pending classification.'],
  };
}

function makeObservation({
  ruleId, claim, severityHint, dataClass, lifecycleStage, classificationObserved,
  file, line, artifact, effectKind, effectAction, effectScope, chainRoles,
  uncertainty, extraMeta = {}, evidenceRefs, sources,
}) {
  return {
    ruleId,
    candidateClass: 'data-privacy',
    claim,
    severityHint,
    sources: sources ?? (artifact ? [artifact.id] : []),
    sinks: artifact ? [artifact.id] : [],
    attackerCapabilities: ['read-repository', 'observe-application-output'],
    preconditions: [{
      kind: 'attacker-position', subject: 'actor:external', action: 'observe-data-handling',
      scope: null, environment: 'application', tenant: null,
    }],
    effects: [{
      kind: effectKind, subject: 'actor:external', action: effectAction,
      object: artifact?.id ?? null, scope: effectScope, environment: 'application', tenant: null,
    }],
    assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
    chainRoles,
    evidenceRefs: evidenceRefs ?? artifact?.evidenceRefs ?? [],
    detectorMetadata: {
      file, line, dataClass, lifecycleStage, classificationObserved,
      ...extraMeta,
    },
    uncertainty,
  };
}

const LOG_CALL = /(?:console|logger)\.(?:log|info|warn|debug|error)\s*\(([^;\n]{0,200})\)/gi;
const LOG_SENSITIVE_FIELD = /\.(email|phone|address|ssn|password|token|apiKey|api_key|secret|creditCard|card_?number)\b/i;
const REDACTION_MARKER = /redact|mask\(|sanitize|scrub|anonymiz/i;

const CONSENT_DESTRUCTURE = /\b(?:const|let)\s*\{[^}]*\b(?:email|phone|ssn|address)\b[^}]*\}\s*=\s*(?:req|request)\.body/gi;
const CONSENT_MARKER = /consent|opt[_-]?in|agree(?:d)?ToTerms/i;

const STORE_CALL = /\.(?:save|insert|create|put)\s*\(\s*\{([^}]{0,200})\}/gi;
const ENCRYPTION_FIELD_MARKER = /encrypt|cipher|kms\.|sealField/i;

const HTTP_SEND_CALL = /(?:fetch|axios\.\w+|http\.request)\s*\(\s*['"]http:\/\/[^'"]+['"][^;\n]{0,200}/gi;

const BACKUP_FILE_GUARD = /backup/i;

const EXPORT_FUNCTION = /(?:export|download)\w*\s*\([^)]{0,120}\)\s*\{[^}]{0,200}/gi;
const EXPORT_CONTROL_MARKER = /authorize|requireRole|redact|mask\(/i;

const RETENTION_MARKER = /retention[_-]?period|\bttl\b|expiresAt|purgeAfter|deleteAfter|retention[_-]?policy/i;

const ERASURE_MARKER = /deleteUser|eraseUser|purgeUser|anonymizeUser|dataErasure|rightToErasure/i;

const TENANT_QUERY_CALL = /\.(?:find|findOne|findAll|query)\s*\(\s*\{([^}]{0,150})\}/gi;
const TENANT_SCOPE_FIELD = /tenant[_-]?id|organization[_-]?id|org[_-]?id/i;
const MULTI_TENANT_MARKER = /tenant[_-]?id|organization[_-]?id|org[_-]?id/i;

const PRIVACY_CLAIM = /we\s+(?:do\s+not|don't|never)\s+(sell|share|store|track|collect|retain)\b[^.\n]{0,80}/gi;
const CONTRADICTION_BY_VERB = {
  sell: /third[_-]?party|dataBroker|sellData/i,
  share: /segment\.track|mixpanel\.track|fbq\(|partner(?:Api|Share)/i,
  store: /\.(?:save|insert|create)\s*\(/i,
  track: /ga\(|gtag\(|mixpanel\.track|segment\.track|fbq\(/i,
  collect: /ga\(|gtag\(|mixpanel\.track|segment\.track|fbq\(/i,
  retain: /\.(?:save|insert|create)\s*\(/i,
};
const LIFECYCLE_BY_VERB = { sell: 'export', share: 'export', store: 'store', track: 'collect', collect: 'collect', retain: 'retain' };

const RULES = [
  {
    id: 'privacy.log.sensitive-data-unredacted',
    lifecycleStage: 'process',
    baseSeverity: 'high',
    detect(context) {
      const found = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const artifact = findArtifact(context, file);
        LOG_CALL.lastIndex = 0;
        let m;
        while ((m = LOG_CALL.exec(text)) !== null) {
          if (!LOG_SENSITIVE_FIELD.test(m[1])) continue;
          if (REDACTION_MARKER.test(m[0])) continue;
          const field = LOG_SENSITIVE_FIELD.exec(m[1])[1];
          const gate = classificationGate(context, file, m[0], this.baseSeverity);
          found.push({
            file, line: lineOf(text, m.index), artifact, gate,
            claim: `A log statement writes a sensitive field (${field}) without a visible redaction call.`,
            uncertainty: ['A log-pipeline redaction/scrubbing filter applied outside this call site is not visible from this file alone.', ...gate.uncertainty],
            matchDigest: digest(m[0] + file + m.index),
          });
        }
      }
      return found;
    },
    build(f) {
      return makeObservation({
        ruleId: this.id, claim: f.claim, severityHint: f.gate.severityHint,
        dataClass: f.gate.dataClass, lifecycleStage: this.lifecycleStage, classificationObserved: f.gate.classificationObserved,
        file: f.file, line: f.line, artifact: f.artifact,
        effectKind: 'confidentiality-impact', effectAction: 'read', effectScope: 'log-output',
        chainRoles: ['starter', 'impact'], uncertainty: f.uncertainty,
      });
    },
  },
  {
    id: 'privacy.collect.pii-without-consent',
    lifecycleStage: 'collect',
    baseSeverity: 'medium',
    detect(context) {
      const found = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const artifact = findArtifact(context, file);
        if (CONSENT_MARKER.test(text)) continue;
        CONSENT_DESTRUCTURE.lastIndex = 0;
        let m;
        while ((m = CONSENT_DESTRUCTURE.exec(text)) !== null) {
          const gate = classificationGate(context, file, m[0], this.baseSeverity);
          found.push({
            file, line: lineOf(text, m.index), artifact, gate,
            claim: 'Personal data fields are read from a request body with no visible consent capture in this file.',
            uncertainty: ['A consent-capture step upstream (e.g. a form-level opt-in) is not visible from this file alone.', ...gate.uncertainty],
            matchDigest: digest(m[0] + file + m.index),
          });
        }
      }
      return found;
    },
    build(f) {
      return makeObservation({
        ruleId: this.id, claim: f.claim, severityHint: f.gate.severityHint,
        dataClass: f.gate.dataClass, lifecycleStage: this.lifecycleStage, classificationObserved: f.gate.classificationObserved,
        file: f.file, line: f.line, artifact: f.artifact,
        effectKind: 'data-access', effectAction: 'collect', effectScope: 'pii-collection',
        chainRoles: ['starter'], uncertainty: f.uncertainty,
      });
    },
  },
  {
    id: 'privacy.store.unencrypted-pii',
    lifecycleStage: 'store',
    baseSeverity: 'high',
    detect(context) {
      const found = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const artifact = findArtifact(context, file);
        STORE_CALL.lastIndex = 0;
        let m;
        while ((m = STORE_CALL.exec(text)) !== null) {
          if (!/\b(?:email|phone|address|ssn|creditCard|card_?number|password)\b/i.test(m[1])) continue;
          if (ENCRYPTION_FIELD_MARKER.test(windowAround(text, m.index, m[0].length, 150))) continue;
          const gate = classificationGate(context, file, m[1], this.baseSeverity);
          found.push({
            file, line: lineOf(text, m.index), artifact, gate,
            claim: 'A persistence call writes a sensitive field with no visible field-level encryption.',
            uncertainty: ['Encryption applied at the storage/driver layer rather than the field level is not visible from this call site alone.', ...gate.uncertainty],
            matchDigest: digest(m[0] + file + m.index),
          });
        }
      }
      return found;
    },
    build(f) {
      return makeObservation({
        ruleId: this.id, claim: f.claim, severityHint: f.gate.severityHint,
        dataClass: f.gate.dataClass, lifecycleStage: this.lifecycleStage, classificationObserved: f.gate.classificationObserved,
        file: f.file, line: f.line, artifact: f.artifact,
        effectKind: 'confidentiality-impact', effectAction: 'persist-unencrypted', effectScope: 'pii-storage',
        chainRoles: ['enabler', 'impact'], uncertainty: f.uncertainty,
      });
    },
  },
  {
    id: 'privacy.transmit.unencrypted-channel',
    lifecycleStage: 'transmit',
    baseSeverity: 'high',
    detect(context) {
      const found = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const artifact = findArtifact(context, file);
        HTTP_SEND_CALL.lastIndex = 0;
        let m;
        while ((m = HTTP_SEND_CALL.exec(text)) !== null) {
          if (!/\b(?:email|phone|address|ssn|password|token)\b/i.test(m[0])) continue;
          const gate = classificationGate(context, file, m[0], this.baseSeverity);
          found.push({
            file, line: lineOf(text, m.index), artifact, gate,
            claim: 'Sensitive data appears to be sent over a plaintext http:// channel.',
            uncertainty: ['A transport-level TLS-terminating proxy in front of this endpoint is not visible from source alone.', ...gate.uncertainty],
            matchDigest: digest(m[0] + file + m.index),
          });
        }
      }
      return found;
    },
    build(f) {
      return makeObservation({
        ruleId: this.id, claim: f.claim, severityHint: f.gate.severityHint,
        dataClass: f.gate.dataClass, lifecycleStage: this.lifecycleStage, classificationObserved: f.gate.classificationObserved,
        file: f.file, line: f.line, artifact: f.artifact,
        effectKind: 'confidentiality-impact', effectAction: 'intercept', effectScope: 'unencrypted-transmission',
        chainRoles: ['starter', 'impact'], uncertainty: f.uncertainty,
      });
    },
  },
  {
    id: 'privacy.retain.unbounded-retention',
    lifecycleStage: 'retain',
    baseSeverity: 'medium',
    detect(context) {
      const combined = context.files.map((f) => context.readFile(f) ?? '').join('\n');
      const hasPiiStorage = /\.(?:save|insert|create|put)\s*\(\s*\{[^}]{0,200}\b(?:email|phone|address|ssn|creditCard)\b/i.test(combined);
      if (!hasPiiStorage) return [];
      if (RETENTION_MARKER.test(combined)) return [];
      const gate = classificationGate(context, null, combined, this.baseSeverity);
      return [{
        file: null, line: null, artifact: null, gate,
        claim: 'Personal data storage was observed with no visible retention period or purge policy anywhere in the scanned surface.',
        uncertainty: ['A retention policy enforced by an external data-lifecycle system is not visible from this repository alone.', ...gate.uncertainty],
        matchDigest: digest('retention-absent'),
      }];
    },
    build(f) {
      return makeObservation({
        ruleId: this.id, claim: f.claim, severityHint: f.gate.severityHint,
        dataClass: f.gate.dataClass, lifecycleStage: this.lifecycleStage, classificationObserved: f.gate.classificationObserved,
        file: f.file, line: f.line, artifact: null,
        extraMeta: { scope: 'repository' },
        effectKind: 'persistence', effectAction: 'retain-indefinitely', effectScope: 'unbounded-retention',
        chainRoles: ['enabler'], uncertainty: f.uncertainty,
        evidenceRefs: this._repoRefs,
      });
    },
  },
  {
    id: 'privacy.retain.backup-unencrypted',
    lifecycleStage: 'retain',
    baseSeverity: 'high',
    detect(context) {
      const found = [];
      for (const file of context.files) {
        if (!BACKUP_FILE_GUARD.test(file)) continue;
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        if (!/\b(?:email|phone|address|ssn|creditCard|password)\b/i.test(text)) continue;
        if (ENCRYPTION_FIELD_MARKER.test(text)) continue;
        const artifact = findArtifact(context, file);
        const gate = classificationGate(context, file, text, this.baseSeverity);
        found.push({
          file, line: 1, artifact, gate,
          claim: 'A backup artifact references sensitive fields with no visible encryption marker.',
          uncertainty: ['Encryption applied by the backup storage layer itself (e.g. an encrypted bucket) is not visible from this file alone.', ...gate.uncertainty],
          matchDigest: digest('backup:' + file),
        });
      }
      return found;
    },
    build(f) {
      return makeObservation({
        ruleId: this.id, claim: f.claim, severityHint: f.gate.severityHint,
        dataClass: f.gate.dataClass, lifecycleStage: this.lifecycleStage, classificationObserved: f.gate.classificationObserved,
        file: f.file, line: f.line, artifact: f.artifact,
        effectKind: 'confidentiality-impact', effectAction: 'read', effectScope: 'unencrypted-backup',
        chainRoles: ['enabler', 'impact'], uncertainty: f.uncertainty,
      });
    },
  },
  {
    id: 'privacy.export.unrestricted-data-export',
    lifecycleStage: 'export',
    baseSeverity: 'high',
    detect(context) {
      const found = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const artifact = findArtifact(context, file);
        EXPORT_FUNCTION.lastIndex = 0;
        let m;
        while ((m = EXPORT_FUNCTION.exec(text)) !== null) {
          if (!/\b(?:email|phone|address|ssn|creditCard|users?)\b/i.test(m[0])) continue;
          if (EXPORT_CONTROL_MARKER.test(m[0])) continue;
          const gate = classificationGate(context, file, m[0], this.baseSeverity);
          found.push({
            file, line: lineOf(text, m.index), artifact, gate,
            claim: 'A data-export function includes personal data fields with no visible authorization or redaction control.',
            uncertainty: ['An authorization check enforced by route middleware rather than inside this function is not visible from this file alone.', ...gate.uncertainty],
            matchDigest: digest(m[0] + file + m.index),
          });
        }
      }
      return found;
    },
    build(f) {
      return makeObservation({
        ruleId: this.id, claim: f.claim, severityHint: f.gate.severityHint,
        dataClass: f.gate.dataClass, lifecycleStage: this.lifecycleStage, classificationObserved: f.gate.classificationObserved,
        file: f.file, line: f.line, artifact: f.artifact,
        effectKind: 'confidentiality-impact', effectAction: 'export', effectScope: 'unrestricted-export',
        chainRoles: ['starter', 'impact'], uncertainty: f.uncertainty,
      });
    },
  },
  {
    id: 'privacy.delete.no-erasure-path',
    lifecycleStage: 'delete',
    baseSeverity: 'medium',
    detect(context) {
      const combined = context.files.map((f) => context.readFile(f) ?? '').join('\n');
      const hasPiiStorage = /\.(?:save|insert|create|put)\s*\(\s*\{[^}]{0,200}\b(?:email|phone|address|ssn|creditCard)\b/i.test(combined);
      if (!hasPiiStorage) return [];
      if (ERASURE_MARKER.test(combined)) return [];
      const gate = classificationGate(context, null, combined, this.baseSeverity);
      return [{
        file: null, line: null, artifact: null, gate,
        claim: 'Personal data storage was observed with no visible deletion/erasure function anywhere in the scanned surface.',
        uncertainty: ['A deletion path implemented in an external service (e.g. a data-processor callback) is not visible from this repository alone.', ...gate.uncertainty],
        matchDigest: digest('erasure-absent'),
      }];
    },
    build(f) {
      return makeObservation({
        ruleId: this.id, claim: f.claim, severityHint: f.gate.severityHint,
        dataClass: f.gate.dataClass, lifecycleStage: this.lifecycleStage, classificationObserved: f.gate.classificationObserved,
        file: f.file, line: f.line, artifact: null,
        extraMeta: { scope: 'repository' },
        effectKind: 'persistence', effectAction: 'retain-without-erasure-path', effectScope: 'missing-erasure',
        chainRoles: ['enabler'], uncertainty: f.uncertainty,
        evidenceRefs: this._repoRefs,
      });
    },
  },
  {
    id: 'privacy.process.tenant-data-crossover',
    lifecycleStage: 'process',
    baseSeverity: 'high',
    detect(context) {
      const combined = context.files.map((f) => context.readFile(f) ?? '').join('\n');
      if (!MULTI_TENANT_MARKER.test(combined)) return [];
      const found = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const artifact = findArtifact(context, file);
        TENANT_QUERY_CALL.lastIndex = 0;
        let m;
        while ((m = TENANT_QUERY_CALL.exec(text)) !== null) {
          if (TENANT_SCOPE_FIELD.test(m[1])) continue;
          const gate = classificationGate(context, file, m[1] || 'tenant-scoped-data', this.baseSeverity);
          found.push({
            file, line: lineOf(text, m.index), artifact, gate,
            claim: 'A data-store query has no visible tenant/organization scoping filter, though tenant scoping is used elsewhere in the repository.',
            uncertainty: ['Tenant scoping enforced by a query middleware/interceptor rather than inline in this call is not visible from this call site alone.', ...gate.uncertainty],
            matchDigest: digest(m[0] + file + m.index),
          });
        }
      }
      return found;
    },
    build(f) {
      return makeObservation({
        ruleId: this.id, claim: f.claim, severityHint: f.gate.severityHint,
        dataClass: f.gate.dataClass, lifecycleStage: this.lifecycleStage, classificationObserved: f.gate.classificationObserved,
        file: f.file, line: f.line, artifact: f.artifact,
        effectKind: 'confidentiality-impact', effectAction: 'read', effectScope: 'cross-tenant-data-access',
        chainRoles: ['starter', 'impact'], uncertainty: f.uncertainty,
      });
    },
  },
  {
    id: 'privacy.claim.marketing-mismatch',
    lifecycleStage: 'store',
    baseSeverity: 'medium',
    detect(context) {
      const found = [];
      const combined = context.files.map((f) => context.readFile(f) ?? '').join('\n');
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const artifact = findArtifact(context, file);
        PRIVACY_CLAIM.lastIndex = 0;
        let m;
        while ((m = PRIVACY_CLAIM.exec(text)) !== null) {
          const verb = m[1].toLowerCase();
          const contradiction = CONTRADICTION_BY_VERB[verb];
          if (!contradiction || !contradiction.test(combined)) continue;
          const lifecycleStage = LIFECYCLE_BY_VERB[verb] ?? 'store';
          const gate = classificationGate(context, file, m[0], this.baseSeverity);
          const claimArtifact = context.projection?.auditFacts?.claimProof?.claims?.find(
            (c) => c?.file === file && typeof c?.text === 'string' && c.text.includes(m[0]),
          );
          found.push({
            file, line: lineOf(text, m.index), artifact, gate, lifecycleStage,
            claim: `A privacy claim ("${m[0].trim()}") appears alongside behavior in the repository that may contradict it.`,
            claimRefs: claimArtifact ? [claimArtifact.id] : [],
            uncertainty: [
              ...gate.uncertainty,
              claimArtifact
                ? 'Cross-linked to a recorded claim-proof artifact; the contradiction itself is still subject to adjudication.'
                : 'No claim-proof/copy artifact was available to cross-link this claim; the reference is a same-file lexical location only.',
            ],
            matchDigest: digest(m[0] + file + m.index),
          });
        }
      }
      return found;
    },
    build(f) {
      return makeObservation({
        ruleId: this.id, claim: f.claim, severityHint: f.gate.severityHint,
        dataClass: f.gate.dataClass, lifecycleStage: f.lifecycleStage, classificationObserved: f.gate.classificationObserved,
        file: f.file, line: f.line, artifact: f.artifact,
        extraMeta: { claimRefs: f.claimRefs },
        effectKind: 'integrity-impact', effectAction: 'contradict-disclosed-claim', effectScope: 'privacy-claim-mismatch',
        chainRoles: ['enabler'], uncertainty: f.uncertainty,
      });
    },
  },
];

function buildVariantStrategy(rule) {
  return {
    rootCause(candidate) {
      return {
        class: `${rule.id}-gap`,
        lifecycleStage: rule.lifecycleStage,
        dataClass: candidate.detectorMetadata?.dataClass ?? null,
        semanticFeatures: [rule.lifecycleStage, candidate.detectorMetadata?.dataClass ?? rule.id],
      };
    },
    enumerate(context) {
      const findings = rule.detect(context);
      const matches = findings.map((f) => ({
        file: f.file ?? 'repository',
        line: f.line ?? 0,
        semanticFingerprint: f.matchDigest,
        disposition: 'CONFIRMED',
      }));
      return {
        denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
        strategies: [{
          id: `${rule.id}-search`, kind: 'lexical-fallback',
          description: `Enumerate every ${rule.lifecycleStage}-stage finding for ${rule.id} across the denominator.`,
          queryDigest: digest(rule.id), complete: true, coverageGaps: [],
        }],
        matches,
        coverageGaps: [],
      };
    },
  };
}

export default Object.freeze({
  id: 'security.data-privacy',
  version: '1.0.0',
  candidateClass: 'data-privacy',
  description: 'Sensitive-data lifecycle handling: logs, collection, storage, transmission, retention, backups, export, tenant separation, and privacy-claim mismatch.',
  rules: RULES.map((rule) => ({ id: rule.id })),
  analyze(context) {
    const observations = [];
    for (const rule of RULES) {
      rule._repoRefs = repoWideEvidenceRefs(context);
      const findings = rule.detect(context);
      for (const f of findings) {
        observations.push(rule.build(f));
      }
    }
    return observations;
  },
  variantStrategies: Object.fromEntries(RULES.map((rule) => [rule.id, buildVariantStrategy(rule)])),
});
