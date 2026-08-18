// Upload security pack: content-type validation, size caps, storage
// location, filename handling, and execution of uploaded content. Every rule
// is a lexical (pattern-only) detector: it never accepts a file, never
// writes to disk, never calls a model, and never certifies a finding. It
// only ever emits UNADJUDICATED candidates via the sealed candidate-engine.

import { digest } from '../contracts.mjs';

function findArtifact(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

function findRelatedControl(context, artifactId, controlTypes) {
  if (artifactId) {
    for (const rel of context.relationsTo(artifactId)) {
      if (rel.kind !== 'protects') continue;
      const control = context.entityById.get(rel.from);
      if (control?.kind === 'control' && controlTypes.includes(control.attributes?.controlType)) return control;
    }
  }
  return context.model.entities.find((e) => e.kind === 'control' && controlTypes.includes(e.attributes?.controlType)) ?? null;
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

function windowAround(text, index, matchLength, radius) {
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + matchLength + radius);
  return text.slice(start, end);
}

function testWindow(pattern, text, index, matchLength, radius) {
  if (!pattern) return false;
  return pattern.test(windowAround(text, index, matchLength, radius));
}

const CANDIDATE_CLASS = 'uploads';
const UPLOAD_MIDDLEWARE = /\b(multer|formidable|busboy)\s*\(\s*(\{[^{}]*\})?\s*\)/gi;

const RULES = [
  {
    id: 'upload.content-type-unvalidated',
    pattern: new RegExp(UPLOAD_MIDDLEWARE.source, 'gi'),
    sinkApiOf: (m) => m[1],
    sourceExprOf: () => 'multipart-upload-stream',
    customSuppress: (m) => Boolean(m[2] && /\b(?:fileFilter|mimetype|accept)\s*:/i.test(m[2])),
    claim: 'An upload handler is configured without a visible content-type/MIME allowlist (fileFilter), accepting any uploaded file type.',
    severityHint: 'medium',
    attackerCapabilities: ['supply-upload-content'],
    preconditionAction: 'supply-upload',
    environment: 'application',
    effectKind: 'integrity-impact', effectAction: 'accept-unvalidated-type', effectScope: 'upload-content-type',
    chainRoles: ['starter', 'enabler'],
    uncertainty: ['Absence of a fileFilter in this call does not prove no validation exists; it may be applied in a separate middleware step.'],
  },
  {
    id: 'upload.size-unbounded',
    pattern: new RegExp(UPLOAD_MIDDLEWARE.source, 'gi'),
    sinkApiOf: (m) => m[1],
    sourceExprOf: () => 'multipart-upload-stream',
    customSuppress: (m) => Boolean(m[2] && /\b(?:limits|maxFileSize|fileSize)\s*:/i.test(m[2])),
    claim: 'An upload handler is configured without a visible size cap (limits/maxFileSize), allowing an oversized upload to exhaust disk or memory.',
    severityHint: 'medium',
    attackerCapabilities: ['supply-upload-content'],
    preconditionAction: 'supply-oversized-upload',
    environment: 'application',
    effectKind: 'availability-impact', effectAction: 'exhaust', effectScope: 'upload-storage',
    chainRoles: ['starter', 'impact'],
    uncertainty: ['Absence of a size limit in this call does not prove no cap exists; it may be enforced by an upstream proxy or platform default.'],
  },
  {
    id: 'upload.storage-in-webroot',
    pattern: /\bdestination\s*:\s*['"`]([^'"`]*(?:public|static|www|assets)[^'"`]*)['"`]/gi,
    sinkApiOf: () => 'upload-destination-config',
    sourceExprOf: (m) => m[1],
    claim: 'Uploaded files are stored inside a publicly web-served directory, making any uploaded content directly retrievable — and potentially executable — by URL.',
    severityHint: 'high',
    attackerCapabilities: ['supply-upload-content'],
    preconditionAction: 'supply-upload',
    environment: 'application',
    effectKind: 'data-access', effectAction: 'expose', effectScope: 'public-web-root',
    chainRoles: ['starter', 'impact'],
    uncertainty: ['Whether the web server actually serves this directory statically, and whether execution of uploaded content is possible, must be adjudicated.'],
  },
  {
    id: 'upload.filename-unsanitized',
    pattern: /\b(fs\.writeFile(?:Sync)?|fs\.rename(?:Sync)?|path\.join)\s*\(\s*([^()\n]*\.originalname\b[^()\n]*)\)/gi,
    sinkApiOf: (m) => m[1],
    sourceExprOf: () => 'file.originalname',
    claim: 'The original uploaded filename is used directly to construct a storage path without visible sanitization, risking path traversal or overwrite via a crafted filename.',
    severityHint: 'high',
    attackerCapabilities: ['supply-upload-content'],
    preconditionAction: 'supply-crafted-filename',
    environment: 'application',
    effectKind: 'data-access', effectAction: 'write', effectScope: 'filesystem-outside-intended-directory',
    chainRoles: ['starter', 'impact'],
    downgrade: {
      controlTypes: ['filename-sanitization'],
      severityHint: 'low',
      lexicalPattern: /sanitize-filename|sanitizeFilename|path\.basename|uuid\(|crypto\.randomUUID|randomBytes/i,
      lexicalNote: 'A filename-sanitization/rename call is present near the sink; treated as a mitigating signal pending adjudication.',
      radius: 200,
    },
    uncertainty: ['Whether the filename is sanitized or replaced elsewhere in the pipeline before this call must be adjudicated.'],
  },
  {
    id: 'upload.executable-content-served',
    pattern: /\bexpress\.static\s*\(\s*([^()\n]*upload[^()\n]*)\)/gi,
    sinkApiOf: () => 'express.static',
    sourceExprOf: (m) => m[1].trim(),
    claim: 'An upload directory is served as static content, allowing any successfully uploaded file (including scripts or HTML) to be directly requested and potentially executed by a browser or misconfigured server.',
    severityHint: 'high',
    attackerCapabilities: ['supply-upload-content'],
    preconditionAction: 'supply-executable-upload',
    environment: 'application',
    effectKind: 'code-execution', effectAction: 'serve', effectScope: 'uploaded-content',
    chainRoles: ['starter', 'impact'],
    downgrade: {
      controlTypes: ['content-disposition-attachment'],
      severityHint: 'low',
      lexicalPattern: /Content-Disposition[\s\S]{0,40}attachment|contentDisposition\(|setHeader\(\s*['"]Content-Disposition['"]/i,
      lexicalNote: 'A Content-Disposition: attachment control is present near the static-serving configuration; treated as a mitigating signal pending adjudication.',
      radius: 300,
    },
    uncertainty: ['Whether the web server executes served files (e.g. via a misconfigured handler) as opposed to merely serving them as static bytes must be adjudicated.'],
  },
];

function analyze(context) {
  const observations = [];
  for (const file of context.files) {
    const text = context.readFile(file) ?? '';
    if (!text) continue;
    const artifact = findArtifact(context, file);
    for (const rule of RULES) {
      rule.pattern.lastIndex = 0;
      let match;
      while ((match = rule.pattern.exec(text)) !== null) {
        if (match[0].length === 0) { rule.pattern.lastIndex += 1; continue; }
        if (rule.customSuppress && rule.customSuppress(match, text)) continue;

        let severityHint = rule.severityHint;
        let observedControls = [];
        let controlObserved = null;
        const uncertainty = [...rule.uncertainty];

        if (rule.downgrade) {
          const control = findRelatedControl(context, artifact?.id, rule.downgrade.controlTypes);
          if (control) {
            severityHint = rule.downgrade.severityHint;
            observedControls = [control.id];
            controlObserved = control.name;
            uncertainty.push(`Observed ${control.attributes?.controlType ?? 'mitigating'} control (${control.name}) on this path; downgraded pending adjudication of coverage completeness.`);
          } else if (testWindow(rule.downgrade.lexicalPattern, text, match.index, match[0].length, rule.downgrade.radius)) {
            severityHint = rule.downgrade.severityHint;
            controlObserved = 'lexical-signal';
            uncertainty.push(rule.downgrade.lexicalNote);
          }
        }

        observations.push({
          ruleId: rule.id,
          candidateClass: CANDIDATE_CLASS,
          claim: rule.claim,
          severityHint,
          sources: artifact ? [artifact.id] : [],
          sinks: artifact ? [artifact.id] : [],
          attackerCapabilities: rule.attackerCapabilities,
          preconditions: [{
            kind: 'attacker-position', subject: 'actor:external', action: rule.preconditionAction,
            scope: null, environment: rule.environment, tenant: null,
          }],
          effects: [{
            kind: rule.effectKind, subject: 'actor:external', action: rule.effectAction,
            object: artifact?.id ?? null, scope: rule.effectScope, environment: rule.environment, tenant: null,
          }],
          assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls,
          chainRoles: rule.chainRoles,
          evidenceRefs: artifact?.evidenceRefs ?? [],
          detectorMetadata: {
            file,
            line: lineOf(text, match.index),
            sourceExpr: rule.sourceExprOf(match),
            sinkApi: rule.sinkApiOf(match),
            controlObserved,
            matchDigest: digest(match[0]),
          },
          uncertainty,
        });
      }
    }
  }
  return observations;
}

function buildVariantStrategy(rule) {
  return {
    rootCause(candidate) {
      return {
        class: `${rule.id}-unmitigated`,
        semanticFeatures: ['upload-boundary', rule.id, candidate.detectorMetadata?.sinkApi ?? rule.id],
      };
    },
    enumerate(context) {
      const matches = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        rule.pattern.lastIndex = 0;
        let match;
        while ((match = rule.pattern.exec(text)) !== null) {
          if (match[0].length === 0) { rule.pattern.lastIndex += 1; continue; }
          const suppressed = rule.customSuppress ? rule.customSuppress(match, text) : false;
          matches.push({
            file,
            line: lineOf(text, match.index),
            semanticFingerprint: digest({ ruleId: rule.id, file, snippet: match[0] }),
            disposition: suppressed ? 'MITIGATED' : 'CONFIRMED',
          });
        }
      }
      return {
        denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
        strategies: [{
          id: `${rule.id}-search`, kind: 'lexical-fallback',
          description: `Enumerate every ${rule.id} occurrence across the denominator.`,
          queryDigest: digest(rule.id), complete: true, coverageGaps: [],
        }],
        matches,
        coverageGaps: [],
      };
    },
  };
}

export default Object.freeze({
  id: 'security.uploads',
  version: '1.0.0',
  candidateClass: CANDIDATE_CLASS,
  description: 'Upload content-type validation, size caps, storage location, filename handling, and execution of uploaded content.',
  rules: RULES.map((rule) => ({ id: rule.id })),
  analyze,
  variantStrategies: Object.fromEntries(RULES.map((rule) => [rule.id, buildVariantStrategy(rule)])),
});
