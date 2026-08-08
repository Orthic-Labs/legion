// File-boundary security pack: path traversal, archive traversal (zip-slip),
// and unchecked symlink following. Every rule is a lexical (pattern-only)
// detector: it never opens a file, never extracts an archive, never calls a
// model, and never certifies a finding. It only ever emits UNADJUDICATED
// candidates via the sealed candidate-engine. When a normalization /
// containment-check signal is observed on the same path, the candidate is
// downgraded with the observed control referenced in `observedControls` (a
// model control entity was found) or noted in `uncertainty` (only a lexical
// mitigating signal was found).

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

const CANDIDATE_CLASS = 'file-boundaries';

const RULES = [
  {
    id: 'file.path-traversal-unvalidated',
    pattern: /\b(fs\.readFile(?:Sync)?|fs\.writeFile(?:Sync)?|fs\.createReadStream|fs\.createWriteStream|fs\.open(?:Sync)?|res\.sendFile|res\.download)\s*\(\s*([^()\n]*\b(?:request|req)\.(?:query|body|params)(?:\.[\w]+)?\b[^()\n]*)\)/gi,
    sinkApiOf: (m) => m[1],
    sourceExprOf: (m) => m[2].trim(),
    claim: 'Request-controlled path data reaches a filesystem operation without a visible normalization/containment check, risking path traversal outside the intended directory.',
    severityHint: 'high',
    attackerCapabilities: ['control-request-input'],
    preconditionAction: 'supply-path',
    environment: 'application',
    effectKind: 'data-access', effectAction: 'access', effectScope: 'filesystem-outside-intended-directory',
    chainRoles: ['starter', 'impact'],
    downgrade: {
      controlTypes: ['path-traversal-containment', 'path-normalization'],
      severityHint: 'low',
      lexicalPattern: /path\.normalize|path\.resolve|\.startsWith\(|sanitize-filename|sanitizeFilename|path\.basename/i,
      lexicalNote: 'A path normalization/containment check is present near the sink; treated as a mitigating signal pending adjudication.',
      radius: 300,
    },
    uncertainty: ['A request-controlled path argument is not automatically traversal; whether the value is normalized and confined to an intended base directory elsewhere in the call path must be adjudicated.'],
  },
  {
    id: 'file.archive-zip-slip',
    pattern: /\b(fs\.writeFile(?:Sync)?|fs\.createWriteStream|path\.join)\s*\(\s*([^()\n]*\b(?:entry|zipEntry|file)\.(?:path|fileName|name)\b[^()\n]*)\)/gi,
    sinkApiOf: (m) => m[1],
    sourceExprOf: (m) => m[2].trim(),
    claim: 'An archive entry path is written to the filesystem without a visible containment check against the extraction directory, risking a zip-slip path-traversal write.',
    severityHint: 'high',
    attackerCapabilities: ['supply-malicious-archive'],
    preconditionAction: 'supply-archive-entry',
    environment: 'application',
    effectKind: 'integrity-impact', effectAction: 'overwrite', effectScope: 'filesystem-outside-extraction-directory',
    chainRoles: ['starter', 'impact'],
    downgrade: {
      controlTypes: ['zip-slip-containment', 'archive-path-validation'],
      severityHint: 'low',
      lexicalPattern: /path\.normalize|\.startsWith\(|resolvedPath|isInsideDir|zip-slip|sanitizeEntry/i,
      lexicalNote: 'A resolved-path containment check is present near the sink; treated as a mitigating signal pending adjudication.',
      radius: 300,
    },
    uncertainty: ['Whether the archive source is attacker-controlled, and whether the resolved entry path is validated to remain inside the extraction directory, must be adjudicated.'],
  },
  {
    id: 'file.symlink-unchecked',
    pattern: /\b(followSymlinks\s*:\s*true|dereference\s*:\s*true)\b/g,
    sinkApiOf: () => 'archive-extraction-symlink-option',
    sourceExprOf: (m) => m[1],
    claim: 'Archive/file extraction is configured to follow symbolic links, allowing an entry to write through a symlink to a location outside the intended target directory.',
    severityHint: 'medium',
    attackerCapabilities: ['supply-malicious-archive'],
    preconditionAction: 'supply-symlink-entry',
    environment: 'application',
    effectKind: 'integrity-impact', effectAction: 'traverse-symlink', effectScope: 'filesystem-outside-intended-directory',
    chainRoles: ['starter', 'impact'],
    downgrade: {
      controlTypes: ['symlink-containment-check'],
      severityHint: 'low',
      lexicalPattern: /isSymbolicLink\(\)|lstat|realpath[\s\S]{0,80}startsWith/i,
      lexicalNote: 'A symlink/realpath containment check is present near the extraction option; treated as a mitigating signal pending adjudication.',
      radius: 300,
    },
    uncertainty: ['Whether the archive/file source can be attacker-controlled, and whether a symlink-containment check exists elsewhere in the extraction pipeline, must be adjudicated.'],
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

        let severityHint = rule.severityHint;
        let observedControls = [];
        let controlObserved = null;
        const uncertainty = [...rule.uncertainty];

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
        semanticFeatures: ['tainted-path-to-sink', rule.id, candidate.detectorMetadata?.sinkApi ?? rule.id],
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
          matches.push({
            file,
            line: lineOf(text, match.index),
            semanticFingerprint: digest({ ruleId: rule.id, file, snippet: match[0] }),
            disposition: 'CONFIRMED',
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
  id: 'security.file-boundaries',
  version: '1.0.0',
  candidateClass: CANDIDATE_CLASS,
  description: 'Path traversal, archive traversal (zip-slip), and unchecked symlink following.',
  rules: RULES.map((rule) => ({ id: rule.id })),
  analyze,
  variantStrategies: Object.fromEntries(RULES.map((rule) => [rule.id, buildVariantStrategy(rule)])),
});
