// Request-boundary security pack: type/length/format validation gaps, body
// size limits, mass-assignment of unexpected fields, and response header
// injection. Every rule is a lexical (pattern-only) detector: it never sends
// a request, never runs a payload, never calls a model, and never certifies
// a finding. It only ever emits UNADJUDICATED candidates via the sealed
// candidate-engine. When a validation/allowlist/sanitization signal is
// observed on the same path, the candidate is downgraded with the observed
// control referenced in `observedControls` (a model control entity was
// found) or noted in `uncertainty` (only a lexical mitigating signal was
// found) — it is never silently hidden once a match exists.

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

const CANDIDATE_CLASS = 'request-boundaries';

// Excludes control-flow keywords so `if (request.query.x)` is not read as a
// call to a sink named "if".
const NOT_KEYWORD = '(?:if|for|while|switch|catch|function|return)';

const RULES = [
  {
    id: 'request.unvalidated-input-to-sink',
    pattern: new RegExp(`\\b(?!${NOT_KEYWORD}\\b)([A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*)\\(\\s*([^()\\n]*\\b(?:request|req)\\.(?:query|body|params)(?:\\.[\\w]+)?\\b[^()\\n]*)\\)`, 'g'),
    sinkApiOf: (m) => m[1],
    sourceExprOf: (m) => m[2].trim(),
    claim: 'Request-derived data reaches an operation without a visible type/length/format validation step.',
    severityHint: 'medium',
    attackerCapabilities: ['control-request-input'],
    preconditionAction: 'supply-input',
    environment: 'application',
    effectKind: 'control-bypass', effectAction: 'bypass', effectScope: 'input-validation-boundary',
    chainRoles: ['starter', 'enabler'],
    downgrade: {
      controlTypes: ['request-schema-validation', 'input-validation'],
      severityHint: 'low',
      lexicalPattern: /\b(?:joi|zod|yup|ajv|celebrate|schema\.(?:parse|validate)|validate\()/i,
      lexicalNote: 'A schema-validation call is present near this input use; treated as a mitigating signal pending adjudication.',
      radius: 300,
    },
    uncertainty: ['An unvalidated call argument is not automatically exploitable; the sink\'s own handling of malformed input must be adjudicated.'],
  },
  {
    id: 'request.body-size-unbounded',
    pattern: /\b(express\.json|express\.urlencoded|bodyParser\.json|bodyParser\.urlencoded)\s*\(\s*(\{[^{}]*\})?\s*\)/g,
    sinkApiOf: (m) => m[1],
    sourceExprOf: () => 'http-request-body',
    customSuppress: (m) => Boolean(m[2] && /\blimit\s*:/.test(m[2])),
    claim: 'A request body parser is configured without a visible size limit, allowing an oversized request body to be accepted.',
    severityHint: 'medium',
    attackerCapabilities: ['control-request-input'],
    preconditionAction: 'supply-oversized-body',
    environment: 'application',
    effectKind: 'availability-impact', effectAction: 'exhaust', effectScope: 'request-body-parsing',
    chainRoles: ['starter', 'impact'],
    uncertainty: ['Whether an upstream proxy or platform default already enforces a body size cap is not visible from source.'],
  },
  {
    id: 'request.mass-assignment-unfiltered',
    pattern: /(?<sinkAssign>Object\.assign)\s*\(\s*(?<target>[\w.$]+)\s*,\s*(?<srcAssign>(?:request|req)\.body)\s*\)|\.(?<sinkMethod>update|create)\s*\(\s*(?<srcMethod>(?:request|req)\.body)\s*\)|(?<sinkSpread>\{\s*\.\.\.(?<srcSpread>(?:request|req)\.body)\s*\})/g,
    sinkApiOf: (m) => m.groups.sinkAssign ?? (m.groups.sinkMethod ? `.${m.groups.sinkMethod}` : null) ?? 'object-spread',
    sourceExprOf: (m) => m.groups.srcAssign ?? m.groups.srcMethod ?? m.groups.srcSpread,
    claim: 'Request body data is assigned directly onto a model/object without a field allowlist, risking mass assignment of unexpected fields.',
    severityHint: 'medium',
    attackerCapabilities: ['control-request-input'],
    preconditionAction: 'supply-unexpected-fields',
    environment: 'application',
    effectKind: 'integrity-impact', effectAction: 'assign', effectScope: 'object-model-fields',
    chainRoles: ['starter', 'impact'],
    downgrade: {
      controlTypes: ['mass-assignment-allowlist', 'field-allowlist'],
      severityHint: 'low',
      lexicalPattern: /\b(?:pick\(|omit\(|only\(|allowlist|whitelist)\b/i,
      lexicalNote: 'A field allowlist/pick call is present near the assignment; treated as a mitigating signal pending adjudication.',
      radius: 250,
    },
    uncertainty: ['Whether the target model/schema restricts which fields are actually persisted is not visible from this call alone.'],
  },
  {
    id: 'request.header-injection',
    pattern: /\bres\.(setHeader|header|set)\s*\(\s*[^,()\n]+,\s*((?:request|req)\.(?:query|body|params|headers)(?:\.[\w]+)?)[^)]*\)/g,
    sinkApiOf: (m) => `res.${m[1]}`,
    sourceExprOf: (m) => m[2],
    claim: 'A response header value is set directly from request-controlled data without a visible CRLF-sanitization step, risking header/response splitting.',
    severityHint: 'high',
    attackerCapabilities: ['control-request-input'],
    preconditionAction: 'supply-header-value',
    environment: 'application',
    effectKind: 'control-bypass', effectAction: 'inject', effectScope: 'http-response-header',
    chainRoles: ['starter', 'impact'],
    downgrade: {
      controlTypes: ['header-sanitization'],
      severityHint: 'low',
      lexicalPattern: /encodeURIComponent|sanitizeHeader/i,
      lexicalNote: 'A header-encoding call is present near the sink; treated as a mitigating signal pending adjudication.',
      radius: 200,
    },
    uncertainty: ['Modern HTTP libraries often reject raw CR/LF in header values at the framework level; whether this framework does so must be adjudicated.'],
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
          } else if (testWindow(rule.downgrade.lexicalPattern, text, match.index, match[0].length, rule.downgrade.radius ?? 250)) {
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
        semanticFeatures: ['tainted-input-to-sink', rule.id, candidate.detectorMetadata?.sinkApi ?? rule.id],
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
  id: 'security.request-boundaries',
  version: '1.0.0',
  candidateClass: CANDIDATE_CLASS,
  description: 'Request-boundary validation: type/length/format gaps, body size limits, mass assignment, and header injection.',
  rules: RULES.map((rule) => ({ id: rule.id })),
  analyze,
  variantStrategies: Object.fromEntries(RULES.map((rule) => [rule.id, buildVariantStrategy(rule)])),
});
