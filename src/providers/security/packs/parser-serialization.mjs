// Parser/serialization security pack: unsafe deserialization, parser bombs
// (XML entity expansion / "billion laughs", decompression bombs), and
// unbounded recursive-descent parsing. Every rule is a lexical
// (pattern-only) detector: it never deserializes anything, never expands an
// archive, never calls a model, and never certifies a finding. It only ever
// emits UNADJUDICATED candidates via the sealed candidate-engine.

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

const CANDIDATE_CLASS = 'parser-serialization';
const XML_PARSER_FILE_GUARD = /libxmljs|lxml|DocumentBuilderFactory|expat|xml2js|xmldom|sax\b/i;

const RULES = [
  {
    id: 'parser.unsafe-deserialization',
    pattern: /\b(pickle\.loads|yaml\.load|ObjectInputStream|BinaryFormatter\.Deserialize|unserialize|Marshal\.load)\s*\(\s*([^()\n]*)\)/g,
    sinkApiOf: (m) => m[1],
    sourceExprOf: (m) => (m[2] ? m[2].trim() : 'input-stream') || 'input-stream',
    claim: 'An unsafe deserialization primitive is used, which can execute arbitrary code if the serialized input is attacker-controlled.',
    severityHint: 'high',
    attackerCapabilities: ['supply-serialized-input'],
    preconditionAction: 'supply-serialized-payload',
    environment: 'application',
    effectKind: 'code-execution', effectAction: 'execute', effectScope: 'deserialization-sink',
    chainRoles: ['starter', 'impact'],
    downgrade: {
      controlTypes: ['safe-deserialization'],
      severityHint: 'low',
      lexicalPattern: /SafeLoader|safe_load|CSafeLoader/i,
      lexicalNote: 'A safe-loader marker is present near the call; treated as a mitigating signal pending adjudication.',
      radius: 150,
    },
    uncertainty: ['Whether the deserialized bytes originate from an untrusted/attacker-reachable source must be adjudicated.'],
  },
  {
    id: 'parser.xml-billion-laughs',
    fileGuard: XML_PARSER_FILE_GUARD,
    pattern: /\b(expand_entities\s*=\s*True|resolve_entities\s*=\s*True|noent\s*:\s*true|DTDLOAD\s*:\s*true|FEATURE_SECURE_PROCESSING['"]?\s*,\s*false)\b/gi,
    sinkApiOf: () => 'xml-parser-entity-expansion',
    sourceExprOf: (m) => m[1],
    claim: 'An XML parser enables DTD/entity expansion without secure-processing limits, allowing a small malicious document to expand exponentially ("billion laughs") and exhaust memory/CPU.',
    severityHint: 'medium',
    attackerCapabilities: ['supply-xml-document'],
    preconditionAction: 'supply-xml-entity-payload',
    environment: 'application',
    effectKind: 'availability-impact', effectAction: 'exhaust', effectScope: 'xml-entity-expansion',
    chainRoles: ['starter', 'impact'],
    downgrade: {
      controlTypes: ['xml-entity-expansion-limit'],
      severityHint: 'low',
      lexicalPattern: /defusedxml|entity_expansion_limit|MAX_ENTITY|billionLaughsProtection|entityExpansionLimit/i,
      lexicalNote: 'An entity-expansion-limit guard is present near the parser configuration; treated as a mitigating signal pending adjudication.',
      radius: 250,
    },
    uncertainty: ['Whether attacker-controlled XML reaches this parser, and whether an upstream size/depth guard exists elsewhere in the pipeline, must be adjudicated.'],
  },
  {
    id: 'parser.decompression-bomb',
    pattern: /\b(zlib\.(?:gunzip|inflate|unzip)(?:Sync)?|gzip\.decompress|gzip\.GzipFile|tarfile\.open|tarfile\.extractall|zipfile\.ZipFile)\s*\(/g,
    sinkApiOf: (m) => m[1],
    sourceExprOf: () => 'compressed-input-stream',
    claim: 'A decompression call has no visible output-size limit, allowing a small compressed payload to expand into an unbounded amount of memory/disk (a decompression/zip bomb).',
    severityHint: 'medium',
    attackerCapabilities: ['supply-compressed-input'],
    preconditionAction: 'supply-compressed-payload',
    environment: 'application',
    effectKind: 'availability-impact', effectAction: 'exhaust', effectScope: 'decompression-output',
    chainRoles: ['starter', 'impact'],
    downgrade: {
      controlTypes: ['decompression-size-limit'],
      severityHint: 'low',
      lexicalPattern: /maxSize|maxOutputSize|decompressionBomb|ZipBombProtection|limit\s*:\s*\d+/i,
      lexicalNote: 'An output-size-limit guard is present near the decompression call; treated as a mitigating signal pending adjudication.',
      radius: 200,
    },
    uncertainty: ['Whether the compressed input is attacker-controlled, and whether an upstream limit exists elsewhere in the pipeline, must be adjudicated.'],
  },
  {
    id: 'parser.unbounded-recursion',
    pattern: /function\s+(\w*[Pp]arse\w*)\s*\(([^)]*)\)\s*\{[\s\S]{0,400}?\b\1\s*\(/g,
    scopeMatch: true,
    sinkApiOf: (m) => m[1],
    sourceExprOf: () => 'nested-input-structure',
    claim: 'A recursive parsing function calls itself with no visible depth limit, allowing deeply nested attacker-controlled input to exhaust the call stack (unbounded recursion / stack-overflow DoS).',
    severityHint: 'medium',
    attackerCapabilities: ['supply-nested-input'],
    preconditionAction: 'supply-deeply-nested-payload',
    environment: 'application',
    effectKind: 'availability-impact', effectAction: 'exhaust', effectScope: 'call-stack',
    chainRoles: ['starter', 'impact'],
    downgrade: {
      controlTypes: ['recursion-depth-limit'],
      severityHint: 'low',
      lexicalPattern: /maxDepth|depthLimit|MAX_DEPTH|depth\s*[<>]=?/i,
      lexicalNote: 'A depth-limit guard is present within the recursive function; treated as a mitigating signal pending adjudication.',
      radius: 0,
      matchScope: true,
    },
    uncertainty: ['Whether the parsed structure\'s nesting depth is attacker-controlled and unbounded upstream must be adjudicated.'],
  },
];

function analyze(context) {
  const observations = [];
  for (const file of context.files) {
    const text = context.readFile(file) ?? '';
    if (!text) continue;
    const artifact = findArtifact(context, file);
    for (const rule of RULES) {
      if (rule.fileGuard && !rule.fileGuard.test(text)) continue;
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
        } else {
          // matchScope-only rules (e.g. unbounded-recursion) test the match
          // text itself, since the mitigating guard — if any — lives inside
          // the same function body captured by the match.
          const mitigated = rule.downgrade.matchScope
            ? rule.downgrade.lexicalPattern.test(match[0])
            : testWindow(rule.downgrade.lexicalPattern, text, match.index, match[0].length, rule.downgrade.radius);
          if (mitigated) {
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
        semanticFeatures: ['parser-boundary', rule.id, candidate.detectorMetadata?.sinkApi ?? rule.id],
      };
    },
    enumerate(context) {
      const matches = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        if (rule.fileGuard && !rule.fileGuard.test(text)) continue;
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
  id: 'security.parser-serialization',
  version: '1.0.0',
  candidateClass: CANDIDATE_CLASS,
  description: 'Unsafe deserialization, parser bombs (XML entity expansion, decompression bombs), and unbounded recursive parsing.',
  rules: RULES.map((rule) => ({ id: rule.id })),
  analyze,
  variantStrategies: Object.fromEntries(RULES.map((rule) => [rule.id, buildVariantStrategy(rule)])),
});
