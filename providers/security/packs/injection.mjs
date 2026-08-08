// Injection security pack: SQL, NoSQL, ORM, command/shell, LDAP, template
// (SSTI), regex (ReDoS), prototype pollution, XML external entity, and
// spreadsheet-formula sinks with typed source-to-sink metadata.
//
// Every rule is a lexical (pattern-only) detector: it never runs a payload,
// never calls a model, and never certifies a finding. It only ever emits
// UNADJUDICATED candidates via the sealed candidate-engine. When a
// parameterization/escaping/sanitization signal is observed on the same
// path, the candidate is either suppressed (clearly mitigated, e.g. a
// genuinely parameterized query) or downgraded with the observed control
// referenced in `observedControls` (a model control entity was found) or
// noted in `uncertainty` (only a lexical mitigating signal was found).

import { digest } from '../contracts.mjs';

function findArtifact(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

// Best-effort control lookup: prefer a control entity bound to the sink
// artifact via a `protects` relation (the precise, model-grounded path);
// fall back to any control entity in the model whose controlType matches
// (a looser but still evidence-grounded signal when the surface model has
// not wired the relation). Never invents a control that is not in the model.
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

// Tests `pattern` either against the exact match text (`scope: 'match'`) or
// against a forward-looking window starting at the match (`scope: 'forward'`,
// the default) — mitigating context such as a parameter array or an
// escaping call usually appears immediately after the risky call itself.
function testAround(pattern, text, index, matchLength, scope) {
  if (!pattern) return false;
  if (scope === 'match') return pattern.test(text.slice(index, index + matchLength));
  const end = Math.min(text.length, index + matchLength + 300);
  return pattern.test(text.slice(index, end));
}

function traceFor(context, file, rule) {
  const traces = context.projection?.auditFacts?.injectionTraces ?? [];
  return traces.find((t) => t.file === file && t.sinkClass === rule.sinkClass) ?? null;
}

const RULES = [
  {
    id: 'injection.sql.dynamic-query',
    sinkClass: 'sql',
    sinkKind: 'sql',
    severityHint: 'high',
    claim: 'Request-derived data may reach a dynamically constructed SQL statement.',
    riskyPattern: /\b(?:query|execute|exec)\s*\(\s*(?:`[^`\n]*\$\{[^}]*(?:request|input|user|body|params|query)[^}]*\}[^`\n]*`|"[^"\n]*"\s*\+\s*(?:request|input|user|body|params|query)|'[^'\n]*'\s*\+\s*(?:request|input|user|body|params|query))/gi,
    suppressPattern: /\b(?:query|execute)\s*\(\s*(?:`[^`\n]*\?[^`\n]*`|"[^"\n]*\?[^"\n]*"|'[^'\n]*\?[^'\n]*')\s*,\s*\[/i,
    suppressScope: 'forward',
    downgrade: {
      controlTypes: ['sql-parameterization', 'sql-escaping'],
      severityHint: 'low',
      lexicalPattern: /\.escape\(|mysql\.escape|sqlstring\.escape|pg-escape/i,
      lexicalNote: 'An escaping helper call is present near the sink; treated as a mitigating signal pending adjudication.',
    },
    effectKind: 'data-access', effectAction: 'query', effectScope: 'sql-sink',
    chainRoles: ['starter', 'impact'],
    sinkEngine(text) {
      if (/\bpg\b|postgres/i.test(text)) return 'postgres';
      if (/mysql/i.test(text)) return 'mysql';
      if (/sqlite/i.test(text)) return 'sqlite';
      if (/knex/i.test(text)) return 'knex';
      return 'sql';
    },
    uncertainty: ['Dynamic SQL construction is not automatically injection; parameter binding elsewhere in the call path must be adjudicated.'],
  },
  {
    id: 'injection.nosql.operator-injection',
    sinkClass: 'nosql',
    sinkKind: 'nosql',
    severityHint: 'high',
    claim: 'Request-derived data may reach a NoSQL query without operator sanitization.',
    riskyPattern: /\.(?:find|findOne|updateOne|updateMany|deleteOne|deleteMany|aggregate)\s*\(\s*(?:request\.(?:body|query|params)\b|\{\s*\$where\b)/gi,
    suppressPattern: /mongo-?sanitize|sanitizeFilter/i,
    suppressScope: 'forward',
    downgrade: {
      controlTypes: ['nosql-sanitization'],
      severityHint: 'low',
      lexicalPattern: /\bpick\(|allowlist|whitelist/i,
      lexicalNote: 'A field allowlist/pick call is present near the sink; treated as a mitigating signal pending adjudication.',
    },
    effectKind: 'data-access', effectAction: 'query', effectScope: 'nosql-sink',
    chainRoles: ['starter', 'impact'],
    sinkEngine(text) {
      if (/mongoose/i.test(text)) return 'mongoose';
      if (/mongodb|mongo/i.test(text)) return 'mongo';
      return 'nosql';
    },
    uncertainty: ['An unfiltered request object reaching a query is not automatically operator injection; the driver and schema must be adjudicated.'],
  },
  {
    id: 'injection.orm.raw-query-with-input',
    sinkClass: 'orm',
    sinkKind: 'orm',
    severityHint: 'high',
    claim: 'Request-derived data may reach a raw ORM query without parameter binding.',
    riskyPattern: /\b(?:sequelize\.query|\$queryRaw|Model\.raw|FromSqlRaw)\s*\(\s*(?:`[^`\n]*\$\{[^}]*(?:request|input|user|body|params)[^}]*\}[^`\n]*`|"[^"\n]*"\s*\+\s*(?:request|input|user|body|params)|'[^'\n]*'\s*\+\s*(?:request|input|user|body|params))/gi,
    suppressPattern: /\breplacements\s*:|\bbind\s*:|Prisma\.sql`/i,
    suppressScope: 'forward',
    downgrade: {
      controlTypes: ['orm-parameterization'],
      severityHint: 'low',
    },
    effectKind: 'data-access', effectAction: 'query', effectScope: 'orm-sink',
    chainRoles: ['starter', 'impact'],
    sinkEngine(text) {
      if (/sequelize/i.test(text)) return 'sequelize';
      if (/prisma/i.test(text)) return 'prisma';
      return 'orm';
    },
    uncertainty: ['A raw ORM escape hatch is not automatically injection; whether replacements/bind parameters are used must be adjudicated.'],
  },
  {
    // Kept intentionally close to the original shell rule: the pattern,
    // `sinkKind: 'shell'`, and the "not automatically command injection"
    // uncertainty text are relied on by a pre-existing pinned test.
    id: 'injection.command.shell-exec',
    sinkClass: 'command',
    sinkKind: 'shell',
    severityHint: 'high',
    claim: 'Request-derived data reaches a shell execution sink.',
    riskyPattern: /(?:exec|system|spawn|child_process\.exec|subprocess\.(?:call|run|Popen))\s*\([^\n]*(?:request|input|user|query|body|params)/g,
    suppressPattern: /shell\s*:\s*false/i,
    suppressScope: 'forward',
    downgrade: {
      controlTypes: ['shell-argument-escaping', 'input-allowlist'],
      severityHint: 'low',
      lexicalPattern: /\bspawn\s*\([^)]*,\s*\[/i,
      lexicalNote: 'An array-argument invocation avoids shell string interpolation; treated as a mitigating signal pending adjudication.',
    },
    effectKind: 'code-execution', effectAction: 'execute', effectScope: 'sink-process',
    chainRoles: ['starter', 'impact'],
    sinkEngine(text) {
      if (/child_process\.exec/.test(text)) return 'child_process.exec';
      if (/subprocess\./.test(text)) return 'subprocess';
      if (/spawn/.test(text)) return 'spawn';
      return 'shell';
    },
    uncertainty: ['A process-argument candidate is not automatically command injection; argument separation and validation must be adjudicated.'],
  },
  {
    id: 'injection.ldap.filter-injection',
    sinkClass: 'ldap',
    sinkKind: 'ldap',
    severityHint: 'high',
    claim: 'Request-derived data may reach an LDAP filter without escaping.',
    fileGuard: /ldap/i,
    riskyPattern: /\bfilter\s*[:=]\s*(?:`[^`\n]*\$\{[^}]+\}[^`\n]*`|"[^"\n]*"\s*\+|'[^'\n]*'\s*\+)[^\n]*(?:request|input|user|body|params)/gi,
    suppressPattern: /escapeFilter|ldapEscape|ldap-escape/i,
    suppressScope: 'forward',
    downgrade: {
      controlTypes: ['ldap-escape'],
      severityHint: 'low',
    },
    effectKind: 'data-access', effectAction: 'query', effectScope: 'ldap-sink',
    chainRoles: ['starter', 'impact'],
    sinkEngine() { return 'ldap'; },
    uncertainty: ['LDAP filter concatenation is not automatically injection; the directory server and escaping library must be adjudicated.'],
  },
  {
    id: 'injection.template.server-side-template-injection',
    sinkClass: 'template',
    sinkKind: 'ssti',
    severityHint: 'high',
    claim: 'Request-derived data may be compiled as a template rather than passed as template data.',
    riskyPattern: /\b(?:ejs\.render|_\.template|Handlebars\.compile|nunjucks\.renderString|render_template_string)\s*\([^\n]*(?:request|input|user|body|params)/gi,
    suppressPattern: /autoescape\s*:\s*true|sandbox\s*:\s*true/i,
    suppressScope: 'forward',
    downgrade: {
      controlTypes: ['template-sandboxing'],
      severityHint: 'low',
    },
    effectKind: 'code-execution', effectAction: 'execute', effectScope: 'template-engine',
    chainRoles: ['starter', 'impact'],
    sinkEngine(text) {
      if (/ejs\.render/.test(text)) return 'ejs';
      if (/Handlebars\.compile/.test(text)) return 'handlebars';
      if (/nunjucks\.renderString/.test(text)) return 'nunjucks';
      if (/_\.template/.test(text)) return 'lodash.template';
      return 'template-engine';
    },
    uncertainty: ['Compiling request-derived text as a template is not automatically SSTI; the engine\'s sandboxing must be adjudicated.'],
  },
  {
    id: 'injection.regex.redos',
    sinkClass: 'redos',
    sinkKind: 'redos',
    severityHint: 'medium',
    claim: 'A regular expression contains a nested-quantifier shape associated with catastrophic backtracking (ReDoS).',
    riskyPattern: /\/(?:[^/\n\\]|\\.)*\([^()]*[+*]\)[+*](?:[^/\n\\]|\\.)*\/[a-z]*/g,
    effectKind: 'availability-impact', effectAction: 'exhaust', effectScope: 'regex-engine',
    chainRoles: ['starter', 'impact'],
    sinkEngine() { return 'RegExp'; },
    uncertainty: ['A nested-quantifier shape is not automatically exploitable; whether attacker-controlled input reaches this expression and its length bound must be adjudicated.'],
  },
  {
    id: 'injection.prototype-pollution.unsafe-key-assignment',
    sinkClass: 'prototype-pollution',
    sinkKind: 'prototype-pollution',
    severityHint: 'medium',
    claim: 'A request-derived property key reaches a dynamic assignment without a prototype-key denylist.',
    riskyPattern: /(?:\[\s*request\.(?:body|query|params)(?:\.\w+)?\s*\]\s*=|(?:_\.merge|deepmerge|merge)\s*\(\s*\{\}\s*,\s*request\.(?:body|query|params))/gi,
    downgrade: {
      controlTypes: ['prototype-key-denylist'],
      severityHint: 'low',
      lexicalPattern: /denylist|blocklist|isSafeKey|hasOwnProperty\.call/i,
      lexicalNote: 'A key-denylist or hasOwnProperty guard is present near the sink; treated as a mitigating signal pending adjudication.',
    },
    effectKind: 'integrity-impact', effectAction: 'pollute', effectScope: 'object-prototype',
    chainRoles: ['starter', 'impact'],
    sinkEngine(text) {
      if (/deepmerge/.test(text)) return 'deepmerge';
      if (/_\.merge/.test(text)) return 'lodash.merge';
      return 'bracket-assignment';
    },
    uncertainty: ['A dynamic property key is not automatically prototype pollution; whether `__proto__`/`constructor` keys are reachable must be adjudicated.'],
  },
  {
    id: 'injection.xxe.external-entity-enabled',
    sinkClass: 'xxe',
    sinkKind: 'xxe',
    severityHint: 'high',
    claim: 'An XML parser is explicitly configured to resolve external entities (XXE).',
    fileGuard: /libxmljs|lxml|DocumentBuilderFactory|XMLParser|expat|xml2js/i,
    riskyPattern: /\b(?:noent\s*:\s*true|resolveEntities\s*:\s*true|resolve_entities\s*=\s*True|setFeature\(\s*["']http:\/\/apache\.org\/xml\/features\/nonvalidating\/load-external-dtd["']\s*,\s*true\s*\))/g,
    effectKind: 'data-access', effectAction: 'read', effectScope: 'xml-parser',
    chainRoles: ['starter', 'impact'],
    sinkEngine(text) {
      if (/libxmljs/.test(text)) return 'libxmljs';
      if (/lxml/.test(text)) return 'lxml';
      if (/DocumentBuilderFactory/.test(text)) return 'DocumentBuilderFactory';
      if (/expat/.test(text)) return 'expat';
      return 'xml-parser';
    },
    uncertainty: ['An external-entity-enabling toggle is not automatically exploitable; whether attacker-controlled XML reaches this parser must be adjudicated.'],
  },
  {
    id: 'injection.formula.csv-export-unescaped',
    sinkClass: 'formula',
    sinkKind: 'formula',
    severityHint: 'medium',
    claim: 'Request-derived data reaches a spreadsheet export row without formula-prefix escaping.',
    fileGuard: /csv|xlsx|exceljs|csv-writer/i,
    riskyPattern: /\b(?:addRow|writeRow|push)\s*\(\s*\[[^\]]*(?:request\.(?:body|query|params)|input)[^\]]*\]\s*\)/gi,
    suppressPattern: /startsWith\(\s*['"][=+\-@]['"]\)|escapeFormula|sanitizeCsv/i,
    suppressScope: 'forward',
    effectKind: 'integrity-impact', effectAction: 'inject-formula', effectScope: 'spreadsheet-export',
    chainRoles: ['starter', 'impact'],
    sinkEngine(text) {
      if (/exceljs/i.test(text)) return 'exceljs';
      if (/csv-writer/i.test(text)) return 'csv-writer';
      if (/xlsx/i.test(text)) return 'xlsx';
      return 'csv';
    },
    uncertainty: ['An unescaped export cell is not automatically formula injection; the consuming spreadsheet application\'s auto-execution settings must be adjudicated.'],
  },
];

function buildVariantStrategy(rule) {
  return {
    rootCause(candidate) {
      return {
        class: `${rule.sinkClass}-unmitigated-sink`,
        sinkClass: rule.sinkClass,
        sinkKind: rule.sinkKind,
        missingControl: rule.downgrade?.controlTypes?.[0] ?? null,
        semanticFeatures: ['tainted-input-to-sink', rule.sinkClass, candidate.detectorMetadata?.sinkEngine ?? rule.sinkClass],
      };
    },
    enumerate(context) {
      const matches = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        if (rule.fileGuard && !rule.fileGuard.test(text)) continue;
        rule.riskyPattern.lastIndex = 0;
        let match;
        while ((match = rule.riskyPattern.exec(text)) !== null) {
          if (match[0].length === 0) { rule.riskyPattern.lastIndex += 1; continue; }
          const suppressed = testAround(rule.suppressPattern, text, match.index, match[0].length, rule.suppressScope ?? 'forward');
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
          description: `Enumerate every ${rule.sinkClass} sink across the denominator.`,
          queryDigest: digest(rule.id), complete: true, coverageGaps: [],
        }],
        matches,
        coverageGaps: [],
      };
    },
  };
}

export default Object.freeze({
  id: 'security.injection',
  version: '1.0.0',
  candidateClass: 'injection',
  description: 'Injection into SQL, NoSQL, ORM, command, LDAP, template, regex, prototype, and XML/formula sinks.',
  rules: RULES.map((rule) => ({ id: rule.id })),
  analyze(context) {
    const observations = [];
    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = findArtifact(context, file);
      for (const rule of RULES) {
        if (rule.fileGuard && !rule.fileGuard.test(text)) continue;
        rule.riskyPattern.lastIndex = 0;
        let match;
        while ((match = rule.riskyPattern.exec(text)) !== null) {
          if (match[0].length === 0) { rule.riskyPattern.lastIndex += 1; continue; }
          if (testAround(rule.suppressPattern, text, match.index, match[0].length, rule.suppressScope ?? 'forward')) continue;

          let severityHint = rule.severityHint;
          let observedControls = [];
          const uncertainty = [...rule.uncertainty];

          if (rule.downgrade) {
            const control = findRelatedControl(context, artifact?.id, rule.downgrade.controlTypes);
            if (control) {
              severityHint = rule.downgrade.severityHint;
              observedControls = [control.id];
              uncertainty.push(`Observed ${control.attributes?.controlType ?? 'mitigating'} control (${control.name}) on this path; downgraded pending adjudication of coverage completeness.`);
            } else if (testAround(rule.downgrade.lexicalPattern, text, match.index, match[0].length, rule.downgrade.lexicalScope ?? rule.suppressScope ?? 'forward')) {
              severityHint = rule.downgrade.severityHint;
              uncertainty.push(rule.downgrade.lexicalNote ?? 'A mitigating pattern is present near the sink; downgraded pending adjudication.');
            }
          }

          const trace = traceFor(context, file, rule);
          const detectionMethod = trace ? 'sast-trace' : 'lexical-pattern';
          uncertainty.push(trace
            ? 'Confirmed by a recorded taint trace; reachability is still subject to adjudication.'
            : 'Lexical pattern match; not confirmed by a recorded taint trace.');

          const reaches = artifact ? context.relationsTo(artifact.id).filter((r) => r.kind === 'reaches' || r.kind === 'flows-to') : [];
          const sources = reaches.length ? [...new Set(reaches.map((r) => r.from))].sort() : (artifact ? [artifact.id] : []);

          observations.push({
            ruleId: rule.id,
            candidateClass: 'injection',
            claim: rule.claim,
            severityHint,
            sources,
            sinks: artifact ? [artifact.id] : [],
            attackerCapabilities: ['control-request-input'],
            preconditions: [{
              kind: 'attacker-position', subject: 'actor:external', action: 'supply-input',
              scope: null, environment: 'application', tenant: null,
            }],
            effects: [{
              kind: rule.effectKind, subject: 'actor:external', action: rule.effectAction,
              object: artifact?.id ?? null, scope: rule.effectScope, environment: 'application', tenant: null,
            }],
            assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls,
            chainRoles: rule.chainRoles,
            evidenceRefs: artifact?.evidenceRefs ?? [],
            detectorMetadata: {
              file,
              line: lineOf(text, match.index),
              sinkClass: rule.sinkClass,
              sinkKind: rule.sinkKind,
              sinkEngine: rule.sinkEngine(text),
              detectionMethod,
              matchDigest: digest(match[0]),
            },
            uncertainty,
          });
        }
      }
    }
    return observations;
  },
  variantStrategies: Object.fromEntries(RULES.map((rule) => [rule.id, buildVariantStrategy(rule)])),
});
