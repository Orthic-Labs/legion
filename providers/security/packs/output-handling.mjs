// Output-handling security pack: untrusted content crossing an explicit
// output context (html-body, html-attribute, js, url, css, shell, sql, log)
// plus stored/email-header/model-output flavors of those contexts.
//
// Same discipline as injection.mjs: lexical (pattern-only) detectors,
// UNADJUDICATED candidates only, mitigation suppresses or downgrades rather
// than inventing an observed control.

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

function testAround(pattern, text, index, matchLength, scope) {
  if (!pattern) return false;
  if (scope === 'match') return pattern.test(text.slice(index, index + matchLength));
  const end = Math.min(text.length, index + matchLength + 300);
  return pattern.test(text.slice(index, end));
}

function traceFor(context, file, rule) {
  const traces = context.projection?.auditFacts?.outputHandlingTraces ?? [];
  return traces.find((t) => t.file === file && t.outputContext === rule.outputContext) ?? null;
}

const RULES = [
  {
    id: 'output.html.body-unescaped',
    outputContext: 'html-body',
    sinkKindDefault: 'html-body-sink',
    severityHint: 'high',
    claim: 'Untrusted content may reach an HTML interpretation sink without visible sanitization.',
    riskyPattern: /(?:innerHTML|dangerouslySetInnerHTML|document\.write|v-html)\s*[=:(][^\n]*(?:input|request|body|content|output|response)/gi,
    suppressPattern: /DOMPurify\.sanitize|sanitize-html|escapeHtml|he\.encode|striptags/i,
    downgrade: { controlTypes: ['html-sanitization', 'output-encoding'], severityHint: 'low' },
    effectKind: 'code-execution', effectAction: 'render', effectScope: 'dom',
    chainRoles: ['starter', 'impact'],
    sinkEngine(text) {
      if (/dangerouslySetInnerHTML/.test(text)) return 'react-dangerously-set-inner-html';
      if (/document\.write/.test(text)) return 'document.write';
      if (/v-html/.test(text)) return 'vue-v-html';
      return 'innerHTML';
    },
    uncertainty: ['An unescaped HTML sink is not automatically XSS; whether the content is attacker-controlled and unsanitized elsewhere must be adjudicated.'],
  },
  {
    id: 'output.html.attribute-unescaped',
    outputContext: 'html-attribute',
    severityHint: 'high',
    claim: 'Untrusted content may reach an HTML attribute without context-aware encoding.',
    riskyPattern: /\.setAttribute\s*\(\s*['"][^'"]+['"]\s*,\s*[^)]*(?:request|input|user|query|params|body)/gi,
    suppressPattern: /encodeURIComponent|escapeAttribute|sanitizeAttr/i,
    downgrade: { controlTypes: ['attribute-encoding'], severityHint: 'low' },
    effectKind: 'code-execution', effectAction: 'render', effectScope: 'dom',
    chainRoles: ['starter', 'impact'],
    sinkEngine() { return 'setAttribute'; },
    uncertainty: ['An unencoded attribute sink is not automatically XSS; the attribute name (e.g. event-handler vs. plain) must be adjudicated.'],
  },
  {
    id: 'output.js.inline-script-unescaped',
    outputContext: 'js',
    severityHint: 'high',
    claim: 'Untrusted content is inlined into a <script> block without JSON-safe serialization.',
    riskyPattern: /<script[^>]*>[\s\S]{0,200}?\$\{[^}]*(?:request|input|user|body|params)[^}]*\}[\s\S]{0,200}?<\/script>/gi,
    suppressPattern: /JSON\.stringify/i,
    suppressScope: 'match',
    effectKind: 'code-execution', effectAction: 'execute', effectScope: 'browser-js',
    chainRoles: ['starter', 'impact'],
    sinkEngine() { return 'inline-script-interpolation'; },
    uncertainty: ['Inline-script interpolation is not automatically injection; whether the value is JSON-safe elsewhere must be adjudicated.'],
  },
  {
    id: 'output.url.open-redirect',
    outputContext: 'url',
    severityHint: 'medium',
    claim: 'Request-controlled data may reach a redirect target without an allowlist check.',
    riskyPattern: /(?:redirect|location\.href)\s*\(?[^\n]*(?:request|query|params|next)/gi,
    suppressPattern: /allowedHosts\.includes|isSafeRedirect|new URL\([^)]*\)\.origin\s*===/i,
    downgrade: { controlTypes: ['redirect-allowlist'], severityHint: 'low' },
    effectKind: 'control-bypass', effectAction: 'bypass', effectScope: 'redirect',
    chainRoles: ['starter', 'control-bypass'],
    sinkEngine() { return 'redirect'; },
    uncertainty: ['A request-controlled redirect target is not automatically an open redirect; whether the value is validated elsewhere must be adjudicated.'],
  },
  {
    id: 'output.css.style-unescaped',
    outputContext: 'css',
    severityHint: 'medium',
    claim: 'Untrusted content may reach a CSS/style sink without sanitization.',
    riskyPattern: /(?:\.style\.cssText\s*=|style\s*=\s*[`"'][^`"']*\$\{)[^\n]*(?:request|input|user|body|params)/gi,
    suppressPattern: /sanitizeCss|cssesc|CSS\.escape/i,
    downgrade: { controlTypes: ['css-sanitization'], severityHint: 'low' },
    effectKind: 'code-execution', effectAction: 'render', effectScope: 'dom',
    chainRoles: ['starter', 'impact'],
    sinkEngine() { return 'style-interpolation'; },
    uncertainty: ['A style sink is not automatically CSS injection; the reachable property set must be adjudicated.'],
  },
  {
    id: 'output.shell.command-template',
    outputContext: 'shell',
    severityHint: 'high',
    claim: 'Rendered output is interpolated into a shell command template without argument escaping.',
    riskyPattern: /\bexec\s*\(\s*`[^`\n]*\$\{[^}]*(?:request|input|user|body|params)[^}]*\}[^`\n]*`/gi,
    suppressPattern: /shellEscape|shell-quote|execFile\(/i,
    downgrade: { controlTypes: ['shell-argument-escaping'], severityHint: 'low' },
    effectKind: 'code-execution', effectAction: 'execute', effectScope: 'sink-process',
    chainRoles: ['starter', 'impact'],
    sinkEngine() { return 'shell-template'; },
    uncertainty: ['A shell command template is not automatically command injection; argument escaping elsewhere must be adjudicated.'],
  },
  {
    id: 'output.sql.stored-content-interpolation',
    outputContext: 'sql',
    severityHint: 'high',
    claim: 'Previously stored content is interpolated into a query string without parameter binding.',
    riskyPattern: /\b(?:query|execute)\s*\(\s*`[^`\n]*\$\{[^}]*(?:record|row|stored|savedTemplate)[^}]*\}[^`\n]*`/gi,
    suppressPattern: /\breplacements\s*:|\bbind\s*:|\?\s*,\s*\[/i,
    downgrade: { controlTypes: ['sql-parameterization'], severityHint: 'low' },
    effectKind: 'data-access', effectAction: 'query', effectScope: 'sql-sink',
    chainRoles: ['starter', 'impact'],
    sinkEngine() { return 'stored-content-query'; },
    uncertainty: ['Stored content reaching a query string is not automatically injection; whether parameter binding is used must be adjudicated.'],
  },
  {
    id: 'output.log.newline-injection',
    outputContext: 'log',
    severityHint: 'medium',
    claim: 'Request-derived data reaches a log sink without newline stripping, enabling log forging.',
    riskyPattern: /\b(?:logger|console)\.(?:info|warn|error|log|debug)\s*\([^)]*(?:request\.|input\b|user\.|body\.|params\.)/gi,
    suppressPattern: /replace\(\s*\/\[\\r\\n\]/i,
    downgrade: { controlTypes: ['log-sanitization'], severityHint: 'low' },
    effectKind: 'integrity-impact', effectAction: 'forge-log-entry', effectScope: 'log-sink',
    chainRoles: ['starter', 'impact'],
    sinkEngine() { return 'log-write'; },
    uncertainty: ['A raw log write is not automatically log forging; whether the sink treats newlines as record separators must be adjudicated.'],
  },
  {
    id: 'output.stored.unescaped-render',
    outputContext: 'html-body',
    severityHint: 'high',
    claim: 'Previously stored content is rendered through an explicitly unescaped template tag.',
    riskyPattern: /<%-\s*[^%]+%>|\{\{\{[^}]+\}\}\}/g,
    downgrade: {
      controlTypes: ['html-sanitization'],
      severityHint: 'low',
      lexicalPattern: /safe|sanitized|trusted/i,
      lexicalScope: 'match',
      lexicalNote: 'The rendered variable name suggests it was already sanitized upstream; downgraded pending adjudication.',
    },
    effectKind: 'code-execution', effectAction: 'render', effectScope: 'dom',
    chainRoles: ['starter', 'impact'],
    sinkEngine(text) {
      return /\{\{\{/.test(text) ? 'handlebars-triple-stache' : 'ejs-unescaped-output';
    },
    uncertainty: ['An unescaped template tag is not automatically stored XSS; whether the rendered value is attacker-controlled must be adjudicated.'],
  },
  {
    id: 'output.email.header-injection',
    outputContext: 'email-header',
    severityHint: 'medium',
    claim: 'Request-derived data reaches an email header without CRLF stripping, enabling header injection.',
    riskyPattern: /(?:setHeader\s*\(\s*['"](?:Cc|Bcc|Subject|To)['"]|mail(?:Options)?\.(?:subject|to|cc|bcc))\s*[,:=][^\n]*(?:request|input|user|body|params)/gi,
    suppressPattern: /replace\(\s*\/\[\\r\\n\]|validator\.isEmail|encodeHeader/i,
    downgrade: { controlTypes: ['header-sanitization'], severityHint: 'low' },
    effectKind: 'integrity-impact', effectAction: 'forge-header', effectScope: 'email-sink',
    chainRoles: ['starter', 'impact'],
    sinkEngine() { return 'email-header'; },
    uncertainty: ['A raw email header write is not automatically header injection; whether the mail library rejects embedded newlines must be adjudicated.'],
  },
  {
    id: 'output.model.unsanitized-render',
    outputContext: 'html-body',
    severityHint: 'high',
    claim: 'Model-generated output is rendered into HTML without visible sanitization.',
    riskyPattern: /(?:dangerouslySetInnerHTML|innerHTML)\s*[=:][^\n]*(?:completion|modelOutput|llmResponse|aiResponse|generatedText)/gi,
    suppressPattern: /DOMPurify\.sanitize|sanitize-html|escapeHtml/i,
    downgrade: { controlTypes: ['html-sanitization'], severityHint: 'low' },
    effectKind: 'code-execution', effectAction: 'render', effectScope: 'dom',
    chainRoles: ['starter', 'impact'],
    sinkEngine() { return 'model-output-render'; },
    uncertainty: ['Model output reaching an HTML sink is not automatically XSS; the model\'s own output-handling controls must be adjudicated.'],
  },
];

function buildVariantStrategy(rule) {
  return {
    rootCause(candidate) {
      return {
        class: `${rule.outputContext}-unmitigated-output`,
        outputContext: rule.outputContext,
        missingControl: rule.downgrade?.controlTypes?.[0] ?? null,
        semanticFeatures: ['untrusted-output', rule.outputContext, candidate.detectorMetadata?.sinkEngine ?? rule.outputContext],
      };
    },
    enumerate(context) {
      const matches = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
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
          description: `Enumerate every ${rule.outputContext} output sink across the denominator.`,
          queryDigest: digest(rule.id), complete: true, coverageGaps: [],
        }],
        matches,
        coverageGaps: [],
      };
    },
  };
}

export default Object.freeze({
  id: 'security.output-handling',
  version: '1.0.0',
  candidateClass: 'output-handling',
  description: 'Untrusted output crossing HTML, attribute, script, URL, CSS, shell, SQL, log, and header sinks.',
  rules: RULES.map((rule) => ({ id: rule.id })),
  analyze(context) {
    const observations = [];
    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = findArtifact(context, file);
      for (const rule of RULES) {
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
            candidateClass: 'output-handling',
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
              outputContext: rule.outputContext,
              sinkKind: rule.sinkKindDefault ?? rule.outputContext,
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
