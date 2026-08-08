import { createHash } from 'node:crypto';

const PROVIDER = 'copy.clarity';
const MEDIA_TYPE = 'application/vnd.nemesis.copy-analysis+json';

function digest(value) {
  return `sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`;
}

function exactSpan(text, pattern) {
  const match = pattern.exec(text);
  return match ? { text: match[0], start: match.index, end: match.index + match[0].length } : null;
}

function contentRole(item) {
  return item.surface?.type ?? item.kind ?? 'unknown';
}

function hasCandidateContext(item) {
  return Boolean(item.audience && contentRole(item) !== 'unknown');
}

function technicalTerm(item, term) {
  const normalized = term.toLocaleLowerCase();
  const terms = [
    ...(item.constraints?.technicalTerms ?? []),
    ...(item.constraints?.technicalUseTerms ?? []),
    ...(item.constraints?.requiredTerms ?? []),
    ...(item.constraints?.explainedTerms ?? []),
  ].map((value) => value.toLocaleLowerCase());
  return item.constraints?.technicalUse === true
    || terms.some((value) => value.includes(normalized) || normalized.includes(value));
}

function clarityCandidate(item, ruleId, span, claim, suggestion, denominatorDigest, binding) {
  const base = {
    schemaVersion: 1,
    kind: 'nemesis-copy-candidate',
    producer: PROVIDER,
    provider: PROVIDER,
    providerVersion: '1.0.0',
    ruleId,
    dimension: 'clarity',
    contentItemIds: [item.id],
    claim,
    severityHint: 'low',
    detectorKind: 'interpretive',
    evidenceRefs: item.evidenceRefs ?? [],
    proofRefs: [],
    uncertainty: ['editorial-judgment-required'],
    denominatorDigest,
    binding,
    verdict: 'UNADJUDICATED',
    adjudicationRequired: true,
    audience: item.audience,
    contentRole: contentRole(item),
    span,
    suggestion,
    suggestionAlternatives: [suggestion],
    suggestionKind: 'meaning-preserving-editorial-option',
    suggestionPolicy: 'advisory-only; preserve factual meaning and technical precision',
    mediaType: MEDIA_TYPE,
  };
  return { ...base, id: digest(base), digest: digest(base) };
}

function requiredAndExplained(item, term) {
  const normalized = term.toLocaleLowerCase();
  const required = (item.constraints?.requiredTerms ?? []).map((value) => value.toLocaleLowerCase());
  const explained = (item.constraints?.explainedTerms ?? []).map((value) => value.toLocaleLowerCase());
  return required.includes(normalized) && explained.includes(normalized);
}

const OPPOSING_ACTIONS = {
  publish: /\b(?:delete|discard|remove|hide)\b/i,
  delete: /\b(?:save|publish|keep|restore)\b/i,
  enable: /\b(?:disable|stop|turn off)\b/i,
  disable: /\b(?:enable|start|turn on)\b/i,
};

const VAGUE_LABEL = /^(?:click here|learn more|read more|continue|submit|next|done|go|ok|yes|no|here)$/i;
const HEDGE = /\b(?:may|might|perhaps|possibly|generally|typically|could|seems?|appears?)\b/gi;
const NOMINALIZATION = /\b(?:utilization|implementation|facilitation|optimization|configuration|administration|authentication|validation|transformation)\b/i;
const NON_SPECIFIC_LANGUAGE = /\b(?:thing|things|stuff|something|somewhere|somehow|various|several)\b/i;
const PASSIVE_ACTION = /\b(?:is|are|was|were|be|being|been)\s+(?:used|done|made|handled|performed|provided|managed|enabled|configured|completed)\b/i;
const NESTED_CLAUSE = /\b(?:which|that|although|because|when|while|if)\b[^.!?;]{8,},/i;
const BURIED_INSTRUCTION = /\b(?:when|if|after|before|once|while)\b[^.!?;]{4,},\s*(?:please\s+)?(?:click|select|open|enter|use|choose|rotate|configure|run|save|delete|publish|enable|disable)\b[^.!?]*/i;

function deterministicLabelFinding(item, ruleId, span, control, binding) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-copy-finding',
    producer: PROVIDER,
    provider: PROVIDER,
    ruleId,
    detectorKind: 'deterministic',
    contentItemIds: [item.id],
    audience: item.audience ?? null,
    contentRole: contentRole(item),
    span,
    control,
    evidenceRefs: item.evidenceRefs ?? [],
    binding,
  };
}

export function analyzeClarity(items = [], options = {}) {
  const binding = options.binding ?? {};
  const denominator = { kind: 'user-visible-content-items', expected: items.length, examined: items.length };
  const denominatorDigest = digest(items.map(({ id, textDigest, text }) => [id, textDigest ?? digest(text ?? '')]));
  const controls = new Map((options.controls ?? []).map((control) => [control.id, control]));
  const candidates = [];
  const findings = [];

  for (const item of items) {
    const text = item.text ?? '';
    const control = controls.get(item.surface?.controlId);
    const contradiction = control && OPPOSING_ACTIONS[control.action]?.exec(text);
    if (contradiction) {
      findings.push(deterministicLabelFinding(item, 'copy.clarity.control-label-contradiction', {
        text: contradiction[0],
        start: contradiction.index,
        end: contradiction.index + contradiction[0].length,
      }, control, binding));
    } else if (control?.outcome && VAGUE_LABEL.test(text.trim())) {
      const start = text.indexOf(text.trim());
      const vagueLabel = { text: text.trim(), start, end: start + text.trim().length };
      findings.push(deterministicLabelFinding(item, 'copy.clarity.control-label-vague', vagueLabel, control, binding));
    }

    if (!hasCandidateContext(item)) continue;

    const ambiguousPronoun = exactSpan(text, /^(?:it|this|that|they)\b/i);
    if (ambiguousPronoun) candidates.push(clarityCandidate(
      item,
      'copy.clarity.ambiguous-pronoun',
      ambiguousPronoun,
      'Opening pronoun has no antecedent in this content unit.',
      'Name the existing subject explicitly; do not add a new factual claim.',
      denominatorDigest,
      binding,
    ));

    const hedges = [...text.matchAll(HEDGE)];
    if (hedges.length === 1) {
      const span = { text: hedges[0][0], start: hedges[0].index, end: hedges[0].index + hedges[0][0].length };
      candidates.push(clarityCandidate(
        item,
        'copy.clarity.hedging',
        span,
        'Qualifier may weaken a precise instruction or claim.',
        'Retain the qualifier only when evidence or policy requires it; do not strengthen the factual claim.',
        denominatorDigest,
        binding,
      ));
    }
    if (hedges.length > 1) {
      const start = hedges[0].index;
      const end = hedges.at(-1).index + hedges.at(-1)[0].length;
      candidates.push(clarityCandidate(
        item,
        'copy.clarity.repeated-hedge',
        { text: text.slice(start, end), start, end },
        'Repeated qualifiers obscure confidence and action.',
        'Retain only qualifiers required by evidence or policy.',
        denominatorDigest,
        binding,
      ));
    }

    const nominalization = exactSpan(text, NOMINALIZATION);
    if (nominalization && !requiredAndExplained(item, nominalization.text) && !technicalTerm(item, nominalization.text)) candidates.push(clarityCandidate(
      item,
      'copy.clarity.nominalization',
      nominalization,
      'Nominalized action may bury who acts and what changes.',
      'Prefer the corresponding concrete action only if factual meaning remains unchanged.',
      denominatorDigest,
      binding,
    ));

    for (const jargon of options.jargon ?? []) {
      const span = exactSpan(text, new RegExp(`\\b${jargon.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i'));
      if (span && !requiredAndExplained(item, jargon) && !technicalTerm(item, jargon)) candidates.push(clarityCandidate(
        item,
        'copy.clarity.unexplained-jargon',
        span,
        'Audience-specific term is neither required nor explained.',
        'Define the existing term for this audience; do not simplify away technical meaning.',
        denominatorDigest,
        binding,
      ));
    }

    const nonSpecific = exactSpan(text, NON_SPECIFIC_LANGUAGE);
    if (nonSpecific) candidates.push(clarityCandidate(
      item,
      'copy.clarity.non-specific-language',
      nonSpecific,
      'Nonspecific noun or modifier obscures the concrete subject or object.',
      'Name the existing subject or object only when the source establishes it; do not invent detail.',
      denominatorDigest,
      binding,
    ));

    const passiveAction = exactSpan(text, PASSIVE_ACTION);
    if (passiveAction) candidates.push(clarityCandidate(
      item,
      'copy.clarity.subject-action',
      passiveAction,
      'Passive construction may hide who acts or what changes.',
      'Name the existing actor and action only if that relationship is already supported; preserve uncertainty.',
      denominatorDigest,
      binding,
    ));

    const nestedClause = exactSpan(text, NESTED_CLAUSE);
    if (nestedClause) candidates.push(clarityCandidate(
      item,
      'copy.clarity.nested-clause',
      nestedClause,
      'Nested clause may bury the primary action or condition.',
      'Separate the existing condition from the main action without adding or removing a condition.',
      denominatorDigest,
      binding,
    ));

    const buriedInstruction = exactSpan(text, BURIED_INSTRUCTION);
    if (buriedInstruction) candidates.push(clarityCandidate(
      item,
      'copy.clarity.buried-instruction',
      buriedInstruction,
      'Instruction is nested after a leading condition and may be hard to locate.',
      'Surface the existing instruction while retaining its condition and action exactly.',
      denominatorDigest,
      binding,
    ));
  }

  const base = {
    schemaVersion: 1,
    producer: PROVIDER,
    provider: PROVIDER,
    status: findings.length ? 'findings' : candidates.length ? 'candidates' : 'pass',
    denominator,
    denominatorDigest,
    candidates,
    findings,
    coverageGaps: items.filter((item) => !item.audience || contentRole(item) === 'unknown' || !item.purpose).map((item) => `context-missing:${item.id}`),
    binding,
    mediaType: MEDIA_TYPE,
  };
  return { ...base, digest: digest(base) };
}
