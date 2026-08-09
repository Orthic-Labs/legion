import { createHash } from 'node:crypto';

const PROVIDER = 'copy.anti-slop';
const MEDIA_TYPE = 'application/vnd.legion.copy-analysis+json';

function digest(value) {
  return `sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`;
}

function escaped(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function contextFor(item) {
  return {
    audience: item.audience ?? null,
    purpose: item.purpose ?? null,
    role: item.surface?.type ?? item.kind ?? 'unknown',
  };
}

function hasContext(item) {
  const context = contextFor(item);
  return Boolean(context.audience && context.purpose && context.role !== 'unknown');
}

function technicalTerm(item, span, options = {}) {
  const needle = span.toLocaleLowerCase();
  const terms = [
    ...(item.constraints?.technicalTerms ?? []),
    ...(item.constraints?.requiredTerms ?? []),
    ...(item.constraints?.explainedTerms ?? []),
    ...(item.constraints?.technicalUseTerms ?? []),
    ...(options.technicalTerms ?? []),
  ];
  return item.constraints?.technicalUse === true
    || terms.some((term) => {
    const normalized = term.toLocaleLowerCase();
    return needle.includes(normalized) || normalized.includes(needle);
    })
    || (item.constraints?.technicalExclusions ?? []).some((term) => needle.includes(term.toLocaleLowerCase()));
}

function sentenceFor(text, span) {
  const start = text.toLocaleLowerCase().indexOf(span.toLocaleLowerCase());
  if (start < 0) return text;
  const end = start + span.length;
  const left = Math.max(text.lastIndexOf('.', start), text.lastIndexOf('!', start), text.lastIndexOf('?', start)) + 1;
  const rightCandidates = [text.indexOf('.', end), text.indexOf('!', end), text.indexOf('?', end)].filter((index) => index >= 0);
  const right = rightCandidates.length ? Math.min(...rightCandidates) + 1 : text.length;
  return text.slice(left, right).trim();
}

function hasPersonalizationEvidence(item) {
  return Boolean(
    item.personalizationRefs?.length
    || item.constraints?.personalizationEvidence?.length
    || item.constraints?.personalizedBy
    || item.surface?.personalization,
  );
}

function isCtaContext(item) {
  const role = contextFor(item).role.toLocaleLowerCase();
  const purpose = String(item.purpose ?? '').toLocaleLowerCase();
  return ['button', 'link', 'cta'].includes(role)
    || Boolean(item.desiredAction)
    || /\b(?:cta|call to action|prompt|invite|signup|sign up|conversion|action)\b/.test(purpose);
}

function featureMatch(rule, text, item, options, duplicateCounts) {
  if (rule.match) return rule.match(text, item, options, duplicateCounts);
  return text.match(rule.pattern);
}

function candidate(item, rule, span, reason, proofRefs, denominatorDigest, binding, options = {}) {
  const featureVector = {
    feature: rule.feature,
    span,
    context: contextFor(item),
    claimType: item.claimRefs?.length ? 'bound-claim' : 'unbound-copy',
    surroundingSentence: sentenceFor(item.text ?? '', span),
    technicalUseExcluded: technicalTerm(item, span, options),
    personalizationEvidenceBound: hasPersonalizationEvidence(item),
  };
  const base = {
    schemaVersion: 1,
    kind: 'legion-copy-candidate',
    producer: PROVIDER,
    provider: PROVIDER,
    providerVersion: '1.0.0',
    ruleId: rule.id,
    dimension: rule.dimension,
    contentItemIds: [item.id],
    claim: `${rule.claim} because ${reason}`,
    severityHint: rule.severity,
    detectorKind: 'interpretive',
    evidenceRefs: item.evidenceRefs ?? [],
    proofRefs,
    uncertainty: proofRefs.length ? [] : ['supporting-proof-not-bound'],
    denominatorDigest,
    binding,
    verdict: 'UNADJUDICATED',
    adjudicationRequired: true,
    featureVector,
    mediaType: MEDIA_TYPE,
  };
  return { ...base, id: digest(base), digest: digest(base) };
}

const INTERPRETIVE_RULES = [
  {
    id: 'copy.anti-slop.generic-opener',
    feature: 'generic-opener',
    dimension: 'specificity',
    severity: 'low',
    claim: 'Opening is interchangeable with unrelated product copy',
    pattern: /\bin (?:today's|this) (?:fast-paced|ever-changing|digital) world\b/i,
    reason: 'its opening supplies no product, audience, or mechanism detail',
  },
  {
    id: 'copy.anti-slop.empty-intensifier',
    feature: 'empty-intensifier',
    dimension: 'density',
    severity: 'low',
    claim: 'Intensifier adds emphasis without information',
    match(text, item) {
      const match = text.match(/\b(?:truly|incredibly|extremely|remarkably)\b/i);
      if (!match) return null;
      const sentence = sentenceFor(text, match[0]);
      return /(?:\d|%|\b(?:ms|milliseconds|seconds?|minutes?|hours?|users?|items?|gb|mb)\b)/i.test(sentence)
        || item.constraints?.measurableQualifiers
        ? null
        : match;
    },
    reason: 'the emphasized quality has no measurable qualifier',
  },
  {
    id: 'copy.anti-slop.fake-personalization',
    feature: 'fake-personalization',
    dimension: 'trust',
    severity: 'medium',
    claim: 'Personalization language has no bound personalization evidence',
    pattern: /\b(?:made|chosen|selected|picked) (?:just |especially )?for you\b/i,
    reason: 'no personalization input or behavior is referenced',
  },
  {
    id: 'copy.anti-slop.vague-transformation',
    feature: 'vague-transformation',
    dimension: 'proof',
    severity: 'medium',
    claim: 'Transformation claim omits mechanism and measurable outcome',
    match(text) {
      const match = text.match(/\b(?:transform|revolutionize|supercharge|unlock) (?:your|the)\b/i);
      if (!match) return null;
      const sentence = sentenceFor(text, match[0]);
      const hasMechanism = /\b(?:with|via|using|through|by)\s+\w+/i.test(sentence);
      const hasOutcome = /(?:\d|%|\b(?:faster|less|more|reduced|increase|decrease|hours?|minutes?|seconds?)\b)/i.test(sentence);
      return hasMechanism && hasOutcome ? null : match;
    },
    reason: 'the sentence names neither mechanism nor bounded outcome',
  },
  {
    id: 'copy.anti-slop.interchangeable-competitor-copy',
    feature: 'interchangeable-competitor-copy',
    dimension: 'specificity',
    severity: 'medium',
    claim: 'Competitor comparison is interchangeable with generic market copy',
    match(text, item, options) {
      const generic = text.match(/\b(?:better|different|ahead|unlike) than (?:our )?(?:competitors?|the rest|everyone else)\b/i);
      if (generic) return generic;
      const names = [
        ...(item.constraints?.competitorNames ?? []),
        ...(options.competitorNames ?? []),
      ].filter(Boolean).map(escaped);
      if (!names.length) return null;
      const comparison = text.match(new RegExp(`\\b(?:better than|different from|ahead of|unlike|similar to|same as|alternative to)\\s+(?:our\\s+)?(?:${names.join('|')})\\b`, 'i'));
      if (!comparison) return null;
      const sentence = sentenceFor(text, comparison[0]);
      const boundedDetail = /(?:\d|%|\b(?:with|via|using|through|by|because|while|whereas)\b)/i.test(sentence);
      const boundEvidence = Boolean(item.evidenceRefs?.length || item.claimRefs?.length);
      return boundedDetail && boundEvidence ? null : comparison;
    },
    reason: 'the comparison names no differentiating capability or bounded outcome',
  },
  {
    id: 'copy.anti-slop.passive-unspecific-cta',
    feature: 'passive-unspecific-cta',
    dimension: 'actionability',
    severity: 'low',
    claim: 'Call to action uses passive language without a specific action',
    match(text, item) {
      return isCtaContext(item)
        ? text.match(/\b(?:can|will|may|should|is|are)\s+(?:be\s+)?(?:made|built|designed|created|enabled|unlocked|transformed|empowered|inspired)\b/i)
        : null;
    },
    reason: 'the copy names a desired state but not who acts or what action follows',
  },
  {
    id: 'copy.anti-slop.abstract-benefit-stacking',
    feature: 'abstract-benefit-stacking',
    dimension: 'density',
    severity: 'medium',
    claim: 'Abstract benefits are stacked without concrete information',
    match(text) {
      const matches = text.match(/\b(?:success|innovation|impact|growth|value|excellence|potential|possibilities|transformation|future|experience|solutions|confidence|insights)\b/gi);
      return matches?.length >= 3 ? [matches[0], text] : null;
    },
    reason: 'the sentence stacks abstract benefits without a concrete mechanism or outcome',
  },
  {
    id: 'copy.anti-slop.template-repetition',
    feature: 'template-repetition',
    dimension: 'originality',
    severity: 'low',
    claim: 'Repeated template copy reduces distinctiveness',
    match(text, item, options, duplicateCounts) {
      const normalized = text.toLocaleLowerCase().replace(/\s+/g, ' ').trim();
      return duplicateCounts.get(normalized) > 1 ? [text.trim()] : null;
    },
    reason: 'the same content template is repeated across content items',
  },
  {
    id: 'copy.anti-slop.informational-filler',
    feature: 'informational-filler',
    dimension: 'density',
    severity: 'low',
    claim: 'Filler phrase adds no information to the copy',
    pattern: /\b(?:at the end of the day|it goes without saying|when it comes to|for all intents and purposes|in order to|as you know|basically|simply)\b/i,
    reason: 'the phrase can be removed without changing the copy\'s information',
  },
];

export function detectAntiSlop(items = [], options = {}) {
  const binding = options.binding ?? {};
  const denominator = { kind: 'user-visible-content-items', expected: items.length, examined: items.length };
  const denominatorDigest = digest(items.map(({ id, textDigest, text }) => [id, textDigest ?? digest(text ?? '')]));
  const proofByClaim = new Map((options.claimProofLedger?.claims ?? []).map((claim) => [claim.id, claim]));
  const duplicateCounts = new Map();
  for (const item of items) {
    const normalized = (item.text ?? '').toLocaleLowerCase().replace(/\s+/g, ' ').trim();
    duplicateCounts.set(normalized, (duplicateCounts.get(normalized) ?? 0) + 1);
  }
  const candidates = [];
  const findings = [];

  for (const item of items) {
    const text = item.text ?? '';
    for (const ban of options.explicitBans ?? []) {
      const match = text.match(new RegExp(escaped(ban.phrase), 'i'));
      if (match) findings.push({
        ruleId: ban.id,
        detectorKind: 'deterministic',
        contentItemIds: [item.id],
        span: match[0],
        evidenceRefs: item.evidenceRefs ?? [],
        binding,
      });
    }

    if (text.trim().split(/\s+/).length < 4 || !hasContext(item)) continue;
    for (const rule of INTERPRETIVE_RULES) {
      if (rule.id === 'copy.anti-slop.fake-personalization' && hasPersonalizationEvidence(item)) continue;
      const match = featureMatch(rule, text, item, options, duplicateCounts);
      const span = match?.[1] ?? match?.[0];
      if (match && span && !technicalTerm(item, span, options)) {
        candidates.push(candidate(item, rule, span, rule.reason, [], denominatorDigest, binding, options));
      }
    }

    const superlative = text.match(/\b(?:best|leading|fastest|most trusted|number one)\b/i);
    if (superlative && !technicalTerm(item, superlative[0], options)) {
      const claims = (item.claimRefs ?? []).map((id) => proofByClaim.get(id)).filter(Boolean);
      const proofRefs = claims.flatMap((claim) => claim.evidenceRefs ?? []);
      if (!claims.length || claims.some(({ disposition }) => disposition !== 'bound')) {
        candidates.push(candidate(item, {
          id: 'copy.anti-slop.unsupported-superlative',
          feature: 'unsupported-superlative',
          dimension: 'proof',
          severity: 'medium',
          claim: 'Product superlative is unsupported',
        }, superlative[0], 'its bound claim has no complete proof', proofRefs, denominatorDigest, binding, options));
      }
    }
  }

  const base = {
    schemaVersion: 1,
    producer: PROVIDER,
    provider: PROVIDER,
    status: findings.length ? 'findings' : candidates.length ? 'candidates' : 'pass',
    denominator,
    denominatorDigest,
    findings,
    candidates,
    coverageGaps: items.filter((item) => !item.audience || !item.purpose).map((item) => `context-missing:${item.id}`),
    binding,
    mediaType: MEDIA_TYPE,
  };
  return { ...base, digest: digest(base) };
}
