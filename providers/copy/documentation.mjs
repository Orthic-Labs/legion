import { createHash } from 'node:crypto';

const PROVIDER = 'copy.documentation';
const MEDIA_TYPE = 'application/vnd.nemesis.documentation-analysis+json';

function digest(value) {
  return `sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`;
}

function unique(values = []) {
  return [...new Set(values.filter(Boolean))];
}

function evidenceRefs(item, extra = []) {
  return unique([...(item.evidenceRefs ?? []), ...extra]);
}

function schemaRefs(item, contract) {
  return unique([
    ...(item.schemaRefs ?? []),
    ...(contract?.schemaRefs ?? []),
    ...(contract?.schemaRef ? [contract.schemaRef] : []),
  ]);
}

function finding(item, ruleId, claim, evidenceRefs, binding, details = {}) {
  return {
    schemaVersion: 1,
    producer: PROVIDER,
    ruleId,
    detectorKind: 'deterministic',
    category: 'factual-drift',
    contentItemIds: [item.id],
    claim,
    evidenceRefs,
    binding,
    ...details,
  };
}

function editorialCandidate(item, span, denominatorDigest, binding) {
  const base = {
    schemaVersion: 1,
    kind: 'nemesis-copy-candidate',
    producer: PROVIDER,
    provider: PROVIDER,
    providerVersion: '1.0.0',
    ruleId: 'copy.documentation.editorial-density',
    dimension: 'clarity',
    category: 'editorial-polish',
    contentItemIds: [item.id],
    claim: 'Editorial preamble delays information without changing documented behavior.',
    severityHint: 'low',
    detectorKind: 'interpretive',
    evidenceRefs: item.evidenceRefs ?? [],
    proofRefs: [],
    uncertainty: ['editorial-judgment-required'],
    denominatorDigest,
    binding,
    verdict: 'UNADJUDICATED',
    adjudicationRequired: true,
    span,
    suggestion: 'Review for concision while preserving every prerequisite, side effect, and factual claim.',
    mediaType: MEDIA_TYPE,
  };
  return { ...base, id: digest(base), digest: digest(base) };
}

function flags(example) {
  return [...example.matchAll(/--[\w-]+/g)].map(([flag]) => flag);
}

function matchesCommand(example, command) {
  const escaped = command.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`^${escaped}(?:\\s|$)`).test(example.trim());
}

function resolveContract(item, contracts, examples) {
  const explicitId = item.commandId ?? item.commandContractId;
  if (explicitId) return { id: explicitId, contract: contracts.get(explicitId) };

  const declaredCommand = item.command ?? item.commandName;
  if (declaredCommand) {
    const match = [...contracts.values()].find((contract) => contract.command === declaredCommand);
    if (match) return { id: match.id, contract: match };
  }

  const matches = [...contracts.values()].filter((contract) => examples.some((example) => matchesCommand(example, contract.command)));
  return matches.length === 1 ? { id: matches[0].id, contract: matches[0] } : { id: null, contract: null };
}

export function analyzeDocumentation(items = [], options = {}) {
  const binding = options.binding ?? {};
  const denominator = { kind: 'documentation-content-items', expected: items.length, examined: items.length };
  const denominatorDigest = digest(items.map(({ id, textDigest, text }) => [id, textDigest ?? digest(text ?? '')]));
  const contracts = new Map((options.commandContracts ?? []).map((contract) => [contract.id, contract]));
  const claims = new Map((options.claimProofLedger?.claims ?? []).map((claim) => [claim.id, claim]));
  const findings = [];
  const candidates = [];
  const commandBindings = [];
  const releaseNotes = [];
  const coverageGaps = [];

  for (const item of items) {
    const authority = String(item.authority ?? '').toLocaleLowerCase();
    const isAuthorityText = authority === 'legal' || authority === 'security' || /(?:legal|security)-notice/i.test(item.kind ?? '');
    if (isAuthorityText) coverageGaps.push(`authority-required:${item.id}`);

    const examples = (item.examples ?? []).filter((example) => typeof example === 'string');
    if (item.commandId || item.commandContractId || item.command || item.commandName || item.kind === 'command-help' || examples.length) {
      const resolved = resolveContract(item, contracts, examples);
      const contract = resolved.contract;
      const contractEvidenceRefs = contract?.evidenceRefs ?? [];
      const itemSchemaRefs = schemaRefs(item, contract);
      if (!contract) {
        findings.push(finding(item, 'copy.documentation.command-contract-missing', 'Command example has no current command contract.', evidenceRefs(item), binding, { schemaRefs: itemSchemaRefs }));
        commandBindings.push({ contentItemId: item.id, commandId: resolved.id, examples, status: 'unbound', evidenceRefs: evidenceRefs(item), schemaRefs: itemSchemaRefs });
      } else {
        const allowedFlags = contract.options ?? contract.flags ?? [];
        const unknownFlags = examples.flatMap(flags).filter((flag) => !allowedFlags.includes(flag));
        const wrongCommand = examples.filter((example) => !matchesCommand(example, contract.command));
        const missingPrerequisites = (contract.prerequisites ?? []).filter((id) => !(item.prerequisiteRefs ?? []).includes(id));
        const missingSideEffects = (contract.sideEffects ?? []).filter((sideEffect) => !(item.sideEffectRefs ?? []).includes(sideEffect.id ?? sideEffect));
        const status = unknownFlags.length || wrongCommand.length || missingPrerequisites.length || missingSideEffects.length ? 'drift' : 'bound';
        commandBindings.push({
          contentItemId: item.id,
          commandId: contract.id,
          examples,
          status,
          evidenceRefs: evidenceRefs(item, contractEvidenceRefs),
          schemaRefs: itemSchemaRefs,
        });
        if (status === 'drift') findings.push(finding(
          item,
          'copy.documentation.command-contract-drift',
          'Command example does not map to current syntax, options, prerequisites, or documented side effects.',
          evidenceRefs(item, contractEvidenceRefs),
          binding,
          { unknownFlags, wrongCommand, missingPrerequisites, missingSideEffects, schemaRefs: itemSchemaRefs },
        ));
      }
    }

    if (item.kind === 'release-note') {
      const releaseState = item.releaseState ?? 'unproven';
      const claimsShipped = item.claimsShipped === true || /\b(?:now|already|currently)\s+(?:ships?|available|supports?)\b|\bshipped\b|\breleased\b/i.test(item.text ?? '');
      releaseNotes.push({
        contentItemId: item.id,
        state: releaseState,
        claim: claimsShipped ? 'shipped' : releaseState === 'planned' ? 'planned' : 'unproven',
        evidenceRefs: evidenceRefs(item),
        schemaRefs: schemaRefs(item),
      });
      if (claimsShipped && releaseState !== 'shipped') {
        findings.push(finding(
          item,
          'copy.documentation.planned-as-shipped',
          'Release note presents behavior as shipped while bound release state is not shipped.',
          evidenceRefs(item),
          binding,
          { releaseState },
        ));
      }
    }

    for (const term of options.terms ?? []) {
      if (new RegExp(`\\b${term.stale.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(item.text ?? '')) findings.push(finding(
        item,
        'copy.documentation.stale-term',
        `Documentation uses stale term ${term.stale}.`,
        term.evidenceRefs ?? [],
        binding,
        { stale: term.stale, current: term.current },
      ));
    }

    for (const claimId of item.claimRefs ?? []) {
      const claim = claims.get(claimId);
      if (!claim || claim.disposition !== 'bound') findings.push(finding(
        item,
        'copy.documentation.unsupported-claim',
        'Documentation claim lacks current bound proof.',
        claim?.evidenceRefs ?? [],
        binding,
        { claimId },
      ));
    }

    const preamble = /\b(?:it should be noted that|it is important to note that|in order to)\b/i.exec(item.text ?? '');
    if (preamble && !isAuthorityText) candidates.push(editorialCandidate(
      item,
      { text: preamble[0], start: preamble.index, end: preamble.index + preamble[0].length },
      denominatorDigest,
      binding,
    ));
  }

  const base = {
    schemaVersion: 1,
    producer: PROVIDER,
    provider: PROVIDER,
    status: findings.length ? 'findings' : candidates.length ? 'candidates' : coverageGaps.length ? 'unproven' : 'pass',
    denominator,
    denominatorDigest,
    findings,
    candidates,
    commandBindings,
    releaseNotes,
    coverageGaps,
    binding,
    mediaType: MEDIA_TYPE,
  };
  return { ...base, digest: digest(base) };
}
