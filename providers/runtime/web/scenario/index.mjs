import { WEB_JOURNEYS, WEB_PROTOCOLS, webRouteEvidenceMatches } from '../journey-plan.mjs';
import { sanitizeProducedArtifact } from '../../../../lib/platform/artifact-sanitize.mjs';
import { canonicalize, denominator, exactBinding, finalize, redact, RESULT_STATUSES, sameBinding } from '../shared.mjs';

const unequal = (expected, actual) => JSON.stringify(canonicalize(expected)) !== JSON.stringify(canonicalize(actual));
const REQUIRED_JOURNEYS = WEB_JOURNEYS.filter((row) => row.applicable === true);
const REQUIRED_CONTROLS = Object.freeze(REQUIRED_JOURNEYS.map((row) => row.controlId));
const ROUTE_CONTROLS = new Set(REQUIRED_JOURNEYS.filter((row) => row.directApplicable === true || row.deepApplicable === true).map((row) => row.controlId));
const BROWSER_DIAGNOSTICS = Object.freeze(['cache', 'console', 'cookies', 'cors', 'csp', 'error', 'headers', 'hydration', 'network']);
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/;
const artifactEvidence = (values, binding) => { if (values === undefined) return { artifacts: [], gaps: [] }; if (!Array.isArray(values)) return { artifacts: [], gaps: ['artifact-collection-invalid'] }; const processed = values.map((artifact) => ({ ...sanitizeProducedArtifact(artifact), bound: sameBinding(binding, artifact?.binding ?? {}) })); return { artifacts: processed.filter((item) => item.valid && item.bound).map((item) => item.artifact), gaps: [...(processed.some((item) => !item.valid || !item.bound) ? ['artifact-evidence-invalid'] : []), ...(processed.some((item) => item.sensitive) ? ['artifact-sensitive-data'] : [])] }; };

function browserDiagnosticGaps(value, binding) {
  if (!value || typeof value !== 'object') return ['browser-diagnostics-missing'];
  const gaps = [];
  const denominatorIds = Array.isArray(value.denominator) ? value.denominator : [];
  if (JSON.stringify([...new Set(denominatorIds)].sort()) !== JSON.stringify(BROWSER_DIAGNOSTICS)) gaps.push('browser-diagnostics-denominator-mismatch');
  const facts = Array.isArray(value.facts) ? value.facts : [];
  for (const id of BROWSER_DIAGNOSTICS) {
    const matches = facts.filter((item) => item?.id === id);
    if (!matches.length) gaps.push(`browser-diagnostic-missing:${id}`);
    else {
      if (matches.length > 1) gaps.push(`browser-diagnostic-duplicate:${id}`);
      const fact = matches[0];
      if (fact.status !== 'pass' || fact.terminal !== true) gaps.push(`browser-diagnostic-unproven:${id}`);
      if (!sameBinding(binding, fact.binding ?? {})) gaps.push(`browser-diagnostic-binding-mismatch:${id}`);
    }
  }
  for (const fact of facts) if (!BROWSER_DIAGNOSTICS.includes(fact?.id)) gaps.push(`browser-diagnostic-unplanned:${fact?.id ?? 'missing'}`);
  return gaps;
}

function serverAuthorizationGaps(value, binding, controlId) {
  if (!value || typeof value !== 'object') return ['server-authorization-evidence-missing'];
  const gaps = [];
  if (value.kind !== 'server-authorization-evidence' || value.source !== 'server' || value.uiDerived !== false) gaps.push('server-authorization-kind-invalid');
  if (value.actorId !== binding.actorId) gaps.push('server-authorization-actor-mismatch');
  if (value.tenantId !== binding.tenantId) gaps.push('server-authorization-tenant-mismatch');
  if (value.controlId !== controlId) gaps.push('server-authorization-control-mismatch');
  if (value.status !== 'pass' || value.terminal !== true) gaps.push('server-authorization-unproven');
  if (!Array.isArray(value.authorizationIds) || !value.authorizationIds.length || value.authorizationIds.some((id) => typeof id !== 'string' || !id)) gaps.push('server-authorization-denominator-empty');
  if (!sameBinding(binding, value.binding ?? {})) gaps.push('server-authorization-binding-mismatch');
  return gaps;
}

export async function runWebScenario({ binding = {}, adapter = {}, controls = [], protocols = [], expectedState = {} } = {}) {
  if (!Array.isArray(controls) || !Array.isArray(protocols) || protocols.some((item) => !item || typeof item !== 'object')) return finalize('nemesis-web-scenario', { status: 'error', terminal: true, binding, denominator: denominator([], []), receipts: [], coverageGaps: ['scenario-collections-invalid'] });
  if (controls.some((id) => typeof id !== 'string' || !SAFE_IDENTIFIER.test(id)) || protocols.some((item) => typeof item.name !== 'string' || !SAFE_IDENTIFIER.test(item.name) || Object.hasOwn(item, 'id') && (typeof item.id !== 'string' || !SAFE_IDENTIFIER.test(item.id)))) return finalize('nemesis-web-scenario', { status: 'error', terminal: true, binding, denominator: denominator([], []), receipts: [], coverageGaps: ['scenario-identifiers-invalid'] });
  const suppliedControls = [...controls];
  const ids = [...REQUIRED_JOURNEYS.map((row) => row.id), ...WEB_PROTOCOLS.map((row) => row.id)].sort();
  const bindingGaps = exactBinding(binding).gaps;
  if (binding.environment === 'production') return finalize('nemesis-web-scenario', { status: 'blocked', terminal: true, binding, denominator: denominator(ids, ids.map((id) => ({ id }))), receipts: ids.map((id) => ({ id, status: 'blocked', terminal: true, reason: 'production-effect-forbidden' })), coverageGaps: ['production-effect-forbidden'] });

  const receipts = [];
  const unrecognizedGaps = [];
  const suppliedIds = [...suppliedControls.map((id) => `control:${id}`), ...protocols.map((item) => `protocol:${item.name}`)];
  const duplicateIds = [...new Set(suppliedIds.filter((id, index) => suppliedIds.indexOf(id) !== index))];
  const suppliedSet = new Set(suppliedControls);
  const protocolsByName = new Map();
  for (const item of protocols) if (!protocolsByName.has(item.name)) protocolsByName.set(item.name, item);
  const unplannedControls = [...new Set(suppliedControls.filter((item) => !REQUIRED_CONTROLS.includes(item)))].sort();
  const unplannedProtocols = [...new Set(protocols.filter((item) => !WEB_PROTOCOLS.some((row) => row.protocolId === item?.name)).map((item) => item?.name ?? 'missing'))].sort();
  const applicabilityMismatches = [...new Set(protocols.filter((item) => WEB_PROTOCOLS.some((row) => row.protocolId === item?.name && row.applicable !== item?.applicable)).map((item) => item.name))].sort();
  const preflightInvalid = Boolean(bindingGaps.length || unplannedControls.length || unplannedProtocols.length || applicabilityMismatches.length || duplicateIds.length);

  for (const journey of REQUIRED_JOURNEYS) {
    const { id, controlId: control } = journey;
    if (!suppliedSet.has(control)) { receipts.push({ id, control, journeyId: id, status: 'unproven', terminal: true, coverageGaps: ['journey-not-observed'] }); continue; }
    if (preflightInvalid) { receipts.push({ id, control, journeyId: id, status: 'unproven', terminal: true, coverageGaps: ['scenario-preflight-invalid', ...(bindingGaps.length ? ['binding-unproven'] : [])] }); continue; }
    try {
      if (typeof adapter.invoke !== 'function') receipts.push({ id, control, journeyId: id, status: 'unproven', terminal: true, coverageGaps: ['adapter-missing'] });
      else {
        const rawObserved = await adapter.invoke({ control, journey, binding, expectedState });
        const artifactResult = artifactEvidence(rawObserved?.artifacts, binding);
        const observed = redact({ ...rawObserved, artifacts: undefined });
        const coverageGaps = [];
        const adapterStatus = rawObserved?.status;
        const adapterStatusValid = adapterStatus === undefined || RESULT_STATUSES.includes(adapterStatus);
        if (!adapterStatusValid) coverageGaps.push('adapter-status-invalid');
        if (adapterStatus !== undefined && rawObserved?.terminal !== true) coverageGaps.push('adapter-result-nonterminal');
        if (adapterStatusValid && adapterStatus !== undefined && adapterStatus !== 'pass') coverageGaps.push(`adapter-status-${adapterStatus}`);
        coverageGaps.push(...artifactResult.gaps);
        if (observed?.observedState === undefined || observed?.observedState === null) coverageGaps.push('observed-state-missing');
        if (observed?.durableState === undefined || observed?.durableState === null) coverageGaps.push('durable-state-missing');
        if (observed?.observedState !== undefined && unequal(expectedState, observed.observedState)) coverageGaps.push('observed-state-mismatch');
        if (observed?.durableState !== undefined && unequal(expectedState, observed.durableState)) coverageGaps.push('durable-state-mismatch');
        if (ROUTE_CONTROLS.has(control)) {
          const route = observed?.routeEvidence;
          if (!route || route.kind !== 'web-route-navigation') coverageGaps.push('route-evidence-missing');
          else if (!webRouteEvidenceMatches(journey, route, (candidate) => sameBinding(binding, candidate))) coverageGaps.push('route-evidence-plan-mismatch');
        }
        coverageGaps.push(...browserDiagnosticGaps(observed?.browserDiagnostics, binding), ...serverAuthorizationGaps(observed?.serverAuthorization, binding, control));
        const status = !adapterStatusValid || adapterStatus !== undefined && rawObserved?.terminal !== true ? 'error' : adapterStatus !== undefined && adapterStatus !== 'pass' ? adapterStatus : coverageGaps.length ? 'unproven' : 'pass';
        receipts.push({ id, control, journeyId: id, routeId: journey.routeId, actionId: journey.actionId, status, terminal: true, expectedState, observedState: observed?.observedState ?? null, durableState: observed?.durableState ?? null, routeEvidence: observed?.routeEvidence ?? null, browserDiagnostics: observed?.browserDiagnostics ?? null, serverAuthorization: observed?.serverAuthorization ?? null, artifacts: artifactResult.artifacts, coverageGaps });
      }
    } catch (error) { receipts.push({ id, control, journeyId: id, status: 'error', terminal: true, errors: [{ name: error?.name ?? 'Error', message: redact(error?.message ?? String(error)) }] }); }
  }

  for (const control of [...new Set(suppliedControls.filter((item) => !REQUIRED_CONTROLS.includes(item)))].sort()) {
    unrecognizedGaps.push(`control:${control}:unplanned`);
  }

  for (const planProtocol of WEB_PROTOCOLS) {
    const { id, protocolId: protocolName } = planProtocol;
    const protocol = protocolsByName.get(protocolName);
    if (!protocol) { receipts.push({ id, protocol: protocolName, status: 'unproven', terminal: true, coverageGaps: ['protocol-not-observed'] }); continue; }
    if (preflightInvalid) { receipts.push({ id, protocol: protocolName, status: 'unproven', terminal: true, coverageGaps: ['scenario-preflight-invalid', ...(applicabilityMismatches.includes(protocolName) ? ['protocol-applicability-mismatch'] : [])] }); continue; }
    if (protocol.applicable !== planProtocol.applicable) { receipts.push({ id, protocol: protocolName, status: 'unproven', terminal: true, coverageGaps: ['protocol-applicability-mismatch', ...(protocol.applicable === true ? ['protocol-unexercised'] : [])] }); continue; }
    if (!planProtocol.applicable) {
      const evidence = protocol.evidence;
      const valid = protocol.reason === planProtocol.reason && evidence?.kind === 'configured-protocol-applicability' && evidence.reason === protocol.reason && typeof evidence.source === 'string' && /^sha256:[a-f0-9]{64}$/.test(evidence.digest ?? '') && sameBinding(binding, evidence.binding ?? {});
      const coverageGaps = ['protocol-excluded', ...(valid ? [] : ['protocol-exclusion-evidence-missing'])];
      receipts.push({ id, protocol: protocolName, status: valid ? 'unsupported' : 'unproven', terminal: true, reason: protocol.reason ?? null, evidence: evidence ?? null, coverageGaps });
      continue;
    }
    const invoke = adapter.invokeProtocol ?? adapter.invoke;
    if (typeof invoke !== 'function') { receipts.push({ id, protocol: protocolName, status: 'unproven', terminal: true, coverageGaps: ['protocol-unexercised'] }); continue; }
    try {
      const rawObserved = await invoke.call(adapter, { protocol: protocolName, binding, expectedState });
      const artifactResult = artifactEvidence(rawObserved?.artifacts, binding);
      const observed = redact({ ...rawObserved, artifacts: undefined });
      const coverageGaps = [...artifactResult.gaps];
      const adapterStatus = rawObserved?.status;
      const adapterStatusValid = adapterStatus === undefined || RESULT_STATUSES.includes(adapterStatus);
      if (!adapterStatusValid) coverageGaps.push('adapter-status-invalid');
      if (adapterStatus !== undefined && rawObserved?.terminal !== true) coverageGaps.push('adapter-result-nonterminal');
      if (adapterStatusValid && adapterStatus !== undefined && adapterStatus !== 'pass') coverageGaps.push(`adapter-status-${adapterStatus}`);
      if (observed?.observedState === undefined || observed?.observedState === null || observed?.durableState === undefined || observed?.durableState === null) coverageGaps.push('protocol-unexercised');
      if (observed?.observedState !== undefined && unequal(expectedState, observed.observedState)) coverageGaps.push('observed-state-mismatch');
      if (observed?.durableState !== undefined && unequal(expectedState, observed.durableState)) coverageGaps.push('durable-state-mismatch');
      const status = !adapterStatusValid || adapterStatus !== undefined && rawObserved?.terminal !== true ? 'error' : adapterStatus !== undefined && adapterStatus !== 'pass' ? adapterStatus : coverageGaps.length ? 'unproven' : 'pass';
      receipts.push({ id, protocol: protocolName, status, terminal: true, observedState: observed?.observedState ?? null, durableState: observed?.durableState ?? null, artifacts: artifactResult.artifacts, coverageGaps });
    } catch (error) { receipts.push({ id, protocol: protocolName, status: 'error', terminal: true, errors: [{ name: error?.name ?? 'Error', message: redact(error?.message ?? String(error)) }], coverageGaps: ['protocol-exercise-error'] }); }
  }

  const counts = denominator(ids, receipts);
  const gaps = bindingGaps.map((key) => `binding-missing:${key}`);
  if (preflightInvalid) gaps.push('scenario-preflight-invalid');
  if (!ids.length || (!suppliedControls.length && !protocols.length)) gaps.push('scenario-denominator-empty');
  gaps.push(...suppliedControls.filter((control) => !REQUIRED_CONTROLS.includes(control)).map((control) => `control-unrecognized:${control}`));
  gaps.push(...protocols.filter((item) => !WEB_PROTOCOLS.some((row) => row.protocolId === item.name)).map((item) => `protocol-unrecognized:${item.name}`));
  gaps.push(...REQUIRED_JOURNEYS.filter((row) => !suppliedSet.has(row.controlId)).flatMap((row) => [`control-missing:${row.controlId}`, `journey-omitted:${row.id}`]));
  gaps.push(...WEB_PROTOCOLS.filter((row) => !protocolsByName.has(row.protocolId)).map((row) => `protocol-omitted:${row.id}`));
  gaps.push(...unrecognizedGaps);
  gaps.push(...duplicateIds.map((id) => `scenario-id-duplicate:${id}`));
  gaps.push(...receipts.flatMap((item) => (item.coverageGaps ?? []).map((gap) => `${item.id}:${gap}`)), ...receipts.filter((item) => !['pass', 'unsupported'].includes(item.status) && !(item.coverageGaps?.length)).map((item) => `control-${item.status}:${item.id}`), ...counts.missing.map((id) => `receipt-missing:${id}`));
  const status = ['error', 'fail', 'blocked', 'partial', 'unproven'].find((candidate) => receipts.some((item) => item.status === candidate)) ?? (gaps.length ? 'partial' : 'pass');
  return finalize('nemesis-web-scenario', { status, terminal: true, binding, planId: 'web', denominator: counts, receipts, coverageGaps: [...new Set(gaps)].sort() });
}
