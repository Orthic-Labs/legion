import { readFileSync } from 'node:fs';

const deepFreeze = (value) => {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
};

export const WEB_JOURNEY_PLAN = deepFreeze(JSON.parse(readFileSync(new URL('../../../registry/platform-scenarios/web.json', import.meta.url), 'utf8')));

export const WEB_JOURNEYS = WEB_JOURNEY_PLAN.journeys;
export const WEB_PROTOCOLS = WEB_JOURNEY_PLAN.protocols;

export function webJourneyForControl(controlId) {
  return WEB_JOURNEYS.find((row) => row.controlId === controlId) ?? null;
}

export function webJourneySurfaceMatches({ journeyId, route, stateId, matrixCombinationId } = {}) {
  return WEB_JOURNEYS.some((row) => row.applicable === true && (journeyId === undefined || row.id === journeyId) && row.route === route && row.stateId === stateId && row.matrixCombinationId === matrixCombinationId);
}

export function webRouteEvidenceMatches(row, evidence = {}, bindingMatches = () => false) {
  return evidence.kind === 'web-route-navigation'
    && evidence.journeyId === row.id
    && evidence.routeId === row.routeId
    && evidence.control === row.controlId
    && evidence.actionId === row.actionId
    && evidence.route === row.route
    && evidence.stateId === row.stateId
    && evidence.matrixCombinationId === row.matrixCombinationId
    && bindingMatches(evidence.binding ?? {});
}
