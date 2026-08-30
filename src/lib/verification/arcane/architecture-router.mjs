import { ArcaneError } from '../../contracts/arcane/errors.mjs';

export const SIGNIFICANCE_RULES = Object.freeze(['quality_or_mission','responsibility_boundary','data_authority_boundary','trust_or_risk_boundary','failure_or_deployment_boundary','durable_contract','broad_impact','hard_to_reverse','durable_governance','material_loss']);
export const OBJECTIVE = Object.freeze(['sufficient','optimize','best_shape']);
export const ARCHITECTURE_DEPTH = Object.freeze(['D0','D1','D2']);
export const ASSURANCE_RIGOR = Object.freeze(['lite','standard','critical']);
export const DOOR = Object.freeze(['reversible','one_way','authority_sensitive']);
export const EFFECT_CATEGORY_RULES = Object.freeze({ FILE_WRITE:'reversible', FILE_MOVE:'reversible', FILE_DELETE:'one_way', VCS_PUSH:'one_way', PUBLISH:'one_way', EXTERNAL_SIDE_EFFECT:'one_way', CREDENTIAL_ACCESS:'authority_sensitive', DEPENDENCY_INSTALL:'authority_sensitive', VCS_COMMIT:'authority_sensitive' });
export const ARCHITECTURE_ROUTER_INPUT_SCHEMA_ID = 'architecture-router-input.v1';
export const ARCHITECTURE_ROUTE_SCHEMA_ID = 'architecture-route.v1';
export const OBJECTIVES = OBJECTIVE; export const DEPTHS = ARCHITECTURE_DEPTH; export const RIGORS = ASSURANCE_RIGOR; export const EFFECT_DOORS = DOOR;
const CRITICAL = new Set(['safety','severe_security_privacy','regulated','irreversible_data','mission_critical','hard_real_time','destructive_migration']);
const DEPTH_FLAGS = Object.freeze(['system_level','cross_boundary','migration','platform','broad_review']);
const ROUTER_FIELDS = new Set(['objective','optimize_axis','significance','effect','flags','prior_route',...CRITICAL,...DEPTH_FLAGS]);
function fail(message, detail = {}) { throw new ArcaneError('ARC_SCHEMA_INVALID', message, detail); }
function value(input, name) { return input?.[name] ?? null; }
export function normalizeArchitectureRoute(input = {}) {
  const objective = String(value(input,'objective') ?? '').trim().toLowerCase().replace(/[ -]+/g, '_');
  const optimizeAxis = value(input,'optimize_axis');
  return Object.freeze({ ...input, objective: objective === 'best_shape' ? 'best_shape' : (typeof optimizeAxis === 'string' && optimizeAxis.trim() ? 'optimize' : 'sufficient'), optimize_axis: typeof optimizeAxis === 'string' && optimizeAxis.trim() ? optimizeAxis.trim() : null });
}
export function normalizeArchitectureAlias(value) { return typeof value === 'string' ? value.trim().toLowerCase().replace(/[ -]+/g, '_') : value; }
export function classifySignificance(facts = {}) { if (!facts || typeof facts !== 'object' || Array.isArray(facts)) fail('significance facts must be an object'); const matched = SIGNIFICANCE_RULES.filter((key) => facts[key] === true); for (const key of Object.keys(facts)) if (!SIGNIFICANCE_RULES.includes(key)) fail(`unknown significance fact: ${key}`); return Object.freeze({ significant: matched.length > 0, matched_significance_facts: Object.freeze(matched) }); }
export function classifyEffect(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('effect classification must be an object');
  for (const key of Object.keys(input)) if (!['declared_type','category','semantic_risk'].includes(key)) fail(`unknown effect classification field: ${key}`);
  const explicit = value(input,'declared_type'); const category = value(input,'category'); const semantic = value(input,'semantic_risk');
  if (explicit && DOOR.includes(explicit)) return Object.freeze({ declared_type: explicit, matched_rule:'declared_type', basis:explicit, door:explicit });
  if (category && EFFECT_CATEGORY_RULES[category]) return Object.freeze({ declared_type: explicit ?? null, matched_rule:'capability_category', basis:category, door:EFFECT_CATEGORY_RULES[category] });
  if (['destructive','irreversible','data_loss','external_commitment'].includes(semantic)) return Object.freeze({ declared_type: explicit ?? null, matched_rule:'semantic_risk', basis:semantic, door:'one_way' });
  if (['authority','credential','trust_boundary','production','spend','send','publish'].includes(semantic)) return Object.freeze({ declared_type: explicit ?? null, matched_rule:'semantic_risk', basis:semantic, door:'authority_sensitive' });
  return Object.freeze({ declared_type: explicit ?? null, matched_rule:'safe_default', basis:semantic ?? 'ambiguous', door:'authority_sensitive' });
}
export function routeArchitecture(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('architecture router input must be an object');
  for (const key of Object.keys(input)) if (!ROUTER_FIELDS.has(key)) fail(`unknown architecture router field: ${key}`);
  if (input.objective !== undefined && !OBJECTIVE.includes(normalizeArchitectureAlias(input.objective))) fail('objective is invalid');
  if (input.prior_route && (typeof input.prior_route !== 'object' || !OBJECTIVE.includes(input.prior_route.objective))) fail('prior_route is invalid');
  if (input.flags !== undefined && (!Array.isArray(input.flags) || input.flags.some((flag) => ![...CRITICAL,...DEPTH_FLAGS].includes(flag)))) fail('flags contain an unknown routing fact');
  const normalized = normalizeArchitectureRoute(input); const significance = classifySignificance(normalized.significance ?? normalized.facts ?? {});
  if (input.prior_route?.objective && input.prior_route.objective !== normalized.objective) fail('objective self-upgrade requires explicit authority');
  const flags = new Set(Array.isArray(input.flags) ? input.flags : []); const critical = [...CRITICAL].some((fact) => input[fact] === true || flags.has(fact));
  const depth = !significance.significant ? 'D0' : (normalized.objective === 'best_shape' || DEPTH_FLAGS.some((fact) => input[fact] === true || flags.has(fact)) ? 'D2' : 'D1');
  return Object.freeze({ schema:ARCHITECTURE_ROUTE_SCHEMA_ID, ...significance, objective:normalized.objective, optimize_axis:normalized.optimize_axis, depth, rigor:critical ? 'critical' : significance.significant ? 'standard' : 'lite', effect_classification:classifyEffect(normalized.effect ?? input) });
}
export function validateArchitectureRouterInput(input) { try { routeArchitecture(input); return Object.freeze({ valid:true, issues:Object.freeze([]) }); } catch (error) { return Object.freeze({ valid:false, issues:Object.freeze([error.message]) }); } }
export function assertArchitectureRouterInput(input) { const result=validateArchitectureRouterInput(input); if (!result.valid) fail(result.issues[0]); return input; }
