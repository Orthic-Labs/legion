export function extractRiskContext(projection = {}, contract = {}) { return { candidates: projection.riskCandidates ?? [], riskAuthority: contract.declared?.riskAuthority ?? null }; }
