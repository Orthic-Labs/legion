export function applyConstraints(cases, constraints = []) { return cases.filter((item) => constraints.every((constraint) => constraint(item))); }
