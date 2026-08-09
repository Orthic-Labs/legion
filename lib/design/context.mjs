import { createHash } from 'node:crypto';
const digest = (value) => `sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`;

export function createDesignContext(input = {}) {
  const declared = input.declared ?? {};
  return { schemaVersion: 1, kind: 'legion-design-context', source: input.source ?? null, declared, inferred: input.inferred ?? {}, binding: input.binding ?? {},
    status: Object.keys(declared).length ? 'pass' : 'unproven', coverageGaps: Object.keys(declared).length ? [] : ['brand-context-missing'], digest: digest({ declared, binding: input.binding ?? {} }) };
}
