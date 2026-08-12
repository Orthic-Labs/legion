import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { validateSchema } from '../../../lib/qualification/schema-validator.mjs';
import { ArcaneError } from './errors.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'schemas');
const FILES = Object.freeze(['contract-seal-v1.schema.json', 'authority-binding-v1.schema.json', 'capability-grant-v1.schema.json', 'capability-transition-v1.schema.json', 'user-approval-v1.schema.json', 'host-event-ledger-record-v1.schema.json', 'authority-invocation-proof-v1.schema.json', 'authority-proof-transition-v1.schema.json', 'pending-terminal-operation-v1.schema.json', 'terminal-operation-transition-v1.schema.json', 'high-risk-assurance-request-v1.schema.json', 'high-risk-assurance-receipt-v1.schema.json', 'high-risk-assurance-consumption-v1.schema.json', 'advisory-artifact-receipt-v1.schema.json', 'advisory-certification-receipt-v1.schema.json', 'host-runtime-output-v1.schema.json', 'host-runtime-result-v1.schema.json', 'budget-governance-v1.schema.json', 'task-budget-seal-v1.schema.json']);
export class RuntimeSchemaSet {
  #schemas;
  constructor() { this.#schemas = new Map(FILES.map((file) => { const schema = JSON.parse(readFileSync(join(root, file), 'utf8')); return [schema.$id, schema]; })); }
  validate(id, value) { const schema = this.#schemas.get(id); if (!schema) throw new ArcaneError('ARC_SCHEMA_INVALID', `unknown runtime schema: ${id}`, { id }); const branches = schema.oneOf ? schema.oneOf.filter((branch) => validateSchema(branch, value).length === 0).length : 1; return [...validateSchema(schema, value), ...(branches === 1 ? [] : ['$: must match exactly one oneOf branch']), ...this.#rfc3339Issues(value)]; }
  assert(id, value) { const issues = this.validate(id, value); if (issues.length) throw new TypeError(issues[0]); return value; }
  isRfc3339(value) { return typeof value === 'string' && !Number.isNaN(Date.parse(value)) && /T.*(?:Z|[+-]\d\d:\d\d)$/.test(value); }
  #rfc3339Issues(value, path = '$') {
    if (!value || typeof value !== 'object') return [];
    if (Array.isArray(value)) return value.flatMap((entry, index) => this.#rfc3339Issues(entry, `${path}[${index}]`));
    return Object.entries(value).flatMap(([key, entry]) => {
      const child = `${path}.${key}`;
      const issue = ['sealedAt', 'observedAt', 'issuedAt', 'expiresAt', 'at'].includes(key) && !this.isRfc3339(entry) ? [`${child}: must be RFC3339`] : [];
      return [...issue, ...this.#rfc3339Issues(entry, child)];
    });
  }
}
