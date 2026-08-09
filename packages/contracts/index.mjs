// Legion shared-contract package entry point — WP2 freeze.
//
// Exports every enum (re-exported from enums.mjs) plus a SCHEMA_PATHS map
// from logical schema name -> absolute filesystem path, so downstream build
// lanes can `import { SCHEMA_PATHS } from '.../packages/contracts/index.mjs'`
// without hand-writing paths or reimplementing enum literals.

import { fileURLToPath } from 'node:url';
import path from 'node:path';

export * from './enums.mjs';

export { validateExecutableContract } from './executable.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const schemasDir = path.join(__dirname, 'schemas');

/** Logical schema name -> absolute .schema.json path. */
export const SCHEMA_PATHS = Object.freeze({
  'execution-contract-v1': path.join(schemasDir, 'execution-contract-v1.schema.json'),
  'execution-task-v1': path.join(schemasDir, 'execution-task-v1.schema.json'),
  'worker-capsule-v1': path.join(schemasDir, 'worker-capsule-v1.schema.json'),
  'artifact-v1': path.join(schemasDir, 'artifact-v1.schema.json'),
  'effect-request-v1': path.join(schemasDir, 'effect-request-v1.schema.json'),
  'effect-receipt-v1': path.join(schemasDir, 'effect-receipt-v1.schema.json'),
  'evidence-capability-receipt-v1': path.join(schemasDir, 'evidence-capability-receipt-v1.schema.json'),
  'blocker-v1': path.join(schemasDir, 'blocker-v1.schema.json'),
  'amendment-v1': path.join(schemasDir, 'amendment-v1.schema.json'),
  'claim-v1': path.join(schemasDir, 'claim-v1.schema.json'),
  'covenant-request-v1': path.join(schemasDir, 'covenant-request-v1.schema.json'),
  'covenant-record-v1': path.join(schemasDir, 'covenant-record-v1.schema.json'),
  'operation-envelope-v1': path.join(schemasDir, 'operation-envelope-v1.schema.json'),
  'legion-result-v1': path.join(schemasDir, 'legion-result-v1.schema.json'),
  'run-identity-v1': path.join(schemasDir, 'run-identity-v1.schema.json'),
  'legacy-envelope-v1': path.join(schemasDir, 'legacy-envelope-v1.schema.json'),
  'authority-dispatch-v1': path.join(schemasDir, 'authority-dispatch-v1.schema.json'),
});

export const SCHEMA_NAMES = Object.freeze(Object.keys(SCHEMA_PATHS));
