// Legion executable-contract validator — EC-C.
//
// Composes (a) draft 2020-12 structural validation against
// `execution-contract-v1.schema.json` via lib/qualification/schema-validator.mjs
// with (b) G9 executability rules JSON Schema cannot express:
//   - openQuestions must be empty (G9)
//   - EXACT artifacts must carry non-null content (ARCHITECTURE §12)
//   - BOUNDED artifacts must carry non-empty locked[] and freedom[] (ARCHITECTURE §12)
//   - shared-mutable-resource edges must carry a resourceKey (ARCHITECTURE §32a)
//   - contract-wide ID uniqueness across R-/D-/I-/AC-/NG-/EC-/F-/B-/A-/CV-/T- prefixes
//
// Backward-compatible surface: returns the contract on success, throws
// TypeError on the first sorted failure (legacy callers in smoke.test.mjs
// assert this round-trip + throw behavior). EC-C consumers that need the
// full sorted error list should call `collectExecutableContractErrors`.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { validateSchema } from '../../lib/qualification/schema-validator.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const schemaPath = path.join(__dirname, 'schemas', 'execution-contract-v1.schema.json');
const schema = JSON.parse(readFileSync(schemaPath, 'utf8'));

const ID_FAMILIES = new Map([
  ['R-', /^R-\d+$/],
  ['D-', /^D-\d+$/],
  ['I-', /^I-\d+$/],
  ['AC-', /^AC-\d+$/],
  ['NG-', /^NG-\d+$/],
  ['EC-', /^EC-\d+$/],
  ['F-', /^F-\d+$/],
  ['B-', /^B-\d+$/],
  ['A-', /^A-\d+$/],
  ['CV-', /^CV-\d+$/],
  ['T-', /^T-\d+(\.\d+)*$/],
]);

function collectIds(contract) {
  const ids = [];
  const buckets = [
    ['requirements', contract.requirements],
    ['decisions', contract.decisions],
    ['invariants', contract.invariants],
    ['nonGoals', contract.nonGoals],
    ['acceptanceCriteria', contract.acceptanceCriteria],
    ['openQuestions', contract.openQuestions],
  ];
  for (const [label, list] of buckets) {
    for (const entry of list ?? []) if (entry?.id) ids.push({ id: entry.id, where: label });
  }
  for (const taskId of contract.tasks ?? []) ids.push({ id: taskId, where: 'tasks' });
  return ids;
}

function runExecutabilityChecks(contract) {
  const errors = [];
  if (!Array.isArray(contract.openQuestions) || contract.openQuestions.length !== 0) {
    errors.push({ code: 'G9_OPEN_QUESTIONS_NONEMPTY', path: '$.openQuestions', message: 'execution contract has open questions' });
  }
  for (const [latitude, list] of [['exact', contract.artifacts?.exact], ['bounded', contract.artifacts?.bounded]]) {
    if (!Array.isArray(list)) continue;
    list.forEach((unit, index) => {
      const unitPath = `$.artifacts.${latitude}[${index}]`;
      const idLabel = unit.id ?? unitPath;
      if (latitude === 'exact') {
        if (unit.content === null || unit.content === undefined) {
          errors.push({ code: 'EXEC_EXACT_CONTENT_NULL', path: `${unitPath}.content`, message: `EXACT artifact ${idLabel} requires content` });
        } else if (typeof unit.content !== 'string') {
          errors.push({ code: 'EXEC_EXACT_CONTENT_TYPE', path: `${unitPath}.content`, message: `EXACT artifact ${idLabel} content must be string; got ${typeof unit.content}` });
        }
      } else if (latitude === 'bounded') {
        if (!Array.isArray(unit.locked) || unit.locked.length === 0) {
          errors.push({ code: 'EXEC_BOUNDED_LOCKED_EMPTY', path: `${unitPath}.locked`, message: `BOUNDED artifact ${idLabel} requires locked and freedom` });
        }
        if (!Array.isArray(unit.freedom) || unit.freedom.length === 0) {
          errors.push({ code: 'EXEC_BOUNDED_FREEDOM_EMPTY', path: `${unitPath}.freedom`, message: `BOUNDED artifact ${idLabel} requires locked and freedom` });
        }
      }
    });
  }
  (contract.dependencies ?? []).forEach((edge, index) => {
    if (edge?.reason === 'shared-mutable-resource') {
      if (edge.resourceKey === null || edge.resourceKey === undefined || (typeof edge.resourceKey === 'string' && edge.resourceKey.length === 0)) {
        errors.push({ code: 'EXEC_RESOURCE_KEY_MISSING', path: `$.dependencies[${index}].resourceKey`, message: 'shared mutable dependency requires resourceKey' });
      }
    }
  });
  const ids = collectIds(contract);
  const seen = new Map();
  for (const entry of ids) {
    if (seen.has(entry.id)) {
      errors.push({ code: 'EXEC_ID_NOT_UNIQUE', path: `$.${seen.get(entry.id).where}[*].id`, message: `execution contract ids must be unique: ${entry.id} appears in ${seen.get(entry.id).where} and ${entry.where}` });
    } else {
      seen.set(entry.id, entry);
    }
  }
  return errors;
}

function sortErrors(errors) {
  return [...new Map(errors.map((e) => [`${e.code}:${e.path}:${e.message}`, e])).values()]
    .sort((a, b) => a.code.localeCompare(b.code) || a.path.localeCompare(b.path) || a.message.localeCompare(b.message));
}

export function collectExecutableContractErrors(contract) {
  if (contract == null || typeof contract !== 'object' || Array.isArray(contract)) {
    return [{ code: 'INPUT_NOT_OBJECT', path: '$', message: 'contract must be a plain object' }];
  }
  const errors = [];
  for (const issue of validateSchema(schema, contract)) {
    errors.push({ code: 'SCHEMA', path: issue, message: issue });
  }
  errors.push(...runExecutabilityChecks(contract));
  return sortErrors(errors);
}

export function validateExecutableContract(contract) {
  const errors = collectExecutableContractErrors(contract);
  if (errors.length > 0) throw new TypeError(errors[0].message);
  return contract;
}
