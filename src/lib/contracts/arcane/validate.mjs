// Frozen-contract validation for Arcane.
//
// Minimize ladder: the structural JSON Schema walk already exists in this repo
// at lib/qualification/schema-validator.mjs (46 lines, zero dependencies,
// covers exactly the draft-2020-12 subset packages/contracts/ uses: type,
// const, enum, required, properties, additionalProperties:false, items,
// pattern, minLength, minimum, $ref -> #/$defs). Arcane imports it read-only
// rather than re-implementing it. This module adds only what that validator
// deliberately omits and Arcane depends on:
//
//   - `format: date-time` (freshness/skew checks are meaningless if a receipt
//     can carry "yesterday" as its timestamp);
//   - schema loading/caching keyed by the frozen SCHEMA_PATHS map, so no
//     Arcane module hand-writes a path into packages/contracts/;
//   - a typed ArcaneError instead of a bare string array, so a contract
//     violation is indistinguishable in handling from any other Arcane refusal.
//
// packages/contracts/ is READ-ONLY to this lane. Nothing here writes to it.

import { readFileSync } from 'node:fs';
import { SCHEMA_PATHS } from '../../../packages/contracts/index.mjs';
import { validateSchema } from '../../qualification/schema-validator.mjs';
import { ArcaneError } from './errors.mjs';

const cache = new Map();

/** Load (and cache) a frozen schema by its logical name, e.g. 'effect-receipt-v1'. */
export function loadSchema(name) {
  if (cache.has(name)) return cache.get(name);
  const p = SCHEMA_PATHS[name];
  if (!p) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', `unknown frozen schema: ${name}`, {
      name,
      known: Object.keys(SCHEMA_PATHS),
    });
  }
  const schema = JSON.parse(readFileSync(p, 'utf8'));
  cache.set(name, schema);
  return schema;
}

// RFC 3339 date-time, the shape every frozen schema's `format: date-time`
// fields are produced in (`new Date().toISOString()`), plus offset forms.
const DATE_TIME_RE = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

/** Walk a schema collecting the JSON pointers of every `format: date-time` field. */
function checkDateTimes(schema, value, path, root, issues) {
  if (!schema || typeof schema !== 'object') return;
  if (schema.$ref) {
    const target = schema.$ref.slice(2).split('/').reduce((n, k) => (n ? n[k] : undefined), root);
    return checkDateTimes(target, value, path, root, issues);
  }
  if (schema.format === 'date-time' && typeof value === 'string' && !DATE_TIME_RE.test(value)) {
    issues.push(`${path}:format-date-time`);
  }
  if (Array.isArray(value) && schema.items) {
    value.forEach((v, i) => {
      checkDateTimes(schema.items, v, `${path}[${i}]`, root, issues);
    });
  }
  if (value && typeof value === 'object' && !Array.isArray(value) && schema.properties) {
    for (const [k, child] of Object.entries(schema.properties)) {
      if (k in value) checkDateTimes(child, value[k], `${path}.${k}`, root, issues);
    }
  }
}

/**
 * Validate `value` against a frozen contract schema.
 * @returns {{valid: boolean, issues: string[]}}
 */
export function validateAgainst(name, value) {
  const schema = loadSchema(name);
  const issues = validateSchema(schema, value);
  checkDateTimes(schema, value, '$', schema, issues);
  return { valid: issues.length === 0, issues };
}

/**
 * Validate against a named `$defs` entry of a frozen schema.
 *
 * `operation-envelope-v1` is a `$defs`-only schema: its top level declares no
 * `properties` and no `required`, so validating a value against the file
 * itself passes trivially. Callers must target `OperationRequest` /
 * `OperationResult` explicitly, and this is the function that lets them.
 */
export function validateAgainstDef(name, defName, value) {
  const root = loadSchema(name);
  const def = root.$defs?.[defName];
  if (!def) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', `${name} has no $defs entry '${defName}'`, {
      schema: name,
      known: Object.keys(root.$defs ?? {}),
    });
  }
  // validateSchema resolves `#/$defs/...` refs against its `root` argument, so
  // the root stays the whole document even though the subject is one $def.
  const issues = validateSchema({ ...def }, value, '$', root);
  checkDateTimes(def, value, '$', root, issues);
  return { valid: issues.length === 0, issues };
}

/** Validate or throw ARC_SCHEMA_INVALID with the full issue list attached. */
export function assertValid(name, value, label = name) {
  const { valid, issues } = validateAgainst(name, value);
  if (!valid) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', `${label} does not satisfy ${name}`, { schema: name, issues });
  }
  return value;
}
