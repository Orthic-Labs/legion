import { readFileSync } from 'node:fs';

import { SCHEMA_PATHS } from '../../contracts/index.mjs';
import { KernelError } from './errors.mjs';

const schemas = new Map();

function schemaFor(name) {
  if (!SCHEMA_PATHS[name]) {
    throw new KernelError('INVALID_ARGUMENT', `unknown contract schema: ${name}`, { category: 'usage' });
  }
  if (!schemas.has(name)) schemas.set(name, JSON.parse(readFileSync(SCHEMA_PATHS[name], 'utf8')));
  return schemas.get(name);
}

function resolveRef(root, reference) {
  if (!reference.startsWith('#/')) throw new Error(`external schema reference is unsupported: ${reference}`);
  return reference.slice(2).split('/').reduce((value, segment) => value?.[segment.replaceAll('~1', '/').replaceAll('~0', '~')], root);
}

function matchesType(value, type) {
  if (type === 'null') return value === null;
  if (type === 'array') return Array.isArray(value);
  if (type === 'object') return value !== null && typeof value === 'object' && !Array.isArray(value);
  if (type === 'integer') return Number.isInteger(value);
  return typeof value === type;
}

function validateNode(schema, value, root, at, errors) {
  if (schema.$ref) return validateNode(resolveRef(root, schema.$ref), value, root, at, errors);
  if (schema.oneOf) {
    const matches = schema.oneOf.filter((candidate) => {
      const candidateErrors = [];
      validateNode(candidate, value, root, at, candidateErrors);
      return candidateErrors.length === 0;
    });
    if (matches.length !== 1) errors.push(`${at} must match exactly one schema branch`);
    return;
  }
  if ('const' in schema && value !== schema.const) errors.push(`${at} must equal ${JSON.stringify(schema.const)}`);
  if (schema.enum && !schema.enum.includes(value)) errors.push(`${at} is not an allowed value`);
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.some((type) => matchesType(value, type))) {
      errors.push(`${at} must be ${types.join('|')}`);
      return;
    }
  }
  if (typeof value === 'string') {
    if (schema.minLength !== undefined && value.length < schema.minLength) errors.push(`${at} is too short`);
    if (schema.pattern && !(new RegExp(schema.pattern)).test(value)) errors.push(`${at} has invalid format`);
    if (schema.format === 'date-time' && Number.isNaN(Date.parse(value))) errors.push(`${at} must be an ISO date-time`);
  }
  if (typeof value === 'number' && schema.minimum !== undefined && value < schema.minimum) {
    errors.push(`${at} is below minimum`);
  }
  if (Array.isArray(value) && schema.items) {
    value.forEach((item, index) => validateNode(schema.items, item, root, `${at}[${index}]`, errors));
  }
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    for (const required of schema.required ?? []) {
      if (!Object.hasOwn(value, required)) errors.push(`${at}.${required} is required`);
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!Object.hasOwn(schema.properties ?? {}, key)) errors.push(`${at}.${key} is unknown`);
      }
    }
    for (const [key, child] of Object.entries(schema.properties ?? {})) {
      if (Object.hasOwn(value, key)) validateNode(child, value[key], root, `${at}.${key}`, errors);
    }
  }
}

export function assertContract(name, value, label = name) {
  const schema = schemaFor(name);
  const errors = [];
  validateNode(schema, value, schema, '$', errors);
  if (errors.length) {
    throw new KernelError('INVALID_ARGUMENT', `invalid ${label}: ${errors.join('; ')}`, {
      category: 'usage',
      details: { schema: name, errors },
    });
  }
  return value;
}

export function bindRunIdentity(fields) {
  const identity = { schemaVersion: 1, kind: 'legion-run-identity', ...fields };
  return assertContract('run-identity-v1', identity, 'run identity');
}
