function typeMatches(value, type) {
  if (Array.isArray(type)) return type.some((candidate) => typeMatches(value, candidate));
  if (type === 'null') return value === null;
  if (type === 'array') return Array.isArray(value);
  if (type === 'object') return value !== null && typeof value === 'object' && !Array.isArray(value);
  if (type === 'integer') return Number.isInteger(value);
  return typeof value === type;
}

function resolveRef(root, ref) {
  if (!ref.startsWith('#/')) throw new Error(`unsupported schema ref: ${ref}`);
  return ref.slice(2).split('/').reduce((node, key) => node[key], root);
}

export function validateSchema(schema, value, path = '$', root = schema) {
  if (schema.$ref) return validateSchema(resolveRef(root, schema.$ref), value, path, root);
  const issues = [];
  if (schema.const !== undefined && value !== schema.const) issues.push(`${path}:const`);
  if (schema.enum && !schema.enum.includes(value)) issues.push(`${path}:enum`);
  if (schema.type && !typeMatches(value, schema.type)) return [...issues, `${path}:type`];

  if (typeof value === 'string') {
    if (schema.minLength !== undefined && value.length < schema.minLength) issues.push(`${path}:min-length`);
    if (schema.maxLength !== undefined && value.length > schema.maxLength) issues.push(`${path}:max-length`);
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) issues.push(`${path}:pattern`);
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) issues.push(`${path}:minimum`);
    if (schema.maximum !== undefined && value > schema.maximum) issues.push(`${path}:maximum`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) issues.push(`${path}:min-items`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) issues.push(`${path}:max-items`);
    if (schema.items) value.forEach((item, index) => issues.push(...validateSchema(schema.items, item, `${path}[${index}]`, root)));
  }
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    for (const key of schema.required ?? []) if (!(key in value)) issues.push(`${path}.${key}:required`);
    const allowed = new Set(Object.keys(schema.properties ?? {}));
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) if (!allowed.has(key)) issues.push(`${path}.${key}:additional-property`);
    }
    for (const [key, child] of Object.entries(schema.properties ?? {})) {
      if (key in value) issues.push(...validateSchema(child, value[key], `${path}.${key}`, root));
    }
  }
  return issues;
}
