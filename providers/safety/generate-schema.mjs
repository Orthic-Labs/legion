#!/usr/bin/env node
// Generates the committed schemas/safety/hazard-model-v1.schema.json from the
// code-owned builder in ./schema-builder.mjs, following the same pattern as
// scripts/generate-security-schemas.mjs. Run: node providers/safety/generate-schema.mjs

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildHazardModelSchema } from './schema-builder.mjs';

const root = fileURLToPath(new URL('../..', import.meta.url));

export function safetySchemaText() {
  return `${JSON.stringify(buildHazardModelSchema(), null, 2)}\n`;
}

function main() {
  const target = resolve(root, 'schemas/safety/hazard-model-v1.schema.json');
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, safetySchemaText(), 'utf8');
  console.log('wrote schemas/safety/hazard-model-v1.schema.json');
}

if (process.argv[1] && process.argv[1].endsWith('generate-schema.mjs')) main();
