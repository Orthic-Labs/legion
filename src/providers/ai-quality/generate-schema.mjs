#!/usr/bin/env node
// Generates the committed schemas/ai-quality/evaluation-receipt-v1.schema.json
// from the code-owned buildEvaluationReceiptSchema(). Run:
//   node providers/ai-quality/generate-schema.mjs
// A test asserts the committed file stays byte-identical to this output.

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildEvaluationReceiptSchema } from './schema-builder.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const target = resolve(root, '..', 'src/schemas/ai-quality/evaluation-receipt-v1.schema.json');
mkdirSync(dirname(target), { recursive: true });
writeFileSync(target, `${JSON.stringify(buildEvaluationReceiptSchema(), null, 2)}\n`, 'utf8');
