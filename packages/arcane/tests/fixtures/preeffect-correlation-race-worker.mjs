// Helper process for preeffect-correlation.test.mjs's concurrent-race proof.
// Mirrors session-binding-race-worker.mjs exactly, one store swapped for the
// other — see that file's header for the full rationale.
//
// argv: [root, toolUseId, outFile]

import { writeFileSync } from 'node:fs';
import { PreEffectCorrelationStore } from '../../lib/preeffect-correlation.mjs';

const [, , root, toolUseId, outFile] = process.argv;
const store = new PreEffectCorrelationStore({ root });
const requestId = store.ensureRequestId(toolUseId);
writeFileSync(outFile, JSON.stringify({ requestId }));
