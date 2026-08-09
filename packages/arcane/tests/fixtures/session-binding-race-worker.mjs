// Helper process for session-binding.test.mjs's concurrent-race proof.
//
// Two of these are spawned (via `child_process.spawn`, not `spawnSync`, so
// they run concurrently rather than one after another) against the SAME
// root and SAME session id, to reproduce the real production scenario the
// module header documents: two separate hook subprocesses each running a
// SessionStart for one session at close to the same instant. Each writer
// records its own `ensureBinding` result to its own output file; the test
// then asserts both output files carry the same `runId`.
//
// argv: [root, sessionId, outFile]

import { writeFileSync } from 'node:fs';
import { SessionBindingStore } from '../../lib/session-binding.mjs';

const [, , root, sessionId, outFile] = process.argv;
const store = new SessionBindingStore({ root });
const binding = store.ensureBinding(sessionId);
writeFileSync(outFile, JSON.stringify(binding));
