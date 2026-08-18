// CLI exit-code mapping. Canonical taxonomy: 0 pass, 1 policy fail, 2
// incomplete/unproven, 3 internal, 4 usage, 5 integrity. Applied only after
// the final audit status is known.

export { EXIT } from '../errors.mjs';
export { exitCodeForReport } from '../core/finalize-run.mjs';
