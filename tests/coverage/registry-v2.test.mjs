import assert from 'node:assert/strict';import test from 'node:test';import registry from '../../src/registry/coverage/index.json' with {type:'json'};import {validateCoverageRegistry,accountCoverage} from '../../src/lib/coverage/index.mjs';
// bench/corpora now ships and every digest recomputes, so this runs for real.
// measured-pack itself stayed 0: the corpora measure provider selection, and
// provider-architecture.md reserves that tier for rule-output precision and
// recall. Raising it needs a rule-output corpus, not a selection one.
test('coverage v2 requires corpus digests for every measured record',()=>{assert.equal(validateCoverageRegistry(registry),registry);assert.ok(registry.records.filter((row)=>row.tiers['measured-pack']).every((row)=>row.corpusDigest&&row.artifactDigest));});
test('unknown detected formats remain explicit tier-zero records',()=>{assert.equal(accountCoverage(['mystery'],registry)[0].cleanClaim,'never');});
