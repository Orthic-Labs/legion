import assert from 'node:assert/strict';import test from 'node:test';import registry from '../../src/registry/coverage/index.json' with {type:'json'};import {validateCoverageRegistry,accountCoverage} from '../../src/lib/coverage/index.mjs';
// TODO: 13 records claim measured-pack coverage, but bench/corpora is not in
// the repository, so their corpus digests cannot be substantiated. Either the
// corpora ship or those records drop to an unmeasured tier; that is a coverage
// decision, not a test fix. Tracked in docs/pending/plans/2026-09-03-dogfood-findings.md.
test('coverage v2 requires corpus digests for every measured record',{todo:'bench/corpora is absent; measured-pack claims are unsubstantiated'},()=>{assert.equal(validateCoverageRegistry(registry),registry);assert.ok(registry.records.filter((row)=>row.tiers['measured-pack']).every((row)=>row.corpusDigest&&row.artifactDigest));});
test('unknown detected formats remain explicit tier-zero records',()=>{assert.equal(accountCoverage(['mystery'],registry)[0].cleanClaim,'never');});
