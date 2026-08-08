import assert from 'node:assert/strict';import test from 'node:test';import {discoverExternalSystems} from '../../../lib/inventory/external-systems/discover.mjs';
test('dependency is reference not production proof',()=>{const result=discoverExternalSystems({projection:{dependencies:['stripe']},components:{components:[]}});assert.equal(result.systems[0].status,'referenced');});
