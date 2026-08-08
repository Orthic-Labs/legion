import assert from 'node:assert/strict';import test from 'node:test';import {buildStackGraph} from '../../../lib/inventory/stacks/build-graph.mjs';
test('stack version evidence remains dimensional',()=>{const graph=buildStackGraph({portfolio:{targets:[]},components:{components:[]},projection:{dependencies:{react:'^19'}}});assert.equal(graph.stacks[0].version.kind,'declared-range');});
