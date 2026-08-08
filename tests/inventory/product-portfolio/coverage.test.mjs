import assert from 'node:assert/strict';import test from 'node:test';import {buildPortfolio} from '../../../lib/inventory/product-targets/build-portfolio.mjs';
test('unknown deliverable remains in portfolio coverage',()=>{const row={id:'u',kind:'unknown-deliverable',root:'.'};assert.deepEqual(buildPortfolio({candidates:[row]}).coverage.unknownDeliverables,['u']);});
