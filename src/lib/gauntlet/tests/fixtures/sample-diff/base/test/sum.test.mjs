// Weak test: only exercises one path. The line `if (v === 0) continue;`
// can be mutated to `if (v !== 0) continue;` and the test still passes,
// because the test never passes a 0. The gauntlet must catch that.
import test from "node:test";
import assert from "node:assert/strict";
import { sum } from "../src/sum.js";

test("sum adds positive integers", () => {
  assert.equal(sum([1, 2, 3]), 6);
  assert.equal(sum([10, 20]), 30);
});
