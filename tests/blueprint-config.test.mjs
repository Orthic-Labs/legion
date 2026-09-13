import assert from 'node:assert/strict';
import test from 'node:test';
import { blueprintConfigReport } from '../scripts/check-blueprint-config.mjs';

test('committed blueprint config excludes agent-local memory from indexing', () => {
	const report = blueprintConfigReport();
	assert.equal(report.status, 'pass', report.issues?.map((issue) => issue.reason).join('; '));
	assert.ok(report.issues.length === 0);
});
