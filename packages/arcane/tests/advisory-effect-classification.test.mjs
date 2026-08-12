import assert from 'node:assert/strict';
import test from 'node:test';

import { mapClaudeCodePreEffect } from '../host/claude-code-adapter.mjs';
import { mapCodexPreEffect } from '../host/codex-adapter.mjs';
import { EFFECT_CLASS } from '../../contracts/enums.mjs';

test('PUBLISH stays frozen while SEND/SPEND remain absent without exact host adapters', () => {
  assert.equal(EFFECT_CLASS.includes('PUBLISH'), true);
  assert.equal(EFFECT_CLASS.includes('SEND'), false);
  assert.equal(EFFECT_CLASS.includes('SPEND'), false);

  for (const tool_name of ['send_email', 'publish_post', 'create_ad_spend']) {
    const payload = { tool_name, tool_input: { target: 'external:exact' }, tool_use_id: `tool-${tool_name}` };
    assert.equal(mapClaudeCodePreEffect(payload), null, `Claude must not invent ${tool_name}`);
    assert.equal(mapCodexPreEffect(payload), null, `Codex must not invent ${tool_name}`);
  }
});
