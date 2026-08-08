import test from 'node:test';
import assert from 'node:assert/strict';
import { planMobilePlatformSurfaces } from '../../../../providers/runtime/mobile/platform-surfaces/index.mjs';

test('B4-028 covers denial, authorization, WebView, IPC, push, and extensions', () => {
  const receipt = planMobilePlatformSurfaces({ permissions: ['camera'], links: ['app-link'], channels: ['push'], extensions: ['widget'] });
  assert.ok(receipt.scenarios.some((item) => item.id === 'permission:camera:denied' && item.expected === 'graceful-degradation'));
  assert.ok(receipt.scenarios.some((item) => item.id === 'link:app-link:malicious' && item.requirements.includes('server-authorization-recheck')));
  for (const family of ['webview', 'ipc', 'push', 'extension']) assert.ok(receipt.scenarios.some((item) => item.family === family));
  assert.ok(receipt.scenarios.filter((item) => ['ipc', 'push'].includes(item.family)).every((item) => item.payloadAuthority === false));
});
