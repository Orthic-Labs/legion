import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { listTools, callTool } from '../../integrations/mcp/tools.mjs';
import { mcpInstallConfig, installPreview } from '../../integrations/mcp/install.mjs';

const SERVER = fileURLToPath(new URL('../../integrations/mcp/server.mjs', import.meta.url));

test('tools are read-only and cover the required surface', () => {
  const tools = listTools();
  const names = tools.map((tool) => tool.name).sort();
  assert.deepEqual(names, [
    'legion_audit', 'legion_doctor', 'legion_explain', 'legion_get_finding',
    'legion_get_run', 'legion_list_families', 'legion_list_languages',
    'legion_list_providers', 'legion_list_skills', 'legion_plan', 'legion_verify',
  ]);
  // No mutation tools.
  assert.ok(!tools.some((tool) => /apply|fix|write|delete/.test(tool.name)));
});

test('tools/list and tools/call work over stdio', () => {
  const input = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '1' } } },
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'legion_list_providers', arguments: {} } },
  ].map((line) => JSON.stringify(line)).join('\n');
  const result = spawnSync(process.execPath, [SERVER], { input, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  assert.equal(result.status, 0);
  const lines = result.stdout.trim().split('\n').map((line) => JSON.parse(line));
  const initialize = lines.find((line) => line.id === 1);
  assert.equal(initialize.result.serverInfo.name, 'legion');
  assert.ok(initialize.result.capabilities.tools);
  const list = lines.find((line) => line.id === 2);
  assert.equal(list.result.tools.length, 11);
  const call = lines.find((line) => line.id === 3);
  assert.equal(call.result.isError, false);
  assert.ok(JSON.parse(call.result.content[0].text).providers.length > 0);
});

test('unknown tool returns an error result, never a crash', () => {
  const input = `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'legion_apply', arguments: {} } })}\n`;
  const result = spawnSync(process.execPath, [SERVER], { input, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  const response = JSON.parse(result.stdout.trim());
  assert.equal(response.result.isError, true);
});

test('stdout carries protocol frames only', () => {
  const input = `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} })}\n`;
  const result = spawnSync(process.execPath, [SERVER], { input, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  // Every stdout line is a JSON-RPC frame.
  for (const line of result.stdout.trim().split('\n')) {
    const frame = JSON.parse(line);
    assert.equal(frame.jsonrpc, '2.0');
  }
});

test('legion_get_run and legion_get_finding read run artifacts', async () => {
  const dir = mkdtempSync(join(process.cwd(), '.legion-mcp-'));
  try {
    writeFileSync(join(dir, 'report.json'), JSON.stringify({ findings: [{ id: 'f1', ruleId: 'r', severity: 'high' }] }));
    const run = await callTool({ name: 'legion_get_run', arguments: { run: dir, artifact: 'report.json' } });
    assert.equal(run.isError, false);
    const finding = await callTool({ name: 'legion_get_finding', arguments: { run: dir, findingId: 'f1' } });
    assert.equal(finding.isError, false);
    assert.equal(JSON.parse(finding.content[0].text).finding.id, 'f1');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('installer prints config but never edits client config without preview', () => {
  const config = mcpInstallConfig();
  assert.equal(config.mcpServers.legion.command, 'legion');
  const preview = installPreview({ host: 'claude', config });
  assert.equal(preview.dryRun, true);
});
