import assert from 'node:assert/strict';
import test from 'node:test';
import dotnetPack from '../../../providers/native/dotnet/index.mjs';
import aspnetPack from '../../../providers/frameworks/aspnet/index.mjs';
import efPack from '../../../providers/frameworks/entity-framework/index.mjs';

const projection = (files = [], deps = []) => ({ files, parsedExtensions: files.map((f) => f.split('.').pop()), auditFacts: { packageManifests: deps } });

test('dotnet pack detects .NET projects', () => {
  assert.equal(dotnetPack.detect({ projection: projection(['App.csproj']) }), true);
  assert.equal(dotnetPack.detect({ projection: projection(['a.py']) }), false);
});

test('dotnet pack emits offline build/test commands', () => {
  const commands = dotnetPack.commands({ root: '/repo', files: ['A.cs'], manifests: ['App.csproj'], profile: 'standard' });
  assert.ok(commands.some((c) => c.id === 'dotnet.build'));
  assert.ok(commands.some((c) => c.id === 'dotnet.test'));
  for (const command of commands) {
    assert.ok(command.args.includes('--no-restore'), `${command.id} must not restore from network`);
  }
});

test('dotnet pack normalizes execution', () => {
  const result = dotnetPack.normalize({ commandId: 'dotnet.build', execution: { exitCode: 0 }, artifacts: {} });
  assert.equal(result.status, 'pass');
});

test('aspnet pack flags permissive CORS and developer exception page', () => {
  const observations = aspnetPack.analyze({ files: ['Program.cs'], readFile: () => 'app.UseCors(b => b.AllowAnyOrigin())\napp.UseDeveloperExceptionPage()' });
  assert.ok(observations.some((o) => o.ruleId === 'aspnet.cors-permissive'));
  assert.ok(observations.some((o) => o.ruleId === 'aspnet.developer-exception-page'));
});

test('aspnet pack flags sensitive routes without [Authorize]', () => {
  const observations = aspnetPack.analyze({ files: ['AdminController.cs'], readFile: () => '[HttpPost]\npublic IActionResult AdminAction() { return Ok(); }' });
  assert.ok(observations.some((o) => o.ruleId === 'aspnet.sensitive-route-no-auth'));
});

test('aspnet pack accepts authorized routes', () => {
  const observations = aspnetPack.analyze({ files: ['AdminController.cs'], readFile: () => '[Authorize]\n[HttpPost]\npublic IActionResult AdminAction() { return Ok(); }' });
  assert.ok(!observations.some((o) => o.ruleId === 'aspnet.sensitive-route-no-auth'));
});

test('ef pack flags raw SQL interpolation', () => {
  const observations = efPack.analyze({ files: ['Repo.cs'], readFile: () => 'db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Id = {id}")' });
  assert.ok(observations.some((o) => o.ruleId === 'ef.raw-sql-interpolation'));
});

test('ef pack flags missing tenant filter', () => {
  const observations = efPack.analyze({ files: ['Repo.cs'], readFile: () => 'db.Projects.Where(p => p.Active).ToList()' });
  assert.ok(observations.some((o) => o.ruleId === 'ef.missing-tenant-filter'));
});

test('ef pack accepts tenant-filtered queries', () => {
  const observations = efPack.analyze({ files: ['Repo.cs'], readFile: () => 'db.Projects.Where(p => p.TenantId == tenantId && p.Active).ToList()' });
  assert.ok(!observations.some((o) => o.ruleId === 'ef.missing-tenant-filter'));
});
