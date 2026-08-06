import assert from 'node:assert/strict';
import test from 'node:test';
import goPack from '../../../providers/native/go/index.mjs';
import goWebPack from '../../../providers/frameworks/go-web/index.mjs';
import grpcPack from '../../../providers/frameworks/grpc/index.mjs';

const projection = (files = [], deps = []) => ({ files, parsedExtensions: files.map((f) => f.split('.').pop()), auditFacts: { packageManifests: deps } });

test('go pack detects go.mod projects', () => {
  assert.equal(goPack.detect({ projection: projection(['go.mod']) }), true);
  assert.equal(goPack.detect({ projection: projection(['a.py']) }), false);
});

test('go pack emits vet/test/vuln commands', () => {
  const commands = goPack.commands({ root: '/repo', files: ['main.go'], manifests: ['go.mod'], profile: 'standard' });
  assert.ok(commands.some((c) => c.id === 'go.vet'));
  assert.ok(commands.some((c) => c.id === 'go.test'));
  assert.ok(commands.some((c) => c.id === 'go.vuln'));
  const fast = goPack.commands({ root: '/repo', files: ['main.go'], manifests: ['go.mod'], profile: 'fast' });
  assert.ok(!fast.some((c) => c.id === 'go.vuln'));
});

test('go pack normalizes execution', () => {
  const result = goPack.normalize({ commandId: 'go.vet', execution: { exitCode: 0 }, artifacts: {} });
  assert.equal(result.status, 'pass');
});

test('go-web pack flags HTTP servers without timeouts', () => {
  const observations = goWebPack.analyze({ files: ['main.go'], readFile: () => 'srv := &http.Server{Addr: ":8080"}' });
  assert.ok(observations.some((o) => o.ruleId === 'go-web.http-no-timeouts'));
});

test('go-web pack accepts timeouts and body bounds', () => {
  const observations = goWebPack.analyze({
    files: ['main.go'],
    readFile: () => 'srv := &http.Server{Addr: ":8080", ReadHeaderTimeout: 5 * time.Second}\nr.Body = http.MaxBytesReader(w, r.Body, 1<<20)',
  });
  assert.ok(!observations.some((o) => o.ruleId === 'go-web.http-no-timeouts'));
  assert.ok(!observations.some((o) => o.ruleId === 'go-web.unbounded-body'));
});

test('go-web pack flags command sinks with request input', () => {
  const observations = goWebPack.analyze({ files: ['main.go'], readFile: () => 'cmd := exec.Command("sh", r.FormValue("cmd"))' });
  assert.ok(observations.some((o) => o.ruleId === 'go-web.command-input'));
});

test('go-web pack flags routes without auth middleware', () => {
  const observations = goWebPack.analyze({ files: ['main.go'], readFile: () => 'r.GET("/admin", adminHandler)' });
  assert.ok(observations.some((o) => o.ruleId === 'go-web.route-no-auth'));
});

test('grpc pack flags services without auth interceptors', () => {
  const observations = grpcPack.analyze({ files: ['api.proto'], readFile: () => 'service Projects { rpc Get(GetReq) returns (GetRes); }' });
  assert.ok(observations.some((o) => o.ruleId === 'grpc.service-no-auth'));
});

test('grpc pack flags servers without limits', () => {
  const observations = grpcPack.analyze({ files: ['server.go'], readFile: () => 's := grpc.NewServer()' });
  assert.ok(observations.some((o) => o.ruleId === 'grpc.server-no-limits'));
});

test('grpc pack accepts servers with keepalive config', () => {
  const observations = grpcPack.analyze({
    files: ['server.go'],
    readFile: () => 's := grpc.NewServer(grpc.KeepaliveParams(keepalive.ServerParameters{Time: 10 * time.Second}))',
  });
  assert.ok(!observations.some((o) => o.ruleId === 'grpc.server-no-limits'));
});
