import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const ENTRY = new URL('../index.mjs', import.meta.url);

async function kernel() {
  try {
    return await import(ENTRY);
  } catch {
    return null;
  }
}

async function tempDir(label) {
  return mkdtemp(path.join(os.tmpdir(), `legion-kernel-${label}-`));
}

function requestEnvelope(runId, requestId, operationId = 'legion.task.start') {
  return {
    schemaVersion: 1,
    kind: 'legion-operation-envelope',
    envelopeKind: 'request',
    operationId,
    operationVersion: '1.0.0',
    requestId,
    runId,
    callerAuthority: 'legion',
    authorityAssertion: {
      assertedBy: 'test-host',
      perMessage: true,
      verificationMethod: 'capability-signature',
    },
    input: {},
    sourceRevision: '1234567',
    requestedAt: '2026-08-08T00:00:00.000Z',
  };
}

test('run/task identity mints contract IDs and binds run-identity-v1', async () => {
  const api = await kernel();
  assert.ok(api, 'kernel package entry point must exist');

  const runId = api.mintId('run', { now: 1_723_072_000_000 });
  const taskId = api.mintId('task', { now: 1_723_072_000_000 });
  assert.match(runId, /^run_[0-9A-HJKMNP-TV-Z]{26}$/);
  assert.match(taskId, /^ktask_[0-9A-HJKMNP-TV-Z]{26}$/);
  assert.equal(api.validateId('run', runId), runId);
  assert.equal(api.validateId('task', taskId), taskId);
  assert.throws(() => api.validateId('task', runId), /invalid task id/);

  const identity = api.bindRunIdentity({
    runId,
    workspace: 'D:/Claude',
    repository: 'nemesis',
    revision: '1234567',
    dirtyDigest: null,
    capturedAt: '2026-08-08T00:00:00.000Z',
  });
  assert.deepEqual(identity, {
    schemaVersion: 1,
    kind: 'legion-run-identity',
    runId,
    workspace: 'D:/Claude',
    repository: 'nemesis',
    revision: '1234567',
    dirtyDigest: null,
    capturedAt: '2026-08-08T00:00:00.000Z',
  });
});

test('durable task lifecycle resumes from append-only journal after crash', async () => {
  const api = await kernel();
  assert.ok(api, 'kernel package entry point must exist');
  const dir = await tempDir('lifecycle');
  const journalPath = path.join(dir, 'tasks.jsonl');

  const first = await api.TaskLifecycle.open(journalPath);
  const runId = api.mintId('run');
  const task = await first.create({ runId, input: { goal: 'ship' }, idempotencyKey: 'request-1' });
  const duplicate = await first.create({ runId, input: { goal: 'ship' }, idempotencyKey: 'request-1' });
  assert.equal(duplicate.taskId, task.taskId);
  await first.start(task.taskId);
  assert.equal((await first.start(task.taskId)).state, 'RUNNING');
  await first.requireInput(task.taskId, { question: 'target?' });
  assert.equal(first.get(task.taskId).state, 'INPUT_REQUIRED');

  const resumed = await api.TaskLifecycle.open(journalPath);
  assert.equal(resumed.get(task.taskId).state, 'INPUT_REQUIRED');
  assert.equal((await resumed.create({ runId, idempotencyKey: 'request-1' })).taskId, task.taskId);
  const concurrent = await Promise.all([
    resumed.create({ runId, idempotencyKey: 'request-2' }),
    resumed.create({ runId, idempotencyKey: 'request-2' }),
  ]);
  assert.equal(concurrent[0].taskId, concurrent[1].taskId);
  await resumed.provideInput(task.taskId, { target: 'kernel' });
  await resumed.cancel(task.taskId, 'operator');
  assert.equal(resumed.get(task.taskId).state, 'CANCELLED');
  await resumed.resume(task.taskId);
  await resumed.complete(task.taskId, { ok: true });
  assert.equal(resumed.get(task.taskId).state, 'COMPLETED');
  assert.deepEqual(resumed.get(task.taskId).result, { ok: true });

  const expiring = await resumed.create({ runId, input: {} });
  await resumed.start(expiring.taskId);
  assert.equal((await resumed.expire(expiring.taskId)).state, 'EXPIRED');

  const lines = (await readFile(journalPath, 'utf8')).trim().split('\n').map(JSON.parse);
  assert.ok(lines.length >= 7);
  assert.deepEqual(lines.map(({ sequence }) => sequence), lines.map((_, index) => index + 1));
  await assert.rejects(() => resumed.resume(task.taskId), (error) => {
    assert.equal(error.code, 'TASK_ALREADY_TERMINAL');
    return true;
  });

  const journalLines = (await readFile(journalPath, 'utf8')).trim().split('\n');
  const corruptTransition = JSON.parse(journalLines[1]);
  corruptTransition.from = 'INPUT_REQUIRED';
  journalLines[1] = JSON.stringify(corruptTransition);
  await writeFile(journalPath, `${journalLines.join('\n')}\n`);
  await assert.rejects(() => api.TaskLifecycle.open(journalPath), (error) => {
    assert.equal(error.code, 'JOURNAL_CORRUPT');
    assert.equal(error.category, 'integrity');
    return true;
  });
});

test('operation registry validates envelopes and returns typed unknown-operation error', async () => {
  const api = await kernel();
  assert.ok(api, 'kernel package entry point must exist');
  const registry = new api.OperationRegistry();
  const runId = api.mintId('run');
  const requestId = api.mintId('request');
  const envelope = requestEnvelope(runId, requestId);

  registry.register({
    operationId: envelope.operationId,
    version: envelope.operationVersion,
    title: 'Start task',
    purpose: 'Create one durable task',
    envelope,
    handlerBinding: 'task.start',
  });
  assert.equal(registry.lookup('legion.task.start').handlerBinding, 'task.start');
  assert.throws(
    () => registry.register({ operationId: 'bad', version: '1', envelope: {} }),
    /invalid operation envelope/,
  );
  assert.throws(() => registry.lookup('legion.missing'), (error) => {
    assert.equal(error.code, 'OPERATION_NOT_AVAILABLE');
    assert.equal(error.category, 'usage');
    assert.equal(error.exitCode, api.EXIT_CODES.usage);
    assert.equal(error.retryable, false);
    return true;
  });

  assert.deepEqual(
    api.negotiateCapabilities({ required: ['task.start', 'artifact.get'], supported: ['task.start'] }),
    { available: ['task.start'], missing: ['artifact.get'], compatible: false },
  );
});

test('event and artifact stores preserve digest-bound append-only records', async () => {
  const api = await kernel();
  assert.ok(api, 'kernel package entry point must exist');
  const dir = await tempDir('stores');
  const runId = api.mintId('run');
  const taskId = api.mintId('task');
  const events = await api.EventStore.open(path.join(dir, 'events.jsonl'));
  const first = await events.append({ runId, taskId, type: 'task.created', actor: 'kernel' });
  const second = await events.append({ runId, taskId, type: 'task.started', actor: 'kernel' });
  assert.equal(first.sequence, 1);
  assert.equal(second.previousEventDigest, first.eventDigest);
  await Promise.all(Array.from({ length: 4 }, (_, index) => events.append({
    runId, taskId, type: `task.progress.${index}`, actor: 'kernel',
  })));
  assert.deepEqual(events.all().map(({ sequence }) => sequence), [1, 2, 3, 4, 5, 6]);
  assert.equal((await api.EventStore.open(path.join(dir, 'events.jsonl'))).all().length, 6);

  const content = Buffer.from('sealed kernel evidence');
  const digest = api.digestContent(content);
  const artifacts = await api.ArtifactStore.open(path.join(dir, 'artifacts'));
  const record = await artifacts.put({
    schemaVersion: 1,
    kind: 'legion-artifact',
    artifactId: api.mintId('artifact'),
    artifactKind: 'evidence',
    digest,
    bytes: content.length,
    immutable: true,
    producerAuthority: 'kernel',
    sourceRevision: '1234567',
    sensitivity: 'internal',
    retention: { policy: 'task' },
    redaction: { applied: false, metadata: [] },
    createdAt: '2026-08-08T00:00:00.000Z',
  }, content);
  assert.equal(record.digest, digest);
  assert.deepEqual(await artifacts.getContent(record.artifactId), content);
  await assert.rejects(
    () => artifacts.put({ ...record, artifactId: api.mintId('artifact'), digest: `sha256:${'0'.repeat(64)}` }, content),
    /artifact digest mismatch/,
  );

  const eventPath = path.join(dir, 'events.jsonl');
  const tampered = (await readFile(eventPath, 'utf8')).replace('task.started', 'task.corrupt');
  await writeFile(eventPath, tampered);
  await assert.rejects(() => api.EventStore.open(eventPath), /event digest mismatch/);
});

test('lane scheduler respects dependencies and concurrency keys with serial equivalence', async () => {
  const api = await kernel();
  assert.ok(api, 'kernel package entry point must exist');
  assert.deepEqual(api.schedulerOptionsFromArgv(['--serial']), { serial: true });
  assert.deepEqual(api.schedulerOptionsFromArgv([]), { serial: false });

  async function run(serial) {
    const active = new Set();
    let collision = false;
    const make = (id, value, dependencies = [], concurrencyKey = null) => ({
      id,
      dependencies,
      concurrencyKey,
      run: async ({ results }) => {
        if (concurrencyKey && active.has(concurrencyKey)) collision = true;
        if (concurrencyKey) active.add(concurrencyKey);
        await new Promise((resolve) => setTimeout(resolve, id === 'a' ? 8 : 2));
        if (concurrencyKey) active.delete(concurrencyKey);
        return value + dependencies.reduce((sum, dep) => sum + results.get(dep), 0);
      },
    });
    const graph = [make('a', 1, [], 'repo'), make('b', 2, [], 'repo'), make('c', 3, ['a']), make('d', 4, ['b'])];
    const results = await new api.LaneScheduler({ serial }).execute(graph);
    return { values: Object.fromEntries(results), collision };
  }

  const parallel = await run(false);
  const serial = await run(true);
  assert.deepEqual(parallel.values, serial.values);
  assert.equal(parallel.collision, false);
  assert.equal(serial.collision, false);
  await assert.rejects(
    () => new api.LaneScheduler().execute([{ id: 'a', dependencies: ['missing'], run: async () => 1 }]),
    /unknown dependency/,
  );
});

test('model profile enforcement is data-driven and only downgrades', async () => {
  const api = await kernel();
  assert.ok(api, 'kernel package entry point must exist');
  const strict = api.loadModelProfile('strict');
  const standard = api.loadModelProfile('standard');
  const advanced = api.loadModelProfile('advanced');
  assert.equal(strict.limits.maxConcurrency, 1);
  assert.ok(strict.limits.maxPacketTasks < standard.limits.maxPacketTasks);
  assert.ok(standard.limits.maxPacketTasks < advanced.limits.maxPacketTasks);
  assert.equal(strict.limits.allowWorkerSpawn, false);
  assert.throws(() => api.loadModelProfile('elite'), /unknown worker profile/);
  assert.equal(api.downgradeModelProfile(advanced, 'scenario-regression').name, 'standard');
  assert.equal(api.downgradeModelProfile(strict, 'adapter-change').name, 'strict');
  assert.throws(
    () => api.downgradeModelProfile(standard, 'self-selected', { requestedBy: 'model' }),
    /model-requested profile changes are forbidden/,
  );
  assert.throws(() => api.downgradeModelProfile(standard, ''), /downgrade reason/);
});

test('kernelTaskId bridge stays distinct from ExecutionTask identity', async () => {
  const api = await kernel();
  assert.ok(api, 'kernel package entry point must exist');
  assert.deepEqual(api.KERNEL_TASK_ID_BRIDGE_DECISION, {
    decision: 'keep-bridge',
    executionTaskId: 'T-#.#',
    kernelTaskId: 'ktask_<ulid>',
    field: 'kernelTaskId',
    rationale: 'ExecutionTask identity is human-facing contract state; Kernel task identity is an opaque durable runtime handle.',
  });
  assert.match(api.mintId('task'), /^ktask_/);
  assert.equal(api.validateExecutionTaskId('T-4.2'), 'T-4.2');
});
