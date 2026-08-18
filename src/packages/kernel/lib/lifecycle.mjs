import { INVOCATION_STATE } from '../../contracts/enums.mjs';
import { KernelError } from './errors.mjs';
import { mintId, validateId } from './ids.mjs';
import { JsonlJournal } from './journal.mjs';

const TERMINAL = new Set(['COMPLETED', 'FAILED_INVOCATION', 'EXPIRED']);
const ALLOWED = Object.freeze({
  ACCEPTED: new Set(['RUNNING', 'CANCELLED', 'EXPIRED', 'FAILED_INVOCATION']),
  RUNNING: new Set(['INPUT_REQUIRED', 'CANCELLED', 'EXPIRED', 'FAILED_INVOCATION', 'COMPLETED']),
  INPUT_REQUIRED: new Set(['RUNNING', 'CANCELLED', 'EXPIRED', 'FAILED_INVOCATION']),
  CANCELLED: new Set(['RUNNING']),
});

export class TaskLifecycle {
  static async open(filePath) {
    const journal = await JsonlJournal.open(filePath);
    const lifecycle = new TaskLifecycle(journal);
    lifecycle.replay();
    return lifecycle;
  }

  constructor(journal) {
    this.journal = journal;
    this.tasks = new Map();
    this.idempotency = new Map();
    this.mutationTail = Promise.resolve();
  }

  replay() {
    for (const event of this.journal.all()) this.apply(event);
  }

  apply(event) {
    if (event.eventType === 'task.created') {
      try {
        validateId('task', event.taskId);
        validateId('run', event.runId);
      } catch (cause) {
        throw new KernelError('JOURNAL_CORRUPT', 'task creation contains invalid identity', { category: 'integrity', cause });
      }
      if (this.tasks.has(event.taskId)) throw new KernelError('JOURNAL_CORRUPT', `duplicate task: ${event.taskId}`, { category: 'integrity' });
      this.tasks.set(event.taskId, {
        taskId: event.taskId,
        runId: event.runId,
        state: 'ACCEPTED',
        input: event.input,
        createdAt: event.recordedAt,
        updatedAt: event.recordedAt,
        result: null,
        pendingInput: null,
        idempotencyKey: event.idempotencyKey ?? null,
      });
      if (event.idempotencyKey) {
        const key = `${event.runId}\0${event.idempotencyKey}`;
        if (this.idempotency.has(key)) throw new KernelError('JOURNAL_CORRUPT', `duplicate idempotency key: ${event.idempotencyKey}`, { category: 'integrity' });
        this.idempotency.set(key, event.taskId);
      }
      return;
    }
    const task = this.tasks.get(event.taskId);
    if (!task) throw new KernelError('JOURNAL_CORRUPT', `transition for unknown task: ${event.taskId}`, { category: 'integrity' });
    if (event.from !== task.state || !INVOCATION_STATE.includes(event.to) || TERMINAL.has(task.state) || !ALLOWED[task.state]?.has(event.to)) {
      throw new KernelError('JOURNAL_CORRUPT', `invalid replayed transition ${event.from} -> ${event.to}`, {
        category: 'integrity', details: { taskId: event.taskId, actualState: task.state },
      });
    }
    task.state = event.to;
    task.updatedAt = event.recordedAt;
    if (event.eventType === 'task.input-required') task.pendingInput = event.payload;
    if (event.eventType === 'task.input-provided') {
      task.input = { ...task.input, ...event.payload };
      task.pendingInput = null;
    }
    if (event.eventType === 'task.completed') task.result = event.payload;
    if (event.eventType === 'task.failed') task.error = event.payload;
    if (event.eventType === 'task.cancelled') task.cancellationReason = event.payload?.reason ?? null;
  }

  get(taskId) {
    const task = this.tasks.get(validateId('task', taskId));
    if (!task) throw new KernelError('TASK_NOT_FOUND', `unknown task: ${taskId}`, { category: 'precondition' });
    return structuredClone(task);
  }

  enqueue(operation) {
    const pending = this.mutationTail.then(operation);
    this.mutationTail = pending.catch(() => undefined);
    return pending;
  }

  create(options) {
    return this.enqueue(() => this.createNow(options));
  }

  async createNow({ runId, input = {}, taskId = mintId('task'), idempotencyKey = null }) {
    validateId('run', runId);
    validateId('task', taskId);
    if (idempotencyKey !== null && (typeof idempotencyKey !== 'string' || !idempotencyKey)) {
      throw new KernelError('INVALID_ARGUMENT', 'idempotency key must be a non-empty string', { category: 'usage' });
    }
    const idempotencyLookup = idempotencyKey ? `${runId}\0${idempotencyKey}` : null;
    if (idempotencyLookup && this.idempotency.has(idempotencyLookup)) return this.get(this.idempotency.get(idempotencyLookup));
    if (this.tasks.has(taskId)) return this.get(taskId);
    const event = await this.journal.append({
      eventType: 'task.created', taskId, runId, input: structuredClone(input), idempotencyKey, recordedAt: new Date().toISOString(),
    });
    this.apply(event);
    return this.get(taskId);
  }

  transition(taskId, to, eventType, payload = null) {
    return this.enqueue(() => this.transitionNow(taskId, to, eventType, payload));
  }

  async transitionNow(taskId, to, eventType, payload = null) {
    const current = this.get(taskId);
    if (!INVOCATION_STATE.includes(to)) {
      throw new KernelError('INVALID_ARGUMENT', `unknown invocation state: ${to}`, { category: 'usage' });
    }
    if (TERMINAL.has(current.state) || !ALLOWED[current.state]?.has(to)) {
      throw new KernelError('TASK_ALREADY_TERMINAL', `task cannot transition ${current.state} -> ${to}`, {
        category: 'precondition', details: { taskId, from: current.state, to },
      });
    }
    const event = await this.journal.append({
      eventType, taskId, runId: current.runId, from: current.state, to, payload: structuredClone(payload), recordedAt: new Date().toISOString(),
    });
    this.apply(event);
    return this.get(taskId);
  }

  start(taskId) {
    return this.enqueue(() => {
      const current = this.get(taskId);
      return current.state === 'RUNNING' ? current : this.transitionNow(taskId, 'RUNNING', 'task.started');
    });
  }
  requireInput(taskId, request) { return this.transition(taskId, 'INPUT_REQUIRED', 'task.input-required', request); }
  provideInput(taskId, input) { return this.transition(taskId, 'RUNNING', 'task.input-provided', input); }
  cancel(taskId, reason) { return this.transition(taskId, 'CANCELLED', 'task.cancelled', { reason }); }
  resume(taskId) { return this.transition(taskId, 'RUNNING', 'task.resumed'); }
  complete(taskId, result) { return this.transition(taskId, 'COMPLETED', 'task.completed', result); }
  expire(taskId) { return this.transition(taskId, 'EXPIRED', 'task.expired'); }
  fail(taskId, error) { return this.transition(taskId, 'FAILED_INVOCATION', 'task.failed', error); }
}
