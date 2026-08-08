import { createHash } from 'node:crypto';
import { mkdir, open, readFile, rename, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { assertContract } from './contracts.mjs';
import { KernelError } from './errors.mjs';
import { mintId, validateId } from './ids.mjs';
import { JsonlJournal } from './journal.mjs';

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function digestContent(content) {
  return `sha256:${createHash('sha256').update(content).digest('hex')}`;
}

function eventDigest(record) {
  const { eventDigest: ignored, ...unsigned } = record;
  return digestContent(Buffer.from(canonical(unsigned)));
}

export class EventStore {
  static async open(filePath) {
    const journal = await JsonlJournal.open(filePath);
    let previous = null;
    for (const event of journal.all()) {
      if (event.previousEventDigest !== previous) {
        throw new KernelError('EVENT_CHAIN_INVALID', `event chain mismatch at sequence ${event.sequence}`, { category: 'integrity' });
      }
      if (event.eventDigest !== eventDigest(event)) {
        throw new KernelError('EVENT_DIGEST_INVALID', `event digest mismatch at sequence ${event.sequence}`, { category: 'integrity' });
      }
      previous = event.eventDigest;
    }
    return new EventStore(journal);
  }

  constructor(journal) {
    this.journal = journal;
    this.appendTail = Promise.resolve();
  }

  all() { return this.journal.all(); }

  append(event) {
    const pending = this.appendTail.then(() => this.appendNow(event));
    this.appendTail = pending.catch(() => undefined);
    return pending;
  }

  async appendNow(event) {
    validateId('run', event.runId);
    if (event.taskId !== undefined && event.taskId !== null) validateId('task', event.taskId);
    if (typeof event.type !== 'string' || !event.type || typeof event.actor !== 'string' || !event.actor) {
      throw new KernelError('INVALID_ARGUMENT', 'event type and actor are required', { category: 'usage' });
    }
    const previous = this.journal.records.at(-1)?.eventDigest ?? null;
    const record = {
      schemaVersion: 1,
      kind: 'legion-kernel-event',
      eventId: mintId('event'),
      recordedAt: new Date().toISOString(),
      previousEventDigest: previous,
      ...structuredClone(event),
      sequence: this.journal.records.length + 1,
    };
    record.eventDigest = eventDigest(record);
    return this.journal.append(record);
  }
}

async function exists(filePath) {
  try { await stat(filePath); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; }
}

export class ArtifactStore {
  static async open(root) {
    await mkdir(path.join(root, 'blobs'), { recursive: true });
    const journal = await JsonlJournal.open(path.join(root, 'artifacts.jsonl'));
    const records = new Map();
    for (const entry of journal.all()) {
      assertContract('artifact-v1', entry.artifact, 'artifact record');
      if (records.has(entry.artifact.artifactId)) {
        throw new KernelError('ARTIFACT_INDEX_CORRUPT', `duplicate artifact ID: ${entry.artifact.artifactId}`, { category: 'integrity' });
      }
      records.set(entry.artifact.artifactId, entry.artifact);
    }
    return new ArtifactStore(root, journal, records);
  }

  constructor(root, journal, records) {
    this.root = root;
    this.journal = journal;
    this.records = records;
    this.putTail = Promise.resolve();
  }

  put(record, content) {
    const safeRecord = structuredClone(record);
    const safeContent = Buffer.from(content);
    const pending = this.putTail.then(() => this.putNow(safeRecord, safeContent));
    this.putTail = pending.catch(() => undefined);
    return pending;
  }

  async putNow(record, bytes) {
    const actualDigest = digestContent(bytes);
    if (record.digest !== actualDigest) {
      throw new KernelError('ARTIFACT_DIGEST_MISMATCH', 'artifact digest mismatch', { category: 'integrity' });
    }
    if (record.bytes !== bytes.length) {
      throw new KernelError('ARTIFACT_SIZE_MISMATCH', 'artifact byte count mismatch', { category: 'integrity' });
    }
    assertContract('artifact-v1', record, 'artifact record');
    if (record.immutable !== true) {
      throw new KernelError('INVALID_ARGUMENT', 'artifact must be immutable', { category: 'usage' });
    }
    if (this.records.has(record.artifactId)) {
      throw new KernelError('SCOPE_CONFLICT', `artifact already exists: ${record.artifactId}`, { category: 'conflict' });
    }
    const hex = actualDigest.slice('sha256:'.length);
    const target = path.join(this.root, 'blobs', hex);
    if (!(await exists(target))) {
      const temporary = `${target}.${process.pid}.${Date.now()}.tmp`;
      await writeFile(temporary, bytes, { flag: 'wx', mode: 0o600 });
      await rename(temporary, target);
    }
    await this.journal.append({ artifact: structuredClone(record) });
    this.records.set(record.artifactId, structuredClone(record));
    return structuredClone(record);
  }

  get(artifactId) {
    const record = this.records.get(validateId('artifact', artifactId));
    if (!record) throw new KernelError('ARTIFACT_NOT_FOUND', `unknown artifact: ${artifactId}`, { category: 'precondition' });
    return structuredClone(record);
  }

  async getContent(artifactId) {
    const record = this.get(artifactId);
    const content = await readFile(path.join(this.root, 'blobs', record.digest.slice('sha256:'.length)));
    if (content.length !== record.bytes || digestContent(content) !== record.digest) {
      throw new KernelError('ARTIFACT_DIGEST_MISMATCH', 'artifact content no longer matches its digest binding', { category: 'integrity' });
    }
    return content;
  }
}
