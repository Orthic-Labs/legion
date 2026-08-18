import { mkdir, open, readFile } from 'node:fs/promises';
import path from 'node:path';

import { KernelError } from './errors.mjs';

export class JsonlJournal {
  static async open(filePath) {
    await mkdir(path.dirname(filePath), { recursive: true });
    let text = '';
    try {
      text = await readFile(filePath, 'utf8');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    const records = [];
    for (const [index, line] of text.split('\n').entries()) {
      if (!line.trim()) continue;
      try {
        records.push(JSON.parse(line));
      } catch (cause) {
        throw new KernelError('JOURNAL_CORRUPT', `invalid JSONL record at line ${index + 1}`, {
          category: 'integrity', cause,
        });
      }
    }
    records.forEach((record, index) => {
      if (record.sequence !== index + 1) {
        throw new KernelError('JOURNAL_CORRUPT', `invalid journal sequence at line ${index + 1}`, { category: 'integrity' });
      }
    });
    return new JsonlJournal(filePath, records);
  }

  constructor(filePath, records) {
    this.filePath = filePath;
    this.records = records;
    this.appendTail = Promise.resolve();
  }

  all() {
    return structuredClone(this.records);
  }

  append(record) {
    const pending = this.appendTail.then(() => this.appendNow(record));
    this.appendTail = pending.catch(() => undefined);
    return pending;
  }

  async appendNow(record) {
    const sealed = { ...record, sequence: this.records.length + 1 };
    const handle = await open(this.filePath, 'a');
    try {
      await handle.write(`${JSON.stringify(sealed)}\n`);
      await handle.sync();
    } finally {
      await handle.close();
    }
    this.records.push(sealed);
    return structuredClone(sealed);
  }
}
