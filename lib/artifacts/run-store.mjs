import { createHash } from 'node:crypto';
import {
  mkdir, open, readFile, rename, stat, writeFile,
} from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';

function digestBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

export class RunArtifactStore {
  #root;
  #records = new Map();

  constructor(root) {
    this.#root = resolve(root);
  }

  async init() {
    await mkdir(this.#root, { recursive: true, mode: 0o700 });
  }

  async writeJson({ path, kind, producer, producerVersion = '1.0.0', schemaVersion, binding, denominatorDigest = null, value }) {
    const body = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
    return this.writeBytes({
      path, kind, producer, producerVersion, schemaVersion, binding, denominatorDigest,
      mediaType: 'application/json',
      bytes: body,
    });
  }

  async writeBytes(spec) {
    const target = resolve(this.#root, spec.path);
    if (!target.startsWith(`${this.#root}${process.platform === 'win32' ? '\\' : '/'}`)) {
      throw new Error(`artifact path escapes run root: ${spec.path}`);
    }
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    const temp = `${target}.${process.pid}.${Date.now()}.tmp`;
    const handle = await open(temp, 'wx', 0o600);
    try {
      await handle.writeFile(spec.bytes);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temp, target);
    const bytes = await readFile(target);
    const record = Object.freeze({
      kind: spec.kind,
      path: relative(this.#root, target).replaceAll('\\', '/'),
      digest: digestBytes(bytes),
      bytes: bytes.length,
      producer: spec.producer,
      producerVersion: spec.producerVersion ?? '1.0.0',
      schemaVersion: spec.schemaVersion,
      mediaType: spec.mediaType,
      binding: spec.binding,
      denominatorDigest: spec.denominatorDigest ?? null,
    });
    this.#records.set(record.path, record);
    return record;
  }

  records() {
    return [...this.#records.values()].sort((a, b) => a.path.localeCompare(b.path));
  }

  async readVerified(path) {
    const record = this.#records.get(path);
    if (!record) throw new Error(`unregistered artifact: ${path}`);
    const bytes = await readFile(join(this.#root, path));
    if (digestBytes(bytes) !== record.digest) throw new Error(`artifact digest mismatch: ${path}`);
    return bytes;
  }
}
