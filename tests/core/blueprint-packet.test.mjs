import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { readBlueprintManifestBinding, readBlueprintPacket } from '../../src/adapters/blueprint-packet.mjs';

function fakeBlueprint(payload) {
  const dir = mkdtempSync(join(tmpdir(), 'legion-blueprint-packet-'));
  const bin = join(dir, 'blueprint');
  writeFileSync(bin, `#!/usr/bin/env node\nconsole.log(${JSON.stringify(JSON.stringify(payload))});\n`);
  chmodSync(bin, 0o755);
  return { dir, bin };
}

test('Blueprint Audit projection is validated, normalized, & bound', () => {
  const sourceObservation = { head: 'a'.repeat(40), dirty: true, statusDigest: 'status' };
  const fixture = fakeBlueprint({
    schema: 'membrane.blueprint-packet.v1',
    status: 'ready',
    state: 'ready',
    generationId: 'xxh128:generation',
    manifestDigest: `sha256:${'b'.repeat(64)}`,
    sourceObservation,
    files: ['z/file.ts', 'a\\file.rs', 'z/file.ts'],
    parsedExtensions: ['rs', 'ts'],
    unsupportedExtensions: [],
  });
  try {
    const packet = readBlueprintPacket(process.cwd(), { blueprintBin: fixture.bin });
    assert.equal(packet.state, 'ready');
    assert.deepEqual(packet.files, ['a/file.rs', 'z/file.ts']);
    assert.equal(packet.fileCount, 2);
    assert.match(packet.fileSetDigest, /^sha256:[0-9a-f]{64}$/);
    assert.deepEqual(
      readBlueprintManifestBinding(process.cwd(), { blueprintBin: fixture.bin }),
      {
        state: 'ready',
        generationId: 'xxh128:generation',
        manifestDigest: `sha256:${'b'.repeat(64)}`,
        sourceObservation,
      },
    );
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('Blueprint transport failure degrades explicitly', () => {
  const packet = readBlueprintPacket(process.cwd(), { blueprintBin: '/missing/blueprint' });
  assert.equal(packet.status, 'unavailable');
  assert.equal(packet.reason, 'membrane-blueprint-transport-unavailable');
});
