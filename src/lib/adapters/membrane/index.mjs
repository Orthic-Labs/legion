import { existsSync, readFileSync } from 'node:fs';
import {
  consumeBlueprintPacket,
  readBlueprintPacket,
  requestBlueprintPacket,
  shouldUseBlueprintOneShot,
  unavailablePacket,
} from '../../../adapters/blueprint-packet.mjs';

/** Membrane adapter: resident transport first, bounded Blueprint one-shot fallback. */
export class MembraneAdapter {
  constructor({ packet = null, transport = null, packetPath = null, blueprintBin = null, outDir = '.audit/blueprint', timeoutMs = 120_000 } = {}) {
    this.packet = packet;
    this.transport = transport;
    this.packetPath = packetPath;
    this.blueprintBin = blueprintBin;
    this.outDir = outDir;
    this.timeoutMs = timeoutMs;
    this.mode = packetPath ? 'packet-file' : transport ? 'resident-transport' : 'bounded-one-shot';
  }

  async ensureCompatible() {
    if (this.packet || (this.packetPath && existsSync(this.packetPath)) || this.transport || this.mode === 'bounded-one-shot') {
      return { ok: true, mode: this.mode, provider: 'membrane' };
    }
    return { ok: false, error: 'Membrane transport unavailable' };
  }

  async generateOrLoadProjection({ request = {} } = {}) {
    if (this.packet) return consumeBlueprintPacket(this.packet);
    if (this.packetPath && existsSync(this.packetPath)) {
      return consumeBlueprintPacket(JSON.parse(readFileSync(this.packetPath, 'utf8')));
    }
    if (this.transport) {
      const resident = await requestBlueprintPacket({ transport: this.transport, request });
      if (resident.status !== 'unavailable' || !shouldUseBlueprintOneShot(resident)) return resident;
    }
    // Direct Blueprint access is explicit, bounded, & independent from
    // enrollment. Enrollment controls resident watcher ownership only.
    const root = request.root ?? request.repoRoot ?? process.cwd();
    return readBlueprintPacket(root, {
      blueprintBin: this.blueprintBin ?? undefined,
      outDir: this.outDir,
      timeoutMs: request.timeoutMs ?? this.timeoutMs,
      signal: request.signal,
    });
  }

  async verifyFreshness({ packet } = {}) {
    if (!packet || packet.status === 'unavailable') return { fresh: false, reason: packet?.reason ?? 'membrane-unavailable' };
    return { fresh: true, packetDigest: packet.packetDigest ?? null };
  }

  async readPacket({ request = {} } = {}) {
    return this.generateOrLoadProjection({ request });
  }
}

export { unavailablePacket };
