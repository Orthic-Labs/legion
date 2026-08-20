import { existsSync, readFileSync } from 'node:fs';
import { consumeBlueprintPacket, requestBlueprintPacket, unavailablePacket } from '../../../adapters/blueprint-packet.mjs';

/** Transport-only Membrane adapter. Blueprint repository truth stays remote. */
export class MembraneAdapter {
  constructor({ packet = null, transport = null, packetPath = null } = {}) {
    this.packet = packet;
    this.transport = transport;
    this.packetPath = packetPath;
    this.mode = packetPath ? 'packet-file' : transport ? 'transport' : 'unavailable';
  }

  async ensureCompatible() {
    if (this.packet || (this.packetPath && existsSync(this.packetPath)) || this.transport) {
      return { ok: true, mode: this.mode, provider: 'membrane' };
    }
    return { ok: false, error: 'Membrane transport unavailable' };
  }

  async generateOrLoadProjection({ request = {} } = {}) {
    if (this.packet) return consumeBlueprintPacket(this.packet);
    if (this.packetPath && existsSync(this.packetPath)) {
      return consumeBlueprintPacket(JSON.parse(readFileSync(this.packetPath, 'utf8')));
    }
    return requestBlueprintPacket({ transport: this.transport, request });
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
