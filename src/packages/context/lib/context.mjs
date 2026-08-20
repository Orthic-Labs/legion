/**
 * Thin Legion transport for Membrane context packets.
 *
 * Membrane owns packet schema, evidence selection, reduction, continuity,
 * receipt production, & persistence. Legion validates only transport shape
 * before forwarding bytes; it never reconstructs or edits packet content.
 */

const PACKET_SCHEMAS = new Set(['membrane.context-packet.v1', 'membrane.blueprint-packet.v1']);

function unavailable(reason) {
  return Object.freeze({ schema: 'legion.context-result.v1', status: 'unavailable', reason });
}

export function validateContextPacket(packet) {
  if (!packet || typeof packet !== 'object' || Array.isArray(packet)) throw new TypeError('Membrane packet must be an object');
  if (!PACKET_SCHEMAS.has(packet.schema)) throw new TypeError('unsupported Membrane packet schema');
  if (packet.status === 'unavailable') throw new TypeError('Membrane packet is unavailable');
  return true;
}

export function consumeMembranePacket(packet) {
  validateContextPacket(packet);
  return packet;
}

export async function requestMembraneContext({ transport, request }) {
  if (typeof transport !== 'function') return unavailable('membrane-transport-unavailable');
  let packet;
  try {
    packet = await transport(request);
  } catch {
    return unavailable('membrane-transport-failed');
  }
  try {
    return consumeMembranePacket(packet);
  } catch {
    return unavailable('membrane-packet-invalid');
  }
}

export function createUnavailableContextAdapter(capabilityName, reason) {
  if (!capabilityName || !reason) throw new TypeError('capabilityName & reason are required');
  return Object.freeze({
    capability: Object.freeze({ capability: capabilityName, status: 'absent', reason }),
    async read() { return unavailable(reason); },
  });
}
