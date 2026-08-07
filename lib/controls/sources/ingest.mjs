import { createHash } from 'node:crypto';
export function ingestSource({ source, items }) { if (!source?.digest || !source?.license) throw new Error('source requires digest and license'); return { source, items: items.map((item, index) => ({ id: `${source.digest}:${index + 1}`, disposition: item.disposition ?? 'unmapped', ...item })) }; }
