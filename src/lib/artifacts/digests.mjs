import { createHash } from 'node:crypto';
export const digestBytes = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
