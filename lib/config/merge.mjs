import { createHash } from 'node:crypto';
import { mergeConfig } from './index.mjs';
export function mergeTrustedConfig(input) { const config = mergeConfig(input); return { value: config, digest: `sha256:${createHash('sha256').update(JSON.stringify(config)).digest('hex')}` }; }
