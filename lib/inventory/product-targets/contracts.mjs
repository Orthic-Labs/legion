import { createHash } from 'node:crypto';
const KINDS = new Set(['website','web-app','api-service','worker','serverless-function','desktop-app','ios-app','android-app','mobile-extension','cli','library-sdk','browser-extension','editor-extension','plugin-system','data-pipeline','infrastructure','ai-agent-system','embedded-firmware','smart-contract','documentation-product','unknown-deliverable']);
export function targetId(kind, root, entrypoints = []) { return `target:${createHash('sha256').update(`${kind}\0${root}\0${[...entrypoints].sort().join('\0')}`).digest('hex').slice(0, 20)}`; }
export function validateTarget(target) { if (!KINDS.has(target.kind)) throw new Error(`unknown target kind: ${target.kind}`); if (!target.id || !target.root) throw new Error('target requires id and root'); return target; }
export { KINDS };
