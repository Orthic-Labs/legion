import { extractLogicalComponents } from './extract-logical.mjs';
export function extractDataComponents(input) { return extractLogicalComponents(input).filter(({kind})=>['data','cache-search','file-media'].includes(kind)); }
