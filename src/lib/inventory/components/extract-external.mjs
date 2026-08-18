import { extractLogicalComponents } from './extract-logical.mjs';
export function extractExternalComponents(input) { return extractLogicalComponents(input).filter(({kind})=>['integration','ai'].includes(kind)).map((item)=>({...item,external:true,status:'referenced'})); }
