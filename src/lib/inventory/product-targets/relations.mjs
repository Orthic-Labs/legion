import { RELATIONS } from './contracts.mjs';
export function targetRelation(kind, from, to, evidence = []) { if(!RELATIONS.has(kind))throw new Error(`unknown target relation: ${kind}`); return {kind,from,to,evidence}; }
