export function externalSystem(record) { if (!record.id || !record.kind || !record.status) throw new Error('external system requires id, kind, status'); return record; }
