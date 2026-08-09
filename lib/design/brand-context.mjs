export function brandContext(designContext) {
  return { schemaVersion: 1, kind: 'legion-brand-context', values: designContext?.declared?.brand ?? {}, source: designContext?.source ?? null,
    authoritative: Boolean(designContext?.declared?.brand), status: designContext?.declared?.brand ? 'pass' : 'unproven' };
}
