export async function loadExternalProjection(executor, spec) { if (!spec?.executable) throw new TypeError('explicit Cortex executable required'); return executor(spec); }
