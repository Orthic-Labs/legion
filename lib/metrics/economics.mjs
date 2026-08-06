// Local opt-in economics per PR41. Content-free aggregates of duration/CPU/
// memory/tool/model-token/cost per provider. No source upload.

export function economicsReceipt({ provider, durationMs, cpuMs, memoryMb, toolCost, modelTokens, modelCost }) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-economics',
    provider,
    durationMs: durationMs ?? 0,
    cpuMs: cpuMs ?? 0,
    memoryMb: memoryMb ?? 0,
    toolCost: toolCost ?? 0,
    modelTokens: modelTokens ?? 0,
    modelCost: modelCost ?? 0,
    // Aggregates are content-free; never includes source excerpts.
  };
}

export function runSummary(records) {
  const total = (field) => (records ?? []).reduce((sum, record) => sum + (record[field] ?? 0), 0);
  return {
    schemaVersion: 1,
    kind: 'nemesis-economics-summary',
    providers: (records ?? []).length,
    totalDurationMs: total('durationMs'),
    totalCpuMs: total('cpuMs'),
    totalMemoryMb: total('memoryMb'),
    totalToolCost: total('toolCost'),
    totalModelTokens: total('modelTokens'),
    totalModelCost: total('modelCost'),
  };
}
