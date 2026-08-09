// Browser runtime evidence provider. Deterministic surface inventory, console
// errors, interaction latency, long tasks, accessibility, screenshot/baseline
// receipts, and shallow-traversal gaps. Never performs destructive browser
// interaction.

export function runtimeReceipt({ surfacesFound, surfacesTested, consoleErrors, longTasks, screenshots, shallow }) {
  return {
    schemaVersion: 1,
    kind: 'legion-browser-runtime',
    surfacesFound: surfacesFound ?? 0,
    surfacesTested: surfacesTested ?? 0,
    consoleErrors: consoleErrors ?? 0,
    longTasks: longTasks ?? 0,
    screenshots: screenshots ?? [],
    complete: surfacesTested === surfacesFound && surfacesFound > 0,
    shallowTraversal: shallow ?? false,
    coverageGaps: shallow ? [{ kind: 'runtime-shallow-traversal' }] : [],
  };
}

export function consoleErrorObservation({ file, message, surface }) {
  return {
    schemaVersion: 1,
    kind: 'legion-console-error',
    file: file ?? null,
    message: message ?? null,
    surface: surface ?? null,
  };
}

export function performanceObservation({ surface, longTasks, interactionLatencyMs, thresholdMs }) {
  return {
    schemaVersion: 1,
    kind: 'legion-performance-observation',
    surface,
    longTasks,
    interactionLatencyMs,
    thresholdMs: thresholdMs ?? 200,
    violated: longTasks > 0 || interactionLatencyMs > (thresholdMs ?? 200),
  };
}
