export function scheduleProviders(providers = [], { mode = 'auto', concurrency = 4 } = {}) {
  const remaining = new Map(providers.map((provider) => [provider.id, provider]));
  const done = new Set(); const waves = [];
  while (remaining.size) {
    const ready = [...remaining.values()].filter((provider) => (provider.dependsOn ?? []).every((id) => done.has(id))).sort((a, b) => a.id.localeCompare(b.id));
    if (!ready.length) throw new Error('provider dependency cycle or missing dependency');
    const selected = mode === 'serial' ? [ready[0]] : ready.filter((provider) => provider.scheduleClass !== 'serial').slice(0, concurrency);
    const wave = selected.length ? selected : [ready[0]];
    waves.push(wave.map((provider) => provider.id));
    for (const provider of wave) { done.add(provider.id); remaining.delete(provider.id); }
  }
  return waves;
}
