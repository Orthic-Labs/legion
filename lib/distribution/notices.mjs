export function renderNotices(components = []) {
  const shipped = components.filter((component) => component.shipped === true);
  if (!shipped.length) throw new Error('notices require at least one shipped component');
  return `${shipped.map((component) => `## ${component.name}\n\nLicense: ${component.license ?? 'UNRESOLVED'}\nSource: ${component.source ?? 'UNRESOLVED'}\n`).join('\n')}`;
}

export function buildNoticeInventory(components = []) {
  const shipped = components.filter(({ shipped }) => shipped === true);
  const blockers = shipped.filter(({ license, source, redistributionGrant }) => !license || !source || (source === 'external' && redistributionGrant !== true)).map(({ name }) => ({ kind: 'redistribution-rights-unresolved', component: name }));
  return { components: shipped, blockers, decision: blockers.length ? 'BLOCKED' : 'QUALIFIED' };
}
