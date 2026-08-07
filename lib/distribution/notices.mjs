export function renderNotices(components = []) {
  const shipped = components.filter((component) => component.shipped === true);
  if (!shipped.length) throw new Error('notices require at least one shipped component');
  return `${shipped.map((component) => `## ${component.name}\n\nLicense: ${component.license ?? 'UNRESOLVED'}\nSource: ${component.source ?? 'UNRESOLVED'}\n`).join('\n')}`;
}
