import { dirname, posix } from 'node:path';
import { skillUri } from './uri.mjs';

export function transformSkillText(text, { bundle, path = 'SKILL.md', profile = 'audit', rules = [] }) {
  let value = String(text).replaceAll('\r\n', '\n').replaceAll('\r', '\n');
  for (const { from, to } of rules) value = value.split(from).join(to);
  value = value.replace(/[A-Za-z]:\\[^\s)`"']+/g, '<local-path>').replace(/\/Users\/[^\s)`"']+/g, '<local-path>');
  value = value.replace(/\]\((?!https?:|mailto:|#|nemesis-skill:)([^)\s]+)\)/g, (_, target) => {
    const resolved = posix.normalize(posix.join(dirname(path.replaceAll('\\', '/')), target.replaceAll('\\', '/')));
    return resolved.startsWith('../') ? '](<external-reference>)' : `](${skillUri(bundle, resolved)})`;
  });
  if (profile === 'audit') value = value
    .replace(/^allowed-tools:.*\n?/gmi, '')
    .replace(/^tools:.*\n?/gmi, '')
    .replace(/^permission-mode:.*\n?/gmi, '')
    .replace(/^.*\b(?:publish|deploy|commit|push)\b.*automatically.*\n?/gmi, '')
    .replace(/^\s*(?:[-*]|\d+[.)])?\s*(?:write|edit|bash|fix|apply|modify|implement|deploy|publish|commit|push)\b.*\n?/gmi, '')
    .replace(/^.*\/(?:audit-fix|fix)\b.*\n?/gmi, '');
  return value.endsWith('\n') ? value : `${value}\n`;
}
