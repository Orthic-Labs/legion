// Profile projection for packaged skills.
//
// Loading a skill under the audit profile strips the instructions that would let a read-only
// reader mutate anything, and rewrites relative links to package URIs so a projected document
// never points at a path outside the package. This is a property of *reading* a skill, not of
// importing one: Legion authors these files, so nothing is redacted on the way in.

import { dirname, posix } from 'node:path';
import { skillUri } from './uri.mjs';

export function projectSkillText(text, { bundle, path = 'SKILL.md', profile = 'audit' }) {
  let value = String(text).replaceAll('\r\n', '\n').replaceAll('\r', '\n');
  if (isDocument(path)) {
    value = value.replace(/\]\((?!https?:|mailto:|#|legion-skill:)([^)\s]+)\)/g, (_, target) => {
      const resolved = posix.normalize(posix.join(dirname(path.replaceAll('\\', '/')), target.replaceAll('\\', '/')));
      return resolved.startsWith('../') ? '](<external-reference>)' : `](${skillUri(bundle, resolved)})`;
    });
  }
  if (profile === 'audit' && isDocument(path)) {
    value = value
      .replace(/^allowed-tools:.*\n?/gmi, '')
      .replace(/^tools:.*\n?/gmi, '')
      .replace(/^permission-mode:.*\n?/gmi, '')
      .replace(/^.*\b(?:publish|deploy|commit|push)\b.*automatically.*\n?/gmi, '')
      .replace(/^\s*(?:[-*]|\d+[.)])?\s*(?:write|edit|bash|fix|apply|modify|implement|deploy|publish|commit|push)\b.*\n?/gmi, '')
      .replace(/^.*\/(?:audit-fix|fix)\b.*\n?/gmi, '');
  }
  return value.endsWith('\n') ? value : `${value}\n`;
}

function isDocument(path) { return /(?:^|\.)(?:md|mdx|txt)$/i.test(path); }
