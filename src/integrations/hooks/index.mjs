// Generated git hooks are thin installed-native CLI adapters; installation is
// explicit and idempotent, with no hook-specific engine or Node launch path.

import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const PRE_COMMIT_HOOK = `#!/bin/sh
exec legion audit . \\
  --profile fast \\
  --type uncommitted \\
  --baseline .legion/baseline.json
`;

export const PRE_PUSH_HOOK = `#!/bin/sh
exec legion audit . \\
  --profile standard \\
  --type local \\
  --baseline .legion/baseline.json
`;

export function installHook({ root, type, hooksDir = '.git/hooks' }) {
  const name = type === 'pre-commit' ? 'pre-commit' : type === 'pre-push' ? 'pre-push' : null;
  if (!name) throw new Error(`unsupported hook type ${type}`);
  const dir = join(root, hooksDir);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const path = join(dir, name);
  const content = type === 'pre-commit' ? PRE_COMMIT_HOOK : PRE_PUSH_HOOK;
  writeFileSync(path, content, { mode: 0o755 });
  return { installed: type, path };
}

export function uninstallHook({ root, type, hooksDir = '.git/hooks' }) {
  const name = type === 'pre-commit' ? 'pre-commit' : type === 'pre-push' ? 'pre-push' : null;
  if (!name) throw new Error(`unsupported hook type ${type}`);
  const path = join(root, hooksDir, name);
  if (!existsSync(path)) return { removed: false, path };
  unlinkSync(path);
  return { removed: true, path };
}

export function hookInstalled({ root, type, hooksDir = '.git/hooks' }) {
  const name = type === 'pre-commit' ? 'pre-commit' : 'pre-push';
  const path = join(root, hooksDir, name);
  if (!existsSync(path)) return false;
  const content = readFileSync(path, 'utf8');
  return content.includes('legion');
}
