// Live hook-registration enumeration across EVERY delivery mechanism.
//
// Built after the 2026-08-10 Mac incident, which cost an hour and nearly broke
// a machine. The sequence was: read `~/.claude/settings.json`, find no Arcane
// entry, conclude "the Mac has no Arcane", wire it into settings.json — while
// Arcane had been loading the whole time from a *plugin* auto-discovered
// through the `~/.claude/skills` symlink (`legion@skills-dir`, usageCount 387).
// The "fix" produced a double registration: two PreToolUse handlers, the second
// hitting an already-reserved tool_use_id and denying every Write with
// ARC_REPLAY_NONCE_SEEN.
//
// Two failures, one root: a negative existence claim ("no Arcane here") made
// from ONE source when four exist, and no mechanism that could see a duplicate.
// `driftForHarness` (./drift.mjs) compares against a written receipt — it says
// nothing about what the host actually loads right now. This module answers the
// question that was actually being asked: what is registered on this host, by
// what mechanism, and is anything registered twice?
//
// Sources enumerated (all of them, always — a partial answer is what caused the
// incident):
//   1. user settings          <home>/.claude/settings.json
//   2. project settings       <root>/.claude/settings.json
//   3. project local settings <root>/.claude/settings.local.json
//   4. skills-dir plugins     <home>/.claude/skills/*/.claude-plugin/plugin.json
//                             (the symlinked directory Claude Code auto-discovers)
//   5. marketplace plugins    <home>/.claude/plugins/installed_plugins.json
//
// A handler reachable from two sources is a DUPLICATE and is reported as a
// failure, because hooks are additive: both fire, in order, every event.

import { existsSync, readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { basename, join } from 'node:path';
import { homedir } from 'node:os';

/**
 * Reduce a hook command to a stable handler identity, so the same script
 * registered through different absolute paths (Windows vs Mac, symlinked vs
 * real) compares equal. `rhook` is keyed by subcommand because one binary
 * serves many distinct gates.
 */
export function handlerId(command, args) {
  const text = String(command ?? '').replace(/\\/g, '/');
  if (/\brhook(\.exe)?\b/.test(text)) return `rhook ${(args ?? []).join(' ')}`.trim();
  const match = text.match(/([^/\s"']+\.(?:py|mjs|cjs|js))\b/);
  if (match) return basename(match[1]);
  return text.slice(0, 60).trim();
}

function readJson(path) {
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return null; }
}

function fromHooksObject(hooks, source, sourcePath, out) {
  for (const [event, rows] of Object.entries(hooks ?? {})) {
    if (!Array.isArray(rows)) continue;
    for (const row of rows) {
      for (const hook of row?.hooks ?? []) {
        out.push({ event, handler: handlerId(hook?.command, hook?.args), source, sourcePath });
      }
    }
  }
}

function settingsSource(path, source, out, sources) {
  if (!existsSync(path)) return;
  const value = readJson(path);
  if (!value) return;
  sources.push({ source, path, kind: 'settings' });
  fromHooksObject(value.hooks, source, path, out);
}

/** A plugin directory contributes hooks through its own hooks/hooks.json. */
function pluginSource(dir, source, out, sources) {
  const manifest = join(dir, '.claude-plugin', 'plugin.json');
  const hooksFile = join(dir, 'hooks', 'hooks.json');
  if (!existsSync(manifest) || !existsSync(hooksFile)) return;
  const value = readJson(hooksFile);
  if (!value) return;
  sources.push({ source, path: hooksFile, kind: 'plugin' });
  fromHooksObject(value.hooks ?? value, source, hooksFile, out);
}

function skillsDirPlugins(home, out, sources) {
  const skills = join(home, '.claude', 'skills');
  if (!existsSync(skills)) return;
  let real = skills;
  try { real = realpathSync(skills); } catch { /* not a link, or unreadable */ }
  let entries = [];
  try { entries = readdirSync(real); } catch { return; }
  for (const name of entries) {
    const dir = join(real, name);
    try { if (!statSync(dir).isDirectory()) continue; } catch { continue; }
    pluginSource(dir, `plugin:${name}@skills-dir`, out, sources);
  }
}

function marketplacePlugins(home, out, sources) {
  const installed = readJson(join(home, '.claude', 'plugins', 'installed_plugins.json'));
  for (const [name, rows] of Object.entries(installed?.plugins ?? {})) {
    for (const row of rows ?? []) {
      if (row?.installPath) pluginSource(row.installPath, `plugin:${name}`, out, sources);
    }
  }
}

/**
 * Enumerate every hook registration visible on this host.
 * @returns {{sources: object[], registrations: object[], duplicates: object[]}}
 */
export function enumerateRegistrations({ home = homedir(), root } = {}) {
  const registrations = [];
  const sources = [];

  settingsSource(join(home, '.claude', 'settings.json'), 'user-settings', registrations, sources);
  if (root) {
    settingsSource(join(root, '.claude', 'settings.json'), 'project-settings', registrations, sources);
    settingsSource(join(root, '.claude', 'settings.local.json'), 'project-local-settings', registrations, sources);
  }
  skillsDirPlugins(home, registrations, sources);
  marketplacePlugins(home, registrations, sources);

  // A duplicate is the SAME handler on the SAME event reachable from more than
  // one source. Hooks are additive, so this always means it runs twice.
  const byKey = new Map();
  for (const entry of registrations) {
    const key = `${entry.event}::${entry.handler}`;
    if (!byKey.has(key)) byKey.set(key, []);
    byKey.get(key).push(entry);
  }
  const duplicates = [];
  for (const [key, entries] of byKey) {
    const distinctSources = [...new Set(entries.map((e) => e.source))];
    if (entries.length > 1) {
      const [event, handler] = key.split('::');
      duplicates.push({
        event,
        handler,
        count: entries.length,
        sources: distinctSources,
        detail: `${handler} runs ${entries.length}x on ${event} (from ${distinctSources.join(' + ')})`,
      });
    }
  }

  registrations.sort((a, b) => `${a.event}${a.handler}${a.source}`.localeCompare(`${b.event}${b.handler}${b.source}`));
  duplicates.sort((a, b) => a.detail.localeCompare(b.detail));
  return { sources, registrations, duplicates };
}
