#!/usr/bin/env node
// Authority description parity.
//
// Claude Code is not a generated harness: `agents/<role>.md` is hand-maintained while
// `src/roster/<role>.md` is the canonical identity source and `doctrine/<role>.md` carries the
// method. Nothing previously compared the two, so a roster edit could silently leave the
// agent card — the text Claude Code actually routes on — behind.
//
// A copy exists only where a consumer requires one. The roster is the author surface; the agent
// card is a physically necessary copy because the harness reads that file and cannot dereference
// the roster at runtime, so it is compared here. `doctrine/<role>.md` has no description consumer
// at all — nothing routes on it or generates from it — so it must not declare one. That third,
// unread copy is exactly where wording drifted unnoticed before this check existed; doctrine
// carries its method in its body.

import { readFileSync } from "node:fs";

const ROLES = ["sage", "alchemist", "oracle"];

function description(path) {
  const text = readFileSync(path, "utf8");
  const frontmatter = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!frontmatter) return { path, error: "missing frontmatter" };
  const match = /^description:[ \t]*(.+)$/m.exec(frontmatter[1]);
  if (!match) return { path, error: "missing frontmatter description" };
  return { path, value: match[1].trim().replace(/\s+/g, " ") };
}

function declaresDescription(path) {
  const text = readFileSync(path, "utf8");
  const frontmatter = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!frontmatter) return false;
  return /^description:[ \t]*(.+)$/m.test(frontmatter[1]);
}

function frontmatterField(path, field) {
  const text = readFileSync(path, "utf8");
  const frontmatter = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!frontmatter) return null;
  const match = new RegExp(`^${field}:[ \\t]*(.+)$`, "m").exec(frontmatter[1]);
  return match ? match[1].trim() : null;
}

// Intelligence tiers are resolved to host-native model ids through one
// configurable policy document. `agents/<role>.md` `model:` fields are that
// mapping's resolved value for claude-code — a host-specific projection, not a
// portable role requirement — so they must match `src/config/model-tiers.json`
// exactly. Changing the host's model choice is a map edit plus agent resync,
// never a roster, doctrine, or skill edit.
const MODEL_TIER_MAP = JSON.parse(readFileSync("src/config/model-tiers.json", "utf8"));
const MODEL_HOST = "claude-code";

const problems = [];
for (const role of ROLES) {
  if (declaresDescription(`doctrine/${role}.md`)) {
    problems.push(
      `${role}: doctrine/${role}.md declares a frontmatter description. Nothing consumes it, so it ` +
        `can only drift. Delete the key; src/roster/${role}.md is the canonical description and ` +
        `doctrine carries its method in the body.`,
    );
  }
  const sources = [description(`agents/${role}.md`), description(`src/roster/${role}.md`)];
  for (const source of sources) {
    if (source.error) problems.push(`${source.path}: ${source.error}`);
  }
  const values = sources.filter((source) => source.value);
  if (values.length !== sources.length) continue;
  const [canonical, ...rest] = values;
  for (const other of rest) {
    if (other.value !== canonical.value) {
      problems.push(
        `${role}: description drift between ${canonical.path} and ${other.path}\n` +
          `  ${canonical.path}: ${canonical.value}\n` +
          `  ${other.path}: ${other.value}`,
      );
    }
  }

  const tier = frontmatterField(`src/roster/${role}.md`, "modelTier");
  const expectedModel = tier && MODEL_TIER_MAP.tiers?.[tier]?.hosts?.[MODEL_HOST];
  const actualModel = frontmatterField(`agents/${role}.md`, "model");
  if (!expectedModel) {
    problems.push(
      `${role}: no ${MODEL_HOST} host model mapping for roster tier '${tier}' in src/config/model-tiers.json`,
    );
  } else if (actualModel !== expectedModel) {
    problems.push(
      `${role}: agents/${role}.md model '${actualModel}' does not match the configured ${MODEL_HOST} mapping ` +
        `for tier '${tier}' (expected '${expectedModel}'). Resolve the mapping in src/config/model-tiers.json.`,
    );
  }
}

if (problems.length > 0) {
  console.error("authority description parity failed:");
  for (const problem of problems) console.error(`- ${problem}`);
  process.exit(1);
}
console.log(`authority agent cards match their roster identity (${ROLES.length} roles)`);
