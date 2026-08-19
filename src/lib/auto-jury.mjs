/**
 * auto-jury.mjs — shared post-artifact review hook for all content/ad pipelines.
 *
 * Why this exists:
 *   On 2026-05-04 the HR ad pipeline shipped a 3-shot 16s cut with --no-gates.
 *   Stages 4 + 6 ("dual-juror QA") just printed "review happens externally" and
 *   moved on — no jury actually ran. Verdict was written by Claude inline as a
 *   single self-juror, violating the dual-juror rule in MEMORY.md
 *   (feedback_model_routing_video.md). Root cause: --no-gates was a permanent
 *   skip, not a replacement. This module fixes that by giving every pipeline
 *   one function to call when it produces a reviewable artifact.
 *
 * Usage (in any pipeline):
 *   import { runAutoJury } from '../../lib/auto-jury.mjs';
 *
 *   const verdict = await runAutoJury({
 *     kind:        'video' | 'image' | 'copy' | 'plan' | 'design' | ...,
 *     artifactPath:'C:/.../final.mp4',
 *     context: {
 *       brand:       'HR',
 *       campaign:    'voice-command-center-30s',
 *       prompt:      '...',                 // for visual artifacts
 *       framePaths:  ['t2s.png', 't6s.png'],// for video artifacts
 *       rubricFlags: { hero_asset: true },  // forwarded to council
 *     },
 *     failHard: true,                       // throw on DON'T-SHIP (default true)
 *   });
 *
 * Vision wiring (live 2026-05-04):
 *   `/jury-image` and `/jury-video` now send actual image bytes to vision-
 *   capable jurors via the council vision_input.py pipeline. Verdicts carry
 *   `vision_active: true` on visual kinds (replaces old `vision_pending`).
 *   See ~/.claude/projects/D--Claude/memory/auto_jury_enforcement.md for full
 *   details on per-juror vision gating + ffmpeg keyframe extraction.
 *
 * Skill-mapping repair (2026-07-18):
 *   KIND_TO_SKILL has always mapped 'image'->jury-image and 'video'->jury-video,
 *   but neither skill survived the tools/jury -> src/lib/review rename (1dca05eb):
 *   models.yaml shipped without them while rubrics/image.md + rubrics/video.md
 *   stayed on disk and kept being maintained. Every visual pipeline calling
 *   runAutoJury({kind:'image'|'video'}) therefore died at the council CLI with
 *   `skill not found in models.yaml` — campaign.mjs Stages 4+6, create.mjs,
 *   gen_concepts.mjs, coloring-batch.js. Fixed by restoring both skill entries
 *   (NOT by remapping to jury-design, which would silently drop the KDP and
 *   motion/continuity criteria those rubrics carry). Verified live: jury-image
 *   vision-active, 2 vision seats + 1 text seat.
 *
 * Reading a verdict correctly:
 *   The council result is NESTED — read `synthesis.majority_verdict`, not a
 *   top-level `.verdict`. Per-seat calls live in `jurors[]`.
 *   Only jurors flagged `vision: true` in models.yaml receive image bytes; the
 *   text-only seat on a visual panel reasons from the prompt alone and WILL
 *   invent pixel claims. On 2026-07-18 `brand_lens` filed a P1 "background is
 *   dark grey #333" against a bone `#f2efe6` export it never saw. Confirm any
 *   visual blocker against the actual artifact before acting on it.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync, readFileSync, unlinkSync } from 'node:fs';
import { dirname, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

// Resolve the workspace from this module's own location. These were pinned to
// `D:/workspace` and the `py -3.11` launcher, which exist only on Windows — so on the
// Mac the gate blocked every artifact while being unable to run a single juror
// (ENOENT on the council CLI). The checkout layout is identical on every platform; derive it.
const WORKSPACE_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const IS_WINDOWS  = process.platform === 'win32';
const COUNCIL_PY  = process.env.JURY_CLI || join(WORKSPACE_ROOT, 'tools', 'review', 'jury.py');
const PYTHON      = process.env.PYTHON_BIN || (IS_WINDOWS ? 'py' : 'python3');
const PYTHON_ARGS = process.env.PYTHON_BIN ? [] : (IS_WINDOWS ? ['-3.11'] : []);
const DEFAULT_COUNCIL_TIMEOUT_MS = 10 * 60_000;

function _councilTimeoutMs() {
  const raw = process.env.AUTO_JURY_TIMEOUT_MS;
  if (!raw) return DEFAULT_COUNCIL_TIMEOUT_MS;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_COUNCIL_TIMEOUT_MS;
}

function _clip(value, limit = 1200) {
  const text = value?.toString?.() || '';
  return text.length > limit ? `${text.slice(0, limit)}...` : text;
}

export function formatCouncilCliError(err, { skill, artifactPath, timeoutMs }) {
  const stderr = _clip(err?.stderr, 1200);
  const stdout = _clip(err?.stdout, 1200);
  const timedOut = err?.signal === 'SIGTERM' || err?.code === 'ETIMEDOUT' || err?.killed;
  const details = [
    timedOut ? `timed out after ${Math.round(timeoutMs / 1000)}s` : null,
    err?.status != null ? `status=${err.status}` : null,
    err?.signal ? `signal=${err.signal}` : null,
    err?.code ? `code=${err.code}` : null,
    stderr ? `stderr: ${stderr}` : 'stderr: <empty>',
    stdout ? `stdout: ${stdout}` : null,
  ].filter(Boolean).join('; ');
  return `auto-jury: council CLI failed for ${skill} on ${artifactPath}. ${details}`;
}

// kind → council subcommand (matches src/lib/review/ skills)
const KIND_TO_SKILL = {
  video:     'jury-video',
  image:     'jury-image',
  copy:      'jury-blogs',
  blog:      'jury-blogs',
  brand:     'jury-brand-voice',
  ad:        'jury-ad',
  design:    'jury-design',
  plan:      'jury-plan',
  business:  'jury-business-plan',
  idea:      'jury-idea',
  launch:    'jury-launch',
  offer:     'jury-offer',
  strategy:  'jury-content-strategy',
  compliance:'jury-compliance-risk',
  code:      'jury-code',
};

// kinds that are visual artifacts. With vision wiring live (2026-05-04),
// the council sends pixels to vision-capable jurors automatically when the
// skill's needs_vision_input flag is set in models.yaml.
const VISUAL_KINDS = new Set(['video', 'image', 'design', 'ad', 'launch']);

// Phase 2.11h follow-on — load and format a shot-type rubric from
// recipes/video/qa-rubrics.json. Returns markdown for inline injection
// into the council input, or null if the key is unknown / file missing.
const QA_RUBRICS_PATH = join(WORKSPACE_ROOT, 'tools', 'recipes', 'video', 'qa-rubrics.json');
let _qaRubricsCache = null;
function _loadQARubricsLib() {
  if (_qaRubricsCache) return _qaRubricsCache;
  try {
    _qaRubricsCache = JSON.parse(readFileSync(QA_RUBRICS_PATH, 'utf8'));
  } catch {
    _qaRubricsCache = { rubrics_by_shot_type: {} };
  }
  return _qaRubricsCache;
}

function _formatQARubric(key) {
  const lib    = _loadQARubricsLib();
  const rubric = lib.rubrics_by_shot_type?.[key];
  if (!rubric) {
    return [
      `(unknown qaRubric key "${key}" — auto-jury skipped overlay)`,
      `Valid keys: ${Object.keys(lib.rubrics_by_shot_type || {}).join(', ')}`,
    ].join('\n');
  }
  const out = [];
  if (rubric._use) out.push(`Use case: ${rubric._use}`);
  if (rubric.dimensions) {
    out.push('');
    out.push('Dimensions (score each 1-10):');
    for (const [dim, desc] of Object.entries(rubric.dimensions)) {
      out.push(`  - ${dim}: ${desc}`);
    }
  }
  if (rubric.must_pass?.length) {
    out.push('');
    out.push('Must pass (any failure = SHIP-WITH-FIXES at minimum):');
    for (const m of rubric.must_pass) out.push(`  - ${m}`);
  }
  if (rubric.ship_threshold) {
    out.push('');
    out.push(`Ship threshold: ${rubric.ship_threshold}`);
  }
  if (rubric.note) {
    out.push('');
    out.push(`Note: ${rubric.note}`);
  }
  return out.join('\n');
}

export function finalDecisionFromCouncilVerdict(verdict) {
  const synthesis = verdict?.synthesis || {};
  if (synthesis.any_error) return 'NEEDS-REVISION';
  if (synthesis.split) return 'NEEDS-REVISION';
  if (typeof synthesis.majority_count === 'string') {
    const match = synthesis.majority_count.match(/^(\d+)\/(\d+)$/);
    if (match) {
      const yes = Number(match[1]);
      const total = Number(match[2]);
      if (total > 0 && yes <= total / 2) return 'NEEDS-REVISION';
    }
  }
  return (
    verdict?.final_verdict ||
    verdict?.verdict ||
    verdict?.decision ||
    verdict?.synthesis?.majority_verdict ||
    verdict?.synthesis?.final_verdict ||
    ''
  ).toString().toUpperCase();
}

/**
 * Build the text description that gets sent to the council. For visual
 * artifacts this is the best honest substitute for actual pixels until vision
 * wiring lands in council/engine.py.
 *
 * Packet contract (locked 2026-07-14 per Fable review):
 *   When the caller passes `context.packet` (a structured object with
 *   ARTIFACT / SUCCESS_CRITERIA / NON_GOALS / CONSTRAINTS /
 *   ALTERNATIVES_CONSIDERED / KNOWN_WEAKNESSES / USER_INTENTION /
 *   OMISSIONS), it's serialized into a fenced ``packet`` markdown block
 *   that the Python validator at src/lib/review/packet.py lints. Engine.run
 *   rejects inputs with invalid packets (hard-fail).
 *
 *   Backwards-compat: callers without `context.packet` get the legacy
 *   raw-context rendering and the packet validator emits a
 *   `no_packet_fence` marker (no hard fail — legacy callers keep
 *   working).
 */
export function buildCouncilInput({ kind, artifactPath, context }) {
  const lines = [];
  lines.push(`# Auto-jury input — ${kind}`);
  lines.push('');

  // Packet envelope — locked 2026-07-14. When present, the Python
  // validator (packet.py) is the source of truth; this renderer only
  // serializes.
  if (context?.packet && typeof context.packet === 'object') {
    lines.push('```packet');
    for (const [section, value] of Object.entries(context.packet)) {
      if (Array.isArray(value)) {
        lines.push(`${section}:`);
        for (const v of value) lines.push(`  - ${v}`);
      } else {
        lines.push(`${section}: ${value}`);
      }
    }
    lines.push('```');
    lines.push('');
  }

  lines.push(`Artifact: ${artifactPath}`);
  if (context?.brand)     lines.push(`Brand: ${context.brand}`);
  if (context?.campaign)  lines.push(`Campaign: ${context.campaign}`);
  if (context?.shot)      lines.push(`Shot: ${context.shot}`);
  if (context?.duration)  lines.push(`Duration: ${context.duration}s`);
  if (context?.resolution)lines.push(`Resolution: ${context.resolution}`);
  if (context?.aspect)    lines.push(`Aspect: ${context.aspect}`);
  lines.push('');

  if (context?.prompt) {
    lines.push('## Prompt');
    lines.push(context.prompt);
    lines.push('');
  }

  if (context?.framePaths?.length) {
    lines.push('## Extracted frames (vision-grounded jurors will see these)');
    for (const f of context.framePaths) lines.push(`- ${f}`);
    lines.push('');
  }

  if (context?.brandRules) {
    lines.push('## Brand rules');
    lines.push(context.brandRules);
    lines.push('');
  }

  if (context?.notes) {
    lines.push('## Pipeline notes');
    lines.push(context.notes);
    lines.push('');
  }

  // ── Embed artifact body for text-based kinds ────────────────────────────
  // Bug fix 2026-05-06: previously the council received only a title + path,
  // so jurors hallucinated content (e.g. plan-code review verdicts referenced
  // generic "Kafka / all departments" themes that didn't appear in the plan).
  // For text-shaped artifacts (plans, docs, specs, briefs, .md/.txt files we
  // can read), embed the full body so jurors actually score the work.
  const TEXT_KINDS = new Set([
    'plan', 'doc', 'spec', 'brief', 'business-plan', 'launch', 'content-strategy',
    'idea', 'offer', 'compliance-risk', 'priority', 'brand-voice', 'blogs',
    'cold-email',
  ]);
  const isTextKind = TEXT_KINDS.has(kind);
  const looksLikeText = artifactPath && /\.(md|markdown|txt|json|mdx)$/i.test(artifactPath);
  if ((isTextKind || looksLikeText) && artifactPath) {
    try {
      // Cap embed at 200 KB so we don't blow juror context with huge files.
      const MAX_EMBED = 200 * 1024;
      let body = readFileSync(artifactPath, 'utf8');
      const origLen = body.length;
      let truncated = false;
      if (body.length > MAX_EMBED) { body = body.slice(0, MAX_EMBED); truncated = true; }
      lines.push('## Artifact contents');
      lines.push('');
      lines.push(body);
      if (truncated) {
        lines.push('');
        lines.push(`(...truncated to first ${MAX_EMBED} bytes of ${origLen} total bytes)`);
      }
      lines.push('');
    } catch (e) {
      lines.push(`## Artifact contents`);
      lines.push(`(could not read artifact: ${e.message})`);
      lines.push('');
    }
  }

  // Phase 2.11h follow-on (Codex-flagged 2026-05-04): if the caller passes
  // context.qaRubric (a key from recipes/video/qa-rubrics.json#rubrics_by_shot_type),
  // overlay the shot-type rubric on top of the council's base rubric. Jurors
  // score against the listed dimensions + must_pass thresholds + ship_threshold.
  // The base rubric (rubrics/video.md) stays in effect — this is additive guidance.
  if (context?.qaRubric) {
    const rubricBlock = _formatQARubric(context.qaRubric);
    if (rubricBlock) {
      lines.push('## Shot-type rubric overlay');
      lines.push(`Source: recipes/video/qa-rubrics.json#rubrics_by_shot_type.${context.qaRubric}`);
      lines.push('Score against THESE dimensions in addition to the base rubric. Apply the must_pass + ship_threshold rules below.');
      lines.push('');
      lines.push(rubricBlock);
      lines.push('');
    }
  }

  // Phase 2.11e follow-on (2026-05-05): if the caller passes context.audioRecipes
  // (an array of resolved-recipe summaries from previewAudioRecipes), inline them
  // so the brand_lens / vision jurors can verify VO style + music feel + SFX
  // landings match the recipe presets the manifest declared. Pairs with the
  // screenComposites injection — overlays carry timing, audio recipes carry
  // texture, jury sees both at once.
  if (Array.isArray(context?.audioRecipes) && context.audioRecipes.length > 0) {
    lines.push('## Audio recipe references (per-layer presets resolved from recipes/video/audio.json)');
    lines.push('Each layer below was filled from a recipe key. Jurors should verify the tonal feel matches the recipe (e.g. founder_direct = warm conversational, premium_narrator = deliberate full-stop). Inline manifest overrides win where they are listed.');
    lines.push('');
    for (const ar of context.audioRecipes) {
      if (!ar.audioRecipe) continue;
      const tag = ar.error ? `✗ ${ar.error.split('.')[0]}` : `${ar.namespace}:${ar.audioRecipe}`;
      const derived = ar.derivedSource || ar.derivedVoice || '';
      lines.push(`  - layer ${ar.index} (${ar.type}) → ${tag}${derived ? `  →  ${derived}` : ''}`);
    }
    lines.push('');
  }

  // Phase 2.11k follow-on (2026-05-05): if the caller passes context.screenComposites
  // (an array of per-shot screen-composite specs), inline them so jurors can
  // verify the composite landed correctly: chat text matches the script, wake-
  // word pulse fires on the right beat, sent tick aligns with the audio SFX.
  // This is the "Veo plate ↔ Remotion truth" boundary surfaced to jury time.
  if (Array.isArray(context?.screenComposites) && context.screenComposites.length > 0) {
    lines.push('## Screen composite specs (Remotion overlays per shot)');
    lines.push('The shots below were rendered with `image_recipe.depth = "foreground_object_blur"` so the screen is soft glow, then a deterministic Remotion overlay was composited on top. Jurors must verify the on-screen content matches the spec listed here, NOT the Veo-hallucinated content underneath.');
    lines.push('');
    for (const sc of context.screenComposites) {
      const block = _formatScreenComposite(sc);
      if (block) {
        lines.push(block);
        lines.push('');
      }
    }
  }

  if (VISUAL_KINDS.has(kind)) {
    lines.push('## Council vision input');
    lines.push('Vision-capable jurors (NIM Nemotron Omni + Gemini 2.5 Flash)');
    lines.push('receive the base64-encoded image(s) and any video keyframes');
    lines.push('extracted from the paths above. The brand_lens juror is text-only');
    lines.push('by design — it scores voice/brand fit from the description.');
  }

  return lines.join('\n');
}

/**
 * Format one shot's screenComposite spec as council-readable markdown.
 * Caller supplies `{ shotName, shotStartS?, screenComposite }`.
 */
function _formatScreenComposite(sc) {
  if (!sc?.screenComposite) return null;
  const out = [];
  out.push(`### Shot \`${sc.shotName || '(unnamed)'}\``);
  if (sc.shotStartS != null) out.push(`Shot start in final cut: ${sc.shotStartS}s`);
  out.push(`Screen mask (canvas pixels): TL(${sc.screenComposite.screenMask.topLeft.x},${sc.screenComposite.screenMask.topLeft.y}) TR(${sc.screenComposite.screenMask.topRight.x},${sc.screenComposite.screenMask.topRight.y}) BL(${sc.screenComposite.screenMask.bottomLeft.x},${sc.screenComposite.screenMask.bottomLeft.y}) BR(${sc.screenComposite.screenMask.bottomRight.x},${sc.screenComposite.screenMask.bottomRight.y})`);
  out.push('Overlays (back-to-front):');
  for (const o of sc.screenComposite.overlays || []) {
    switch (o.recipe) {
      case 'chat_message_typing':
        out.push(`  - chat_message_typing: words ${JSON.stringify(o.words)} at times ${JSON.stringify(o.wordTimes)}s${o.sentAt != null ? `, sentAt=${o.sentAt}s` : ''}`);
        if (o.thread?.length) {
          for (const t of o.thread) out.push(`      thread (${t.side}): "${t.text}"`);
        }
        break;
      case 'window_switch_animation':
        out.push(`  - window_switch_animation: ${o.fromWindow} → ${o.toWindow} at ${o.switchAt}s${o.durationS != null ? ` (slide ${o.durationS}s)` : ''}`);
        break;
      case 'wake_word_pulse':
        out.push(`  - wake_word_pulse: pulseAt=${o.pulseAt}s${o.holdFromS != null ? `, holdFromS=${o.holdFromS}s` : ''}`);
        break;
      case 'sent_tick':
        out.push(`  - sent_tick: tickAt=${o.tickAt}s`);
        break;
      case 'notification_toast':
        out.push(`  - notification_toast: "${o.text}"${o.sender ? ` from ${o.sender}` : ''} at ${o.toastAt}s${o.holdS != null ? ` (hold ${o.holdS}s)` : ''}`);
        break;
      case 'screen_glow_only':
        out.push(`  - screen_glow_only: (no UI overlay — screen reads as ambient glow)`);
        break;
      default:
        out.push(`  - ${o.recipe}: (unknown recipe — jury cannot verify)`);
    }
  }
  return out.join('\n');
}

/**
 * Run the council on an artifact. Returns the verdict object.
 * Throws on DON'T-SHIP if failHard=true (default).
 */
export async function runAutoJury({
  kind,
  artifactPath,
  context  = {},
  failHard = true,
  outDir   = null,
}) {
  const skill = KIND_TO_SKILL[kind];
  if (!skill) {
    throw new Error(`auto-jury: unknown kind "${kind}". Allowed: ${Object.keys(KIND_TO_SKILL).join(', ')}`);
  }
  if (!artifactPath) throw new Error('auto-jury: artifactPath required');

  // Where verdicts land. Default: <artifact_dir>/jury/<artifact_basename>.verdict.json
  const verdictDir  = outDir || join(dirname(artifactPath), 'jury');
  if (!existsSync(verdictDir)) mkdirSync(verdictDir, { recursive: true });
  const verdictPath = join(verdictDir, `${basename(artifactPath)}.verdict.json`);
  const inputPath   = join(verdictDir, `${basename(artifactPath)}.input.md`);

  const input = buildCouncilInput({ kind, artifactPath, context });
  writeFileSync(inputPath, input, 'utf8');

  // Build council CLI args
  const cliArgs = [...PYTHON_ARGS, COUNCIL_PY, skill, '--input', inputPath, '--json'];
  for (const [k, v] of Object.entries(context.rubricFlags || {})) {
    cliArgs.push('--flag', `${k}=${v}`);
  }
  // Phase 2.11h follow-on: forward qaRubric key as a flag so rubric .md
  // files / synthesizer logic can branch on shot type if desired.
  if (context.qaRubric) {
    cliArgs.push('--flag', `qa_rubric=${context.qaRubric}`);
  }

  console.log(`  ⚖  auto-jury: ${skill} on ${basename(artifactPath)}${VISUAL_KINDS.has(kind) ? ' (vision-active)' : ''}`);

  let raw;
  const timeoutMs = _councilTimeoutMs();
  try {
    raw = execFileSync(PYTHON, cliArgs, {
      encoding: 'utf8',
      maxBuffer: 50 * 1024 * 1024,
      timeout:   timeoutMs,
      stdio:     ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    throw new Error(formatCouncilCliError(err, { skill, artifactPath, timeoutMs }));
  }

  let verdict;
  try {
    verdict = JSON.parse(raw);
  } catch {
    // Council printed markdown not JSON — keep it as-is for the operator.
    verdict = { raw_output: raw, parse_error: true };
  }

  // Stamp meta. Council vision wiring landed 2026-05-04 — vision-capable
  // jurors (NIM Nemotron Omni + Gemini 2.5 Flash) now receive base64 frames
  // for visual kinds. brand_lens juror remains text-only by design.
  verdict.auto_jury_meta = {
    kind,
    skill,
    artifact:        artifactPath,
    input:           inputPath,
    timestamp:       new Date().toISOString(),
    vision_active:   VISUAL_KINDS.has(kind),   // true = pixels reach vision jurors
    failHard,
  };

  writeFileSync(verdictPath, JSON.stringify(verdict, null, 2), 'utf8');
  console.log(`     verdict → ${verdictPath}`);

  // Ledger write (locked 2026-07-14). Every verdict round registers a
  // round in the per-artifact ledger so the auto-jury Stop hook can
  // gate on blocker disposition. Failure to write the ledger is logged
  // but does NOT throw — the hook itself will surface the missing
  // ledger with a clear "block-open-blockers" message.
  await _writeLedgerFromVerdict({ verdict, artifactPath, verdictPath, kind });

  // Decide ship/don't-ship. Council synthesizer typically returns
  // { final_verdict: "SHIP" | "REVISE" | "DON'T-SHIP" } or similar shape.
  const final = finalDecisionFromCouncilVerdict(verdict);

  const blocked = /DON'?T[-\s_]?SHIP|NEEDS[-\s_]?REVISION|REVISE|REJECT|BLOCK|FAIL|ERROR|PARSE/.test(final);

  if (blocked && failHard) {
    throw new Error(
      `auto-jury BLOCKED — ${skill} returned "${final}" for ${basename(artifactPath)}. ` +
      `See ${verdictPath} for jurors' reasoning. ` +
      `To bypass: re-run with auto-jury failHard=false or fix the issue and rebuild.`,
    );
  }

  if (blocked) {
    console.warn(`  ⚠ auto-jury: ${skill} returned "${final}" (failHard=false, continuing)`);
  } else if (final) {
    console.log(`  ✓ auto-jury: ${skill} returned "${final}"`);
  }

  return verdict;
}

/**
 * Write the per-artifact verdict ledger. Locked 2026-07-14: every jury
 * round appends a row to `<artifact>.verdict.ledger.json`. The Stop hook
 * (`enforce_auto_jury.py`) checks the ledger for unresolved blockers and
 * blocks ship unless every blocker has a disposition.
 *
 * We delegate to the Python ledger CLI so the file schema stays in one
 * place (src/lib/review/ledger.py). Pure stdlib child_process; no extra deps.
 */
async function _writeLedgerFromVerdict({ verdict, artifactPath, verdictPath, kind }) {
  const { spawnSync } = await import('node:child_process');
  const ledgerPath = verdictPath.replace(/\.verdict\.json$/, '.verdict.ledger.json');

  // Walk the verdict jurors and assemble per-juror blocker lists.
  const jurorBlockers = {};
  const jurors = verdict?.jurors || [];
  for (const j of jurors) {
    if (!j || !j.juror_id) continue;
    const blocks = j.blockers || [];
    if (blocks.length === 0) continue;
    jurorBlockers[j.juror_id] = blocks;
  }

  // Serialize to a JSON file the Python CLI can consume via stdin.
  const payload = {
    artifact: artifactPath,
    verdict_path: verdictPath,
    juror_blockers: jurorBlockers,
  };
  const payloadPath = `${verdictPath}.ledger-payload.json`;
  try {
    writeFileSync(payloadPath, JSON.stringify(payload), 'utf8');
  } catch (err) {
    console.warn(`  ⚠ ledger payload write failed: ${err.message}`);
    return;
  }

  // Build a tiny Python helper that registers the round. We import the
  // ledger module and call register_verdict_round + save_ledger.
  const helperPath = join(dirname(verdictPath), '.ledger-write.py');
  const helper = `
import json
import sys
from pathlib import Path
sys.path.insert(0, r"${process.env.JURY_LIB || join(WORKSPACE_ROOT, 'tools', 'review')}")
from ledger import Ledger, register_verdict_round, save_ledger, load_ledger

payload = json.loads(Path(r"${payloadPath}").read_text(encoding="utf-8"))
ledger_path = Path(r"${ledgerPath}")
ledger = load_ledger(ledger_path) or Ledger(schema_version=1, artifact=payload["artifact"])
register_verdict_round(
    ledger,
    verdict_path=payload["verdict_path"],
    juror_blockers=payload["juror_blockers"],
)
save_ledger(ledger, ledger_path)
print(f"ledger → {ledger_path}")
`;
  try {
    writeFileSync(helperPath, helper, 'utf8');
    const py = process.env.PYTHON_BIN || 'py';
    const pyArgs = process.env.PYTHON_BIN ? [] : ['-3.11'];
    const result = spawnSync(py, [...pyArgs, helperPath], {
      encoding: 'utf8',
      timeout: 30_000,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, PYTHONIOENCODING: 'utf-8' },
    });
    if (result.status !== 0) {
      console.warn(`  ⚠ ledger write failed (exit ${result.status}): ${(result.stderr || '').slice(0, 300)}`);
    } else {
      console.log(`     ledger → ${ledgerPath}`);
    }
  } catch (err) {
    console.warn(`  ⚠ ledger write exception: ${err.message}`);
  } finally {
    try { unlinkSync(payloadPath); } catch {}
    try { unlinkSync(helperPath); } catch {}
  }
}


/**
 * Convenience wrapper for batch artifacts (e.g. all clips in a campaign).
 * Runs jurors sequentially (council CLI is not parallel-safe per cache file).
 * Returns { verdicts: [...], blocked: [...] }.
 */
export async function runAutoJuryBatch(items, { failHard = true } = {}) {
  const verdicts = [];
  const blocked  = [];
  for (const item of items) {
    try {
      const v = await runAutoJury({ ...item, failHard });
      verdicts.push(v);
    } catch (err) {
      blocked.push({ artifact: item.artifactPath, error: err.message });
      if (failHard) throw err;
    }
  }
  return { verdicts, blocked };
}
