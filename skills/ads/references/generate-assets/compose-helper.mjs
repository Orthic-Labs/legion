/**
 * Helper for /ads-generate Phase 2.5c integration (plan v5).
 *
 * Same architecture as seo-image-gen/compose-helper.mjs. Skill builds prompt via
 * composeImagePrompt(), passes string to existing banana-claude MCP. No backend swap.
 *
 * v5 directive: NO use-case presets. Recipe selectors EXPLICIT per call. Aspect
 * ratio is the only allowed default (per platform channel).
 *
 * Channel aspect-ratio map (the only allowed default per v5):
 *   meta_static       → 1:1   (Instagram Feed, Facebook Feed default)
 *   meta_static_4x5   → 4:5   (Instagram Feed tall)
 *   meta_story        → 9:16  (Stories, Reels)
 *   google_responsive → 1:1   (single output; multi-aspect handled by Google)
 *   linkedin_carousel → 1:1
 *   linkedin_single   → 1.91:1
 *   tiktok_vertical   → 9:16
 *   pinterest_pin     → 2:3
 *   custom            → caller supplies --aspect
 *
 * Old campaign-brief.md format (raw prompt strings) is supported in
 * /ads-generate SKILL.md fallback path; this helper is for Mode A new format.
 */

import { composeImagePrompt } from '../../pipelines/video/create.mjs';

const CHANNEL_ASPECT = {
  meta_static:       '1:1',
  meta_static_4x5:   '4:5',
  meta_story:        '9:16',
  google_responsive: '1:1',
  linkedin_carousel: '1:1',
  linkedin_single:   '1.91:1',
  tiktok_vertical:   '9:16',
  pinterest_pin:     '2:3',
  custom:            null,
};

function parseArgs(argv) {
  const out = {};
  for (const a of argv.slice(2)) {
    if (a.startsWith('--')) {
      const [k, ...v] = a.slice(2).split('=');
      out[k] = v.join('=') || true;
    }
  }
  return out;
}

function main() {
  const args = parseArgs(process.argv);

  if (!args.channel) {
    console.error('Usage: --channel=<meta_static|meta_static_4x5|meta_story|google_responsive|linkedin_carousel|linkedin_single|tiktok_vertical|pinterest_pin|custom> + recipe selectors');
    console.error('Channels:');
    for (const [k, v] of Object.entries(CHANNEL_ASPECT)) {
      console.error(`  ${k.padEnd(20)} aspect=${v ?? '(specify --aspect)'}`);
    }
    process.exit(1);
  }
  if (!(args.channel in CHANNEL_ASPECT)) {
    console.error(`Unknown channel "${args.channel}". Valid: ${Object.keys(CHANNEL_ASPECT).join(', ')}`);
    process.exit(1);
  }
  const aspect = args.aspect || CHANNEL_ASPECT[args.channel];
  if (!aspect) {
    console.error(`Channel "custom" requires --aspect=<...>`);
    process.exit(1);
  }
  const negatives = args.negatives ? args.negatives.split(',').map((s) => s.trim()) : undefined;

  const composed = composeImagePrompt({
    subject:         args.subject,
    setting:         args.setting,
    action:          args.action,
    subject_type:    args.subject_type,
    lighting:        args.lighting,
    composition:     args.composition,
    depth:           args.depth,
    lens:            args.lens,
    colorPsychology: args.colorPsychology,
    skinTexture:     args.skinTexture,
    emotion:         args.emotion,
    wardrobe:        args.wardrobe,
    productSpec:     args.productSpec,
    negatives,
    brand_palette:   args.brand_palette,
    targetBackend:   'banana-claude',
    silent:          true,
  });

  console.log(JSON.stringify({
    channel: args.channel,
    aspect,
    prompt:         composed.prompt,
    negativePrompt: composed.negativePrompt,
    meta:           composed.meta,
  }, null, 2));
}

main();
