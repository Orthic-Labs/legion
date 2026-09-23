//! Port of `skills/designer/engine/scripts/palette.mjs`
//! (chunk w2_023, area `skills/designer/engine/scripts`, target crate
//! `legion-runtime`).
//!
//! Coverage check: `git grep` across `engine/` for the source's distinctive
//! names (`BRAND SEED`, `hueWord`, `weightedPick`, seed ids such as
//! `seed-200`) turned up nothing outside `l6_designer_checks::css_color`
//! and `p9_skills::brand_identity`, neither of which contains the seed
//! library or the picker logic. This file is a fresh, faithful port.
//!
//! The source is a CLI brand-seed picker: it selects one of 129 hand-curated
//! OKLCH seed colors — either uniformly at random, by explicit `--id`, or
//! deterministically by hashing a `--from`/`IMPECCABLE_PALETTE_SEED` key —
//! using inverse-hue-bucket-frequency weighting, then prints a long
//! instructional message (the "fat tool-exit response") built around that
//! seed.
//!
//! Ported faithfully:
//! - the full 129-entry `SEEDS` table (id, oklch [L, C, H], mood, strategy),
//! - `hashUnit` (SHA-256 of the key, first 4 bytes read as a big-endian
//!   u32, divided by 2^32 — bit-for-bit what Node's
//!   `crypto.createHash('sha256').update(key).digest().readUInt32BE(0) /
//!   0x100000000` computes),
//! - `buildWeights` / `weightedPick` (inverse 30°-hue-bucket-frequency
//!   weighting; identical bucket/weight/target-subtraction algorithm, so
//!   for the same `unit` value the same seed is chosen),
//! - `pickSeed`'s three-way precedence: explicit id > explicit/env `from`
//!   key (hashed) > uniform random,
//! - `fmtOklch` and `hueWord` (identical bucket boundaries and labels),
//! - the full instructional stdout text (`render_seed_report`), verbatim
//!   modulo dynamic substitutions the source itself makes (seed id, oklch
//!   values, hue word, mood hint, strategy hint, hue degrees).
//!
//! Not ported (out of scope for a pure library function): CLI argv parsing
//! and `process.exit` — the source's `--id "unknown"` case exits the whole
//! process with code 2 and a stderr message; here that is modeled as
//! `Err(PaletteError::UnknownSeedId)`, letting the caller decide how to
//! exit. `IMPECCABLE_PALETTE_SEED` env-var reading is left to the caller
//! (pass it in as `from`) rather than reached into `std::env` from a
//! library function, matching this crate's general style of keeping I/O at
//! the edges.

use sha2::{Digest, Sha256};

/// One hand-curated brand-seed color.
#[derive(Debug, Clone, Copy)]
pub struct Seed {
    pub id: &'static str,
    /// `[L, C, H]` in OKLCH.
    pub oklch: [f64; 3],
    pub mood: &'static str,
    pub strategy: &'static str,
}

include!("seeds.rs");

/// Errors from picking a seed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PaletteError {
    #[error("no seed with id \"{0}\"")]
    UnknownSeedId(String),
}

/// Mirrors the source's `parseArgs`: `--id <id>` and `--from <key>` are
/// mutually exclusive selectors (id takes precedence if both are somehow
/// supplied, matching `pickSeed`'s `if (id) { ... }` short-circuit).
#[derive(Debug, Clone, Default)]
pub struct PickArgs {
    pub id: Option<String>,
    pub from: Option<String>,
}

/// SHA-256 of `key`, first 4 bytes read big-endian, divided by 2^32.
/// Bit-for-bit equivalent to the source's `hashUnit`.
pub fn hash_unit(key: &str) -> f64 {
    let digest = Sha256::digest(key.as_bytes());
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    (n as f64) / (0x1_0000_0000_u64 as f64)
}

/// 30°-wide hue bucket index for a hue in degrees (wrapped into [0, 360)).
fn bucket_of(seed: &Seed) -> i64 {
    let h = seed.oklch[2];
    let wrapped = ((h % 360.0) + 360.0) % 360.0;
    (wrapped / 30.0).floor() as i64
}

/// Per-seed weight (`1 / count of seeds sharing its hue bucket`) and the
/// sum of all weights. Mirrors `buildWeights`.
fn build_weights(seeds: &[Seed]) -> (Vec<f64>, f64) {
    use std::collections::HashMap;
    let mut bucket_count: HashMap<i64, usize> = HashMap::new();
    for s in seeds {
        *bucket_count.entry(bucket_of(s)).or_insert(0) += 1;
    }
    let weights: Vec<f64> = seeds
        .iter()
        .map(|s| 1.0 / (bucket_count[&bucket_of(s)] as f64))
        .collect();
    let total: f64 = weights.iter().sum();
    (weights, total)
}

/// Weighted pick by cumulative-subtraction, matching the source's
/// `weightedPick` (including its `unit` semantics and fallback to the last
/// seed if floating-point rounding leaves `target >= 0` after the loop).
pub fn weighted_pick(seeds: &[Seed], unit: f64) -> Seed {
    let (weights, total) = build_weights(seeds);
    let mut target = unit * total;
    for (i, s) in seeds.iter().enumerate() {
        target -= weights[i];
        if target < 0.0 {
            return *s;
        }
    }
    *seeds.last().expect("SEEDS is non-empty")
}

/// A source of randomness for the uniform-random branch. Production callers
/// pass a real RNG; tests pass a fixed value for determinism (the source
/// itself uses `Math.random()`, which this crate has no equivalent
/// dependency for — callers own that choice).
pub trait UnitRandom {
    /// Must return a value in `[0, 1)`.
    fn next_unit(&mut self) -> f64;
}

/// Mirrors `pickSeed`: explicit `id` wins, then `from` (hashed via
/// [`hash_unit`]), then a caller-supplied uniform-random unit.
pub fn pick_seed(
    seeds: &[Seed],
    args: &PickArgs,
    rng: &mut dyn UnitRandom,
) -> Result<Seed, PaletteError> {
    if let Some(id) = &args.id {
        return seeds
            .iter()
            .find(|s| s.id == id)
            .copied()
            .ok_or_else(|| PaletteError::UnknownSeedId(id.clone()));
    }
    let unit = match &args.from {
        Some(key) => hash_unit(key),
        None => rng.next_unit(),
    };
    Ok(weighted_pick(seeds, unit))
}

/// Formats `[L, C, H]` as `oklch(L.LLL C.CCC H.H)`, matching `fmtOklch`.
pub fn fmt_oklch([l, c, h]: [f64; 3]) -> String {
    format!("oklch({:.3} {:.3} {:.1})", l, c, h)
}

/// Maps a hue in degrees to its descriptive word, matching `hueWord`'s
/// bucket boundaries exactly (half-open `[lo, hi)` ranges, wrapping red at
/// both ends of the circle).
pub fn hue_word(h: f64) -> &'static str {
    if h < 15.0 || h >= 345.0 {
        "pure red"
    } else if h < 35.0 {
        "warm red / crimson"
    } else if h < 55.0 {
        "warm coral / burnt orange"
    } else if h < 80.0 {
        "orange / honey"
    } else if h < 105.0 {
        "warm amber / honey-gold"
    } else if h < 135.0 {
        "yellow-green / olive"
    } else if h < 170.0 {
        "green"
    } else if h < 200.0 {
        "teal"
    } else if h < 230.0 {
        "sky blue"
    } else if h < 265.0 {
        "cobalt / indigo"
    } else if h < 295.0 {
        "violet / purple"
    } else if h < 330.0 {
        "magenta / pink"
    } else {
        "deep pink / rose"
    }
}

/// Renders the full "fat tool-exit response" stdout text for a chosen
/// seed, verbatim modulo the dynamic substitutions the source itself makes.
pub fn render_seed_report(seed: &Seed) -> String {
    let [l, c, h] = seed.oklch;
    let hue = hue_word(h);
    let mood_hint = if seed.mood.is_empty() {
        String::new()
    } else {
        format!(" (one read: \"{}\")", seed.mood)
    };
    let strategy_hint = if seed.strategy.is_empty() {
        String::new()
    } else {
        format!("\n  - one example strategy: {}", seed.strategy)
    };

    let _ = l;
    let _ = c;
    format!(
        "BRAND SEED · {id}\n\n\
Seed color (anchor for your primary brand color):\n\
  {oklch} — {hue}{mood_hint}\n\n\
This is the brand's anchor — a single beautiful color. Compose the rest of\n\
the palette around it using YOUR judgment, the brief (PRODUCT.md /\n\
DESIGN.md / the user's prompt), and the color-strategy guidance already in\n\
SKILL.md.\n\n\
How to use:\n\n\
1. Read the brief. Write one specific phrase describing the mood this\n\
   product calls for. Be granular. Good: \"1970s travel poster — sun-baked\n\
   warmth, considered\", \"midnight jazz club — smoky brass, saxophone\n\
   light\", \"Scandinavian winter morning — quiet light through frost\". Bad:\n\
   \"modern and clean\", \"warm and inviting\". The first lets you compose; the\n\
   second is generic and will produce generic palettes.\n\n\
2. The seed's hue ({h_deg:.0}°) anchors your primary brand color. You\n\
   choose L and C to match the mood. The same hue can be deep-and-velvet,\n\
   bright-and-confident, or pale-and-faded — pick the one the mood demands.\n\
   Primary's hue should stay within ±10° of the seed.{strategy_hint}\n\n\
3. Now compose the full palette in OKLCH (5 more roles):\n\
     • bg       — the most important architectural choice.\n\
                  CORE PRINCIPLE: the mood lives in the BRAND COLORS\n\
                  (primary + accent) and typography, NOT in the surface.\n\
                  Stripe is warm — its purple does that, bg is pure\n\
                  white. Linear is cool — its blue does that, bg is\n\
                  pure. Notion is warm — its accents do that, bg is\n\
                  near-pure-white. Putting warmth in BOTH primary AND\n\
                  bg is the AI cliché.\n\n\
                  DEFAULT A — PURE white: exactly oklch(1.000 0.000 0).\n\
                    Not 0.99, not chroma 0.002. Stripe / Notion / Apple\n\
                    use literal #ffffff. Don't add hidden warmth.\n\
                    Refs: Stripe, Notion, Linear (light), Apple.com,\n\
                    Vercel docs, Figma marketing, Loom, Substack.\n\n\
                  DEFAULT B — PURE black/near-black: L 0.04-0.12,\n\
                    chroma exactly 0.000. No hue tint. Vercel is\n\
                    roughly oklch(0.08 0 0). Pick L for mood; C is 0.\n\
                    Refs: Vercel, A24, Acne, Apple dark, MUBI.\n\n\
                  ALT 2 — TINTED: chroma 0.015-0.05.\n\
                    Use ONLY when:\n\
                    (a) the mood is EXPLICITLY environmental — the surface\n\
                        IS part of the brand (1920s lacquered interior,\n\
                        leather library, ceramic studio, hotel lobby), or\n\
                    (b) the seed itself is desaturated (chroma < 0.10) and\n\
                        needs a tinted surface to read as a brand.\n\
                    NOT for \"feels warm\" / \"modern + warm\" / \"moody\". If\n\
                    your mood says \"warm\" but doesn't name a specific\n\
                    environment, use PURE white and let primary carry\n\
                    the warmth.\n\n\
                  HEURISTIC: if seed chroma > 0.10 AND mood is product-\n\
                  focused (not environment-focused), it's almost always\n\
                  PURE white. Target distribution across many palettes:\n\
                  ~50% pure white, ~25% pure black, ~25% tinted.\n\
     • surface  — bg pulled slightly toward ink (10-15% mix). Same hue\n\
                  family as bg. Used for cards, panels, sections.\n\
     • ink      — body text color. Must reach ≥7:1 contrast vs bg.\n\
                  Can carry the brand hue at low chroma in light mode\n\
                  (slight warmth or coolness toward the brand).\n\
     • accent   — a SECOND brand color, distinct from primary in BOTH\n\
                  hue AND lightness. Picked to complement the mood (not\n\
                  default-complementary across the wheel). Used for\n\
                  badges, status pills, links, accent rules.\n\
     • muted    — secondary text. Ink pulled 40% toward bg, keeping ink's\n\
                  hue. Must reach ≥3.5:1 contrast vs bg.\n\n\
4. Pick a color STRATEGY (the four steps from SKILL.md):\n\
     • Restrained: tinted neutrals + accent ≤10% — product default\n\
     • Committed: one saturated color carries 30-60% — identity-driven\n\
     • Full palette: 3-4 named roles each used deliberately — brand work\n\
     • Drenched: the surface IS the color — campaign, hero, statement\n\
   The brief picks the strategy. A startup dashboard ≠ a perfume brand.\n\n\
Hard rules (already in SKILL.md, recapped because the seed step is where\n\
they actually bite):\n\n\
  - OKLCH only — never hex. Never #RRGGBB.\n\
  - ink-vs-bg WCAG contrast ≥ 7 (body text must be readable)\n\
  - primary chroma ≤ 0.23 (above this, primary glows perceptually and\n\
    no text on it is readable — acid-bright is a UI failure)\n\
  - if primary L > 0.78, primary chroma ≤ 0.18 (the fluorescent zone)\n\
  - primary-vs-accent contrast ≥ 1.7 (they must be visually distinct,\n\
    not two variants of the same hue at similar lightness)\n\
  - accent must carry readable text on a filled badge/pill: EITHER\n\
    saturated (chroma ≥ 0.10) OR clearly light (L ≥ 0.85) OR clearly\n\
    dark (L ≤ 0.30). Never a muddy mid-tone (L 0.45-0.72 + chroma < 0.10)\n\
    — taupe/mushroom/dusty-grey accents read as weak and can't hold text\n\
    either way. Saturate it or push its lightness to a clear light/dark.\n\
  - avoid the saturated AI attractor zones: claude-beige (warm-cream bg\n\
    + dusty brown primary), forest-green-on-cream, AI-purple-on-white,\n\
    navy-cream-with-orange-accent\n\n\
TEXT-ON-COLOR FILLS — pick by perceptual contrast, not just WCAG. The\n\
rule applies to ANY element where text sits on a saturated color fill:\n\
primary buttons, accent buttons, badges, status pills, tag highlights,\n\
filled callouts. Don't only think \"primary button\" — apply consistently.\n\n\
For any saturated mid-luminance color (L between 0.42 and 0.78, chroma ≥\n\
0.08), use WHITE text (or near-white from your bg), not dark text — even\n\
if WCAG says dark technically passes. The Helmholtz-Kohlrausch effect\n\
makes saturated colors appear brighter than their luminance suggests,\n\
and dark text on a warm-or-cool-saturated fill reads as muddy.\n\n\
Convention: Stripe orange CTAs, McDonald's red, every fintech orange\n\
button, Vercel's filled badges, Linear's status pills — all use white\n\
text on saturated bg fills.\n\n\
Dark text is correct only on PALE fills (L > 0.85) or PURE-NEUTRAL fills\n\
(chroma near 0). Everything else: white text.\n\n\
Return your composed palette in CSS custom properties using OKLCH, then\n\
build with it. The seed is the start, not the recipe.\n",
        id = seed.id,
        oklch = fmt_oklch(seed.oklch),
        hue = hue,
        mood_hint = mood_hint,
        h_deg = h,
        strategy_hint = strategy_hint,
    )
}
