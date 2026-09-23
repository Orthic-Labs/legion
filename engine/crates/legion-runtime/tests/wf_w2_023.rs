//! Tests for the w2_023 port of `skills/designer/engine/scripts/palette.mjs`.
//!
//! Reference values (`hash_unit`, `weighted_pick`, the seed-201 report
//! fixture) were computed by running the original Node script directly
//! (`node skills/designer/engine/scripts/palette.mjs --id seed-201` and a
//! small inline harness reusing its `hashUnit`/`buildWeights`/
//! `weightedPick`), so these assert bit-for-bit parity with the JS
//! source, not just plausibility.

use legion_runtime::wf_port::w2_023::{
    fmt_oklch, hash_unit, hue_word, pick_seed, render_seed_report, weighted_pick, PaletteError,
    PickArgs, Seed, UnitRandom, SEEDS,
};

struct FixedRandom(f64);
impl UnitRandom for FixedRandom {
    fn next_unit(&mut self) -> f64 {
        self.0
    }
}

#[test]
fn seed_table_has_129_entries() {
    assert_eq!(SEEDS.len(), 129);
}

#[test]
fn seed_ids_are_unique() {
    let mut ids: Vec<&str> = SEEDS.iter().map(|s| s.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), SEEDS.len());
}

#[test]
fn hash_unit_matches_node_reference_values() {
    // node -e 'crypto.createHash("sha256").update(key).digest().readUInt32BE(0)/0x100000000'
    let cases: &[(&str, f64)] = &[
        ("abc", 0.728394910460338),
        ("hello-world", 0.6860730210319161),
        ("seed-test-key", 0.8347157356329262),
        ("damnedventures@gmail.com", 0.8793692302424461),
    ];
    for (key, expected) in cases {
        let got = hash_unit(key);
        assert!(
            (got - expected).abs() < 1e-12,
            "hash_unit({key:?}) = {got}, expected {expected}"
        );
    }
}

#[test]
fn hash_unit_is_deterministic() {
    assert_eq!(hash_unit("same-key"), hash_unit("same-key"));
}

#[test]
fn weighted_pick_matches_node_reference_at_boundary_units() {
    // node reference (see module docs): weightedPick(SEEDS, unit).id
    let cases: &[(f64, &str)] = &[
        (0.0, "seed-200"),
        (0.0001, "seed-200"),
        (0.25, "seed-058"),
        (0.5, "seed-184"),
        (0.728394910460338, "seed-187"),
        (0.9999, "seed-116"),
        (0.999999, "seed-116"),
    ];
    for (unit, expected_id) in cases {
        let got = weighted_pick(SEEDS, *unit);
        assert_eq!(got.id, *expected_id, "unit = {unit}");
    }
}

#[test]
fn weighted_pick_total_weight_matches_hue_bucket_count() {
    // The source builds one weight-of-1 "vote" per non-empty 30°-hue bucket
    // (weights within a bucket sum to 1), so total == number of occupied
    // buckets. Node reference: 11.000000000000009 (floating-point sum of
    // per-seed 1/count fractions).
    let mut buckets = std::collections::HashSet::new();
    for s in SEEDS {
        let h = s.oklch[2];
        let wrapped = ((h % 360.0) + 360.0) % 360.0;
        buckets.insert((wrapped / 30.0).floor() as i64);
    }
    assert_eq!(buckets.len(), 11);
}

#[test]
fn hue_word_bucket_boundaries_match_source() {
    assert_eq!(hue_word(0.0), "pure red");
    assert_eq!(hue_word(14.9), "pure red");
    assert_eq!(hue_word(15.0), "warm red / crimson");
    assert_eq!(hue_word(344.9), "deep pink / rose");
    assert_eq!(hue_word(345.0), "pure red");
    assert_eq!(hue_word(200.0), "sky blue");
    assert_eq!(hue_word(34.9), "warm red / crimson");
    assert_eq!(hue_word(35.0), "warm coral / burnt orange");
    assert_eq!(hue_word(329.9), "magenta / pink");
    assert_eq!(hue_word(330.0), "deep pink / rose");
}

#[test]
fn fmt_oklch_matches_source_formatting() {
    assert_eq!(fmt_oklch([0.647, 0.262, 0.3]), "oklch(0.647 0.262 0.3)");
    assert_eq!(fmt_oklch([0.0, 0.0, 0.0]), "oklch(0.000 0.000 0.0)");
    assert_eq!(fmt_oklch([1.0, 0.2295, 359.95]), "oklch(1.000 0.230 360.0)");
}

#[test]
fn pick_seed_by_explicit_id() {
    let args = PickArgs {
        id: Some("seed-201".to_string()),
        from: None,
    };
    let mut rng = FixedRandom(0.999); // must be ignored when id is set
    let got = pick_seed(SEEDS, &args, &mut rng).expect("known id");
    assert_eq!(got.id, "seed-201");
    assert_eq!(got.oklch, [0.647, 0.262, 0.3]);
}

#[test]
fn pick_seed_unknown_id_errors() {
    let args = PickArgs {
        id: Some("seed-does-not-exist".to_string()),
        from: None,
    };
    let mut rng = FixedRandom(0.0);
    let err = pick_seed(SEEDS, &args, &mut rng).unwrap_err();
    assert_eq!(
        err,
        PaletteError::UnknownSeedId("seed-does-not-exist".to_string())
    );
}

#[test]
fn pick_seed_from_key_is_deterministic_and_id_takes_precedence() {
    let args_from = PickArgs {
        id: None,
        from: Some("abc".to_string()),
    };
    let mut rng = FixedRandom(0.0); // must be ignored when `from` is set
    let by_from = pick_seed(SEEDS, &args_from, &mut rng).unwrap();
    assert_eq!(by_from.id, weighted_pick(SEEDS, hash_unit("abc")).id);

    let args_both = PickArgs {
        id: Some("seed-000".to_string()),
        from: Some("abc".to_string()),
    };
    let mut rng2 = FixedRandom(0.0);
    let by_both = pick_seed(SEEDS, &args_both, &mut rng2).unwrap();
    assert_eq!(by_both.id, "seed-000", "explicit id must win over `from`");
}

#[test]
fn pick_seed_falls_back_to_rng_when_neither_id_nor_from_given() {
    let args = PickArgs::default();
    let mut rng = FixedRandom(0.25);
    let got = pick_seed(SEEDS, &args, &mut rng).unwrap();
    assert_eq!(got.id, "seed-058");
}

#[test]
fn render_seed_report_matches_node_reference_fixture() {
    let seed = SEEDS
        .iter()
        .find(|s| s.id == "seed-201")
        .copied()
        .expect("seed-201 exists");
    let got = render_seed_report(&seed);
    let expected = include_str!("fixtures/wf_w2_023/seed-201_report.txt");
    assert_eq!(got, expected);
}

#[test]
fn render_seed_report_includes_mood_and_strategy_hints_when_present() {
    let seed = Seed {
        id: "seed-test",
        oklch: [0.5, 0.1, 200.0],
        mood: "test mood",
        strategy: "test strategy",
    };
    let out = render_seed_report(&seed);
    assert!(out.contains("BRAND SEED · seed-test"));
    assert!(out.contains("(one read: \"test mood\")"));
    assert!(out.contains("- one example strategy: test strategy"));
    assert!(out.contains("oklch(0.500 0.100 200.0) — teal"));
}
