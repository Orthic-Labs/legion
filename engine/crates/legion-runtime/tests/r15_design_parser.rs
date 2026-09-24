//! Integration tests for chunk r15
//! (`skills/designer/engine/scripts/lib/design-parser.mjs`), exercising the
//! port through the crate's public `wf_port::r15` module.

use legion_runtime::wf_port::r15::{assess_coverage, parse_design_md, SectionCoverage};

const SAMPLE: &str = r#"# My Design System

## Overview
**Creative North Star: "Calm confidence"**

Body copy about the philosophy of the system.

**Key Characteristics:**
- Warm
- Precise

## Colors
### Brand
- **Primary (`#00478d` to `#005eb8`):** Use for primary actions.
- **Secondary** (`#f4f4f4`): Use for backgrounds.

### Named Rules
**The Contrast Rule.** Always keep 4.5:1 contrast for text.

## Typography
**Display Font:** Inter (with system-ui fallback)

**Character:** Confident and modern, never loud.

### Hierarchy
- **Display** (Inter, weight 700, clamp(2rem, 4vw, 4rem)): Page titles.

## Elevation
- **Card shadow** (`box-shadow: 0 2px 8px rgba(0,0,0,0.1)`): Default card elevation.

## Components
### Button
- **Primary:** Filled background, white text.
- **Shape:** Rounded, 8px radius.

## Do's and Don'ts
### Do
- Do use consistent spacing.

### Don't
- Don't mix more than two typefaces.
"#;

#[test]
fn parses_title_and_schema_version() {
    let model = parse_design_md(SAMPLE);
    assert_eq!(model.schema_version, 2);
    assert_eq!(model.title.as_deref(), Some("My Design System"));
}

#[test]
fn parses_overview_north_star_and_key_characteristics() {
    let model = parse_design_md(SAMPLE);
    let overview = model.overview.expect("overview present");
    assert_eq!(overview.creative_north_star.as_deref(), Some("Calm confidence"));
    assert_eq!(overview.key_characteristics, vec!["Warm", "Precise"]);
    assert!(!overview.philosophy.is_empty());
}

#[test]
fn parses_colors_groups_and_named_rule() {
    let model = parse_design_md(SAMPLE);
    let colors = model.colors.expect("colors present");
    assert!(!colors.groups.is_empty());
    let total: usize = colors.groups.iter().map(|g| g.colors.len()).sum();
    assert_eq!(total, 2);
    assert_eq!(colors.rules.len(), 1);
    assert_eq!(colors.rules[0].name, "The Contrast Rule");
}

#[test]
fn parses_typography_fonts_and_character() {
    let model = parse_design_md(SAMPLE);
    let typography = model.typography.expect("typography present");
    assert!(typography.fonts.contains_key("display"));
    assert_eq!(typography.fonts["display"].family, "Inter");
    // The legacy regex captures everything inside `(with ...)` verbatim
    // (`fm[3] = ([^)]+)` in design-parser.mjs), including the literal word
    // "fallback" from the source text — it does not strip it.
    assert_eq!(typography.fonts["display"].fallback.as_deref(), Some("system-ui fallback"));
    assert_eq!(typography.character.as_deref(), Some("Confident and modern, never loud."));
    assert_eq!(typography.hierarchy.len(), 1);
}

#[test]
fn parses_elevation_shadow() {
    let model = parse_design_md(SAMPLE);
    let elevation = model.elevation.expect("elevation present");
    // The bullet parser keeps the full `rgba(...)` value, but the inline
    // `box-shadow:` fallback scan (ported verbatim from
    // design-parser.mjs's `value.replace(/[`.)]+$/, '')`) also strips the
    // shadow's own trailing `)` since it can't distinguish it from a
    // markdown/backtick artifact. That gives the bullet-parsed and
    // inline-scanned values different dedupe keys, so both survive here,
    // matching the legacy JS behaviour on this sample.
    assert_eq!(elevation.shadows.len(), 2);
    assert_eq!(elevation.shadows[0].name.as_deref(), Some("Card shadow"));
    assert!(elevation.shadows[0].value.contains("rgba(0,0,0,0.1)"));
}

#[test]
fn parses_components_variants_and_properties() {
    let model = parse_design_md(SAMPLE);
    let components = model.components.expect("components present");
    assert_eq!(components.components.len(), 1);
    let button = &components.components[0];
    assert_eq!(button.name, "Button");
    assert_eq!(button.variants.len(), 1);
    assert_eq!(button.variants[0].name, "Primary");
    assert!(button.properties.contains_key("shape"));
}

#[test]
fn parses_dos_and_donts() {
    let model = parse_design_md(SAMPLE);
    let dd = model.dos_donts.expect("dos/donts present");
    assert_eq!(dd.dos, vec!["Do use consistent spacing."]);
    assert_eq!(dd.donts, vec!["Don't mix more than two typefaces."]);
}

#[test]
fn missing_sections_report_missing_in_model_and_coverage() {
    let model = parse_design_md("# Only Title\n\nSome prose, no canonical sections.\n");
    assert!(model.overview.is_none());
    assert!(model.colors.is_none());
    assert!(model.typography.is_none());
    assert!(model.elevation.is_none());
    assert!(model.components.is_none());
    assert!(model.dos_donts.is_none());

    let coverage = assess_coverage(&model);
    assert_eq!(coverage.overview, Some(SectionCoverage::Missing));
    assert_eq!(coverage.colors, Some(SectionCoverage::Missing));
    assert_eq!(coverage.typography, Some(SectionCoverage::Missing));
    assert_eq!(coverage.elevation, Some(SectionCoverage::Missing));
    assert_eq!(coverage.components, Some(SectionCoverage::Missing));
    assert_eq!(coverage.dos_donts, Some(SectionCoverage::Missing));
}

#[test]
fn coverage_counts_reflect_parsed_model() {
    let model = parse_design_md(SAMPLE);
    let coverage = assess_coverage(&model);
    match coverage.colors {
        Some(SectionCoverage::Colors { total_colors, rules, .. }) => {
            assert_eq!(total_colors, 2);
            assert_eq!(rules, 1);
        }
        other => panic!("expected Colors coverage, got {other:?}"),
    }
    match coverage.dos_donts {
        Some(SectionCoverage::DosDonts { dos, donts }) => {
            assert_eq!(dos, 1);
            assert_eq!(donts, 1);
        }
        other => panic!("expected DosDonts coverage, got {other:?}"),
    }
}

#[test]
fn frontmatter_is_parsed_when_present() {
    let md = "---\ntitle: \"Stitch Spec\"\ncolor:\n  primary: \"#00478d\"\n---\n\n# Title\n\n## Overview\nSome text.\n";
    let model = parse_design_md(md);
    let fm = model.frontmatter.expect("frontmatter present");
    assert_eq!(fm.get("title").and_then(|v| v.as_str()), Some("Stitch Spec"));
    let color = fm.get("color").and_then(|v| v.as_map()).expect("nested map");
    assert_eq!(color.get("primary").and_then(|v| v.as_str()), Some("#00478d"));
}
