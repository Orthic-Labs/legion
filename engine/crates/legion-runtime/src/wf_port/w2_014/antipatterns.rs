//! Port of `skills/designer/engine/scripts/detector/registry/antipatterns.mjs`
//! (chunk w2_014).
//!
//! `ANTIPATTERNS` is a static data registry (id/category/name/description/
//! severity/gated/skillSection/skillGuideline per rule) plus five small pure
//! functions over it: `getAntipattern`, `getRulesForCategory`,
//! `getRuleEngineSupport`, `GATED_PROVIDERS`, `filterByProviders`. Ported in
//! full, including `RULE_ENGINE_SUPPORT`.

use std::collections::HashSet;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Slop,
    Quality,
    Structure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Default severity (JS: no `severity` field present).
    Default,
    Advisory,
}

/// Mirrors one entry of the JS `ANTIPATTERNS` array.
#[derive(Debug, Clone, Copy)]
pub struct Antipattern {
    pub id: &'static str,
    pub category: Category,
    pub severity: Severity,
    /// Provider tag gating this rule off by default (`gpt` / `gemini`), or
    /// `None` for ungated rules.
    pub gated: Option<&'static str>,
    pub name: &'static str,
    pub description: &'static str,
    pub skill_section: Option<&'static str>,
    pub skill_guideline: Option<&'static str>,
}

macro_rules! ap {
    ($id:expr, $cat:expr, $sev:expr, $gated:expr, $name:expr, $desc:expr, $section:expr, $guideline:expr) => {
        Antipattern {
            id: $id,
            category: $cat,
            severity: $sev,
            gated: $gated,
            name: $name,
            description: $desc,
            skill_section: $section,
            skill_guideline: $guideline,
        }
    };
}

pub static ANTIPATTERNS: LazyLock<Vec<Antipattern>> = LazyLock::new(|| {
    vec![
        ap!("side-tab", Category::Slop, Severity::Default, None,
            "Side-tab accent border",
            "Thick colored border on one side of a card — the most recognizable tell of AI-generated UIs. Use a subtler accent or remove it entirely.",
            Some("Visual Details"), Some("colored accent stripe")),
        ap!("border-accent-on-rounded", Category::Slop, Severity::Default, None,
            "Border accent on rounded element",
            "Thick accent border on a rounded card — the border clashes with the rounded corners. Remove the border or the border-radius.",
            Some("Visual Details"), Some("colored accent stripe")),
        ap!("overused-font", Category::Slop, Severity::Default, None,
            "Overused font",
            "Inter, Roboto, Fraunces, Geist, Plus Jakarta Sans, and Space Grotesk are used on so many sites they no longer feel distinctive. Each new wave of AI-generated UIs converges on the same handful of faces. Choose a face that gives your interface personality.",
            Some("Typography"), Some("overused fonts like Inter")),
        ap!("single-font", Category::Slop, Severity::Default, None,
            "Single font for everything",
            "Only one font family is used for the entire page. Pair a distinctive display font with a refined body font to create typographic hierarchy.",
            Some("Typography"), Some("only one font family for the entire page")),
        ap!("flat-type-hierarchy", Category::Slop, Severity::Default, None,
            "Flat type hierarchy",
            "Font sizes are too close together — no clear visual hierarchy. Use fewer sizes with more contrast (aim for at least a 1.25 ratio between steps).",
            Some("Typography"), Some("flat type hierarchy")),
        ap!("gradient-text", Category::Slop, Severity::Default, None,
            "Gradient text",
            "Gradient text is decorative rather than meaningful — a common AI tell, especially on headings and metrics. Use solid colors for text.",
            Some("Color & Contrast"), Some("gradient text for")),
        ap!("ai-color-palette", Category::Slop, Severity::Default, None,
            "AI color palette",
            "Purple/violet gradients and cyan-on-dark are the most recognizable tells of AI-generated UIs. Choose a distinctive, intentional palette.",
            Some("Color & Contrast"), Some("AI color palette")),
        ap!("cream-palette", Category::Slop, Severity::Default, None,
            "Cream / beige palette",
            "A warm cream or beige page background has become the default \"tasteful\" AI surface, reached for by reflex. Choose a background that comes from a deliberate palette, not the safe warm off-white.",
            Some("Color & Contrast"), Some("cream and beige as the default surface")),
        ap!("nested-cards", Category::Slop, Severity::Default, None,
            "Nested cards",
            "Cards inside cards create visual noise and excessive depth. Flatten the hierarchy — use spacing, typography, and dividers instead of nesting containers.",
            Some("Layout & Space"), Some("Nest cards inside cards")),
        ap!("monotonous-spacing", Category::Slop, Severity::Default, None,
            "Monotonous spacing",
            "The same spacing value used everywhere — no rhythm, no variation. Use tight groupings for related items and generous separations between sections.",
            Some("Layout & Space"), Some("same spacing everywhere")),
        ap!("bounce-easing", Category::Slop, Severity::Default, None,
            "Bounce or elastic easing",
            "Bounce and elastic easing feel dated and tacky. Real objects decelerate smoothly — use exponential easing (ease-out-quart/quint/expo) instead.",
            Some("Motion"), Some("bounce or elastic easing")),
        ap!("dark-glow", Category::Slop, Severity::Default, None,
            "Dark mode with glowing accents",
            "Dark backgrounds with colored box-shadow glows are the default \"cool\" look of AI-generated UIs. Use subtle, purposeful lighting instead — or skip the dark theme entirely.",
            Some("Color & Contrast"), Some("dark mode with glowing accents")),
        ap!("icon-tile-stack", Category::Slop, Severity::Default, None,
            "Icon tile stacked above heading",
            "A small rounded-square icon container above a heading is the universal AI feature-card template — every generator outputs this exact shape. Try a side-by-side icon and heading, or let the icon sit in flow without its own container.",
            Some("Typography"), Some("large icons with rounded corners above every heading")),
        ap!("italic-serif-display", Category::Slop, Severity::Default, None,
            "Italic serif display headline",
            "Oversized italic serif (Fraunces, Recoleta, Playfair, Newsreader-italic) as the primary hero headline reads as taste in isolation but has become the universal AI-startup landing page hero. Set roman, or move to a non-serif display face. Editorial / magazine register may legitimately want this — judge by context.",
            Some("Typography"), Some("oversized italic serif as the hero headline")),
        ap!("hero-eyebrow-chip", Category::Slop, Severity::Default, None,
            "Hero eyebrow / pill chip",
            "A tiny uppercase letter-spaced label sitting immediately above an oversized hero headline — or the same shape rendered as a pill chip — is now the default AI SaaS hero. Drop the eyebrow, integrate the kicker into the headline, or run it as a navigation breadcrumb instead.",
            Some("Typography"), Some("tiny uppercase tracked label above the hero headline")),
        ap!("repeated-section-kickers", Category::Slop, Severity::Advisory, None,
            "Repeated section kicker labels",
            "Repeating tiny uppercase tracked labels above section headings turns a brand page into AI editorial scaffolding. Replace them with stronger structure, artifacts, imagery, or a deliberate brand system.",
            Some("Typography"), Some("repeated eyebrow or kicker labels as section scaffolding")),
        ap!("numbered-section-markers", Category::Slop, Severity::Advisory, None,
            "Numbered section markers (01 / 02 / 03)",
            "Numbered display markers as section labels (01, 02, 03) are the AI editorial scaffold one tier deeper than tracked eyebrow chips. If you find yourself reaching for them, choose a different section cadence.",
            Some("Layout & Space"), Some("numbered section markers")),
        ap!("em-dash-overuse", Category::Slop, Severity::Default, None,
            "Em-dash overuse",
            "More than two em-dashes (— or --) in body copy is an AI cadence tell. Use commas, colons, periods, or parentheses instead.",
            Some("Copy"), Some("no em dashes")),
        ap!("marketing-buzzword", Category::Slop, Severity::Default, None,
            "Marketing buzzword",
            "Generic SaaS phrases (streamline / empower / supercharge / world-class / enterprise-grade / next-generation / cutting-edge / etc) are instant AI tells. Pick a specific verb and noun that says what the product literally does.",
            Some("Copy"), Some("marketing buzzwords")),
        ap!("aphoristic-cadence", Category::Slop, Severity::Default, None,
            "Aphoristic-cadence copy",
            "Three or more sections landing on a short rebuttal sentence (\"X. No Y.\" / \"X. Just Y.\") or a manufactured-contrast aphorism (\"Not a feature. A platform.\") reads as AI cadence, not voice. Once is fine; the pattern is the tell.",
            Some("Copy"), Some("aphoristic cadence")),
        ap!("oversized-h1", Category::Slop, Severity::Default, None,
            "Oversized hero headline",
            "A full-sentence headline set at display size ends up dominating the viewport, leaving no room for anything else above the fold. A punchy one- or two-word headline at that size is fine — the problem is a long headline blown up too large. Set long headlines smaller, or tighten the copy.",
            Some("Typography"), Some("long headline set at display size")),
        ap!("extreme-negative-tracking", Category::Slop, Severity::Default, None,
            "Crushed letter spacing",
            "Letter-spacing pulled tighter than the point where characters keep their own shapes costs legibility. Tighten display type optically, not destructively.",
            Some("Typography"), Some("letter spacing crushed past legibility")),
        ap!("broken-image", Category::Quality, Severity::Default, None,
            "Broken or placeholder image",
            "<img> tags with empty src, missing src, or placeholder values ship as broken-image boxes. Use real images, generated assets, or remove the tag.",
            Some("Imagery"), Some("broken image references")),
        ap!("gray-on-color", Category::Quality, Severity::Default, None,
            "Gray text on colored background",
            "Gray text looks washed out on colored backgrounds. Use a darker shade of the background color instead, or white/near-white for contrast.",
            Some("Color & Contrast"), Some("gray text on colored backgrounds")),
        ap!("low-contrast", Category::Quality, Severity::Default, None,
            "Low contrast text",
            "Text does not meet WCAG AA contrast requirements (4.5:1 for body, 3:1 for large text). Increase the contrast between text and background.",
            None, None),
        ap!("layout-transition", Category::Quality, Severity::Default, None,
            "Layout property animation",
            "Animating width, height, padding, or margin causes layout thrash and janky performance. Use transform and opacity instead, or grid-template-rows for height animations.",
            Some("Motion"), Some("Animate layout properties")),
        ap!("line-length", Category::Quality, Severity::Default, None,
            "Line length too long",
            "Text lines wider than ~80 characters are hard to read. The eye loses its place tracking back to the start of the next line. Add a max-width (65ch to 75ch) to text containers.",
            Some("Layout & Space"), Some("wrap beyond ~80 characters")),
        ap!("cramped-padding", Category::Quality, Severity::Default, None,
            "Cramped padding",
            "Text is too close to the edge of its container. Two shapes: (1) an element with its own text where the padding is too low for the font size, and (2) a wrapper with text-bearing children and near-zero padding against a visible boundary (border, outline, or non-transparent background) — children land flush against the boundary line. Add at least 8px (ideally 12–16px) of padding inside bordered, outlined, or colored containers.",
            Some("Layout & Space"), Some("inside bordered or colored containers")),
        ap!("body-text-viewport-edge", Category::Quality, Severity::Default, None,
            "Body text touching viewport edge",
            "Body paragraphs render flush against the left or right viewport edge with no container providing horizontal padding. Wrap content in a container with at least 16px (ideally 24-32px) of horizontal padding, or apply max-width with mx-auto.",
            None, None),
        ap!("tight-leading", Category::Quality, Severity::Default, None,
            "Tight line height",
            "Line height below 1.3x the font size makes multi-line text hard to read. Use 1.5 to 1.7 for body text so lines have room to breathe.",
            None, None),
        ap!("skipped-heading", Category::Quality, Severity::Default, None,
            "Skipped heading level",
            "Heading levels should not skip (e.g. h1 then h3 with no h2). Screen readers use heading hierarchy for navigation. Skipping levels breaks the document outline.",
            None, None),
        ap!("justified-text", Category::Quality, Severity::Default, None,
            "Justified text",
            "Justified text without hyphenation creates uneven word spacing (\"rivers of white\"). Use text-align: left for body text, or enable hyphens: auto if you must justify.",
            None, None),
        ap!("tiny-text", Category::Quality, Severity::Default, None,
            "Tiny body text",
            "Body text below 12px is hard to read, especially on high-DPI screens. Use at least 14px for body content, 16px is ideal.",
            None, None),
        ap!("all-caps-body", Category::Quality, Severity::Default, None,
            "All-caps body text",
            "Long passages in uppercase are hard to read. We recognize words by shape (ascenders and descenders), which all-caps removes. Reserve uppercase for short labels and headings.",
            Some("Typography"), Some("long body passages in uppercase")),
        ap!("wide-tracking", Category::Quality, Severity::Default, None,
            "Wide letter spacing on body text",
            "Letter spacing above 0.05em on body text disrupts natural character groupings and slows reading. Reserve wide tracking for short uppercase labels only.",
            None, None),
        ap!("text-overflow", Category::Quality, Severity::Default, None,
            "Content overflowing its container",
            "Content renders wider than its container, spilling out or forcing a horizontal scrollbar. Let text wrap, constrain widths, or give the region a deliberate scroll affordance.",
            Some("Layout & Space"), Some("content wider than its container")),
        ap!("clipped-overflow-container", Category::Quality, Severity::Default, None,
            "Positioned child clipped by overflow container",
            "A clipping container (overflow hidden or clip) wrapping an absolutely-positioned child cuts off tooltips, menus, and popovers that need to escape. Let the overflow be visible, or move the positioned layer out of the clip.",
            Some("Layout & Space"), Some("overflow container clipping positioned children")),
        ap!("design-system-font", Category::Quality, Severity::Default, None,
            "Font outside DESIGN.md",
            "A font is used that is not declared in DESIGN.md typography. Use the documented type system or update DESIGN.md if this is an intentional brand addition.",
            Some("Typography"), Some("font family outside the project design system")),
        ap!("design-system-color", Category::Quality, Severity::Advisory, None,
            "Color outside DESIGN.md",
            "A literal color is outside the DESIGN.md palette and sidecar tonal ramps. This may be legitimate, but it should be an intentional design-system addition rather than drift.",
            Some("Color & Contrast"), Some("literal color outside the project design system")),
        ap!("design-system-radius", Category::Quality, Severity::Advisory, None,
            "Radius outside DESIGN.md",
            "A border-radius value is outside the DESIGN.md rounded scale. Use a documented radius token or update the design system if the new shape is intentional.",
            Some("Visual Details"), Some("border radius outside the project design system")),
        ap!("gpt-thin-border-wide-shadow", Category::Slop, Severity::Advisory, Some("gpt"),
            "Hairline border with wide shadow",
            "A hairline border paired with a wide, diffuse shadow is a recurring generated-UI signature. Commit to one — a defined edge or a soft elevation — rather than both at once.",
            Some("Visual Details"), Some("hairline border plus wide diffuse shadow")),
        ap!("repeating-stripes-gradient", Category::Slop, Severity::Advisory, Some("gpt"),
            "Repeating-gradient stripes",
            "Repeating-gradient stripes used as surface decoration are a recurring generated-UI signature. Reach for a deliberate texture or leave the surface plain.",
            Some("Visual Details"), Some("repeating-gradient decorative stripes")),
        ap!("theater-slop-phrase", Category::Slop, Severity::Advisory, Some("gpt"),
            "Theater framing copy",
            "Dismissing something as \"theater\" is a recurring generated-copy tic. Say plainly what the thing does or does not do.",
            Some("Copy"), Some("theater framing copy")),
        ap!("image-hover-transform", Category::Slop, Severity::Advisory, Some("gemini"),
            "Image hover transform",
            "Scaling or rotating an image on hover is a recurring generated-UI signature. Let imagery sit still, or use a subtler, purposeful interaction.",
            Some("Motion"), Some("image scale or rotate on hover")),
        ap!("cta-below-fold", Category::Structure, Severity::Default, None,
            "Primary CTA below the fold",
            "The page has call-to-action buttons but none is fully visible in the first viewport. ~57-80% of attention stays above the fold; the primary CTA must render there and may repeat below.",
            Some("Structure"), Some("primary CTA above the fold")),
        ap!("hero-cta-competition", Category::Structure, Severity::Default, None,
            "Competing CTAs above the fold",
            "Three or more distinct filled call-to-action buttons render above the fold. Competing equal-weight actions measurably depress conversion (Hick's law). Keep one primary CTA, at most one visually secondary.",
            Some("Structure"), Some("one primary CTA decision")),
        ap!("headline-word-wall", Category::Structure, Severity::Default, None,
            "Headline word wall",
            "The h1 runs past ~14 words. A hero headline must state what this is in under ~10 words; move the elaboration into the subheader.",
            Some("Structure"), Some("descriptive headline under ten words")),
        ap!("one-word-lines", Category::Structure, Severity::Default, None,
            "Heading wraps to word-per-line column",
            "A display heading wraps into 4+ lines averaging fewer than ~2.5 words per line — a narrow column of stacked words instead of a headline. Widen the container, shorten the copy, or reduce the font size.",
            Some("Structure"), Some("headline wraps as a readable line, not a word stack")),
        ap!("missing-hero-media", Category::Structure, Severity::Advisory, None,
            "No visual anchor above the fold",
            "The first viewport of a landing-shaped page contains no meaningful image, video, illustration, or product visual — text only. Show the product or a purposeful visual; if a type-only hero is deliberate, the typography must carry the entire first impression.",
            Some("Structure"), Some("hero imagery shows the product")),
        ap!("hero-viewport-hog", Category::Structure, Severity::Default, None,
            "Text-wall hero over a full viewport",
            "The hero section runs taller than ~1.15 viewports with no media inside — a wall of text pushing all proof and action out of the first screen. Cut hero copy to headline + subheader + CTA, or add the visual that earns the height.",
            Some("Structure"), Some("hero states the offer inside one viewport")),
        ap!("hover-contrast", Category::Structure, Severity::Default, None,
            "Illegible hover state",
            "A :hover rule changes text or background color into a combination below WCAG contrast — the label becomes unreadable exactly when the user is about to click it. Hover styles must keep the same contrast floor as the resting state.",
            Some("Color & Contrast"), Some("hover states stay legible")),
        ap!("oversized-header", Category::Structure, Severity::Default, None,
            "Oversized header or wordmark",
            "The site header (or the logo inside it) is dramatically taller than convention — it eats the first viewport and dwarfs the content. Keep headers ~56-88px tall and wordmarks ~20-40px; the brand is a signature, not a billboard.",
            Some("Structure"), Some("header and wordmark scale")),
        ap!("broken-internal-link", Category::Structure, Severity::Default, None,
            "Broken internal link",
            "A same-origin link on the page responds with an error status. Every internal link must resolve — a broken link is lost trust and a lost crawl path.",
            Some("Structure"), Some("internal links resolve")),
        ap!("missing-required-page", Category::Structure, Severity::Default, None,
            "Required page not linked",
            "A page this site type must have (privacy, terms, pricing, downloads, returns/refunds, about, contact) is not linked anywhere on the scanned page. Ship the page and link it from the footer at minimum.",
            Some("Structure"), Some("required page set is linked")),
    ]
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Engine {
    Regex,
    StaticHtml,
    Browser,
    Visual,
}

/// Mirrors `RULE_ENGINE_SUPPORT`'s value sets (rule-scope tags, not this
/// crate's own type — kept as plain strings since the JS source never
/// enumerates a closed set for them).
pub fn rule_engine_support(engine: Engine) -> HashSet<&'static str> {
    match engine {
        Engine::Regex => ["source", "page-analyzer"].into_iter().collect(),
        Engine::StaticHtml => ["element", "page"].into_iter().collect(),
        Engine::Browser => ["element", "page", "layout"].into_iter().collect(),
        Engine::Visual => ["visual-contrast"].into_iter().collect(),
    }
}

/// Mirrors `getRuleEngineSupport(engine)`: an unrecognized engine name
/// returns the empty set. Since `Engine` is a closed enum here, callers
/// parsing an external string should map unknown names to `None` before
/// calling; this helper mirrors the by-name lookup directly.
pub fn get_rule_engine_support(engine: &str) -> HashSet<&'static str> {
    match engine {
        "regex" => rule_engine_support(Engine::Regex),
        "static-html" => rule_engine_support(Engine::StaticHtml),
        "browser" => rule_engine_support(Engine::Browser),
        "visual" => rule_engine_support(Engine::Visual),
        _ => HashSet::new(),
    }
}

/// Mirrors `getAntipattern(id)`.
pub fn get_antipattern(id: &str) -> Option<&'static Antipattern> {
    ANTIPATTERNS.iter().find(|rule| rule.id == id)
}

/// Mirrors `getRulesForCategory(category)`.
pub fn get_rules_for_category(category: Category) -> Vec<&'static Antipattern> {
    ANTIPATTERNS
        .iter()
        .filter(|rule| rule.category == category)
        .collect()
}

/// Mirrors `GATED_PROVIDERS`.
pub static GATED_PROVIDERS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    ANTIPATTERNS
        .iter()
        .filter_map(|rule| rule.gated)
        .collect()
});

/// A finding as consumed by `filterByProviders`: only the rule id
/// (`.antipattern` in the JS source) matters to the filter.
pub trait HasAntipatternId {
    fn antipattern_id(&self) -> &str;
}

/// Mirrors `filterByProviders(findings, providers = [])`.
///
/// Generic over any finding type implementing `HasAntipatternId` so callers
/// can filter their own finding structs without an intermediate copy.
pub fn filter_by_providers<T: HasAntipatternId>(
    findings: Vec<T>,
    providers: &[&str],
) -> Vec<T> {
    if GATED_PROVIDERS.is_empty() {
        return findings;
    }
    let enabled: HashSet<&str> = providers.iter().copied().collect();
    findings
        .into_iter()
        .filter(|f| match get_antipattern(f.antipattern_id()) {
            None => true,
            Some(rule) => match rule.gated {
                None => true,
                Some(g) => enabled.contains(g),
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_expected_length() {
        // Matches `grep -c "id: '" antipatterns.mjs` == 54 entries.
        assert_eq!(ANTIPATTERNS.len(), 54);
    }

    #[test]
    fn get_antipattern_found_and_missing() {
        let rule = get_antipattern("side-tab").unwrap();
        assert_eq!(rule.name, "Side-tab accent border");
        assert_eq!(rule.category, Category::Slop);
        assert!(get_antipattern("does-not-exist").is_none());
    }

    #[test]
    fn get_rules_for_category_filters() {
        let structure = get_rules_for_category(Category::Structure);
        assert_eq!(structure.len(), 10);
        assert!(structure.iter().all(|r| r.category == Category::Structure));
    }

    #[test]
    fn rule_engine_support_sets_match_js() {
        assert_eq!(
            get_rule_engine_support("regex"),
            ["source", "page-analyzer"].into_iter().collect::<HashSet<_>>()
        );
        assert_eq!(
            get_rule_engine_support("browser"),
            ["element", "page", "layout"].into_iter().collect::<HashSet<_>>()
        );
        assert!(get_rule_engine_support("unknown-engine").is_empty());
    }

    #[test]
    fn gated_providers_are_gpt_and_gemini() {
        assert_eq!(
            GATED_PROVIDERS.clone(),
            ["gpt", "gemini"].into_iter().collect::<HashSet<_>>()
        );
    }

    struct FakeFinding {
        antipattern: &'static str,
    }
    impl HasAntipatternId for FakeFinding {
        fn antipattern_id(&self) -> &str {
            self.antipattern
        }
    }

    #[test]
    fn filter_by_providers_drops_ungated_provider() {
        let findings = vec![
            FakeFinding { antipattern: "side-tab" }, // ungated -> always kept
            FakeFinding { antipattern: "gpt-thin-border-wide-shadow" }, // gated gpt
            FakeFinding { antipattern: "image-hover-transform" }, // gated gemini
        ];
        let kept = filter_by_providers(findings, &["gpt"]);
        let ids: Vec<&str> = kept.iter().map(|f| f.antipattern).collect();
        assert_eq!(ids, vec!["side-tab", "gpt-thin-border-wide-shadow"]);
    }

    #[test]
    fn filter_by_providers_no_providers_drops_all_gated() {
        let findings = vec![
            FakeFinding { antipattern: "side-tab" },
            FakeFinding { antipattern: "gpt-thin-border-wide-shadow" },
        ];
        let kept = filter_by_providers(findings, &[]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].antipattern, "side-tab");
    }

    #[test]
    fn filter_by_providers_unknown_rule_id_passes_through() {
        let findings = vec![FakeFinding { antipattern: "not-a-real-rule" }];
        let kept = filter_by_providers(findings, &[]);
        assert_eq!(kept.len(), 1);
    }
}
