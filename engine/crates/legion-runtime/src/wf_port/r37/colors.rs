//! Port of `google_report.py`'s `BRAND` palette and the four color/class helpers
//! (`_score_color`, `_rating_color`, `_score_class`, `_rating_css_class`).

/// Verbatim port of the `BRAND` dict. Field names mirror the Python keys
/// (`best_practices` stands in for the hyphenated `"best-practices"` key,
/// which is not a valid Rust identifier; callers use `BRAND.best_practices`
/// only where the source used `BRAND["best-practices"]`, which it never does
/// -- the hyphenated key only ever appears as a JSON lookup key, not a BRAND
/// color, so no field is needed for it here).
pub struct Brand {
    pub primary: &'static str,
    pub secondary: &'static str,
    pub accent: &'static str,
    pub success: &'static str,
    pub warning: &'static str,
    pub danger: &'static str,
    pub dark: &'static str,
    pub light_bg: &'static str,
    pub grid: &'static str,
    pub muted: &'static str,
}

pub const BRAND: Brand = Brand {
    primary: "#1e3a5f",
    secondary: "#4a5568",
    accent: "#b8860b",
    success: "#2d6a4f",
    warning: "#d4740e",
    danger: "#c53030",
    dark: "#1a1a2e",
    light_bg: "#faf9f7",
    grid: "#d6d3cc",
    muted: "#6b7280",
};

/// Port of `_score_color`: Lighthouse-style score thresholds.
pub fn score_color(score: f64) -> &'static str {
    if score >= 90.0 {
        BRAND.success
    } else if score >= 50.0 {
        BRAND.warning
    } else {
        BRAND.danger
    }
}

/// Port of `_rating_color`: CrUX rating strings, normalized the same way
/// (`lower()`, `-`/` ` -> `_`).
pub fn rating_color(rating: &str) -> &'static str {
    let r = rating.to_lowercase().replace(['-', ' '], "_");
    match r.as_str() {
        "good" | "pass" | "fast" => BRAND.success,
        "needs_improvement" | "average" | "warn" => BRAND.warning,
        _ => BRAND.danger,
    }
}

/// Port of `_score_class`: CSS class for TOC score badges.
pub fn score_class(score: f64) -> &'static str {
    if score >= 80.0 {
        "score-good"
    } else if score >= 50.0 {
        "score-warn"
    } else {
        "score-bad"
    }
}

/// Port of `_rating_css_class`.
pub fn rating_css_class(rating: &str) -> &'static str {
    let r = rating.to_lowercase();
    if r.contains("good") || r.contains("pass") {
        "status-pass"
    } else if r.contains("poor") || r.contains("fail") {
        "status-fail"
    } else {
        "status-warn"
    }
}
