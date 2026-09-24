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
    let r = rating.to_lowercase().replace('-', "_").replace(' ', "_");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_color_thresholds() {
        assert_eq!(score_color(95.0), BRAND.success);
        assert_eq!(score_color(90.0), BRAND.success);
        assert_eq!(score_color(89.9), BRAND.warning);
        assert_eq!(score_color(50.0), BRAND.warning);
        assert_eq!(score_color(49.9), BRAND.danger);
    }

    #[test]
    fn rating_color_normalizes_dashes_and_spaces() {
        assert_eq!(rating_color("Needs-Improvement"), BRAND.warning);
        assert_eq!(rating_color("needs improvement"), BRAND.warning);
        assert_eq!(rating_color("GOOD"), BRAND.success);
        assert_eq!(rating_color("poor"), BRAND.danger);
    }

    #[test]
    fn score_class_thresholds() {
        assert_eq!(score_class(80.0), "score-good");
        assert_eq!(score_class(79.9), "score-warn");
        assert_eq!(score_class(50.0), "score-warn");
        assert_eq!(score_class(49.9), "score-bad");
    }

    #[test]
    fn rating_css_class_substrings() {
        assert_eq!(rating_css_class("GOOD"), "status-pass");
        assert_eq!(rating_css_class("pass"), "status-pass");
        assert_eq!(rating_css_class("poor"), "status-fail");
        assert_eq!(rating_css_class("fail"), "status-fail");
        assert_eq!(rating_css_class("needs_improvement"), "status-warn");
    }
}
