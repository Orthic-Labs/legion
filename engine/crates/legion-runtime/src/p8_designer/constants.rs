//! Port of `skills/designer/engine/scripts/detector/shared/constants.mjs`.
//!
//! `isBrandFontOnOwnDomain` read `location.hostname` implicitly in the
//! browser-executed JS. The Rust port takes the hostname explicitly
//! (`current_hostname: Option<&str>`); `None` mirrors the JS
//! `typeof location === 'undefined'` early-return of `false`.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

pub static SAFE_TAGS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "blockquote",
        "nav",
        "a",
        "input",
        "textarea",
        "select",
        "pre",
        "code",
        "span",
        "th",
        "td",
        "tr",
        "li",
        "label",
        "button",
        "hr",
        "html",
        "head",
        "body",
        "script",
        "style",
        "link",
        "meta",
        "title",
        "br",
        "img",
        "svg",
        "path",
        "circle",
        "rect",
        "line",
        "polyline",
        "polygon",
        "g",
        "defs",
        "use",
    ]
    .into_iter()
    .collect()
});

/// `SAFE_TAGS` minus `label` (border/side-tab anti-pattern check needs
/// `label` to remain detectable).
pub static BORDER_SAFE_TAGS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    SAFE_TAGS
        .iter()
        .copied()
        .filter(|t| *t != "label")
        .collect()
});

pub static OVERUSED_FONTS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "inter",
        "roboto",
        "open sans",
        "lato",
        "montserrat",
        "arial",
        "helvetica",
        "fraunces",
        "instrument sans",
        "instrument serif",
        "geist",
        "geist sans",
        "geist mono",
        "mona sans",
        "plus jakarta sans",
        "space grotesk",
        "recoleta",
    ]
    .into_iter()
    .collect()
});

pub static GOOGLE_DOMAINS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        "google.com",
        "youtube.com",
        "android.com",
        "chromium.org",
        "chrome.com",
        "web.dev",
        "gstatic.com",
        "firebase.google.com",
    ]
});

pub static VERCEL_DOMAINS: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| vec!["vercel.com", "nextjs.org", "v0.app"]);

pub static GITHUB_DOMAINS: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| vec!["github.com", "githubnext.com"]);

pub static BRAND_FONT_DOMAINS: LazyLock<HashMap<&'static str, &'static Vec<&'static str>>> =
    LazyLock::new(|| {
        let mut m: HashMap<&'static str, &'static Vec<&'static str>> = HashMap::new();
        m.insert("roboto", &GOOGLE_DOMAINS);
        m.insert("google sans", &GOOGLE_DOMAINS);
        m.insert("product sans", &GOOGLE_DOMAINS);
        m.insert("geist", &VERCEL_DOMAINS);
        m.insert("geist sans", &VERCEL_DOMAINS);
        m.insert("geist mono", &VERCEL_DOMAINS);
        m.insert("mona sans", &GITHUB_DOMAINS);
        m
    });

/// Mirrors `isBrandFontOnOwnDomain(font)`. `current_hostname` is `None` when
/// there is no notion of a "current page" (mirrors `typeof location ===
/// 'undefined'`).
pub fn is_brand_font_on_own_domain(font: &str, current_hostname: Option<&str>) -> bool {
    let Some(host) = current_hostname else {
        return false;
    };
    let Some(allowed) = BRAND_FONT_DOMAINS.get(font) else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    allowed
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}

pub static GENERIC_FONTS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "serif",
        "sans-serif",
        "monospace",
        "cursive",
        "fantasy",
        "system-ui",
        "ui-serif",
        "ui-sans-serif",
        "ui-monospace",
        "ui-rounded",
        "-apple-system",
        "blinkmacsystemfont",
        "segoe ui",
        "inherit",
        "initial",
        "unset",
        "revert",
    ]
    .into_iter()
    .collect()
});

/// 18pt normal text at 96px/inch.
pub const WCAG_LARGE_TEXT_PX: f64 = 18.0 * (96.0 / 72.0);
/// 14pt bold text at 96px/inch.
pub const WCAG_LARGE_BOLD_TEXT_PX: f64 = 14.0 * (96.0 / 72.0);

pub static KNOWN_SERIF_FONTS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "fraunces",
        "recoleta",
        "newsreader",
        "playfair display",
        "playfair",
        "cormorant",
        "cormorant garamond",
        "garamond",
        "eb garamond",
        "tiempos",
        "tiempos headline",
        "tiempos text",
        "lora",
        "vollkorn",
        "spectral",
        "source serif pro",
        "source serif 4",
        "source serif",
        "ibm plex serif",
        "merriweather",
        "libre caslon",
        "libre baskerville",
        "baskerville",
        "georgia",
        "times new roman",
        "times",
        "dm serif display",
        "dm serif text",
        "instrument serif",
        "gt sectra",
        "ogg",
        "canela",
        "freight display",
        "freight text",
    ]
    .into_iter()
    .collect()
});
