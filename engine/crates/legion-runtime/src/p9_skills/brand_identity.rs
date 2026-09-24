//! Packet P9-skill-scripts: Rust port of `skills/brand-identity/scripts/color-check.mjs`.
//!
//! Zero-dependency color math for the brand-identity Color Science gate: WCAG 2.2 contrast
//! ratios and OKLCH<->sRGB conversion (Bjorn Ottosson OKLab, CSS Color 4), computed from the
//! standard formulas so callers never report a contrast grade or OKLCH value from memory.
//!
//! CLI surface ported 1:1 (`legion brand-identity color <verb>`):
//!   contrast <fg-hex> <bg-hex>       -> ratio + AA/AAA verdict
//!   oklch <hex>                      -> sRGB hex -> OKLCH (L C H)
//!   oklch-to-hex <L> <C> <H>         -> OKLCH -> nearest in-gamut sRGB hex
//!   audit '<json>'                   -> [{name,fg,bg,min?}] -> pass/fail table

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq)]
pub struct ColorCheckError(pub String);

impl std::fmt::Display for ColorCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ColorCheckError {}

fn hex_to_rgb(hex: &str) -> Result<(f64, f64, f64), ColorCheckError> {
    let h = hex.trim().trim_start_matches('#');
    let s = if h.len() == 3 {
        h.chars().flat_map(|c| [c, c]).collect::<String>()
    } else {
        h.to_string()
    };
    if s.len() != 6 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ColorCheckError(format!("bad hex: {hex}")));
    }
    let r = u8::from_str_radix(&s[0..2], 16).unwrap() as f64;
    let g = u8::from_str_radix(&s[2..4], 16).unwrap() as f64;
    let b = u8::from_str_radix(&s[4..6], 16).unwrap() as f64;
    Ok((r, g, b))
}

fn rgb_to_hex(r: f64, g: f64, b: f64) -> String {
    let c = |n: f64| n.round().clamp(0.0, 255.0) as u8;
    format!("#{:02x}{:02x}{:02x}", c(r), c(g), c(b))
}

fn srgb_to_linear(c: f64) -> f64 {
    let x = c / 255.0;
    if x <= 0.04045 {
        x / 12.92
    } else {
        ((x + 0.055) / 1.055).powf(2.4)
    }
}

fn linear_to_srgb(x: f64) -> f64 {
    let c = if x <= 0.0031308 {
        x * 12.92
    } else {
        1.055 * x.powf(1.0 / 2.4) - 0.055
    };
    c * 255.0
}

fn rel_luminance((r, g, b): (f64, f64, f64)) -> f64 {
    let (r, g, b) = (srgb_to_linear(r), srgb_to_linear(g), srgb_to_linear(b));
    0.2126 * r + 0.7152 * g + 0.0722 * b
}

pub fn contrast_ratio(fg_hex: &str, bg_hex: &str) -> Result<f64, ColorCheckError> {
    let l1 = rel_luminance(hex_to_rgb(fg_hex)?);
    let l2 = rel_luminance(hex_to_rgb(bg_hex)?);
    let (hi, lo) = if l1 >= l2 { (l1, l2) } else { (l2, l1) };
    Ok((hi + 0.05) / (lo + 0.05))
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Oklch {
    pub l: f64,
    pub c: f64,
    pub h: f64,
}

pub fn srgb_to_oklch(hex: &str) -> Result<Oklch, ColorCheckError> {
    let (r, g, b) = hex_to_rgb(hex)?;
    let (r, g, b) = (srgb_to_linear(r), srgb_to_linear(g), srgb_to_linear(b));
    let l = (0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b).cbrt();
    let m = (0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b).cbrt();
    let s = (0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b).cbrt();
    let ll = 0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s;
    let a = 1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s;
    let bb = 0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s;
    let c = a.hypot(bb);
    let mut h = bb.atan2(a) * 180.0 / std::f64::consts::PI;
    if h < 0.0 {
        h += 360.0;
    }
    Ok(Oklch { l: ll, c, h })
}

#[derive(Debug, Clone, PartialEq)]
pub struct OklchToRgbResult {
    pub hex: String,
    pub in_gamut: bool,
}

pub fn oklch_to_rgb(l: f64, c: f64, h: f64) -> OklchToRgbResult {
    let a = c * (h * std::f64::consts::PI / 180.0).cos();
    let b = c * (h * std::f64::consts::PI / 180.0).sin();
    let l_ = l + 0.3963377774 * a + 0.2158037573 * b;
    let m_ = l - 0.1055613458 * a - 0.0638541728 * b;
    let s_ = l - 0.0894841775 * a - 1.2914855480 * b;
    let (l3, m3, s3) = (l_.powi(3), m_.powi(3), s_.powi(3));
    let r = 4.0767416621 * l3 - 3.3077115913 * m3 + 0.2309699292 * s3;
    let g = -1.2684380046 * l3 + 2.6097574011 * m3 - 0.3413193965 * s3;
    let bl = -0.0041960863 * l3 - 0.7034186147 * m3 + 1.7076147010 * s3;
    let clamped = [r, g, bl].iter().any(|v| *v < -0.001 || *v > 1.001);
    OklchToRgbResult {
        hex: rgb_to_hex(linear_to_srgb(r), linear_to_srgb(g), linear_to_srgb(bl)),
        in_gamut: !clamped,
    }
}

fn round(n: f64, d: i32) -> f64 {
    let f = 10f64.powi(d);
    (n * f).round() / f
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContrastReport {
    pub fg: String,
    pub bg: String,
    pub ratio: f64,
    #[serde(rename = "AA_normal")]
    pub aa_normal: bool,
    #[serde(rename = "AA_large_or_ui")]
    pub aa_large_or_ui: bool,
    #[serde(rename = "AAA_normal")]
    pub aaa_normal: bool,
}

pub fn check_contrast(fg: &str, bg: &str) -> Result<ContrastReport, ColorCheckError> {
    let ratio = contrast_ratio(fg, bg)?;
    Ok(ContrastReport {
        fg: fg.to_string(),
        bg: bg.to_string(),
        ratio: round(ratio, 2),
        aa_normal: ratio >= 4.5,
        aa_large_or_ui: ratio >= 3.0,
        aaa_normal: ratio >= 7.0,
    })
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditPair {
    pub name: Option<String>,
    pub fg: String,
    pub bg: String,
    pub min: Option<f64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AuditRow {
    pub name: String,
    pub fg: String,
    pub bg: String,
    pub ratio: f64,
    pub min: f64,
    pub pass: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AuditReport {
    pub rows: Vec<AuditRow>,
    #[serde(rename = "allPass")]
    pub all_pass: bool,
}

pub fn audit_pairs(pairs: &[AuditPair]) -> Result<AuditReport, ColorCheckError> {
    let mut rows = Vec::with_capacity(pairs.len());
    for p in pairs {
        let ratio = contrast_ratio(&p.fg, &p.bg)?;
        let min = p.min.unwrap_or(4.5);
        rows.push(AuditRow {
            name: p
                .name
                .clone()
                .unwrap_or_else(|| format!("{}/{}", p.fg, p.bg)),
            fg: p.fg.clone(),
            bg: p.bg.clone(),
            ratio: round(ratio, 2),
            min,
            pass: ratio >= min,
        });
    }
    let all_pass = rows.iter().all(|r| r.pass);
    Ok(AuditReport { rows, all_pass })
}

/// CLI entry point mirroring `color-check.mjs`'s `process.argv.slice(2)` dispatch.
/// `argv` is the script's own arguments (no program name, no leading `color`).
/// Returns the process exit code: 0 success, 1 `audit` with a failing pair, 2 usage/parse error.
pub fn run(argv: &[String]) -> i32 {
    let cmd = argv.first().map(String::as_str).unwrap_or("");
    let rest = if argv.is_empty() { &argv[..] } else { &argv[1..] };
    match cmd {
        "contrast" => {
            let (fg, bg) = match (rest.first(), rest.get(1)) {
                (Some(fg), Some(bg)) => (fg, bg),
                _ => {
                    eprintln!("error: usage: contrast <fg> <bg>");
                    return 2;
                }
            };
            match check_contrast(fg, bg) {
                Ok(report) => {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap());
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    2
                }
            }
        }
        "oklch" => {
            let hex = match rest.first() {
                Some(h) => h,
                None => {
                    eprintln!("error: usage: oklch <hex>");
                    return 2;
                }
            };
            match srgb_to_oklch(hex) {
                Ok(ok) => {
                    let out = serde_json::json!({
                        "hex": hex,
                        "L": round(ok.l, 4),
                        "C": round(ok.c, 4),
                        "H": round(ok.h, 2),
                    });
                    println!("{}", serde_json::to_string_pretty(&out).unwrap());
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    2
                }
            }
        }
        "oklch-to-hex" => {
            if rest.len() < 3 {
                eprintln!("error: usage: oklch-to-hex <L> <C> <H>");
                return 2;
            }
            let parsed: Result<Vec<f64>, _> = rest[..3].iter().map(|s| s.parse::<f64>()).collect();
            let vals = match parsed {
                Ok(v) => v,
                Err(_) => {
                    eprintln!("error: L, C, H must be numbers");
                    return 2;
                }
            };
            let (l, c, h) = (vals[0], vals[1], vals[2]);
            let res = oklch_to_rgb(l, c, h);
            let out = serde_json::json!({
                "L": l, "C": c, "H": h,
                "hex": res.hex, "inGamut": res.in_gamut,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
            0
        }
        "audit" => {
            let raw = match rest.first() {
                Some(r) => r,
                None => {
                    eprintln!("error: usage: audit '<json>'");
                    return 2;
                }
            };
            let pairs: Vec<AuditPair> = match serde_json::from_str(raw) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: {e}");
                    return 2;
                }
            };
            match audit_pairs(&pairs) {
                Ok(report) => {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap());
                    if report.all_pass {
                        0
                    } else {
                        1
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    2
                }
            }
        }
        _ => {
            eprintln!(
                "usage: contrast <fg> <bg> | oklch <hex> | oklch-to-hex <L> <C> <H> | audit '<json>'"
            );
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contrast_black_white_is_21() {
        let r = check_contrast("#000000", "#ffffff").unwrap();
        assert_eq!(r.ratio, 21.0);
        assert!(r.aa_normal && r.aaa_normal);
    }

    #[test]
    fn contrast_matches_js_reference_gray() {
        // node color-check.mjs contrast #767676 #ffffff -> 4.54 (WCAG AA boundary gray)
        let r = check_contrast("#767676", "#ffffff").unwrap();
        assert!((r.ratio - 4.54).abs() < 0.01, "ratio={}", r.ratio);
        assert!(r.aa_normal);
    }

    #[test]
    fn hex_shorthand_expands() {
        let r = check_contrast("#000", "#fff").unwrap();
        assert_eq!(r.ratio, 21.0);
    }

    #[test]
    fn bad_hex_errors() {
        assert!(hex_to_rgb("zzzzzz").is_err());
        assert!(check_contrast("nothex", "#fff").is_err());
    }

    #[test]
    fn oklch_roundtrip_stays_in_gamut_and_close() {
        let hex = "#3366ff";
        let ok = srgb_to_oklch(hex).unwrap();
        let back = oklch_to_rgb(ok.l, ok.c, ok.h);
        assert!(back.in_gamut);
        // Round-trip should reproduce the same hex within a couple of units.
        let (r1, g1, b1) = hex_to_rgb(hex).unwrap();
        let (r2, g2, b2) = hex_to_rgb(&back.hex).unwrap();
        assert!((r1 - r2).abs() < 2.0);
        assert!((g1 - g2).abs() < 2.0);
        assert!((b1 - b2).abs() < 2.0);
    }

    #[test]
    fn oklch_black_is_zero_lightness() {
        let ok = srgb_to_oklch("#000000").unwrap();
        assert!(ok.l.abs() < 1e-9);
        assert!(ok.c.abs() < 1e-9);
    }

    #[test]
    fn audit_reports_all_pass_and_failure() {
        let pairs = vec![
            AuditPair { name: Some("body".into()), fg: "#000000".into(), bg: "#ffffff".into(), min: None },
            AuditPair { name: Some("low-contrast".into()), fg: "#aaaaaa".into(), bg: "#ffffff".into(), min: None },
        ];
        let report = audit_pairs(&pairs).unwrap();
        assert!(!report.all_pass);
        assert!(report.rows[0].pass);
        assert!(!report.rows[1].pass);
    }
}
