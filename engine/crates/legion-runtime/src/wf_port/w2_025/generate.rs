//! Port of `skills/seo/extensions/banana/scripts/generate.py`.
//!
//! The Python script is a stdlib-only Gemini REST fallback: it validates
//! CLI input, builds a `generateContent` request body, performs the HTTP
//! call with `urllib.request`, and extracts/saves the returned image.
//! This port covers every deterministic, side-effect-free piece — input
//! validation, request-body construction, response-part extraction, output
//! filename/path construction, and result shaping — as pure functions.
//!
//! The actual HTTP call is intentionally NOT implemented here: this crate's
//! `Cargo.toml` carries no HTTP client dependency, and this module is not
//! permitted to edit it. Wiring `network::generate_request` (or similar)
//! against `legion-runtime`'s eventual HTTP transport is left for whoever
//! adds that dependency; see the integrator report for the exact patch
//! needed (`reqwest`, matching the version already in `Cargo.lock`).

use serde::Serialize;
use std::collections::BTreeSet;

pub const DEFAULT_MODEL: &str = "gemini-3.1-flash-image-preview";
pub const DEFAULT_RESOLUTION: &str = "1K";
pub const DEFAULT_RATIO: &str = "1:1";
pub const API_BASE: &str = "https://generativelanguage.googleapis.com/v1beta/models";

pub fn valid_ratios() -> BTreeSet<&'static str> {
    [
        "1:1", "16:9", "9:16", "4:3", "3:4", "2:3", "3:2", "4:5", "5:4", "1:4", "4:1", "1:8",
        "8:1", "21:9",
    ]
    .into_iter()
    .collect()
}

pub fn valid_resolutions() -> BTreeSet<&'static str> {
    ["512", "1K", "2K", "4K"].into_iter().collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerateError {
    InvalidAspectRatio(String),
    InvalidResolution(String),
    MissingApiKey,
}

impl std::fmt::Display for GenerateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAspectRatio(v) => {
                let mut ratios: Vec<_> = valid_ratios().into_iter().collect();
                ratios.sort_unstable();
                write!(f, "Invalid aspect ratio '{v}'. Valid: {ratios:?}")
            }
            Self::InvalidResolution(v) => {
                let mut resolutions: Vec<_> = valid_resolutions().into_iter().collect();
                resolutions.sort_unstable();
                write!(f, "Invalid resolution '{v}'. Valid: {resolutions:?}")
            }
            Self::MissingApiKey => write!(
                f,
                "No API key. Set GOOGLE_AI_API_KEY env or pass --api-key"
            ),
        }
    }
}

impl std::error::Error for GenerateError {}

/// Validate CLI-style generation inputs, matching `main()`'s validation
/// block (aspect ratio, then resolution, then API key presence). Returns
/// the first failure in that order, exactly like Python's sequential exits.
pub fn validate_inputs(
    aspect_ratio: &str,
    resolution: &str,
    api_key: Option<&str>,
) -> Result<(), GenerateError> {
    if !valid_ratios().contains(aspect_ratio) {
        return Err(GenerateError::InvalidAspectRatio(aspect_ratio.to_string()));
    }
    if !valid_resolutions().contains(resolution) {
        return Err(GenerateError::InvalidResolution(resolution.to_string()));
    }
    if api_key.map(str::is_empty).unwrap_or(true) {
        return Err(GenerateError::MissingApiKey);
    }
    Ok(())
}

/// Resolve the API key the way Python's `args.api_key or
/// os.environ.get("GOOGLE_AI_API_KEY") or os.environ.get("GOOGLE_API_KEY")`
/// does: first non-empty of (explicit flag, `GOOGLE_AI_API_KEY`,
/// `GOOGLE_API_KEY`).
pub fn resolve_api_key(
    flag: Option<&str>,
    google_ai_api_key: Option<&str>,
    google_api_key: Option<&str>,
) -> Option<String> {
    for candidate in [flag, google_ai_api_key, google_api_key] {
        if let Some(v) = candidate {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ImageConfig {
    #[serde(rename = "aspectRatio")]
    pub aspect_ratio: String,
    #[serde(rename = "imageSize")]
    pub image_size: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ThinkingConfig {
    #[serde(rename = "thinkingLevel")]
    pub thinking_level: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GenerationConfig {
    #[serde(rename = "responseModalities")]
    pub response_modalities: Vec<String>,
    #[serde(rename = "imageConfig")]
    pub image_config: ImageConfig,
    #[serde(rename = "thinkingConfig", skip_serializing_if = "Option::is_none")]
    pub thinking_config: Option<ThinkingConfig>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Part {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Content {
    pub parts: Vec<Part>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GenerateRequestBody {
    pub contents: Vec<Content>,
    #[serde(rename = "generationConfig")]
    pub generation_config: GenerationConfig,
}

/// Build the `generateContent` request body, matching `generate_image`'s
/// `body` dict exactly (including that `responseModalities` omits `"TEXT"`
/// when `image_only` is set, and `thinkingConfig` is present only when a
/// thinking level was given).
pub fn build_request_body(
    prompt: &str,
    aspect_ratio: &str,
    resolution: &str,
    thinking_level: Option<&str>,
    image_only: bool,
) -> GenerateRequestBody {
    let response_modalities = if image_only {
        vec!["IMAGE".to_string()]
    } else {
        vec!["TEXT".to_string(), "IMAGE".to_string()]
    };

    GenerateRequestBody {
        contents: vec![Content {
            parts: vec![Part {
                text: prompt.to_string(),
            }],
        }],
        generation_config: GenerationConfig {
            response_modalities,
            image_config: ImageConfig {
                aspect_ratio: aspect_ratio.to_string(),
                image_size: resolution.to_string(),
            },
            thinking_config: thinking_level.map(|level| ThinkingConfig {
                thinking_level: level.to_string(),
            }),
        },
    }
}

/// Build the request URL, matching
/// `f"{API_BASE}/{model}:generateContent?key={api_key}"`.
pub fn request_url(model: &str, api_key: &str) -> String {
    format!("{API_BASE}/{model}:generateContent?key={api_key}")
}

/// A single `parts[]` entry from the Gemini response, as far as this
/// script inspects it.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ResponsePart {
    pub inline_data_b64: Option<String>,
    pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExtractError {
    /// Mirrors `"No candidates returned. Reason: {finish_reason}"`.
    NoCandidates { block_reason: String },
    /// Mirrors `"No image in response. finishReason: {finish_reason}"`.
    NoImage { finish_reason: String },
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCandidates { block_reason } => {
                write!(f, "No candidates returned. Reason: {block_reason}")
            }
            Self::NoImage { finish_reason } => {
                write!(f, "No image in response. finishReason: {finish_reason}")
            }
        }
    }
}

impl std::error::Error for ExtractError {}

/// Extracted result of a successful generation, before it is written to
/// disk: matches the fields Python assembles into its returned dict, minus
/// `path` (filesystem-dependent — see [`output_filename`]).
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractedImage {
    pub image_data_b64: String,
    pub text: String,
}

/// Extract the generated image (base64) and any text from a candidate's
/// parts, matching the `for part in parts: ...` loop plus the two
/// `if not candidates` / `if not image_data` failure branches.
///
/// `candidates` is `(finish_reason, parts)` per candidate, already decoded
/// from JSON by the caller (this module owns no JSON parsing of the wire
/// response, only the shape-walking logic).
pub fn extract_image(
    candidates: &[(Option<String>, Vec<ResponsePart>)],
    prompt_feedback_block_reason: Option<&str>,
) -> Result<ExtractedImage, ExtractError> {
    let Some((finish_reason, parts)) = candidates.first() else {
        return Err(ExtractError::NoCandidates {
            block_reason: prompt_feedback_block_reason.unwrap_or("UNKNOWN").to_string(),
        });
    };

    let mut image_data = None;
    let mut text_response = String::new();
    for part in parts {
        if let Some(data) = &part.inline_data_b64 {
            image_data = Some(data.clone());
        } else if let Some(text) = &part.text {
            text_response = text.clone();
        }
    }

    match image_data {
        Some(image_data_b64) => Ok(ExtractedImage {
            image_data_b64,
            text: text_response,
        }),
        None => Err(ExtractError::NoImage {
            finish_reason: finish_reason.clone().unwrap_or_else(|| "UNKNOWN".to_string()),
        }),
    }
}

/// Build the output filename, matching
/// `f"banana_{timestamp}.png"` with `timestamp` from
/// `datetime.now().strftime("%Y%m%d_%H%M%S_%f")`. `timestamp` is injected
/// so this stays pure and deterministic in tests.
pub fn output_filename(timestamp: &str) -> String {
    format!("banana_{timestamp}.png")
}

/// The final JSON-able result Python prints, matching the dict
/// `generate_image` returns (minus `path`, which is filesystem-dependent
/// and constructed by the caller as `OUTPUT_DIR / output_filename(...)`).
#[derive(Debug, Clone, PartialEq)]
pub struct GenerateResult {
    pub model: String,
    pub aspect_ratio: String,
    pub resolution: String,
    pub text: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_inputs_rejects_bad_ratio_first() {
        assert_eq!(
            validate_inputs("bogus", "1K", Some("key")),
            Err(GenerateError::InvalidAspectRatio("bogus".into()))
        );
    }

    #[test]
    fn validate_inputs_rejects_bad_resolution() {
        assert_eq!(
            validate_inputs("1:1", "8K", Some("key")),
            Err(GenerateError::InvalidResolution("8K".into()))
        );
    }

    #[test]
    fn validate_inputs_requires_api_key() {
        assert_eq!(
            validate_inputs("1:1", "1K", None),
            Err(GenerateError::MissingApiKey)
        );
        assert_eq!(
            validate_inputs("1:1", "1K", Some("")),
            Err(GenerateError::MissingApiKey)
        );
    }

    #[test]
    fn validate_inputs_accepts_defaults() {
        assert_eq!(
            validate_inputs(DEFAULT_RATIO, DEFAULT_RESOLUTION, Some("key")),
            Ok(())
        );
    }

    #[test]
    fn resolve_api_key_prefers_flag_then_env_vars() {
        assert_eq!(
            resolve_api_key(Some("flag"), Some("ai"), Some("plain")),
            Some("flag".to_string())
        );
        assert_eq!(
            resolve_api_key(None, Some("ai"), Some("plain")),
            Some("ai".to_string())
        );
        assert_eq!(
            resolve_api_key(None, None, Some("plain")),
            Some("plain".to_string())
        );
        assert_eq!(resolve_api_key(None, None, None), None);
        // Empty flag is falsy in Python's `or` chain.
        assert_eq!(
            resolve_api_key(Some(""), Some("ai"), None),
            Some("ai".to_string())
        );
    }

    #[test]
    fn build_request_body_text_and_image_modalities() {
        let body = build_request_body("a cat in space", "16:9", "1K", None, false);
        assert_eq!(
            body.generation_config.response_modalities,
            vec!["TEXT".to_string(), "IMAGE".to_string()]
        );
        assert!(body.generation_config.thinking_config.is_none());
        assert_eq!(body.contents[0].parts[0].text, "a cat in space");
    }

    #[test]
    fn build_request_body_image_only_omits_text_modality() {
        let body = build_request_body("p", "1:1", "2K", Some("high"), true);
        assert_eq!(body.generation_config.response_modalities, vec!["IMAGE".to_string()]);
        assert_eq!(
            body.generation_config.thinking_config,
            Some(ThinkingConfig {
                thinking_level: "high".to_string()
            })
        );
    }

    #[test]
    fn request_url_matches_python_format() {
        assert_eq!(
            request_url("gemini-3.1-flash-image-preview", "KEY123"),
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-image-preview:generateContent?key=KEY123"
        );
    }

    #[test]
    fn extract_image_errors_on_no_candidates() {
        let err = extract_image(&[], Some("SAFETY")).unwrap_err();
        assert_eq!(
            err,
            ExtractError::NoCandidates {
                block_reason: "SAFETY".to_string()
            }
        );
    }

    #[test]
    fn extract_image_errors_on_no_candidates_defaults_unknown() {
        let err = extract_image(&[], None).unwrap_err();
        assert_eq!(
            err,
            ExtractError::NoCandidates {
                block_reason: "UNKNOWN".to_string()
            }
        );
    }

    #[test]
    fn extract_image_errors_when_no_image_part() {
        let candidates = vec![(
            Some("SAFETY".to_string()),
            vec![ResponsePart {
                inline_data_b64: None,
                text: Some("blocked".to_string()),
            }],
        )];
        let err = extract_image(&candidates, None).unwrap_err();
        assert_eq!(
            err,
            ExtractError::NoImage {
                finish_reason: "SAFETY".to_string()
            }
        );
    }

    #[test]
    fn extract_image_returns_image_and_text() {
        let candidates = vec![(
            Some("STOP".to_string()),
            vec![
                ResponsePart {
                    inline_data_b64: None,
                    text: Some("here you go".to_string()),
                },
                ResponsePart {
                    inline_data_b64: Some("QUJD".to_string()),
                    text: None,
                },
            ],
        )];
        let extracted = extract_image(&candidates, None).unwrap();
        assert_eq!(extracted.image_data_b64, "QUJD");
        assert_eq!(extracted.text, "here you go");
    }

    #[test]
    fn output_filename_matches_python_pattern() {
        assert_eq!(
            output_filename("20260923_120000_000000"),
            "banana_20260923_120000_000000.png"
        );
    }
}
