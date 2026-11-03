//! Port of `skills/seo/extensions/banana/scripts/edit.py`.
//!
//! Same shape as [`super::generate`]: a stdlib-only Gemini REST fallback
//! for image editing. This module ports the deterministic, side-effect-
//! free pieces — MIME-type detection, request-body construction, response
//! extraction, output filename construction — as pure functions. The
//! actual file read, HTTP call, and file write stay with the caller; see
//! [`super::generate`]'s module doc for why (no HTTP client dependency in
//! this crate, and this port may not edit `Cargo.toml`).

use crate::wf_port::w2_025::generate::{ExtractError, ExtractedImage, ResponsePart};
use serde::Serialize;

pub const DEFAULT_MODEL: &str = "gemini-3.1-flash-image-preview";
pub const API_BASE: &str = "https://generativelanguage.googleapis.com/v1beta/models";

/// Determine the MIME type from a file extension, matching `edit.py`'s
/// `mime_types` dict with the same `"image/png"` fallback for anything
/// unrecognized. `suffix` should include the leading dot (as
/// `Path.suffix` gives) and is matched case-insensitively, matching
/// Python's `image_path.suffix.lower()`.
pub fn mime_type_for_suffix(suffix: &str) -> &'static str {
    match suffix.to_lowercase().as_str() {
        ".png" => "image/png",
        ".jpg" | ".jpeg" => "image/jpeg",
        ".webp" => "image/webp",
        ".gif" => "image/gif",
        _ => "image/png",
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct InlineData {
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(untagged)]
pub enum EditPart {
    Text {
        text: String,
    },
    InlineData {
        #[serde(rename = "inlineData")]
        inline_data: InlineData,
    },
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EditContent {
    pub parts: Vec<EditPart>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EditGenerationConfig {
    #[serde(rename = "responseModalities")]
    pub response_modalities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EditRequestBody {
    pub contents: Vec<EditContent>,
    #[serde(rename = "generationConfig")]
    pub generation_config: EditGenerationConfig,
}

/// Build the `generateContent` request body for an edit, matching
/// `edit_image`'s `body` dict: a text part with the prompt followed by an
/// `inlineData` part with the base64-encoded source image, and
/// `responseModalities` always `["TEXT", "IMAGE"]` (edit.py has no
/// `--image-only` flag, unlike generate.py).
pub fn build_edit_request_body(prompt: &str, image_b64: &str, mime_type: &str) -> EditRequestBody {
    EditRequestBody {
        contents: vec![EditContent {
            parts: vec![
                EditPart::Text {
                    text: prompt.to_string(),
                },
                EditPart::InlineData {
                    inline_data: InlineData {
                        mime_type: mime_type.to_string(),
                        data: image_b64.to_string(),
                    },
                },
            ],
        }],
        generation_config: EditGenerationConfig {
            response_modalities: vec!["TEXT".to_string(), "IMAGE".to_string()],
        },
    }
}

/// Build the request URL, matching
/// `f"{API_BASE}/{model}:generateContent?key={api_key}"`.
pub fn request_url(model: &str, api_key: &str) -> String {
    format!("{API_BASE}/{model}:generateContent?key={api_key}")
}

/// Extract the edited image and any text response, matching
/// `edit_image`'s response-walking loop. Delegates to
/// [`super::generate::extract_image`] since the extraction logic is
/// identical between `generate.py` and `edit.py`.
pub fn extract_image(
    candidates: &[(Option<String>, Vec<ResponsePart>)],
    prompt_feedback_block_reason: Option<&str>,
) -> Result<ExtractedImage, ExtractError> {
    crate::wf_port::w2_025::generate::extract_image(candidates, prompt_feedback_block_reason)
}

/// Build the output filename, matching
/// `f"banana_edit_{timestamp}.png"` with `timestamp` from
/// `datetime.now().strftime("%Y%m%d_%H%M%S_%f")`.
pub fn output_filename(timestamp: &str) -> String {
    format!("banana_edit_{timestamp}.png")
}

/// The final JSON-able result Python prints, matching the dict
/// `edit_image` returns (minus `path`, filesystem-dependent).
#[derive(Debug, Clone, PartialEq)]
pub struct EditResult {
    pub model: String,
    pub source: String,
    pub text: String,
}
