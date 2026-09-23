//! Port of `skills/seo/extensions/banana/scripts/batch.py`.
//!
//! Parses a CSV of image-generation requests into a structured plan,
//! matching Python's `csv.DictReader`-based row handling and per-row
//! validation/defaulting. The CSV text is parsed with a small, dependency-
//! free parser supporting the RFC 4180 subset `csv.DictReader` exercises
//! here: comma-separated fields, optional double-quoting, and `""` as an
//! escaped quote inside a quoted field. Filesystem access (reading the CSV
//! path) stays with the caller; this module is pure text-in/rows-out.

use serde::{Deserialize, Serialize};

/// Inline pricing for estimates, matching Python's `PRICING` in `batch.py`
/// (intentionally duplicated there rather than imported — same here).
pub fn pricing_table() -> [(&'static str, [(&'static str, f64); 4]); 2] {
    [
        (
            "gemini-3.1-flash-image-preview",
            [("512", 0.020), ("1K", 0.039), ("2K", 0.078), ("4K", 0.156)],
        ),
        (
            "gemini-2.5-flash-image",
            [("512", 0.020), ("1K", 0.039), ("", 0.0), ("", 0.0)],
        ),
    ]
}

pub const DEFAULT_MODEL: &str = "gemini-3.1-flash-image-preview";
pub const DEFAULT_RESOLUTION: &str = "1K";
pub const DEFAULT_RATIO: &str = "1:1";

/// Estimate cost for a single image, matching `estimate_cost`: falls back
/// to `DEFAULT_MODEL`'s table when `model` is unrecognized, then to that
/// table's `"1K"` price (or `0.039`) when `resolution` is unrecognized.
pub fn estimate_cost(model: &str, resolution: &str) -> f64 {
    let table = pricing_table();
    let model_table = table
        .iter()
        .find(|(name, _)| *name == model)
        .map(|(_, prices)| *prices)
        .unwrap_or_else(|| {
            table
                .iter()
                .find(|(name, _)| *name == DEFAULT_MODEL)
                .unwrap()
                .1
        });
    model_table
        .iter()
        .find(|(res, _)| *res == resolution)
        .map(|(_, price)| *price)
        .unwrap_or_else(|| {
            model_table
                .iter()
                .find(|(res, _)| *res == "1K")
                .map(|(_, price)| *price)
                .unwrap_or(0.039)
        })
}

/// One validated/defaulted CSV row, matching the Python `rows` dict shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BatchRow {
    pub row: usize,
    pub prompt: String,
    pub ratio: String,
    pub resolution: String,
    pub model: String,
    pub preset: Option<String>,
}

/// The structured plan Python prints as JSON at the end of `main()`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BatchPlan {
    pub rows: Vec<BatchRow>,
    pub total_count: usize,
    pub estimated_cost: f64,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchCsvError {
    /// Mirrors `"CSV must have a 'prompt' column header"`.
    MissingPromptColumn,
}

impl std::fmt::Display for BatchCsvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPromptColumn => write!(f, "CSV must have a 'prompt' column header"),
        }
    }
}

impl std::error::Error for BatchCsvError {}

/// Parse CSV text into rows of fields, honoring RFC 4180-style quoting:
/// a field starting with `"` may contain commas/newlines and escapes an
/// embedded quote as `""`. This covers everything `csv.DictReader` needs
/// for the fixtures/examples this script documents.
fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut field = String::new();
    let mut row = Vec::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();
    let mut any_content_on_row = false;

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
            continue;
        }

        match c {
            '"' if field.is_empty() => {
                in_quotes = true;
                any_content_on_row = true;
            }
            ',' => {
                row.push(std::mem::take(&mut field));
                any_content_on_row = true;
            }
            '\r' => {
                // Swallow bare CR; handled together with following \n below.
            }
            '\n' => {
                row.push(std::mem::take(&mut field));
                if any_content_on_row || row.len() > 1 || !row[0].is_empty() {
                    rows.push(std::mem::take(&mut row));
                } else {
                    row.clear();
                }
                any_content_on_row = false;
            }
            other => {
                field.push(other);
                any_content_on_row = true;
            }
        }
    }

    if any_content_on_row || !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }

    rows
}

/// Parse CSV text into a [`BatchPlan`], matching `main()`'s row-processing
/// loop: line numbers start at 2 (1 is the header), a blank/whitespace-only
/// prompt is an error for that row (not fatal to the whole batch as long as
/// at least one valid row remains), and unset optional columns fall back to
/// the module defaults.
///
/// Returns [`BatchCsvError::MissingPromptColumn`] when the header has no
/// `prompt` column (Python exits 1 immediately in that case).
pub fn parse_batch_csv(text: &str) -> Result<BatchPlan, BatchCsvError> {
    let raw_rows = parse_csv(text);
    let mut iter = raw_rows.into_iter();
    let header = iter.next().unwrap_or_default();

    let prompt_idx = header
        .iter()
        .position(|h| h == "prompt")
        .ok_or(BatchCsvError::MissingPromptColumn)?;
    let ratio_idx = header.iter().position(|h| h == "ratio");
    let resolution_idx = header.iter().position(|h| h == "resolution");
    let model_idx = header.iter().position(|h| h == "model");
    let preset_idx = header.iter().position(|h| h == "preset");

    let mut rows = Vec::new();
    let mut errors = Vec::new();

    for (offset, record) in iter.enumerate() {
        let line = offset + 2; // header is line 1, first data row is line 2
        let get = |idx: Option<usize>| -> String {
            idx.and_then(|i| record.get(i))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };

        let prompt = get(Some(prompt_idx));
        if prompt.is_empty() {
            errors.push(format!("Row {line}: missing prompt"));
            continue;
        }

        let ratio = get(ratio_idx);
        let resolution = get(resolution_idx);
        let model = get(model_idx);
        let preset = get(preset_idx);

        rows.push(BatchRow {
            row: line,
            prompt,
            ratio: if ratio.is_empty() { DEFAULT_RATIO.to_string() } else { ratio },
            resolution: if resolution.is_empty() {
                DEFAULT_RESOLUTION.to_string()
            } else {
                resolution
            },
            model: if model.is_empty() { DEFAULT_MODEL.to_string() } else { model },
            preset: if preset.is_empty() { None } else { Some(preset) },
        });
    }

    let total_cost: f64 = rows
        .iter()
        .map(|r| estimate_cost(&r.model, &r.resolution))
        .sum();

    Ok(BatchPlan {
        total_count: rows.len(),
        estimated_cost: (total_cost * 1000.0).round() / 1000.0,
        rows,
        errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_rows_with_defaults() {
        let csv = "prompt,ratio,resolution\n\"coffee shop hero image\",16:9,2K\n\"team photo placeholder\",1:1,1K\n";
        let plan = parse_batch_csv(csv).unwrap();
        assert_eq!(plan.total_count, 2);
        assert_eq!(plan.rows[0].row, 2);
        assert_eq!(plan.rows[0].prompt, "coffee shop hero image");
        assert_eq!(plan.rows[0].ratio, "16:9");
        assert_eq!(plan.rows[0].resolution, "2K");
        assert_eq!(plan.rows[0].model, DEFAULT_MODEL);
        assert_eq!(plan.rows[0].preset, None);
        assert!(plan.errors.is_empty());
    }

    #[test]
    fn missing_prompt_column_errors() {
        let csv = "foo,bar\n1,2\n";
        assert_eq!(parse_batch_csv(csv), Err(BatchCsvError::MissingPromptColumn));
    }

    #[test]
    fn blank_prompt_is_a_row_error_not_fatal() {
        let csv = "prompt,ratio\n,16:9\n\"a cat\",1:1\n";
        let plan = parse_batch_csv(csv).unwrap();
        assert_eq!(plan.errors, vec!["Row 2: missing prompt".to_string()]);
        assert_eq!(plan.total_count, 1);
        assert_eq!(plan.rows[0].row, 3);
    }

    #[test]
    fn missing_optional_columns_use_defaults() {
        let csv = "prompt\n\"just a prompt\"\n";
        let plan = parse_batch_csv(csv).unwrap();
        let row = &plan.rows[0];
        assert_eq!(row.ratio, DEFAULT_RATIO);
        assert_eq!(row.resolution, DEFAULT_RESOLUTION);
        assert_eq!(row.model, DEFAULT_MODEL);
        assert_eq!(row.preset, None);
    }

    #[test]
    fn estimate_cost_matches_pricing_table() {
        assert_eq!(estimate_cost("gemini-3.1-flash-image-preview", "2K"), 0.078);
        assert_eq!(estimate_cost("unknown-model", "1K"), 0.039);
        assert_eq!(estimate_cost("gemini-3.1-flash-image-preview", "unknown-res"), 0.039);
    }

    #[test]
    fn total_estimated_cost_is_summed_and_rounded() {
        let csv = "prompt,resolution\n\"a\",2K\n\"b\",2K\n";
        let plan = parse_batch_csv(csv).unwrap();
        assert_eq!(plan.estimated_cost, 0.156);
    }

    #[test]
    fn quoted_field_with_embedded_comma_and_escaped_quote() {
        let csv = "prompt,ratio\n\"a \"\"quoted\"\" cat, sitting\",16:9\n";
        let plan = parse_batch_csv(csv).unwrap();
        assert_eq!(plan.rows[0].prompt, "a \"quoted\" cat, sitting");
        assert_eq!(plan.rows[0].ratio, "16:9");
    }
}
