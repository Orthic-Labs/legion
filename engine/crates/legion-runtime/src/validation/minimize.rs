use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovableSegment {
    pub category: String,
    pub start: usize,
    pub end: usize,
    pub recoverability: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedElement {
    pub id: String,
    pub start: usize,
    pub end: usize,
    pub category: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizeInput {
    pub source: String,
    pub removable: Vec<RemovableSegment>,
    #[serde(default)]
    pub protected: Vec<ProtectedElement>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalAccount {
    pub category: String,
    pub start: usize,
    pub end: usize,
    pub byte_delta: usize,
    pub token_delta: usize,
    pub recoverability: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizeResult {
    pub schema_version: u32,
    pub source: String,
    pub minimized: String,
    pub original_bytes: usize,
    pub minimized_bytes: usize,
    pub original_tokens: usize,
    pub minimized_tokens: usize,
    pub removals: Vec<RemovalAccount>,
    pub protected_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MinimizeError {
    Invalid(String),
    ProtectedOverlap(String),
    OutOfBounds(String),
}

impl std::fmt::Display for MinimizeError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(value) | Self::ProtectedOverlap(value) | Self::OutOfBounds(value) => {
                output.write_str(value)
            }
        }
    }
}
impl std::error::Error for MinimizeError {}

/// Remove only explicitly marked, non-overlapping ranges.  Ranges are applied from the end
/// of the source so byte positions remain stable, and accounts are returned in source order.
pub fn minimize(input: &MinimizeInput) -> Result<MinimizeResult, MinimizeError> {
    let bytes = input.source.as_bytes();
    let mut segments = input.removable.clone();
    segments.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| left.end.cmp(&right.end))
            .then_with(|| left.category.cmp(&right.category))
    });
    let mut last_end = 0;
    for segment in &segments {
        if segment.start >= segment.end
            || segment.end > bytes.len()
            || !input.source.is_char_boundary(segment.start)
            || !input.source.is_char_boundary(segment.end)
        {
            return Err(MinimizeError::OutOfBounds(format!(
                "invalid removable range {}..{}",
                segment.start, segment.end
            )));
        }
        if segment.start < last_end {
            return Err(MinimizeError::Invalid("removable ranges overlap".into()));
        }
        if segment.category.trim().is_empty() || segment.recoverability.trim().is_empty() {
            return Err(MinimizeError::Invalid(
                "removal category and recoverability are required".into(),
            ));
        }
        for protected in &input.protected {
            if segment.start < protected.end && protected.start < segment.end {
                return Err(MinimizeError::ProtectedOverlap(format!(
                    "removal {} overlaps protected element {}",
                    segment.category, protected.id
                )));
            }
        }
        last_end = segment.end;
    }
    for protected in &input.protected {
        if protected.start >= protected.end
            || protected.end > bytes.len()
            || !input.source.is_char_boundary(protected.start)
            || !input.source.is_char_boundary(protected.end)
            || protected.id.trim().is_empty()
        {
            return Err(MinimizeError::OutOfBounds(format!(
                "invalid protected range for {}",
                protected.id
            )));
        }
    }
    let original_tokens = token_count(&input.source);
    let mut minimized = input.source.clone();
    let mut accounts = Vec::with_capacity(segments.len());
    for segment in segments.iter().rev() {
        let removed = minimized[segment.start..segment.end].to_owned();
        let token_delta = token_count(&removed);
        minimized.replace_range(segment.start..segment.end, "");
        accounts.push(RemovalAccount {
            category: segment.category.clone(),
            start: segment.start,
            end: segment.end,
            byte_delta: removed.len(),
            token_delta,
            recoverability: segment.recoverability.clone(),
        });
    }
    accounts.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| left.category.cmp(&right.category))
    });
    let protected_ids = input
        .protected
        .iter()
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    let minimized_bytes = minimized.len();
    let minimized_tokens = token_count(&minimized);
    Ok(MinimizeResult {
        schema_version: 1,
        source: input.source.clone(),
        minimized,
        original_bytes: bytes.len(),
        minimized_bytes,
        original_tokens,
        minimized_tokens,
        removals: accounts,
        protected_ids,
    })
}

pub fn verify_protected(result: &MinimizeResult) -> bool {
    result.protected_ids.iter().all(|id| !id.trim().is_empty())
        && result.minimized_bytes <= result.original_bytes
        && result.minimized_tokens <= result.original_tokens
        && result
            .removals
            .iter()
            .all(|item| item.byte_delta > 0 && item.recoverability.trim().len() > 0)
}

fn token_count(value: &str) -> usize {
    value.split_whitespace().count()
}
