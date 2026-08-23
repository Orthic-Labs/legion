use crate::error::{HandoffError, Result};

/// Token counting is injected so handoff construction is deterministic and testable.
pub trait Tokenizer: Send + Sync {
    fn count(&self, text: &str) -> usize;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CharTokenizer;

impl Tokenizer for CharTokenizer {
    fn count(&self, text: &str) -> usize {
        text.chars().count()
    }
}

/// Production tokenizer adapter.  Construction may fail when bundled encoding data is absent;
/// callers must surface that failure instead of silently selecting another authority.
pub struct TiktokenTokenizer {
    encoder: tiktoken_rs::CoreBPE,
}

impl TiktokenTokenizer {
    pub fn o200k() -> Result<Self> {
        tiktoken_rs::o200k_base()
            .map(|encoder| Self { encoder })
            .map_err(|error| {
                HandoffError::Invalid(format!("tiktoken initialization failed: {error}"))
            })
    }
}

impl Tokenizer for TiktokenTokenizer {
    fn count(&self, text: &str) -> usize {
        self.encoder.encode_with_special_tokens(text).len()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenBudget {
    pub max_tokens: usize,
}

impl TokenBudget {
    pub fn new(max_tokens: usize) -> Self {
        Self { max_tokens }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenAccounting {
    pub budget: usize,
    pub selected: usize,
    pub externalized: usize,
    pub omitted: usize,
}

impl TokenAccounting {
    pub fn remaining(&self) -> usize {
        self.budget.saturating_sub(self.selected)
    }
    pub fn add(&mut self, tokens: usize) -> bool {
        if self.selected.saturating_add(tokens) > self.budget {
            return false;
        }
        self.selected = self.selected.saturating_add(tokens);
        true
    }
    pub fn omit(&mut self, tokens: usize) {
        self.omitted = self.omitted.saturating_add(tokens);
    }
    pub fn externalize(&mut self, tokens: usize) {
        self.externalized = self.externalized.saturating_add(tokens);
    }
}
