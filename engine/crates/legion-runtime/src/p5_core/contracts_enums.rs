//! Port of `src/lib/contracts/enums.mjs` (packet P5c).
//!
//! The JS module exports frozen string-array enums plus two guard functions,
//! `assertEnum` and `assertSchemaVersion`. Rust callers get real enum types
//! (so invalid values cannot be constructed at all) plus the two guard
//! functions ported at their original, string-based call sites so free-form
//! data coming off the wire (JSON payloads, provider output) can still be
//! validated the same way the JS adapter validated it.

use std::fmt;

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $repr:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $repr),+
                }
            }

            pub fn parse(value: &str) -> Option<Self> {
                match value {
                    $($repr => Some($name::$variant),)+
                    _ => None,
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

string_enum!(ProviderStatus {
    Pass => "pass",
    Fail => "fail",
    Partial => "partial",
    Unproven => "unproven",
    Skipped => "skipped",
    Error => "error",
    Pending => "pending",
    Missing => "missing",
    Candidates => "candidates",
    Blocked => "blocked",
});

string_enum!(ProviderRole {
    Deterministic => "deterministic",
    CandidateGenerator => "candidate-generator",
    Adjudicator => "adjudicator",
    VariantAnalysis => "variant-analysis",
    Renderer => "renderer",
});

string_enum!(EvidenceClass {
    Deterministic => "deterministic",
    Measured => "measured",
    Interpretive => "interpretive",
    External => "external",
    Human => "human",
});

string_enum!(JudgmentVerdict {
    Confirmed => "confirmed",
    Rejected => "rejected",
    Unproven => "unproven",
    NeedsHuman => "needs-human",
});

string_enum!(ReasoningRequirement {
    None => "none",
    BoundedReview => "bounded-review",
    IndependentAdjudication => "independent-adjudication",
    HumanDecision => "human-decision",
});

#[derive(Debug, thiserror::Error)]
#[error("unknown {label}: {value}")]
pub struct UnknownEnumValue {
    pub label: String,
    pub value: String,
}

/// Port of `assertEnum(label, values, value)`: validates a free-form string
/// against an explicit allowed set, for call sites that receive untyped
/// data (JSON payloads) rather than a Rust enum.
pub fn assert_enum<'a>(
    label: &str,
    values: &[&'a str],
    value: &str,
) -> Result<&'a str, UnknownEnumValue> {
    match values.iter().find(|candidate| **candidate == value) {
        Some(found) => Ok(*found),
        None => Err(UnknownEnumValue {
            label: label.to_string(),
            value: value.to_string(),
        }),
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{label} unsupported schema version: {version}")]
pub struct UnsupportedSchemaVersion {
    pub label: String,
    pub version: i64,
}

/// Port of `assertSchemaVersion(label, version, supported = [1])`.
pub fn assert_schema_version(
    label: &str,
    version: i64,
    supported: &[i64],
) -> Result<i64, UnsupportedSchemaVersion> {
    if supported.contains(&version) {
        Ok(version)
    } else {
        Err(UnsupportedSchemaVersion {
            label: label.to_string(),
            version,
        })
    }
}

/// Port of the default `supported = [1]` argument.
pub fn assert_schema_version_default(
    label: &str,
    version: i64,
) -> Result<i64, UnsupportedSchemaVersion> {
    assert_schema_version(label, version, &[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_round_trips_through_str() {
        for status in ProviderStatus::ALL {
            assert_eq!(ProviderStatus::parse(status.as_str()), Some(*status));
        }
    }

    #[test]
    fn assert_enum_matches_js_allowlist_semantics() {
        let values = ["pass", "fail"];
        assert_eq!(assert_enum("status", &values, "pass").unwrap(), "pass");
        assert!(assert_enum("status", &values, "bogus").is_err());
    }

    #[test]
    fn assert_schema_version_defaults_to_one() {
        assert_eq!(assert_schema_version_default("plan", 1).unwrap(), 1);
        assert!(assert_schema_version_default("plan", 2).is_err());
        assert!(assert_schema_version("plan", 2, &[1, 2]).is_ok());
    }
}
