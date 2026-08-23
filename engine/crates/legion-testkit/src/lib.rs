#![forbid(unsafe_code)]

use legion_contracts::{canonical_json_bytes, InvocationReceipt};
use serde_json::Value;

pub mod clock;
pub mod fixtures;
pub mod fs;
pub mod network;
pub mod permutation;
pub mod process;

pub use clock::FakeClock;
pub use fixtures::{FixtureError, FixtureManifest, FixtureSet};
pub use fs::{normalize_path, FakeFilesystem, FsError, LinkKind};
pub use network::{FakeNetwork, NetworkError, NetworkRequest, NetworkResponse};
pub use permutation::{completion_orders, deterministic_permutations, seeded_permutation};
pub use process::{FakeProcess, ProcessError, ProcessEvent, ProcessRequest};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssertionError(pub String);

impl std::fmt::Display for AssertionError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str(&self.0)
    }
}

impl std::error::Error for AssertionError {}

pub fn assert_canonical_bytes(left: &Value, right: &Value) -> Result<(), AssertionError> {
    let left = canonical_json_bytes(left).map_err(|error| AssertionError(error.to_string()))?;
    let right = canonical_json_bytes(right).map_err(|error| AssertionError(error.to_string()))?;
    if left == right {
        Ok(())
    } else {
        Err(AssertionError("canonical JSON bytes differ".into()))
    }
}

pub fn assert_receipt(receipt: &InvocationReceipt) -> Result<(), AssertionError> {
    receipt
        .validate()
        .map_err(|error| AssertionError(error.to_string()))
}

pub fn assert_no_omissions<T>(omissions: &[T]) -> Result<(), AssertionError> {
    if omissions.is_empty() {
        Ok(())
    } else {
        Err(AssertionError(format!(
            "{} omission(s) present",
            omissions.len()
        )))
    }
}

pub fn assert_sorted<T: Ord>(values: &[T]) -> Result<(), AssertionError> {
    if values.windows(2).all(|pair| pair[0] <= pair[1]) {
        Ok(())
    } else {
        Err(AssertionError("collection is not stably sorted".into()))
    }
}
