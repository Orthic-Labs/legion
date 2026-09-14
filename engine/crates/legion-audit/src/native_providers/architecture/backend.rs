pub use super::framework::{analyze_backend, analyze_backend_framework};

pub fn analyze(input: &serde_json::Value) -> Result<super::common::Analysis, String> {
    super::framework::analyze_backend(input)
}
