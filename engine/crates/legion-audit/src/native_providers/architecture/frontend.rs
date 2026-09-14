pub use super::framework::{analyze_frontend, analyze_frontend_framework};

pub fn analyze(input: &serde_json::Value) -> Result<super::common::Analysis, String> {
    super::framework::analyze_frontend(input)
}
