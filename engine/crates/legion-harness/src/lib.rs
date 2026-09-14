#![forbid(unsafe_code)]

mod assets;
mod descriptor;
mod engine;
mod error;
mod host_projection;
mod markers;
mod registry;
mod skills;
mod surfaces;

pub use error::HarnessError;
pub use registry::{
    capabilities_response, detect_value, install_response, list_value, matrix_value,
    uninstall_response, verify_response, HarnessRegistry,
};
