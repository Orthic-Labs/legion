#![forbid(unsafe_code)]

pub mod auth;
pub mod context;
pub mod coverage;
pub mod error;
pub mod http_client;
pub mod inference;
pub mod provider;
pub mod registry;
pub mod result;
pub mod retry;
pub mod stream;
pub mod testkit;

pub use context::{EffectInterface, ProviderContext, SourceInterface};
pub use coverage::{normalize_coverage, CoverageAssessment};
pub use error::{ProviderError, ProviderErrorKind};
pub use inference::{HostInference, InferenceClient, InferenceRequest, InferenceResponse};
pub use provider::{Provider, ProviderDefinition, ProviderFactory, ProviderMetadata};
pub use registry::{ImplementationRegistry, ProviderRegistry, ProviderRegistryDocument};
pub use result::{normalize_result, ProviderResult, ResultStatus};
