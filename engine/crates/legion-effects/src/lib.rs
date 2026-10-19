pub mod artifact;
pub mod credential;
pub mod environment;
pub mod error;
pub mod executable;
pub mod executor;
pub mod gradle_sandbox;
pub mod platform;
pub mod receipt;
pub mod request;
pub mod sandbox;

pub use artifact::{ArtifactRecord, ArtifactSink, ArtifactWriter};
pub use error::EffectError;
pub use executable::{DigestState, ExecutableIdentity, SignatureState, VersionProbeEvidence};
pub use executor::{EffectExecutor, PolicyAuthorizer, PolicyDecision, StaticPolicy};
pub use platform::{PlatformProcess, ProcessLaunch, ProcessOutput};
pub use receipt::{
    ExecutionReceipt, ExecutionState, ParserState, ProcessTreeEvidence, SandboxEvidence,
    TimingEvidence,
};
pub use request::{ExternalToolRequest, RedactedRequest, SandboxReceipt, Sensitivity, ToolOrigin};
pub use sandbox::{
    authenticate as authenticate_sandbox, authenticate_tflint_scoped,
    validate_tflint_ipc_namespace, OwnedIpcNamespace, SandboxAuthentication, SandboxGap,
    SandboxMode,
};

pub use gradle_sandbox::GradleBindOnlySandbox;
