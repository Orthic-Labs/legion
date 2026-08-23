use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use tokio_util::sync::CancellationToken;

use crate::{error::EffectError, receipt::ProcessTreeEvidence};

pub type ProcessFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ProcessOutput, EffectError>> + Send + 'a>>;

#[derive(Clone, Debug)]
pub struct ProcessLaunch {
    pub executable: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub environment: BTreeMap<String, String>,
    pub stdout_limit: usize,
    pub stderr_limit: usize,
    pub timeout_ms: u64,
    pub termination_grace_ms: u64,
    pub cancellation: CancellationToken,
}

#[derive(Clone, Debug)]
pub struct ProcessOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub cancelled: bool,
    pub output_limited: bool,
    pub kill_succeeded: bool,
    pub process_tree: ProcessTreeEvidence,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
}

/// Platform modules own process APIs; executor code only depends on this trait.
pub trait PlatformProcess: Send + Sync {
    fn run<'a>(&'a self, launch: ProcessLaunch) -> ProcessFuture<'a>;
}

#[cfg(unix)]
#[path = "unix.rs"]
pub mod unix;
#[cfg(windows)]
#[path = "windows.rs"]
pub mod windows;
