//! L1b literal port of `src/lib/coder-api-worker/api-worker.py`, reached
//! unmodified via the `skills/coder/scripts/api-worker.py` delegator.
//!
//! `worker` ports the pure preflight/shaping logic: model catalog + fallback
//! chains, prompt/model validation with secret-marker preflight, argv
//! construction, redacted receipt argv, `<think>`-stripping, and per-item
//! model selection. `execution` ports the process-transport layer on top of
//! it: `run_pi`/`_terminate`, `run_item`, `run_batch`, and the `argparse`
//! `main()`, behind a `ProcessRunner` trait so tests never spawn a real `pi`
//! CLI.

pub mod execution;
pub mod worker;

pub use execution::{
    run, run_with_io, ManifestItem, ProcessOutcome, ProcessRunner, RealProcessRunner, RunResult,
    run_batch, run_item, run_pi, utc_now_iso,
};
pub use worker::{
    build_argv, clip, fallback_chain, free_models, model_catalog, models_for_item,
    prepare_prompt, redacted_argv, strip_think, validate_model, validate_prompt, ModelSelector,
    WorkerFailure, DEFAULT_TIMEOUT_SECONDS, FREE_FALLBACK_MODELS, FREE_PRIMARY_MODELS,
    MAX_FALLBACK_ATTEMPTS, MAX_OUTPUT_CHARS, MAX_POOL_SIZE, MAX_PROMPT_CHARS,
    MAX_RECEIPT_TEXT_CHARS, MAX_TIMEOUT_SECONDS, NO_THINK, PAID_MODELS, PI_COMMAND, PI_TOOLS,
    READ_ONLY_DIRECTIVE,
};
