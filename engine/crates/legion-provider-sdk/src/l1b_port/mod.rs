//! L1b literal port of `src/lib/coder-api-worker/api-worker.py`.
//!
//! Ports the pure preflight/shaping logic only: model catalog + fallback
//! chains, prompt/model validation with secret-marker preflight, argv
//! construction, redacted receipt argv, `<think>`-stripping, and per-item
//! model selection. Subprocess execution (`run_pi`/`run_batch`) and the
//! `argparse` CLI are process-transport, not logic, and are not ported.

pub mod worker;

pub use worker::{
    build_argv, clip, fallback_chain, free_models, model_catalog, models_for_item,
    prepare_prompt, redacted_argv, strip_think, validate_model, validate_prompt, ModelSelector,
    WorkerFailure, DEFAULT_TIMEOUT_SECONDS, FREE_FALLBACK_MODELS, FREE_PRIMARY_MODELS,
    MAX_FALLBACK_ATTEMPTS, MAX_OUTPUT_CHARS, MAX_POOL_SIZE, MAX_PROMPT_CHARS,
    MAX_RECEIPT_TEXT_CHARS, MAX_TIMEOUT_SECONDS, NO_THINK, PAID_MODELS, PI_COMMAND, PI_TOOLS,
    READ_ONLY_DIRECTIVE,
};
