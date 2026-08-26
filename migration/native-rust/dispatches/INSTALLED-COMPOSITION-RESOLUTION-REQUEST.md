# Installed MCP protocol contract — edit-only wave

Baseline `91d0e4b9120bf4d4693356b5a1db1da6b7a3a16f`. Freeze only reusable asynchronous MCP transport contract required by later installed composition. No application composition, CLI wiring, asset production, standalone-binary changes, Membrane changes, new dependencies, config fallback, filesystem discovery, provider behavior, legacy deletion, or qualification claims.

## Exact implementation

- In `tools.rs`, define public boxed-future alias using `std::future::Future` + `std::pin::Pin`: `pub type NativeFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, RuntimeError>> + Send + 'a>>`.
- Preserve source-compatible synchronous `NativeApi::invoke` & `NativeEngine::execute_tool` signatures for existing bootstrap/test consumers. Add `invoke_async<'a>` & `execute_tool_async<'a>` boxed-future methods with defaults that wrap those synchronous methods; existing non-installed implementers compile unchanged.
- `EngineAdapter::invoke_async` forwards `NativeEngine::execute_tool_async` directly.
- `NativeApplicationEngine` stores optional canonical `repository_id`. Preserve `new(application)` only for existing fail-closed standalone construction; add `for_repository(application, repository_id)` for installed use.
- `NativeApplicationEngine::execute_tool_async` requires bound repository identity, maps requests, then directly awaits `self.application.invoke(native_operation)` inside returned boxed future. Its synchronous `execute_tool` fails closed with stable unavailable error; it never creates a runtime or thread.
- `doctor`, `plan`, `audit`, & `verify` use bound `repository_id`; remove `root` from every public tool schema & response. Reject any supplied `root` through closed schemas.
- `ToolService::call` becomes async. Internal dispatch becomes async & awaits API invocation.
- `Server::handle` & `Server::call` become async; `run_stdio` awaits handling. Initialization, notification, release-gate, output-limit, & one-process behavior remain unchanged.
- Preserve existing two-argument `run_with_application` for fail-closed standalone source compatibility. Add `run_with_repository_application(application, repository_id, binding_gate)` using `NativeApplicationEngine::for_repository`; later installed CLI composition must use only this repository-bound entry.
- Do not edit standalone `main.rs`; later CLI composition owns canonical startup-cwd binding & standalone disposition.

## Exact MCP/RightKit wire contract

- Expose exactly eleven existing tool names; no aliases or bootstrap tools.
- Every description includes both literal clauses `Use this when` & `Do not use`.
- Every input schema is a closed object with `required` array + `additionalProperties:false`; no filesystem-path argument.
- Every tool advertises an `outputSchema` matching one common closed envelope: required `status`, `data`, `error`, `truncated`, `continuationCursor`; `status` enum `ok|error`; `data` accepts JSON; `error` is null or closed object requiring string `code`, boolean `retryable`, string `remediation`; `truncated` boolean; `continuationCursor` null. No pagination is claimed.
- Every definition has annotations `{readOnlyHint:true, destructiveHint:false, idempotentHint:true}`.
- Successful `structuredContent` uses `{status:"ok",data:<native value>,error:null,truncated:false,continuationCursor:null}` & validates against advertised schema.
- Tool failure returns MCP tool result with `isError:true` plus same structured envelope using stable public error code, retryability, remediation; text is generic public message. Never include backend details, stack, secret, or filesystem path.
- JSON-RPC errors include `error.data` with same `{code,retryable,remediation}` fields.
- Output over one-megabyte bound fails with typed `OUTPUT_LIMIT`; never truncates or invents continuation.

## Acceptance

- Change only `error.rs`, `lib.rs`, `server.rs`, `tools.rs` under `engine/bins/legion-mcp/src`.
- Update unit tests in those files for async calls, bound repository identity, closed no-root schemas, exact eleven tools, output schemas/annotations, typed tool failures, typed JSON-RPC errors, output bound, & reuse of one API.
- Worker may inspect files & run `git diff --check` only. No Cargo, build, test, clippy, rustfmt, Node, Python, package manager, signing, qualification, staging, commit, or push. Root owns integration & all execution.
