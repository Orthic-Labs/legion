# Optional `asc workflow` automation

`asc workflow` is repo-local automation provided by an external CLI. Follow [external `asc` setup](../tool-setup.md#asc), keep this process-scoped environment active before any command, & verify `asc version` plus `asc workflow --help`, `asc workflow validate --help`, `asc workflow list --help` & `asc workflow run --help` before relying on any flag or schema:

```bash
export ASC_TELEMETRY_DISABLED=1
export DO_NOT_TRACK=1
asc version
```

It is optional; manual release procedures remain valid. This reference does not imply Legion has a native adapter with matching flags, nor does it require agent orchestration.

## File & step model

Default file is `.asc/workflow.json`; `asc workflow run --file ./path/to/workflow.json NAME` selects another file. JSONC comments are supported. Top-level hooks are `before_all`, `after_all` & `error`. Workflow definitions may include `description`, `private`, `env` & `steps`.

Steps may be string shorthand or objects with `run`, `workflow`, `name`, `if`, `with`, `outputs`, `retry` & `timeout`. Workflow-call steps use `workflow`; only run steps may declare outputs. A step declaring `outputs` needs a reference-safe `name`; output-producing names must be unique across workflows that can execute in one run graph. References use `${steps.step_name.OUTPUT_NAME}`; command stdout must be JSON, so use `--output json` for `asc` commands feeding outputs.

## Validate, preview & run

Inspect the installed help, then validate structure & references:

```bash
asc workflow validate
asc workflow list
asc workflow run --dry-run release BUILD_ID:123456789
asc workflow run release BUILD_ID:123456789
```

Use `--output json` in run steps whose stdout feeds outputs. Keep machine-readable JSON on stdout & progress/diagnostics on stderr. Treat a JSON result with invalid, partial or failed status as failure even when process exit is zero.

## Parameters, environment & conditions

`asc workflow run NAME KEY:VALUE ...` & `KEY=VALUE` are accepted when installed help confirms both. Repeated keys are last-write-wins. Main-workflow precedence is:

```text
definition.env < workflow.env < CLI params
```

For a sub-workflow call with `with`:

```text
sub-workflow env < caller env and params < step with
```

An `if` value names a merged env/parameter variable; lookup checks merged workflow env/params before process environment. Truthy values are `1`, `true`, `yes`, `y` & `on`, case-insensitive. Keep IDs, credentials & other sensitive data out of persisted outputs.

## Retry, timeout & resume

Retry only a command proven safe to repeat; runner does not classify mutation safety. For run steps, `retry.max_attempts` counts first attempt & must be 2–100; retry delay must be positive & no longer than 24 hours. A per-attempt `timeout` must be positive & no longer than 24 hours. Workflow calls & lifecycle hooks do not accept these run-step policies.

Timeout without retry is terminal because remote command may have completed. Resume requires a successful checkpoint or a retry-enabled failed step; output-extraction failures are not resumable. Resume with run ID only—do not pass extra `KEY:VALUE` parameters—so saved workflow file, params & persisted outputs remain authoritative:

```bash
asc workflow run release --resume "release-20260312T120000Z-deadbeef"
```

## Release use

Keep release workflow steps explicit: validate target, stage metadata/build, conditionally submit only when requested. Use dry-run before mutation, stable step names, exact IDs & final readback. A workflow file does not replace readiness repair, review-draft inspection, confirmation or terminal submission evidence.
