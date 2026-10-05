# Release contract & CLI selection

`asc` examples in this reference are raw external CLI path. Read [asc tool setup](../tool-setup.md#asc).
Before any `asc` call, export telemetry opt-outs,
run known-version check, then inspect exact leaf `--help`:

```sh
export ASC_TELEMETRY_DISABLED=1 DO_NOT_TRACK=1
asc version
```

Legion-native commands may not implement same verbs/options, so never infer
native support from examples.

## Inventory before mutation

Read project files and existing CI to resolve bundle ID, app ID, team, target/scheme, platform, deployment targets, architectures, entitlements, privacy manifests, version/build, signing style, archive/export commands, artifact locations & release owner. Resolve human names to IDs with complete, deterministic lists; do not select first row from an ambiguous response.

## Choose one App Store Connect adapter

`asc` and Xopoko `ascctl` are different CLIs. Detect the installed command & version, read the exact leaf `--help`, then perform one read-only status/list call. Do not mix flags, auth profiles or output assumptions.

`asc` is a task-oriented CLI. Prefer `view` over legacy `get`, explicit long flags, `--output json` for automation, `--pretty` only with JSON, `--paginate` where help supports it, `--dry-run` before supported writes & `--confirm` for destructive or submission effects. Use `asc search`, `asc schema` & `asc capabilities` to discover current verbs, fields & API/web-session limits. `asc` output may be TTY-sensitive, so force format in scripts.

`ascctl` is OpenAPI-first. Its stdout is exactly one JSON envelope (`ok`, `command`, `data` or `error`, `meta`); stderr is progress/warnings. Use `openapi spec update` to a stable local spec, then `ops list` → `op show` → `op template` → `op run`. Template `data.argv`, `data.body` & `data.hints` are the source of invocation shape. `--select` uses JSON Pointer; escaped `/` & `~` follow RFC 6901.

## ascctl outcomes

Interpret exit codes with the JSON envelope: `0` success; `2` usage, validation, missing spec, missing confirmation, selection failure or non-JSON without `--out`; `3` auth/config/credential/signing; `4` network/transport; `5` API non-2xx; `6` internal error. A JSON object with `ok:false` is failure even when a wrapper obscures exit status. Non-JSON responses require `--out`; never parse binary/body data from stdout.

Mutating OpenAPI methods (`POST`, `PUT`, `PATCH`, `DELETE`) require `--confirm`; run `--dry-run` first. GET pagination is `--paginate` with `--limit` (`200` default, `0` unlimited); follow Apple `links.next` through the CLI, never reconstruct URLs or manually alter continuation query state. `--record` stores replayable request/response evidence without secrets; `--replay` is offline and does not prove current server state.

## Credentials & effects

For `asc`, prefer existing keychain auth; supported environment fallback is `ASC_KEY_ID`, `ASC_ISSUER_ID`, `ASC_PRIVATE_KEY_PATH`, `ASC_PRIVATE_KEY`, `ASC_PRIVATE_KEY_B64`. For `ascctl`, precedence is flags > environment > config (`ASC_ISSUER_ID`, `ASC_KEY_ID`, `ASC_PRIVATE_KEY_PATH` or `ASC_PRIVATE_KEY_PEM`, optional `ASC_PROFILE`). Keep P8 contents, tokens, signed URLs & API output private. Authenticated status proves credentials only, not permission for every endpoint.

Before upload, metadata write, profile change, submission or publication, state app/team/version/build/destination and inspect dry-run effects. Read back resulting resource and follow processing/review until requested terminal state.

## Private registered-device distribution boundary

Use existing approved private distribution contract when requested. Treat
config, devices, identity, password, plan/state & link artifact as owner-only;
keep credentials and bearer URLs private. Storage effects stay bounded to an
existing caller-owned bucket/prefix: do not create buckets, change policy,
delete old builds, install app or launch app unless request explicitly adds
that effect. Plan is read-only; apply only exact authorized plan hash; verify
publication/fetch separately from device install/launch.

Account, business, paid capability, Developer Portal/App Group, marketing,
ASO, paid pricing & signing-authority changes require explicit request; this
reference does not infer them from ordinary release work. Ambient in-scope
requests remain authorized; host-declared locked effects & explicitly
contracted work follow their required contract. Release procedures do not copy
foreign agent orchestration or require AXe/Koubou/other helper installation.
