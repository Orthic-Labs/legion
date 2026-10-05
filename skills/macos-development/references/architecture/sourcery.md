# Sourcery in an existing generator workflow

Use the project-pinned Sourcery executable or approved package plugin. Confirm its version,
supported flags, Swift compatibility, configuration owner, template owner & generated-file
owner before changing a generation step. Edit those inputs, then regenerate & review output.

## Explicit invocation & configuration

For a matched executable, make every input/output path explicit:

```sh
sourcery --sources Sources/Models --templates Codegen/Templates --output Sources/Generated
sourcery --config Codegen/.sourcery.yml
```

These are alternative command shapes. Preserve the repository's existing wrapper & working
directory; do not run both to the same output as unrelated steps. Multiple `--sources` or
`--templates` arguments can select separate roots. Never rely on default current-directory
output for a new integration.

A configuration owns source roots, template roots, output, optional `forceParse` entries &
template arguments. Resolve its relative paths according to the pinned tool version & keep
generated output out of ordinary input roots unless an explicit later generation stage
consumes it. With an approved SwiftPM command plugin, its `.sourcery.yml` belongs at the
target's source-directory root, such as `Sources/Feature/.sourcery.yml`, rather than assuming
a package-root file will be found. Run from the package root:

```sh
swift package plugin --list
swift package --allow-writing-to-package-directory sourcery-command
```

The second command authorizes package-directory writes. Use it only for the selected,
approved generator & owned output paths; plugin discovery alone does not execute generation.
For Xcode's package-plugin route, select the intended package command & targets explicitly.

## Multi-stage parsing & template arguments

Sourcery normally avoids re-parsing its generated output. A later generation stage that
deliberately consumes it needs `--force-parse` or configuration `forceParse`. Select only the
stage's generated suffix: `--force-parse modelgen` allows `Record.modelgen.swift` to be read.
The pinned tool also accepts a named inline annotation identifier, such as a project's
`AutoEquatable` marker. Match that identifier to the actual annotation before enabling it.
Order stages explicitly & keep their outputs distinct to prevent self-consuming regeneration.

CLI template arguments use comma-separated entries without spaces:

```sh
sourcery --config Codegen/.sourcery.yml --args module=Feature,emitMocks
```

Here `module` receives a value & bare `emitMocks` is true; templates read
`argument.module` & `argument.emitMocks`. Configuration can supply typed values through its
`args` mapping. Check the pinned version's precedence before mixing config & CLI arguments.

## Watch, cache & output controls

- `--watch` monitors source & template folders and keeps regenerating. Give that process a
  development-session owner & stop it before a competing one-shot generation or CI check.
- `--disableCache` bypasses parsed-data caching for a diagnostic comparison;
  `--cacheBasePath` selects cache storage, but config can override it. Record effective cache
  settings when investigating stale output; cache bypass does not change owned output paths.
- `--buildPath` controls scratch build storage for `.swifttemplate` templates. Keep it
  separate from generated source output & account for concurrent generator runs.
- `--hideVersionHeader` suppresses version text & `--headerPrefix` adds header text. If the
  project suppresses version headers, retain tool version in its lock/config evidence.
- `--prune` removes empty generated files. Use only within generator-owned outputs & review
  deletions alongside additions; it is not a general cleanup command.
- Prefer `--verbose` when diagnosing generation. `--quiet` leaves only errors & can hide
  useful context; always retain the process exit status.

Review the generated diff & compile the consuming target. Re-run the same pinned inputs when
checking reproducibility; unexplained changes indicate unstable templates, inputs or settings.

Source: Sourcery README at `f9d80ddec1d42b83b776064162ce0a93a0289334`;
see [source manifest](../../config/source-manifest.json) for rights & provenance.
