# Repeatable build loop

## One command per intent

Expose project-native commands for `build`, `test`, and `run` through the existing Makefile,
Swift package commands, or an equivalent checked-in wrapper. Each command must resolve the
workspace/project, scheme, configuration, destination, and derived-data policy from project
truth rather than guessing. Keep test targets fast enough for iterative work.

At minimum, a loop should make these stages obvious:

1. inspect target/scheme/destination;
2. build or test with raw logs retained;
3. present concise diagnostics;
4. preserve the underlying exit status;
5. report artifact path, tool versions, and failure location.

## Output & status

`xcbeautify` or another formatter may reduce xcodebuild noise when already installed and
approved. Pipe stderr to stdout where formatter requires it, use `set -o pipefail`, and keep
the raw log for diagnosis. A pretty log without the xcodebuild status is not proof of success.
CI renderers are optional presentation; they must not hide warnings/errors or alter build
semantics.

## Project structure

Xcode buildable folders can reduce target-membership churn for projects that support them.
Adopt only after checking Xcode/project format, resources, generated files, package targets,
and CI compatibility. Existing projects may retain explicit file references when migration
cost or tooling support is not justified.

Treat warnings-as-errors as an opt-in quality gate. First make warning output visible, clean
or baseline existing warnings, then enable the flag for selected targets/configurations. Do
not flip it globally as a first step or hide warnings with `-quiet`.

## Version evidence

Record Xcode, Swift, SDK, formatter, generator, and package versions when they affect output.
Pin tools where project policy permits and verify lockfiles/resolved packages. A newer tool may
change diagnostics or generated output; compare before/after rather than assuming equivalence.

## Optional generators & reloaders

Run Sourcery only from an approved, pinned configuration with deterministic output and a
reviewable diff. Use Inject only for existing Debug-only hot reload integration. Neither tool
is part of a required build loop, and neither replaces compilation, tests, or runtime evidence.
