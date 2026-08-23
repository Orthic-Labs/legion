# Legion native parity fixtures

LEG-001 freezes language-neutral inputs and semantic expectations against Legion baseline `90678a130dc26937d544304b79a22f24d74383ac`.

Each case has a unique, lexical `case_id`, source proof, one or more future packet owners, language-neutral `input`, semantic `expected` fields, explicit `normalization.ignore_paths`, deterministic `sort_paths`, and intentional `deltas`. Inputs never contain executable legacy code. Mutating cases are simulations: they assert policy/receipt shape and zero real effects.

Comparators must ignore only paths listed by each case; timestamps, temporary paths, generated digests, and request IDs are excluded by name where nondeterministic. Stable IDs, command names, flags, exit codes, JSON/SARIF/report fields, policy decisions, finding IDs, provider completeness, host mutations, and receipt fields remain normative. Arrays are compared in declared order unless a case names a `sort_paths` entry.

`manifest.v1.json` binds every fixture file with SHA-256. Integrators execute only side-effect-free cases in an isolated legacy baseline, seal observed outputs, and record baseline defects separately from native regressions. No fixture permits shadow execution of a real effect.
