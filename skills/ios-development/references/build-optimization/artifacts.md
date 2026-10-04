# Benchmark artifacts

Canonical evidence directory is `.build-benchmark/`. Keep JSON plus raw logs so later lanes can reparse timing, inspect failures, find compiler warnings, and correlate phases without rerunning setup.

Recommended files: `<UTC>-<scheme>.json`, clean-1..3 logs, cached-clean-1..3 logs when cache enabled, and incremental/zero-change-1..3 logs. Use no spaces in UTC names.

Required JSON: `schema_version`, `created_at`, `build` (`entrypoint`, path, scheme, configuration, destination, command, optional DerivedData), optional `environment`, `runs.clean`, `runs.incremental`, optional `runs.cached_clean`, and `summary` for each measured type. Each run has id, build type, duration, success, command, exit code, raw log path, and `timing_summary_categories`; category entries have name, seconds, optional task count. Include notes for warm-up, cache mode, touch file, variance, failures, and parser limitations.

`duration_seconds` and summary medians are wall-clock. Timing categories are aggregate task time across cores and can exceed wall-clock; compare their sum with median before prioritizing. Never merge clean/cached-clean/incremental arrays. Cached-clean means DerivedData removed while system compilation cache remains warm; only emit it when setting is enabled and evidence proves cache condition.

Consumers must answer what was measured, how, whether each run succeeded, and whether results are stable. If category parser returns empty, preserve logs and reparse/manual inspect before making claims.
