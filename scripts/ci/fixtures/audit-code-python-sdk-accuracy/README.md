# Python SDK known-answer corpus

Original Python tools remain compile, lint, type, test & package, with packageRoots context. Package semantics are explicit new `python-package/v1`, not a claim about historical package behavior.

Production stages digest-bound frozen inputs outside audited source, then submits compile/Ruff/mypy/pytest/PEP517 build/wheel-validation requests through existing SDK admission & native deny-network/deny-project-write sandbox. Default owner admission remains denied. No project installation, network access, backend fallback, result injection or copied receipt is supplied.

Package/v1 uses `python -I -B -m build --wheel --no-isolation --outdir <private scratch> <frozen packageRoot>` with declared installed backend requirements & dependency validation enabled. Genuine stdlib validation checks built wheel METADATA, WHEEL, every RECORD member hash/size & frozen source identity. Unsupported/dynamic metadata, missing backend requirements, malformed output, changed source/runtime & unbound generated staged code remain gaps.

Pinned managed-CI enrollment binds CPython 3.14.7, Ruff 0.17.1, mypy 2.4.0, pytest 9.1.1, build 1.6.1 & Hatchling 1.32.4 with complete active wheel/runtime/native closure. Managed interpreter provenance is observed authenticated runner identity; no official interpreter archive claim. Fixture pytest config explicitly adds frozen source root to import path, without installation.

Run target & exact selector: `real_python_code_command_accuracy`. Retain separate `LEGION_PROVIDER_BENCHMARK_DIR`, exact `python-sdk-enrollment.json`, `code_python.json`, original per-case SDK/raw-stream artifacts & child execution/stdout/stderr. Log only digest/path/size locators. Dedicated replay: `scripts/ci/audit-python-code-sdk-accuracy.py --root <repository> --receipts <retained root>`.

Ruff retains project config/exclusions. Its JSON diagnostics do not enumerate checked files, so production retains `code.python:lint-scope-unproven`; successful sealed fixture controls require this exact gap rather than clearing runtime incompleteness.

Bounded known-answer eligibility requires all thirteen source-owned controls plus four same-policy request mutations. Correct negative gaps stay incomplete at runtime. These controls never grant production admission, semantic finding adjudication, arbitrary-input completeness or qualification before actual authenticated CI observation.
