# Corrected M4 Wave B — Audit

Continue from immutable Wave A commit `a32c56b966f71d1b66936b3c2585ac8c2eef52ac` and complete
Audit as one coupled Luna lane. Wave A Rules, Research, Review, corrected M5, Report, M1-M3,
Node/Python development tooling, legacy runtime, and Membrane remain frozen. The ownership amendment
reopens only Audit CLI integration, its shared inventory helper/Rules projection, and exact CLI tests.

Implement the frozen Audit semantics, not a new audit system. Freeze repository binding, inventory
generation/digest, selected provider set, full ProviderSpec semantics, dependency plan, scope, and
coverage denominator before execution. Preserve every ProviderSpec field that affects identity,
selection, execution ownership, reasoning, benchmark qualification, clean claims, controls, or
scope. Selected providers reconcile exactly once with no duplicate, missing, or unplanned result.

Classify provider runners only through the frozen boundary: `runtime-script` is a Rust algorithm,
`legacy-check` is a typed external-project-tool, `reasoning-contract` is a host service, and
Blueprint is optional typed evidence. Audit never shells out, constructs an executor, wraps Cargo,
invokes a model, synthesizes graph truth, or treats unavailable tooling/service as empty success.
An external-project-tool result is incomplete unless its result details contain a valid terminal
projection of the frozen M5 ExecutionReceipt bound to provider/plan, policy, command identity,
timing, process-tree, parser, artifacts, terminal state, completeness, and gaps.

Blueprint absence or invalidity continues every applicable non-Blueprint provider, preserves the
selected-provider denominator and results, and emits one typed degradation with exact fields:
`provider`, `operation`, `reasonCode`, `structuralCoverageLimits`, `recommendation`, and
`unaffectedProviders`. Only explicitly Blueprint-dependent operations degrade at provider level.
Filesystem fallback may enumerate source files only; it cannot fabricate symbols, dependencies, or
local graph truth. No Membrane or Blueprint storage change/read is authorized.

Coverage must bind the frozen inventory/selector denominator, not an arbitrary fixture string.
Selector evaluation is the exact frozen legacy language: `always`, `any`, `all`, `anyPath`,
`anyExtension`, `anyDependency`, `anyPackageScript`, `sourceFilesAtLeast`,
`securityCandidatesSelected`, and `confirmedSecurityFinding`. Nested selection, normalized path
matching, dependency/package-script evidence, source-file counts, and already-selected provider
state retain their prior meanings. Direct Application validation must accept only the same
plan-derived selector denominator; it cannot force every provider back to the whole inventory.
Complete results require exact expected/examined reconciliation, no coverage gap, valid finding
evidence plus source locations, and qualification proof when clean claims require it. Candidate
generators cannot emit or close findings; independent adjudication remains separate. Denial,
timeout, cancellation, unavailable host service/tool, malformed result, missing receipt, and
dependency failure each produce one truthful terminal incomplete result for every selected provider.

Keep `auditStatus`, `qualityGate`, process execution state, and independent Completion Validation as
separate verdicts. Plan-only is `auditStatus=incomplete`, `qualityGate=unproven`, process not run,
and Completion Validation not run. Audit never claims Oracle PASS. Canonical report status cannot be
clean while typed degradations, receipt gaps, missing evidence/locations, incomplete denominators,
unqualified providers, or execution gaps exist.

Own exactly the 20 packet paths. Do not add dependencies or change Cargo.lock. Inspect live
consumers and selected M4 legacy Audit/provider evidence read-only. Run rustfmt and diff checks only;
do not run Cargo, stage, commit, push, create receipts, or touch generated state. Return exact
changed paths, checks, raw failures, blockers, baseline revision, and patch digest to the sole
integration owner.
