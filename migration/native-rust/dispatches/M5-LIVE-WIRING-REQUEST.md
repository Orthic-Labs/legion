# Corrected M5 live wiring

Continue from immutable M5 core commit `0b26116dad21c0f2bc8a4d7a99966684ca51648f` in two
isolated worktrees. Complete M5 live reachability without changing its frozen typed API.

Follow frozen architecture, M0 contracts, M2-M7 ownership amendment, corrected M5 core dispatch,
and `M5-LIVE-WIRING-OWNERSHIP-AMENDMENT.json`. Blueprint is unavailable; preserve typed
degradation, never synthesize graph truth, and never access Membrane.

Windows lane owns only Windows process-tree truth. Runtime/application lane carries optional
`Arc<dyn ExternalProjectTool>` from application composition through `ContextRequest` and
`Scheduler` into `ProviderContext`, binding every direct, Run, RunRequest, custom RunSource,
and cancellation invocation. Application and scheduler cancellation/deadline branches must signal
the active provider/effect future, await bounded cleanup rather than dropping it, retain returned
terminal evidence, and force incomplete cancellation/timeout truth. Non-cooperative cleanup must
return bounded explicit cleanup-unconfirmed evidence. Runtime and SDK never construct
`EffectExecutor`, evaluate policy, spawn processes, or create another receipt.

Legacy Node/Python runtime paths remain read-only evidence until M7. Workers may edit only exact
packet allowlists, must not edit `engine/Cargo.lock`, commit, push, or stage, and must use direct
Cargo if a declared check is run. Return patch hashes and truthful evidence to sole integration
owner. This work does not assert M6 PASS or authorize M7.
