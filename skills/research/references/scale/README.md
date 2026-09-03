# Scale

| Scale | External requests | Active workers | Use |
|---|---:|---:|---|
| `focused` | 12 | 0–1 | One bounded decision or issue. |
| `broad` | 30 | ≤4 | Multi-angle market, customer, or technical scan. |
| `dossier` | explicit | explicit | Opt-in long report with an operator-declared budget. |

The native `legion research` command atomically consumes the route-scoped budget before every
provider request and worker start (`BudgetAccount` in `engine/crates/legion-research/src/budget.rs`).
A breach blocks the run; models never count or widen their own budget. Dossier initialization fails
until both request and worker ceilings are supplied. (`src/lib/research-core/meter.py` was the
retired Python prototype's equivalent and is not part of the installed plugin.)
