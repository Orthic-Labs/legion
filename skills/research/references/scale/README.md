# Scale

| Scale | External requests | Active workers | Use |
|---|---:|---:|---|
| `focused` | 12 | 0–1 | One bounded decision or issue. |
| `broad` | 30 | ≤4 | Multi-angle market, customer, or technical scan. |
| `dossier` | explicit | explicit | Opt-in long report with an operator-declared budget. |

`tools/research-core/meter.py` atomically consumes the route-scoped budget before every provider
request and worker start. A breach blocks the run; models never count or widen their own budget.
Dossier initialization fails until both request and worker ceilings are supplied.
