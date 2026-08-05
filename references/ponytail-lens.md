# Ponytail lens — full over-engineering hunt (the `minimize` lens)

This is the canonical, verbatim prompt for the audit `minimize` lens. It is the FULL ponytail
hunt — not the narrow "unused dep replaceable in ≤10 lines" check the lens used to be. The audit
absorbs ponytail so there is never a separate ponytail round: a finished `/audit` has already done
this pass.

Hunt **only** over-engineering — NOT correctness/security/perf (those are the `correctness`,
`security`, `performance` lenses). Read the actual code; never guess from names.

## The five tags

- **`delete`** — dead code, unused flexibility, a speculative feature nobody uses, a not-wired
  experiment, docs/config for a removed path. *Replacement: nothing.* (E.g. a "not wired into the
  shipped engine" top-k decode; env-var docs for a deleted streaming mode; install/activate scripts
  for a capability the repo's own guardrail says never to enable.)
- **`stdlib`** — a hand-rolled thing the standard library already ships. *Name the std fn.*
- **`native`** — a dependency or block of code doing what the platform/framework already does.
  *Name the feature.* (Two HTTP clients; a hand-rolled debounce when the framework ships one.)
- **`yagni`** — an abstraction with ONE implementation: a trait/interface with one impl, config
  nobody sets, a layer with one caller, a factory with one product, a wrapper that only delegates,
  a file that exports one thing, a flag never toggled. *Replacement: inline the one real path.*
- **`shrink`** — same logic in materially fewer lines. *Show the shorter form.* **Mechanical file
  splitting counts here** — see below.

## `shrink` includes mechanical splitting — include-split is NOT decomposition

A logical module chopped into `partNN` files and stitched with `include!` / `mod`+`pub use` /
barrel re-exports does **not** reduce complexity — it only games the per-file LOC metric. It IS
over-engineering (indirection with no payoff). Flag it `shrink`:

- N `*_parts/partNN.rs` (or `.ts`/etc.) files stitched by `include!` wrappers → "real `mod`
  boundaries with named responsibilities, or keep it one contiguous file." The split into 9/24/81
  fragments hides one module across many files; it is file-size optics, not decomposition.
- A "worker"/"engine" loop split into 5 `include!`'d chunks of one conceptual responsibility →
  extract the ACTUAL responsibilities (named modules with a real interface) or keep it contiguous.

The deterministic `decomposition` scanner now reconstructs these (`facts.decomposition.mechanical_splits`)
and reports the summed logical LOC, so this finding is backed by evidence, not just the lens.

## Package/script sprawl is in scope

`yagni`/`delete` also cover non-source over-engineering the other lenses miss:

- Dozens of bake-off / research / one-off scripts living in a SHIPPED app's `package.json` →
  "one runner command, or move the research harness to a shared `tools/` package." (E.g. 45 bakeoff
  scripts in a desktop app's scripts block.)
- Scripts that expose a capability the repo explicitly guards against re-enabling → `delete`.

## False-positive discipline (STRICT — this is what makes the lens trustworthy)

Be strict about false positives, or the lens becomes noise:

- A trait/interface with one impl that exists for a **testing/DI seam**, or that the codebase
  **clearly plans to extend** (documented, or an obvious extension point), is **NOT** `yagni`.
  Only flag genuinely *dead* flexibility.
- A barrel/`mod` file that organizes genuinely distinct modules with real boundaries is **NOT** a
  mechanical split. The tell is `partNN`-style naming or a `*_parts/` dir where the fragments have
  no independent meaning.
- Read the code before flagging. Don't infer "wrapper that only delegates" from a name — open it
  and confirm it only delegates.

## Output

One line per finding, ranked **biggest-cut-first**:

```
<tag> <what to cut>. <replacement>. [path:line]
```

If an area is genuinely lean, say so — do not invent cuts. End with a net estimate:
`net: -<N> lines, -<M> deps, -<K> files possible.`

Every finding still needs a real `file:line`. The lens reads RAW bodies (never skeletonized) —
`yagni`/`delete` cannot be judged from a tree-sitter skeleton.
