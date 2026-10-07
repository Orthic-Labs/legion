# OKF output + LLMLingua compression for doc-heavy skills

Canonical pattern for skills that emit **many agent-facing documents + one human doc**
(`blueprint`, `audit`, `architecture`, `seo`). Tool: the `okf` host capability (declared in `src/registry/capabilities.json`), which is **not part of
the installed plugin**. Without it, emit the uncompressed human deliverable only and state that no OKF
bundle was produced. The on-disk format is portable to any OKF-aware agent.

## Why

Google Cloud's **Open Knowledge Format** (OKF v0.1, 2026-06-12) is a directory of markdown
concept-files: one file = one concept, YAML frontmatter with a **required `type`** field,
concepts linked by ordinary markdown links, an `index.md` per dir. Any agent reads it directly —
no SDK, no parser. It is the portable, incrementally-updatable form of the multi-doc agent
artifacts these skills already produce.

Compression is the second half: agent-facing prose is the compressible part. LLMLingua-2
style compression drops low-information tokens — but it **breaks code and paths**.
So `okf` compression is **structure-safe**: frontmatter, code fences, markdown links, URLs,
inline code, and `path:line` refs are passed through VERBATIM; only the prose *between* protected
spans is token-dropped. The one human doc is never compressed.

## The split (unchanged contract, new format for the agent half)

| Output | Audience | Format | Compressed |
|---|---|---|---|
| Agent artifacts (understanding / findings / map concepts) | agents | **OKF bundle** (`okf/` dir) | yes (prose only) |
| The one human doc (`START-HERE.md` / report) | the operator | prose markdown | **no** |

## Usage

When the host provides the `okf` capability:

```bash
# emit an OKF bundle from a concepts manifest (one concept per file + index.md)
okf emit <out_dir>/okf <concepts.json> --compress --rate 0.5
#   concepts.json = [{"name","type","title"?,"description"?,"tags"?,"body","links"?}, ...]

# structure-safe compress one existing markdown doc (for an already-emitted agent doc)
okf compress <doc.md> --rate 0.5 > <doc.min.md>
```

A skill builds `concepts.json` from its structured output (e.g. blueprint's `understanding.json`
sections → one concept per component / interface / risk; audit findings → one concept per finding;
seo → one concept per page/issue), then calls `okf emit --compress`.

## Verified (2026-06-29)

- Structure-safety: on a mixed concept (prose + `engine/.../shell.rs:212` + a ```rust fence + a
  a `sandbox` markdown link plus `type:` frontmatter) — prose compressed ~50% at `--rate 0.5`,
  **every** ref / fence / link / frontmatter field preserved.
- Real doc floor: `docs/competitors/GROK-BUILD.md` (ref-dense) → **2235→1799 tokens (−20%)**,
  16/16 `path:line` refs + inline code intact. Prose-heavy docs compress more; ref-dense docs are
  the conservative floor and prove the protection holds on the hardest case.

## Rules

- **Never compress the human doc.** Compression is for the agent bundle only.
- **`type` is required** on every OKF concept (the one OKF-mandated field) — `okf` raises if missing.
- Link concepts with ordinary markdown links so the bundle is a graph; `index.md` is auto-generated.
- LLMLingua model loads once (CPU, ~110M, cached in HF cache); reuse `_pc` across a bundle.
