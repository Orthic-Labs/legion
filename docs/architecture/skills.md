# Packaged skills

This page describes the shipped skill surface from the [compact skill catalog](../../src/registry/skills/index.json), the corresponding [manifests](../../skills/manifests/), and each skill's `SKILL.md` frontmatter. It does not restate role doctrine; see [Sage architecture](sage.md), [Alchemist architecture](alchemist.md), [Oracle architecture](oracle.md), and the relevant files under `doctrine/` for that material.

## Reading this page

A packaged skill is a bundle or entrypoint declared by `skills/<id>/SKILL.md`. Its frontmatter declares the bundle's `kind`, capability class where applicable, discoverability, optional domain, operations, effects, and host requirements. The catalog is the compact generated view of those declarations.

Each per-skill manifest records the bundle identity and version, `SKILL.md` entry, package URI, provenance and license state, rights receipt, audit and authoring profiles, parity inputs, consumers, and a `files` inventory. Each declared file has a package URI and a SHA-256 digest. The manifest therefore provides the shipped-file inventory and content-addressed provenance; it does not add semantic fields that the skill frontmatter does not declare.

The four reference classes in `src/registry/capabilities.json` are:

- **`PACKAGE_INTERNAL`** — resolves to a file shipped inside this package and must exist on disk at validation time.
- **`HOST_CAPABILITY`** — is provided by the embedding host, such as an MCP server, CLI, or graph engine; it is never shipped and must have declared absence behavior.
- **`PROJECT_OVERLAY`** — is supplied by the consuming project at run time; it is never shipped, must be optional, and must state what happens when absent.
- **`HISTORICAL_EVIDENCE`** — is a past-run record kept for provenance; it is never executed and is not resolved as a live path.

### Catalog grouping note

The catalog currently exposes a flat `bundles` array and does not contain a `groups` field. The headings below use its five declared non-null `domain` values (`commercial`, `engineering`, `design`, `editorial`, and `research`), followed by the catalog's `domain: null` bundles. No additional grouping semantics are inferred. Skills remain in catalog order within each heading.

## Host capability degradation

The following absence behavior is copied from `src/registry/capabilities.json` and applies wherever the corresponding host requirement appears below. The remedy is included because it is part of the registry declaration; no fallback is inferred.

### `blueprint-graph`

- **Absent behavior:** Use resident Membrane transport when available, then bounded Blueprint one-shot regardless of enrollment. Return a `NO_CAPABILITY` result naming `blueprint-graph` only when both are unavailable; never fall back to ad-hoc grep or present ungraphed results as graph results.
- **Remedy:** Provide resident Membrane transport or install the Blueprint graph engine and put its `blueprint` executable on `PATH`, then re-run. This package does not ship it.

### `legion`

- **Absent behavior:** The legion MCP server fails to start and `legion_m1_invoke`/`legion_m1_status` are absent from the tool list. Skills that shell out to `legion` must treat it as unavailable, never as returning an empty result.
- **Remedy:** Install the Legion native release so `legion` is on `PATH`, or run against a host that provides it.

### `local-corpus`

- **Absent behavior:** Research skips the local-corpus provider and records it as unrun.
- **Remedy:** Point the host at a local document corpus for offline retrieval.

### `notebooklm`

- **Absent behavior:** Research skips the notebooklm provider and records it as unrun.
- **Remedy:** Provide NotebookLM access in the host.

### `omniroute`

- **Absent behavior:** Alchemist exits 4 (gateway down). Callers must treat Alchemist as unavailable, not as returning an empty result.
- **Remedy:** Install the OmniRoute gateway and put `omniroute` on `PATH`, or run Alchemist against a host that provides it.

### `pi-cli`

- **Absent behavior:** Coder returns a typed unavailable-provider result and performs no outsourced analysis.
- **Remedy:** Install the Pi CLI and expose its `pi` command on `PATH`, then invoke Coder again.

### `python-runtime`

- **Absent behavior:** The dependent skill reports that its local validator or worker adapter is unavailable and does not substitute another runtime.
- **Remedy:** Install Python 3 and expose either `python3` or `python` on `PATH`.

### `scholarly-search`

- **Absent behavior:** Research returns `UNPROVEN` for scholarly claims.
- **Remedy:** Expose a scholarly-search tool in the host.

### `web-search`

- **Absent behavior:** Research returns `UNPROVEN` for any claim that required live retrieval.
- **Remedy:** Expose a web-search tool in the host; Research blocks rather than guessing.

## commercial

### `ads`

- **Manifest:** [ads.json](../../skills/manifests/ads.json)
- **Kind:** `capability`
- **Purpose:** Audit, plan, create, or optimize paid campaigns across Google, Meta, YouTube, LinkedIn, TikTok, Microsoft, or Apple. Use for PPC, ROAS, CPA, targeting, bidding, retargeting, budgets, creative, or ad-spend questions.
- **Capability class:** `domain`
- **Domain:** `commercial`
- **Operations:** `analyze`, `decide`, `produce`
- **Effects:** `source-read`, `network-request`
- **Host requirements:** None declared.
- **Discoverability:** `public`

### `marketing`

- **Manifest:** [marketing.json](../../skills/manifests/marketing.json)
- **Kind:** `capability`
- **Purpose:** Route positioning, offers, packaging, guarantees, launches, validation, growth, analytics, pricing, CRO, retention, and commercial ideation. Use for Grand Slam Offers or what, whom, why, and how to market; route execution to Ads, SEO, Social, Research, or Writing.
- **Capability class:** `domain`
- **Domain:** `commercial`
- **Operations:** `analyze`, `decide`, `produce`
- **Effects:** `source-read`, `network-request`
- **Host requirements:** None declared.
- **Discoverability:** `public`

### `seo`

- **Manifest:** [seo.json](../../skills/manifests/seo.json)
- **Kind:** `capability`
- **Purpose:** Audit or improve SEO, GEO or AEO, AI citations, crawlability, indexing, Core Web Vitals, schema, sitemaps, content quality, E-E-A-T, images, hreflang, llms.txt, traffic drops, page speed, or repository SEO.
- **Capability class:** `domain`
- **Domain:** `commercial`
- **Operations:** `analyze`, `diagnose`, `produce`
- **Effects:** `source-read`, `artifact-write`, `process-exec`, `network-request`
- **Host requirements:** None declared.
- **Discoverability:** `public`

### `social`

- **Manifest:** [social.json](../../skills/manifests/social.json)
- **Kind:** `capability`
- **Purpose:** Route Instagram, Pinterest, YouTube, Twitter or X, LinkedIn, Reels, Shorts, pins, threads, calendars, distribution, analytics, and social growth. Use `/social` or when social strategy or content is the deliverable.
- **Capability class:** `domain`
- **Domain:** `commercial`
- **Operations:** `analyze`, `decide`, `produce`
- **Effects:** `source-read`, `artifact-write`, `network-request`
- **Host requirements:** None declared.
- **Discoverability:** `public`

## engineering

### `architect`

- **Manifest:** [architect.json](../../skills/manifests/architect.json)
- **Kind:** `capability`
- **Purpose:** Software and system architecture capability for architecture decisions, ADRs, quality attributes, interfaces, invariants, migrations, and architecture-significant planning.
- **Capability class:** `domain`
- **Domain:** `engineering`
- **Operations:** `analyze`, `decide`, `produce`
- **Effects:** `source-read`, `artifact-write`
- **Host requirements:** None declared.
- **Discoverability:** `public`

### `audit`

- **Manifest:** [audit.json](../../skills/manifests/audit.json)
- **Kind:** `capability`
- **Purpose:** Diagnose a whole repository through Legion's frozen Audit provider plan. Use for `/audit` or repository-wide read-only health, security, runtime, & evidence review.
- **Capability class:** `domain`
- **Domain:** `engineering`
- **Operations:** `analyze`, `evaluate`, `produce`
- **Effects:** `source-read`, `process-exec`, `artifact-write`
- **Host requirements:** `blueprint-graph`, `legion`. See [their declared absence behavior](#host-capability-degradation).
- **Discoverability:** `public`

### `audit-fix`

- **Manifest:** [audit-fix.json](../../skills/manifests/audit-fix.json)
- **Kind:** `capability`
- **Purpose:** Apply bounded remediation from a frozen Legion Audit report, then rerun its same provider plan. Use only for `/audit-fix` after `/audit` evidence exists.
- **Capability class:** `workflow`
- **Domain:** `engineering`
- **Operations:** `analyze`, `evaluate`, `execute`, `produce`
- **Effects:** `source-read`, `repository-write`, `process-exec`
- **Host requirements:** `blueprint-graph`, `legion`. See [their declared absence behavior](#host-capability-degradation).
- **Discoverability:** `public`

### `audit-visual`

- **Manifest:** [audit-visual.json](../../skills/manifests/audit-visual.json)
- **Kind:** `capability`
- **Purpose:** Enumerate, capture, compare, and reconcile rendered UI evidence through Legion's shared Audit visual provider. Use for `/audit-visual`, visual regressions, screenshot baselines, or rendered-state coverage.
- **Capability class:** `domain`
- **Domain:** `engineering`
- **Operations:** `analyze`, `evaluate`, `produce`
- **Effects:** `source-read`, `artifact-write`, `process-exec`
- **Host requirements:** `blueprint-graph`, `legion`. See [their declared absence behavior](#host-capability-degradation).
- **Discoverability:** `public`

### `debugger`

- **Manifest:** [debugger.json](../../skills/manifests/debugger.json)
- **Kind:** `capability`
- **Purpose:** Diagnosis capability for reproducing failures, isolating evidence, forming disconfirmable hypotheses, establishing root cause, and selecting routine repairs. Do not use for preflight or completion-only verification.
- **Capability class:** `domain`
- **Domain:** `engineering`
- **Operations:** `analyze`, `diagnose`, `decide`, `produce`
- **Effects:** `source-read`, `process-exec`
- **Host requirements:** `blueprint-graph`. See [its declared absence behavior](#host-capability-degradation).
- **Discoverability:** `public`

### `qa`

- **Manifest:** [qa.json](../../skills/manifests/qa.json)
- **Kind:** `capability`
- **Purpose:** Add, run, or audit local web or Tauri app QA: hidden servers, deterministic mocks, functional/browser assertions, supporting viewport captures, runtime checks, & contract-test authoring.
- **Capability class:** `domain`
- **Domain:** `engineering`
- **Operations:** `analyze`, `evaluate`, `execute`, `produce`
- **Effects:** `source-read`, `artifact-write`, `process-exec`
- **Host requirements:** None declared.
- **Discoverability:** `public`

## design

### `brand-identity`

- **Manifest:** [brand-identity.json](../../skills/manifests/brand-identity.json)
- **Kind:** `capability`
- **Purpose:** Create, audit, evolve, or apply brand identities, systems, guidelines, visual identity, voice, naming, logo direction, brand books, rebrands, website or app identity, pitch decks, or social kits.
- **Capability class:** `domain`
- **Domain:** `design`
- **Operations:** `analyze`, `decide`, `produce`, `evaluate`
- **Effects:** `source-read`, `artifact-write`
- **Host requirements:** None declared.
- **Discoverability:** `public`

### `designer`

- **Manifest:** [designer.json](../../skills/manifests/designer.json)
- **Kind:** `capability`
- **Purpose:** Create, critique, redesign, or polish websites, app UI, dashboards, components, static creative, print, motion systems, glass materials, illustration direction, and frontend craft. Route deterministic rendered-state coverage/regression evidence to Audit Visual and identity systems to Brand Identity.
- **Capability class:** `domain`
- **Domain:** `design`
- **Operations:** `analyze`, `decide`, `produce`, `evaluate`
- **Effects:** `source-read`, `artifact-write`
- **Host requirements:** None declared.
- **Discoverability:** `public`

## editorial

### `writing`

- **Manifest:** [writing.json](../../skills/manifests/writing.json)
- **Kind:** `capability`
- **Purpose:** Route editorial prose, essays, newsletters, scripts, captions, threads, research articles, blogs, SEO posts, conversion copy, bios, DMs, product copy, email, and changelogs. Use when words are the deliverable.
- **Capability class:** `domain`
- **Domain:** `editorial`
- **Operations:** `analyze`, `produce`, `evaluate`
- **Effects:** `source-read`, `artifact-write`
- **Host requirements:** None declared.
- **Discoverability:** `public`

## research

### `research`

- **Manifest:** [research.json](../../skills/manifests/research.json)
- **Kind:** `capability`
- **Purpose:** Sole top-level evidence router: general, market, technical, scientific, medical, legal, competitor, Reddit, audience, trends, scholarly, documents, authority, and NotebookLM. Medical and legal are private internal routes; India consumer-commission filing is a Legal workflow.
- **Capability class:** `domain`
- **Domain:** `research`
- **Operations:** `route`, `analyze`, `produce`
- **Effects:** `source-read`, `artifact-write`, `network-request`
- **Host requirements:** `legion`, `local-corpus`, `notebooklm`, `scholarly-search`, `web-search`. See [their declared absence behavior](#host-capability-degradation).
- **Discoverability:** `public`

## No domain declared

The following catalog entries have `domain: null`. The `entrypoint` bundles omit a `domain` declaration in frontmatter; this page does not infer one. Their `capabilityClass` is likewise omitted in frontmatter and represented as `null` in the catalog, so it is recorded as not declared. The `brand` capability explicitly declares `domain: null`.

### `alchemist`

- **Manifest:** [alchemist.json](../../skills/manifests/alchemist.json)
- **Kind:** `entrypoint`
- **Purpose:** Execute a settled, bounded change through Legion's Alchemist authority. Use `/alchemist` after scope, ownership, checks, and acceptance are decided.
- **Capability class:** Not declared; catalog value is `null`.
- **Domain:** Not declared; catalog value is `null`.
- **Operations:** `execute`
- **Effects:** `source-read`, `repository-write`, `process-exec`
- **Host requirements:** `omniroute`, `python-runtime`. See [their declared absence behavior](#host-capability-degradation).
- **Discoverability:** `explicit`

### `brand`

- **Manifest:** [brand.json](../../skills/manifests/brand.json)
- **Kind:** `capability`
- **Purpose:** Load a source-bound brand card before branded content, design, marketing, social, or media work. Use `/brand` when a named brand or approved identity source governs an output.
- **Capability class:** `context`
- **Domain:** Declared `null`.
- **Operations:** `analyze`, `produce`
- **Effects:** `source-read`
- **Host requirements:** None declared.
- **Discoverability:** `public`

### `coder`

- **Manifest:** [coder.json](../../skills/manifests/coder.json)
- **Kind:** `entrypoint`
- **Purpose:** Explicit opt-in router for scoped read-only code analysis through a declared external model-provider CLI. Use only for `/coder`, explicit outsourced analysis, or a named provider model/tier.
- **Capability class:** Not declared; catalog value is `null`.
- **Domain:** Not declared; catalog value is `null`.
- **Operations:** `analyze`
- **Effects:** `source-read`, `network-request`
- **Host requirements:** `pi-cli`, `python-runtime`. See [their declared absence behavior](#host-capability-degradation).
- **Discoverability:** `explicit`

### `commit`

- **Manifest:** [commit.json](../../skills/manifests/commit.json)
- **Kind:** `entrypoint`
- **Purpose:** Review, verify, commit, & push one frozen diff through Legion's guarded Commit workflow. Use for `/commit`, review and commit, or commit and push.
- **Capability class:** Not declared; catalog value is `null`.
- **Domain:** Not declared; catalog value is `null`.
- **Operations:** `analyze`, `evaluate`, `execute`
- **Effects:** `source-read`, `repository-write`, `process-exec`, `network-request`
- **Host requirements:** None declared.
- **Discoverability:** `explicit`

### `covenant`

- **Manifest:** [covenant.json](../../skills/manifests/covenant.json)
- **Kind:** `entrypoint`
- **Purpose:** Convene Legion's optional independent challenge chamber for a named decision, work artifact, blocker, or packet-only review preparation. Use `/covenant`.
- **Capability class:** Not declared; catalog value is `null`.
- **Domain:** Not declared; catalog value is `null`.
- **Operations:** `analyze`, `evaluate`, `produce`
- **Effects:** `source-read`
- **Host requirements:** None declared.
- **Discoverability:** `explicit`

### `dispatch`

- **Manifest:** [dispatch.json](../../skills/manifests/dispatch.json)
- **Kind:** `capability`
- **Purpose:** Create a validated zero-context work packet for another agent or executor while current orchestrator retains responsibility. Use for delegation, parallel workers, or copy-paste executor instructions. Same-agent work stays inline; session continuity uses handoff.
- **Capability class:** `workflow`
- **Domain:** Not declared; catalog value is `null`.
- **Operations:** `route`, `produce`
- **Effects:** `source-read`, `artifact-write`, `process-exec`
- **Host requirements:** `python-runtime`. See [its declared absence behavior](#host-capability-degradation).
- **Discoverability:** `public`

### `gotchas`

- **Manifest:** [gotchas.json](../../skills/manifests/gotchas.json)
- **Kind:** `capability`
- **Purpose:** Capture user-confirmed recurring agent failures as concise deduplicated lessons in repository gotchas.md; record symptom, root cause, correction, prevention, & evidence without invention.
- **Capability class:** `workflow`
- **Domain:** Not declared; catalog value is `null`.
- **Operations:** `analyze`, `execute`, `produce`
- **Effects:** `source-read`, `repository-write`
- **Host requirements:** None declared.
- **Discoverability:** `public`

### `handoff`

- **Manifest:** [handoff.json](../../skills/manifests/handoff.json)
- **Kind:** `capability`
- **Purpose:** Transfer an ongoing task into a fresh chat through a hash-bound transcript pointer and a validated cold-start continuation packet. Use for fresh-thread continuity, context rollover, or transfer of decisions, state, failures, and landmines; never use for bounded executor delegation.
- **Capability class:** `workflow`
- **Domain:** Not declared; catalog value is `null`.
- **Operations:** `analyze`, `produce`
- **Effects:** `source-read`, `artifact-write`, `process-exec`
- **Host requirements:** `python-runtime`. See [its declared absence behavior](#host-capability-degradation).
- **Discoverability:** `public`

### `oracle`

- **Manifest:** [oracle.json](../../skills/manifests/oracle.json)
- **Kind:** `entrypoint`
- **Purpose:** Independent read-only Completion Validation against the raw user request. Use `/oracle` before successful delivery.
- **Capability class:** Not declared; catalog value is `null`.
- **Domain:** Not declared; catalog value is `null`.
- **Operations:** `evaluate`
- **Effects:** `source-read`
- **Host requirements:** None declared.
- **Discoverability:** `explicit`

### `tasklist`

- **Manifest:** [tasklist.json](../../skills/manifests/tasklist.json)
- **Kind:** `capability`
- **Purpose:** Create an executable same-agent task list. Use `/tasklist`; keep it inline unless persistence, audit receipts, or a reusable record is requested. Use Dispatch for another agent & Handoff for a new chat.
- **Capability class:** `workflow`
- **Domain:** Not declared; catalog value is `null`.
- **Operations:** `analyze`, `produce`, `execute`
- **Effects:** `source-read`, `artifact-write`, `process-exec`
- **Host requirements:** `python-runtime`. See [its declared absence behavior](#host-capability-degradation).
- **Discoverability:** `public`

### `wake`

- **Manifest:** [wake.json](../../skills/manifests/wake.json)
- **Kind:** `capability`
- **Purpose:** Schedule one bounded wakeup for an active job, external review, or goal-alignment check; inspect once per wake, stop polling, & continue only from observed state.
- **Capability class:** `workflow`
- **Domain:** Not declared; catalog value is `null`.
- **Operations:** `analyze`, `execute`, `produce`
- **Effects:** `source-read`, `artifact-write`
- **Host requirements:** None declared.
- **Discoverability:** `public`

## Source map

- Catalog and catalog order: [`src/registry/skills/index.json`](../../src/registry/skills/index.json)
- Per-bundle manifest: the manifest linked in each entry above under [`skills/manifests/`](../../skills/manifests/)
- Skill declarations: `skills/<id>/SKILL.md`
- Reference classes and host capability degradation: [`src/registry/capabilities.json`](../../src/registry/capabilities.json)
