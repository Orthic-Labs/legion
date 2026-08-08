# Portfolio Site Registry — visual differentiation ledger

The differentiation guard (`/designer` website surface, Phase 3) checks every new/redesigned site against this
ledger. **No two sibling sites may share ≥3 of the 5 axes.** When a site is (re)designed, update its
row. The whole point: a stranger should not be able to tell these four were made by the same person.

## The "-Right" suite — four products, four identities

| Site | Register | Base | Type category | Accent hue | Layout grid | Motion signature |
|---|---|---|---|---|---|---|
| **SampleApp** | Editorial / print | Warm paper (light) | Reading serif (Source Serif / Spectral) | Oxblood `#7A2E2E` | Two-column: source → rendered | Ink-settle / page-render sweep |
| **SampleApp** | Swiss / utilitarian | Crisp off-white (light) | Grotesque (Söhne / Suisse Int'l) | Signal blue `#1B5FFF` | Strict baseline grid + kbd chips | Keyboard-snap micro-motion |
| **SampleApp** | Sonic / acoustic | Night (dark) | Humanist sans (used as "voice") | Signal teal `#16B8A6` on indigo | Waveform-as-spine | Audio-reactive transcribe |
| **SampleApp** | Runtime schematic / terminal | Warm near-black (dark) | Mono + condensed (Spline Mono / Saira) or display serif (Instrument) | Copper `#C8794A` (+ sage = verified) | Runtime diagram → RUN panel | Data-flow trace + arbiter-reject pulse |

Spread check: base = 2 light / 2 dark; type = serif / grotesque / humanist / mono — all four different;
accent = oxblood / blue / teal / copper — four different hue families; layout + motion all distinct.
**No pair shares ≥3 axes.** ✅

> ⚠ **Drift to fix:** SampleApp's locked brand (`sampleapp/brand.md`) currently uses ink/paper/**copper**
> — the SAME warm-neutral+copper family as SampleApp. That overlap is the exact "AI tell." The registry
> re-points SampleApp to a **night + teal acoustic** identity to break the twinning. Reconcile
> `brand.md` when SampleApp is redesigned (the approving human's call — this changes a locked brand).

---

## Signature Mechanism per site (Phase 1 — the interactive hero)

Each hero SHOWS the product doing its one real thing. None could be pasted onto another.

### SampleApp — "the render reveal"
Split hero. **Left:** raw source (plain markdown / code / a messy file), monospace, deliberately
unstyled. **Right:** the same content as SampleApp *renders* it — typeset, beautiful, readable.
A copper—no, **oxblood** sweep line travels left→right and the rendered side "settles" like ink
drying as it passes. Drag the divider to compare. The whole pitch (ugly in → beautiful reading out)
is the hero, live. (the approving human's original idea — now the template-killer for this site.)

### SampleApp — "the triage deck"
Hero IS a working inbox: thread list left, reading pane right, a real keyboard-shortcut HUD. As you
watch, keys fire (`E` archive, `R` reply, `⌘K` command) and the UI responds with snappy micro-motion;
each shortcut chip lights as its action runs. The promise (fast keyboard triage on the desktop) is
demonstrated, not claimed. Crisp light, Swiss grid. (the approving human's original idea.)

### SampleApp — "the spoken line"
Hero is a single living **waveform** spanning the screen on a night background. A caption types itself
in sync — *"zephyr, new note…"* — words materializing from the waveform as if dictated in real time;
the wake word pulses teal when it fires; an inline command (`zephyr send`) visibly ends the utterance.
Sound made visible. Motion is the brand. Reduced-motion → a static spectrogram + completed transcript.

### SampleApp — "the runtime, not the agent" (CORRECTED 2026-06-02 — the moat)
**The moat is NOT an approval gate — every harness waits for you. SampleApp is a self-improving
orchestration RUNTIME; the model is a swappable worker, the runtime is the product** (source:
`sampleapp/docs/architecture/00-BREWS.md`). The hero must SHOW what no single-model harness can:
a **Conductor** routing a goal across a **roster of specialist models** (Architect·Kimi, Code·DeepSeek,
Red Team·GLM…), an **independent jury** reviewing the output, and a **Completion Arbiter that rejects
false "done"** ("worker said done — goal isn't; tests never ran; remediation spawned") — plus the
**evolution loop** that promotes a better model on benchmark evidence (GLM→Kimi, 83% win / 412 tasks).
Two proven realizations: **Blueprint** = the runtime as an engineering schematic (Conductor → roster →
jury → arbiter-rejects → evolution feedback); **Editorial** = the thesis line "Your model is a worker.
The *runtime* is the product." + a live RUN panel where the arbiter refuses a premature done.
BANNED framing for SampleApp: "supervise / approve / one attention color / waits for you" — table
stakes, and the exact thing the approving human called out. Files: `_mockups/b-blueprint-v2.html`, `c-editorial-v2.html`.

---

## Other ventures (registers already established — keep distinct from the suite)

| Brand | Register | Base | Accent | Don't drift toward |
|---|---|---|---|---|
| Northwind Tools | Dark premium EDC | Ink / beige | Copper `#B87333` | (SampleApp is also copper — DD is product/e-com, keep its Cormorant serif + beige to separate) |
| Harbor Coffee | Honest slow-fashion | Warm light | Muted rose `#b07a84` | SampleApp blue / SampleApp oxblood |
| Static Riot | Counter-culture streetwear | Black | Toxic green `#39FF14` | n/a (already loud + distinct) |

---

## How to use this file
1. New/redesign site → read this registry first.
2. Choose axes that keep ≥3 different from every sibling above.
3. After the approving human approves, write the chosen row back here so the next site differentiates against it.
