# Brand Registry: Differentiation Ledger

The Phase 3 guard in `brand-identity` checks every new or revised brand against this registry.

No sibling brand should share four or more of the seven axes unless the user explicitly wants a same-family system. When a brand identity is approved, update this file. The registry is mutable memory, not a static reference.

## Axes

1. **Base theme:** light, dark, paper, night, vivid, neutral, high-contrast.
2. **Type category:** reading serif, grotesque, humanist sans, mono-forward, display, script/hand, slab.
3. **Accent family:** hue family and usage behavior.
4. **Composition system:** editorial, Swiss grid, deck, radial, spine, asymmetrical, dense utility, cinematic.
5. **Mark logic:** wordmark, symbol, monogram, seal, system mark, kinetic mark, no-logo identity.
6. **Asset language:** photography, illustration, iconography, pattern, texture, motion, UI-native.
7. **Voice signature:** plainspoken, editorial, precise, warm, provocative, ceremonial, technical, playful.

## Portfolio Snapshot

| Brand | Register | Base | Type category | Accent family | Composition system | Mark logic | Asset language | Voice signature | Signature mechanism / notes |
|---|---|---|---|---|---|---|---|---|---|
| ViewRight | Editorial / print | Warm paper | Reading serif | Oxblood | Two-column source-to-render | System mark / wordmark | Document typography, render sweep | Editorial, precise | Render reveal: source becomes readable output. |
| MailRight | Swiss / utilitarian | Crisp off-white | Grotesque | Signal blue | Strict baseline + inbox triage | Wordmark / UI-native mark | Inbox rows, keyboard chips | Plainspoken, operational | Triage deck: inbox responds to keyboard action. |
| HeardRight | Sonic / acoustic | Night | Humanist sans | Signal teal | Waveform spine | Kinetic/audio mark | Waveform, transcript, spectrogram | Warm, immediate | Spoken line: words materialize from voice. |
| CodeRight | Calm terminal | Warm near-black | Mono-forward | Copper | Sidebar + console deck | Wordmark / terminal mark | Agent sessions, approval states | Technical, calm | Quiet room: copper appears only where approval is needed. |
| Damned Designs | Dark premium EDC | Ink / beige | Display serif | Copper / brass | Product editorial | Seal / wordmark | Product photography, metal/leather texture | Ceremonial, premium | Distinguish from CodeRight through product materiality and serif luxury. |
| Rotten Hand | Honest slow-fashion | Warm light | Humanist / craft | Muted rose | Lookbook editorial | Wordmark / stitch-like mark | Fabric texture, garment details | Honest, intimate | Slow-fashion identity, avoid tech/copper overlap. |
| Toxic Sundae | Counter-culture streetwear | Black / vivid | Display / street | Toxic green | Poster / drop culture | Loud symbol / wordmark | Stickers, street graphics | Provocative, playful | Loud by design; keep distinct from muted suite brands. |

## Update Template

```markdown
| [Brand] | [Register] | [Base] | [Type category] | [Accent family] | [Composition system] | [Mark logic] | [Asset language] | [Voice signature] | [Signature mechanism / notes] |
```

## Guard Procedure

1. Read this registry before Phase 3.
2. Compare the candidate brand to every row across the seven axes.
3. If it shares four or more axes with any sibling, adjust the candidate and re-run.
4. After user approval, add or update the row.
