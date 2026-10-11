# Route gates

Every gate returns `ok`, `ask`, or `block`. `ask` can become `ok` only through a recorded
approval receipt; the resolver never silently drops a gate.

## Medical

- **anonymous-no-history:** anonymous routes forbid personal-history evidence and never grant
  `load-medical-history`.
- **personal-route:** `self|other-identified` queues `confirm-personal-medical-route`.
- **history-available:** after approval, a personal route still blocks unless its configured
  history source is readable.
- **red flags:** the medical engine performs urgency/red-flag checks before synthesis.

## Legal

- **context-complete:** country, area, and issue are mandatory.
- **criminal isolation:** India criminal routes are allowed to research, but consumer and
  e-Jagriti paths are listed in `forbidden_resources` and cannot be loaded.
- **consumer filing facts:** India consumer `draft|procedure` routes ask for pecuniary value,
  cause-of-action date, and notice status before pack generation.
- **send/sign/file:** drafting may proceed as a draft; sending, signing, notarising, filing,
  accepting, or relying requires `approve-send-sign-file`.

## NotebookLM

- private/highly-sensitive or medical upload → `approve-notebooklm-upload`;
- NotebookLM answer → lead only; underlying source must be opened and located;
- notebook ID is explicit in automation; shared `notebooklm use` state is not authoritative.

## Verified assurance

- every load-bearing claim has opened, passage-located evidence;
- domain verifier passes;
- citation-to-sentence support checker passes;
- cited DOI retraction status is freshly verified; unknown status blocks unless explicitly
  degraded by the operator;
- corrections issue a receipt with `legion research --step issue-patch --draft <draft>
  --run-id <id> --key-file <existing-key> --out <receipt>`, then apply one diff with
  `legion research --step apply-patch --draft <draft> --run-id <id> --key-file <existing-key>
  --receipt <receipt> --diff <single-file.diff>`. The native CLI receipt binds run ID,
  canonical draft path and source hash, grants exactly `Read` + `Edit`, and caps patches at
  eight hunks and 4096 UTF-8 bytes per hunk. The key file must already contain at least 32
  raw bytes created from OS cryptographic randomness outside this CLI. This is ambient CLI
  integrity evidence; it does not attest hook execution or
  provide a general single-use authorization.

## Discovery provenance

Every evidence record has `suggested_by` and `seed_chain`. Missing discovery provenance blocks
ledger admission. Substituted/OA-recovered bodies declare `body_is_not_from_source` and a
`body_substitution` description wherever rendered.
