---
name: gotchas
description: Capture user-confirmed recurring agent failures as concise deduplicated lessons in repository gotchas.md; record symptom, root cause, correction, prevention, & evidence without invention.
kind: capability
capabilityClass: workflow
discoverability: public
domain: null
operations:
  - analyze
  - execute
  - produce
effects:
  - source-read
  - repository-write
hostRequirements: []
---

# Gotchas

`/gotchas` turns a repeated agent failure into one durable repository lesson. It
does not replace incident diagnosis, write speculation, or rewrite an existing
history of lessons.

## Trigger & eligibility

Use when the same agent failure has recurred and its cause has been reasoned
through with the user. Natural language such as “record this gotcha”, “save this
lesson for future agents”, or “we hit this failure again” routes here only when
the lesson is evidence-backed.

Require all of the following before appending:

- at least two observed occurrences tied to the same symptom or failure pattern;
- a root cause established from source, command output, artifacts, or other
  inspectable evidence;
- user-confirmed reasoning or correction, not an agent-only hypothesis;
- a concrete correction and prevention rule; and
- evidence references that another agent can inspect.

If any requirement is missing, keep the observation transient, state what is
missing, and do not write a durable lesson. Never invent a root cause, occurrence,
user confirmation, or evidence reference.

## Append protocol

1. Resolve repository root from current workspace/git state. Target exactly
   `<repository-root>/gotchas.md`, not this skill directory or an unrelated
   workspace.
2. Read existing entries before writing. Compare normalized symptom, root cause,
   affected area, and prevention; an exact or materially equivalent lesson is a
   duplicate. If duplicate, do not append or rewrite it; report its heading and
   any new evidence separately.
3. Append one concise Markdown entry at end of file. If file is absent, create it
   with a `# Gotchas` heading followed by the entry. Preserve existing entries,
   formatting, and unrelated changes.
4. Use this exact field set, with concrete values rather than generic advice:

   ```markdown
   ### YYYY-MM-DD — short lesson title
   - Symptom: <what repeated>
   - Root cause: <confirmed cause>
   - Correction: <what fixed or mitigated it>
   - Prevention: <check or rule future agents must follow>
   - Evidence: <paths, line numbers, command output, artifact IDs, or user-confirmed observation>
   ```

5. Verify only that one entry was appended to the intended repository file and
   that no secret values were recorded. Do not run generators or alter source,
   tests, manifests, or unrelated documentation as part of this skill.

## Evidence & safety

Separate observed symptom from inferred cause; promote a cause only after the
user's reasoning and available evidence support it. Evidence may cite a path,
line, command/result, task ID, or concise user-confirmed observation; redact
credentials, tokens, personal data, and proprietary payloads. “It probably…” is
not evidence. A useful prevention rule is specific enough to check before the
failure recurs.

When a duplicate exists, prefer no mutation. Update it only if the user
explicitly asks to enrich that entry and the new material is verified. A gotcha
entry is a lesson, not a license to broaden current task scope.

## Result contract

Return a compact `GOTCHA_RESULT` containing:

```text
status: appended | duplicate | not-ready
path: <repository-root>/gotchas.md
entry: <heading or none>
symptom: <short description>
root_cause: <confirmed cause or none>
evidence: <references or missing requirement>
```

Say `appended` only after the repository file contains the new entry. Say
`duplicate` when equivalent content already exists. Say `not-ready` when
repetition, user reasoning, correction, prevention, or evidence is insufficient.
