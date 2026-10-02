# Semantic review contract

Use this reference when the repository includes an explicit product specification, acceptance
criteria, team standard, public contract, or ADR relevant to frozen audit scope. This extends
existing lenses; it does not create a second workflow or provider.

## Two independent axes

Run two separate reviews when their inputs exist:

- **SPEC fidelity → `correctness`.** Feed exact requirements, acceptance criteria, public API
  contracts, and applicable ADR consequences. Report each requirement as `satisfied`, `partial`,
  `wrong`, `missing`, `unrequested`, or `unproven`, with exact requirement and implementation
  citations. Test behavior through public interface where possible.
- **STANDARDS → `ai-slop`.** Feed repository-local standards, coding conventions, lint/config
  policy, documented exceptions, and applicable ADR/design conventions. Report separate verdict and
  findings. Do not infer a standard from model preference or generic style advice.

Never merge these verdicts: behavior can satisfy SPEC while violating STANDARDS, or satisfy a
standard while failing SPEC. Emit no-source `unproven` unless whole-repo review is explicitly
justified as `not-applicable`, with searched scope and nonempty reason. If a source is present but
incomplete, inaccessible, or ambiguous, emit typed `unproven` with missing evidence. Neither state
is a clean pass.

The native result is `details.semanticReview`:
`{axis: "spec"|"standards", status: "pass"|"findings"|"unproven"|"not-applicable", reason,
sources: [{location: "file:line", quote}]}`. `pass` and `findings` require source evidence.

## Finding discipline

Every semantic finding carries `reviewAxis`, nonempty `sourceQuote`, `sourceLocation`, and
axis-specific `disposition`: SPEC uses `missing|partial|wrong|unrequested`; STANDARDS uses
`documented-violation|design-heuristic`. Name exact source rule or requirement, implementation/test
evidence, behavioral consequence, and one bounded remediation. `satisfied` is a per-requirement
status, separate from axis verdict and finding disposition. Do not turn an absent request into a
defect. Attribute each finding with `changeAttribution: {status: introduced|pre-existing|unknown,
reason, baselineEvidence: [file:line]}`; use `unknown` when no usable baseline exists, and require
real baseline evidence for other statuses.

Architecture output carries `details.changeRisk` with `reversibility: reversible|one-way|unknown`,
nonempty `blastRadius` and `reason`, plus `beforeEvidence` and `afterEvidence` arrays. Summarize
bounded next action; whole-repo runs without diff context use `unknown` and do not invent evidence.

Tests are evidence, not a style gate. Prefer tests that exercise behavior through public seams,
use independently derived expected values, and avoid excessive internal mocks or assertions tied
to implementation structure. Flag snapshot-only/source-substring tests as weak evidence and
refactor-fragile tests when they can pass while behavior is wrong. Preserve valid dependency-
injection seams and framework conventions before suggesting simplification.

For design review, inspect feature envy, data clumps, primitive obsession, repeated dispatch, and
shotgun surgery. Apply an interface-complexity/deletion test: identify callers, implementations,
and behavior added by an abstraction before proposing deletion. Respect ADRs and documented
exceptions; cite them when a smell is intentional.
