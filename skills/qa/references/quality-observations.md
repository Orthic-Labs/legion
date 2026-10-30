# Honest imported quality observations

Use `legion quality summarize --input normalized.json --report original.json` to interpret an
existing provider report. This command does not run a test/coverage/mutation tool. Retain provider
name/version, exact source digest and scoped paths, original report digest/reference, execution
status and completeness. The CLI hashes the original report bytes and rejects a mismatching
`reportDigest`; matching bytes do not prove the provider's measurements or the normalizer's truth.

Coverage reports a measured numerator and denominator only when evidence supports them. Empty,
unavailable, partial, not-requested and failed execution are distinct; no report means no score.
Duplication pairs are investigation candidates, never confirmed defects or automatic deletion
instructions. Explain whether shared behavior warrants reuse before recommending a rewrite.

Mutation detection counts **assertion-detected** outcomes over assertion-detected + survived +
uncovered outcomes. Preserve invalid compilation, timeout, infrastructure failure, not-run and
unclassified upstream "killed" outcomes separately and exclude them from that denominator. A raw
"killed" label alone proves no assertion detected the mutation. A failed baseline cannot establish
test effectiveness; partial outcomes cannot establish complete effectiveness. The declared
denominator must match the normalized eligible outcomes.

Thresholds must name exactly the same scoped paths as the observation. Repository aggregates do
not judge a smaller changed scope. Report policy attention independently from measurement
availability. Never convert an imported score into a clean repository verdict, independent review
or effect authority. Project-native structure/test providers remain measurement owners.

Reuse cached observations only when source, tests, fixtures, toolchain, dependencies, command,
configuration and environment fingerprints all match; equal identifiers are compatibility
claims, not authenticated proof. Omitted or changed bindings require new measurement or an honest
unavailable result. Run actual checks only through the project's existing admission rules.
