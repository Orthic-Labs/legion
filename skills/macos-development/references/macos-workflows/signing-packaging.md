# Signing, packaging, and notarization

Separate local debug, a local app bundle, a signed app, a notarized/stapled artifact, an
installer, and a distribution channel. Identify bundle IDs, targets, architectures,
minimum OS, signing settings, entitlements, hardened runtime, version/build metadata,
archive/export commands, and CI ownership before changing anything. Preserve one existing
release pipeline and keep credentials out of source/logs.

For inspection, locate the main binary under `Contents/MacOS` and inspect actual state:

```sh
codesign -dvvv --entitlements :- MyApp.app
spctl -a -vv MyApp.app
security find-identity -p codesigning -v
plutil -p MyApp.app/Contents/Info.plist
```

Classify unsigned/ad-hoc state, wrong identity, entitlement mismatch, hardened-runtime
failure, sandbox/file-access denial, nested-code signature failure, Gatekeeper policy,
or distribution/notarization prerequisite separately. `spctl` results are trust-policy
evidence; they do not replace signature/entitlement inspection. Never invent entitlements
or apply blanket exceptions.

Use the diagnostic wording to choose the next read-only check: “code object is not
signed at all” points to the selected target/output; “a sealed resource is missing or
invalid” points to post-signing bundle edits or nested resources; an entitlement error
points to the signed entitlement blob versus target settings; “bundle format is
unrecognized, invalid, or unsuitable” points to path/product type or malformed bundle
metadata; a Gatekeeper rejection after a valid signature points to trust/notarization
state. Reinspect the exact artifact after every repair; do not mask an error with an
ad-hoc signature or broad entitlement.

For packaging, verify bundle structure, nested frameworks/helpers, resources, symbols,
architectures, Info.plist, version metadata, and the selected archive/export scheme.
For notarization, submit only through an explicitly authorized route, then verify accepted
status and staple/validate the exact artifact. A successful upload or transport is not
approval or publication. Local debug need not be notarized; an unsigned build cannot prove
installation, trust, sandbox, notarization, or store acceptance.

Do not disable code signing, Gatekeeper, sandboxing, library validation, or macro security
to force a pass. Report missing certificates/profiles, accounts, or exported artifacts as
specific unrun prerequisites and continue source-level preparation where possible.
