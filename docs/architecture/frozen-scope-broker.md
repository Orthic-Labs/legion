# Explicit reviewed-scope freezes

`legion authority freeze` implements a narrow host broker for explicitly frozen
source closures. Ordinary repositories acquire no freeze merely because someone
reviewed them. [Implementation issue: #50](https://github.com/Orthic-Labs/legion/issues/50).

## Authority & trust

Owner-controlled enrollment pins repository identity/root, baseline object,
closure selectors, permitted operations, exact push destination, reviewer
executables/digests/models, nonroot execution UID, protected delivery storage,
explicit protected push-hook directory & launch ceiling. Only a native
Unix root administrator may create enrollment. Normal broker requests cannot
enroll, substitute commands, import votes, reset attempts or clear revocation.

Protected configuration/state live beneath:

- macOS: `/Library/Application Support/Orthic Labs/Legion/authority/<id>`;
- Linux: `/var/lib/legion/authority/<id>`.

Every ancestor must be root-owned, nonsymlink & unwritable by other users.
State writes require an exclusive transaction lock, atomic replacement & fsync.
Missing/corrupt/inaccessible state fails closed. Existing enrollment & revocation
tombstones cannot be replaced by enrollment. State is not stored in a repository,
an issue comment, a transcript import or an agent-writable approval file.

Trust rests on installed broker, protected enrollment, OS separation & configured
native provider behavior. Broker runs reviewers as an enrolled nonroot UID;
only controller writes authority state. Root administrators, provider compromise
& hostile same-user process injection are outside this cooperating-agent model.
No ownership signing service, signed ownership exception or human policy-bundle
pinning is restored.

Use existing RightKit installation/host administration for protected deployment.
A restricted launcher or authenticated SSH forced command may expose **only**
`legion authority freeze broker`, never `admin-enroll` or arbitrary command args.
Windows clients connect to this same authoritative Unix broker; native Windows
privileged storage is unsupported. Do not share HMAC keys or cached grants.

## Exact candidates & review

1. Administrator enrolls explicit file/tree selectors, including acceptance
   sources, helpers, generators, outputs & their definition. Closure completeness
   is an enrollment responsibility; no automatic semantic dependency claim exists.
2. Client submits an immutable full baseline object ID, exact scratch patch &
   explanation of why prior review missed this gap.
3. Broker builds expected tree through a separate index/object directory. It
   does not change repository HEAD, worktree or normal index. Snapshot binds sorted
   paths, modes, actual blob bytes, missing selectors & selector definition.
   Symlinks, gitlinks, noncanonical paths & ambiguous object IDs fail.
4. Broker reserves three launches durably, then starts Sage necessity review.
   Unnecessary findings stop there. Fable & Astra then receive identical candidate
   bytes in separate fresh sessions, without sibling decisions.
5. Native launchers pin executable bytes, restrict customization/tools, bound
   input/output/time, capture pipes & validate actual CLI session/model metadata.
   Unsupported metadata, substitution, malformed output or failure cannot approve.
6. Both named reviewers must agree with this exact candidate. Revised patch,
   result, explanation, baseline or freeze revision needs a new candidate. Attempts
   do not reset after transport failure. At most 30 reserved launches per enrollment
   & 32 preparation attempts (including failures) are permitted; enrollment may
   impose a smaller launch ceiling.

Model identities & authority differ: Sage is enrolled necessity authority;
Fable/Astra are independently launched reviewers. Caller-provided persona strings
or copied session IDs cannot satisfy these requirements. No approval is inferred
from Git authorship, Oracle PASS or technically passing tests.

## Current revision & managed delivery

`check` reads current protected state, verifies actual immutable source objects &
returns `deliveryLease: false`. Its output is diagnostic, **not** a transferable
grant or permission to publish later. It never authenticates an artifact/source
relationship supplied by a caller.

`push` holds the authoritative transaction through authorization & managed push.
It pushes an explicit object ID to enrolled URL/ref as nonroot owner from a fresh
protected bare repository. Only source objects are shared; mutable repository/user
configuration, replacement refs, URL rewrites & follow-tags settings are excluded.
Existing gates run through explicitly enrolled protected push-hook directory;
installation must preserve their launcher behavior. Worktree HEAD, remote aliases
& caller argv are not substituted.
Successful delivery advances baseline/revision. Subsequent unchanged closures
require deterministic checks only, with zero model launches.

Before external push, broker durably journals a pending delivery. Failure or
uncertain outcome holds subsequent delivery for protected reconciliation. No
automatic retry pretends an uncertain external effect did not happen.

`revoke` is denial-only, monotonically advances revision & invalidates pending
candidate decisions. Reviews release transaction lock during model latency;
revocation can win before delivery. A revocation ordered after delivery starts
cannot recall an in-flight external effect. There is no midbuild-cancellation
promise, TTL-only freshness proof or cached crosshost approval.

## Shared consumers & coverage boundary

`consume` accepts only enrolled freeze `id`, typed `operation` (`Build`, `Dequeue`
or `Publish`) & `native_record_id`. It cannot select an executable, argv,
environment, source, artifact relationship, destination, candidate or approval.
Protected enrollment selects at most one fixed native adapter per operation,
pins executable SHA-256 & runtime/config dependency inventory, nonroot UID/HOME,
exact endpoint/destination & bounded transaction deadline. Missing enrollment
returns `native_consumer_not_enrolled`. Existing enrollments default to no adapters.

Adapter executable & declared dependencies require canonical literal paths with
root-owned ancestry, no symlinks or other-user write access & matching byte
digests. Executable must have native ELF/Mach-O format; scripts are rejected.
HOME belongs to enrolled nonroot UID, resists other writers & has root-owned
ancestry. Child uses fixed `sudo`/`env -i`, cwd `/`, scrubbed environment & private
stdin/stdout pipes. Enrollment administrator must inventory complete runtime &
configuration custody; adapter must never load user plugins, scripts or mutable
HOME configuration as executable authority. OS runtime remains trusted. No
automatic transitive dependency discovery or sandbox claim exists.

Private pipe uses `legion-native-consume-v1` JSON lines:

1. Broker sends `prepare` with operation, native record ID & fresh
   `preparation_nonce`. Native owner resolves authoritative record, locks its
   transaction & prepares exact immutable source/effect/provenance. It performs
   no required effect during preparation.
2. Adapter returns `prepared`, echoing protocol/preparation nonce & typed `effect`:
   repository, operation, native record ID, immutable `source_oid`, optional
   native-resolved candidate, endpoint/destination, `native_effect_sha256`,
   `provenance_sha256` & optional `artifact_sha256` (required for publication).
   Digests use 64 lowercase hex digits; enrolled file pins use `sha256:` prefix.
3. Broker independently snapshots actual Git bytes, evaluates current protected
   freeze/reviews & fsyncs typed `pendingConsume` journal. Lock order is native
   owner transaction first, then freeze lock; preflight releases freeze lock
   before preparation. Final authority state is re-read under freeze lock, which
   stays held through commit/completion. Broker then sends `commit` with fresh
   `transaction_nonce` revealed only at commit & SHA-256 of broker's compact
   serialized `PreparedEffect` struct (fields in order listed above).
4. Adapter checks exact prepared digest & commits that same locked effect. Only
   after actual effect finishes does it return `complete`, echoing protocol,
   transaction nonce & prepared digest, close pipes & exit successfully. An old
   or prequeued completion cannot predict fresh transaction nonce.

Every frame is capped at 32 KiB; total transaction deadline includes native
pinning, preparation & completion. Failed child is terminated through managed
process-tree cleanup. Any failure after durable journal, including lost commit
or completion, preserves reconciliation hold. Pending consume blocks subsequent
prepare, review, check, push & consume; status exposes exact pending record.
Protected reconciliation has no client clear/retry route. Successful consume
clears journal without advancing baseline/revision. `check` still grants no lease.

Build/dequeue adapters run at actual native start, never merely queue admission;
queue admission cannot authorize future dequeue. Nonroot native owner starts
build itself; broker never runs nested root builds. Publication adapter resolves
exact immutable artifact bytes & authenticates source/qualification provenance
inside its owner transaction before preparation, retains custody through commit
& performs actual publication. Caller-supplied commit/digest fields cannot replace
owner verification. There is no general runner, portable token, daemon or new
transport service.

Legion owns authority policy, host review capture & this broker. RightKit owns
shared managed push/publication integration; RustRight owns build admission.
Consumers must use current broker state at actual effect boundary. A publication
consumer additionally verifies exact built artifact bytes against existing
RightKit source/qualification provenance inside its managed delivery transaction.
Neither a successful `check` nor a claimed commit field implements that step.

This implementation provides broker-mediated Git push & native consumer transaction
substrate. No real RightKit/RustRight owner adapters or native consumer deployment
are supplied yet; this is not complete build/publication enforcement. It does not
claim universal Git enforcement, a completed publication adapter, installed build/dequeue gates,
automatic human-prompt capture, or hooks covering arbitrary Python/editor/SSH
mutations. Local hooks can be bypassed; universal push enforcement also requires
remote required checks without agent-accessible bypass. Shared consumer deployment
is separate from qualifying this source.

## CLI transport

Native CLI accepts bounded JSON on stdin; responses are JSON, failures exit nonzero.

```text
legion authority freeze admin-enroll < owner-controlled-enrollment.json
legion authority freeze broker < request.json
```

Requests: `status`, `prepare`, `review`, `check`, `push`, `consume`, `revoke`. Each names enrolled
`id`; consumers pin that id in protected host configuration. `prepare` takes
`base_source`, `patch`, `missed_review_reason`; `review` takes `candidate`; `check`
takes `source`, optional `candidate` & typed `operation`; `push` takes `source` &
optional `candidate`. There is no caller-selected store, reviewer, provider, shell
or approval import route. Do not expose administrative enrollment to agent RPC.
`consume` takes `operation` & `native_record_id` only, alongside enrollment `id`.

## Qualification

Pure policy tests cover missing/forged/stale/wrong-repository evidence, changed
patch/result/definition, aliased reviewers, shared context, wrong chronology,
revocation & zero-observation ambient/unchanged paths. Native tests cover strict
model/session parsing, protected store behavior & immutable Git selectors.
CI-only macOS integration exercises actual broker CLI, protected state & launched
fixture transports, including successful exact push, changed-source denial,
unchanged delivery without new reviews & revocation. Fixture metadata is transport
test evidence, not proof of a live provider or installed mandatory-set pilot.
New CI-only native consumer source cases remain unexecuted & unqualified. Fixture
compiles fixed record/source mapping into pinned native bytes to exercise actual
private pipes, privilege drop, commit digest,
successful effect, changed-source denial, revocation, lost completion,
replayed completion & persistent reconciliation hold. Fixture effect is trace
append, not a product build or publication. Pure tests cover strict request/frame
parsing, typed operation enrollment, exact source/destination/artifact binding &
durable authorization before commit.

Pilot acceptance: zero accepted forged/stale/changed candidates; zero model calls
for unchanged closure; no ordinary-repository freeze; three reserved launches per
new candidate; no calls after exhausted ceiling; every failed required observation
holds delivery. Before expanding deployment, run ten unchanged checks on each
participating host: every check must complete within ten seconds, with zero model
launches. This budget excludes model review & external network delivery. Record
actual gate latency & live-provider installation separately.
