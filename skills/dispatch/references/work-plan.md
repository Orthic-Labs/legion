# Bounded executable work declarations

Use the native work-plan validator when independently executable units share a
repository or completion needs explicit evidence accounting. Legion still owns
orchestration; producing capabilities settle acceptance criteria. Validation
does not add a role, authorize effects, dispatch workers, or issue receipts.

1. Create a schema-version-1 work plan with a plan identity and one unit per
   independently executable result. Each unit names a unique task identity,
   owner identity, explicit `read_only` or `write` access, current unit revision,
   actual dependencies, observable completion predicates, and named evidence needs.
   Write units declare one or more exclusive write scopes. Read-only units declare
   no write scopes and may bind completion predicates to observed repository artifacts.
2. Declare each scope as a repository-relative `file` or `directory`. Paths use
   normalized ASCII components separated by `/`. Root paths, traversal, globs,
   platform aliases, device names and ambiguous separators are rejected. Scope
   comparison conservatively folds ASCII case. Filesystem resolution, symlink
   containment and effect enforcement remain the host's responsibility.
3. Give every predicate an artifact path, revision and lowercase SHA-256 digest.
   For write units, the artifact must fall within the unit's declared write scope.
   Read-only units may identify an observed artifact outside write ownership. Each
   predicate needs at least one uniquely named evidence requirement; a requirement
   can demand a distinct reviewer identity.
4. Validate before assignment. Resolve missing dependencies, cycles and scope
   conflicts. Shared owner identities do not permit concurrent conflicting
   writes. A genuine direct or transitive dependency permits serialized writes;
   inventing step order does not create authority. Dispatch only ready units
   within actual host capacity and the existing Guard/effect boundaries.
5. Keep units `pending` until all named evidence is supplied as `passed` and all
   dependencies are complete. Evidence must match its requirement, predicate,
   owner, current unit identity/revision and exact artifact path/revision/digest.
   Required review names a reviewer different from the author/owner. Update
   declarations and replace stale evidence after a material artifact or unit
   change, then validate again.

The Rust API is `legion_runtime::workplan::parse_work_plan_json` followed by
`validate_work_plan`. Its assessment returns deterministic `topologicalOrder`,
`readyUnits`, `assertedCompleteUnits` and the explicit assurance value
`imported_assertions_only`. Failures have a reason code, field and optional unit
identity. The JSON entry point admits at most 2 MiB; validation admits 128 units,
32 items in each unit list and 1024 bytes per free-text field. Unknown JSON
fields are rejected. Use a bounded read before the JSON entry point.

JSON fields use camelCase; enum values use snake_case.

Evidence is structurally checked caller-supplied assertion data. The validator
does not inspect artifact bytes, execute checks, authenticate authors/reviewers,
or prove that predicate descriptions are satisfied. A matching digest is a
binding declaration, not a verified filesystem digest. Independent assurance and
effect authorization continue through Oracle and Guard where required; this
assessment cannot substitute for their evidence.

The checked-in native fixture `engine/crates/legion-runtime/tests/workplan-ready.json`
shows two disjoint ready units and one integration unit serialized behind both.
Its repeated placeholder digests are example declarations, not measured proof.
