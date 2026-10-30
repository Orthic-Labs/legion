# Bounded ordinary review ledger

Use `legion review-loop assess --input review-ledger.json` when successive reviews need explicit
finding continuity. It validates imported records; it does not review source, run tests, invoke
Oracle, issue a Guard receipt or permit commit/push. This optional local assessment adds no GitHub
requests and preserves Commit's four-request budget and frozen-diff endpoint.

Bind the ledger to the exact current artifact digest and base, name its implementer and independent
reviewer, and set a finite round budget before starting. Commit's existing maximum of two repair/
recheck cycles still applies even if the native schema permits a larger round budget. Begin with a
complete full review with evidence. A delta review must name the prior digest, follow a complete
evidenced round and retain the same base. A base change requires a new full review; never reuse
stale approval. Independent review of another agent's work belongs to Oracle.

Keep stable finding IDs, kind (`outcome`, `safety`, `advisory`) and criterion. A fix is
`fixed_pending` until independent source/evidence review resolves it at the reviewed digest.
Omission never closes a finding; relabeling a blocker advisory does not resolve it. Open,
disputed, fixed-pending or deferred outcome/safety findings block approval. Advisory residue may be
reported without blocking. A self-review, incomplete round, missing evidence or invalid lineage
cannot yield approval. Stop with named findings and resume action at exhaustion; a tool's approved
diagnostic is imported evidence with `effectAuthority: none`, never authorization.

Invalid historical rounds remain non-approvable even after a later valid round. Correct erroneous
source records with traceable evidence while retaining genuine unresolved findings and the actual
round budget; never discard invalid history or restart an exhausted budget to manufacture approval.
The command assesses a supplied ledger; it does not repair records or drive an execution loop.
The integration owner can record an Oracle response as an imported assertion; Oracle creates no
review artifact and retains its own smaller repair/recheck limit.
