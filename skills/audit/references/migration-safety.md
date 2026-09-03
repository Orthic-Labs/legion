# data-safety lens — migration & destructive-SQL safety

The `data-safety` lens runs ONLY when the target or diff touches a DB migration or raw/ORM SQL. It is
the review that destructive-data ops never got — previously they only tripped a human-STOP, they were
never actually *read*. High value, low false-positive: the signals are greppable and the failure mode
(data loss / a prod lock) is severe. Every finding cites a real `file:line` in a migration/query.

In `/commit` a confirmed data-loss or prod-locking finding is a **hard stop** — surface it, do not push.

## What to flag

**Reversibility**
- Migration with no `down`/rollback path (or an empty/throwing one) — can't be undone if it's wrong.
- Irreversible step (drop, type-narrowing cast) with no backup/export noted first.

**Data loss**
- `DROP TABLE` / `DROP COLUMN` / `TRUNCATE` on a table that holds data — the column's data is gone.
  A "remove column" should be: stop writing → deploy → drop later, not drop-in-one-shot.
- Type change that can't round-trip (e.g. `text`→`int`, narrowing length) — silent truncation/failure.
- `DELETE`/`UPDATE` with no `WHERE`, or a `WHERE` that doesn't scope to the intended rows.

**Locking / availability (large tables)**
- Blocking DDL that rewrites or `ACCESS EXCLUSIVE`-locks a big table during the migration
  (`ALTER TABLE ... ADD COLUMN ... DEFAULT` on old engines, adding a `NOT NULL` without a default,
  changing a column type) — locks out reads/writes for the duration.
- `CREATE INDEX` without `CONCURRENTLY` on a large table (Postgres) — locks writes.
- Adding a `NOT NULL` or `CHECK`/FK constraint validated against the whole table in one statement.

**Backfills**
- Unbatched backfill (`UPDATE whole_table SET ...`) in the migration — long transaction, lock, replication lag.
  Prefer batched/throttled backfill outside the schema migration.

**Boundaries**
- Migration mixing schema change + data backfill + app logic in one irreversible step.
- A migration pointed at (or runnable against) a PROD connection from this tooling — never. Migrations
  run through the project's runner against dev/test; prod is the user's explicit, separate action
  (`prod-db-guard` enforces this — do not route around it).

## Output

`<class>: <what> — <safer pattern>. [file:line]`. The fix is usually the multi-step safe pattern
(expand → migrate → contract; concurrent index; batched backfill), not "don't do it." If the scope has
no migration/SQL, the lens reports `not applicable`, not "clean."
