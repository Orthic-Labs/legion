# SQLite / local-first checklist — cues for `performance`, `data-safety`, `resilience`

House reference for embedded-DB apps (every Right Suite app is local-first SQLite/SQLCipher).
Carried by the lenses when the target opens a SQLite DB (rusqlite/sqlx/better-sqlite3/sql.js/
Drizzle-sqlite in deps, or `.db`/`PRAGMA` hits in source). The generic checklist stops at
"missing indexes / N+1"; this is the embedded-DB depth beneath it.

## Connection + PRAGMA posture (`performance`)

- No PRAGMA tuning at open is a finding on a shipped app: check for explicit `journal_mode`,
  `synchronous`, `cache_size`, `mmap_size`, `busy_timeout`, `foreign_keys`. Defaults are
  conservative-to-wrong for desktop workloads.
- WAL: is `journal_mode=WAL` set? Who checkpoints, when, and NOT inside a hot lock
  (checkpoint-inside-lock is a concurrency finding — see desktop-tauri-checklist §1)?
  Unbounded WAL growth (no `wal_autocheckpoint` / manual `TRUNCATE` checkpoint) on long-running apps.
- Single-writer discipline: one writer connection + reader pool, or every caller opens ad-hoc
  connections (lock contention, `SQLITE_BUSY` swallowed)?
- `busy_timeout` unset + `SQLITE_BUSY` treated as fatal or silently retried in a loop.

## Query patterns (`performance`)

- Leading-wildcard `LIKE '%term%'` on an indexed column — defeats the index; wants FTS.
- FTS5 invariants: `UNINDEXED` columns can NOT be used in `WHERE`/`MATCH` (query silently falls
  back to full scan); `rowid` joins to the content table for filters instead.
- Full-scan `DELETE`/`UPDATE` on FTS or history tables where a rowid-ranged or indexed path exists.
- Missing `ANALYZE` (or `PRAGMA optimize` on close) — the planner runs blind on real data shapes.
- No EXPLAIN-QUERY-PLAN regression test for the hot queries (cheap to add, catches plan flips).
- N+1 across IPC: a per-row `invoke()`/query loop where one query with `IN (...)`/join serves.

## Durability + safety (`data-safety`, `resilience`)

- Unbounded growth: history/log/event tables with no pruning, no orphan sweep, no size cap.
- Migrations: irreversible/no-down, table-rebuild (12-step ALTER) without a backup/tx wrapper,
  destructive `DROP`/column-drop = data loss (per migration-safety.md — same rules apply locally).
- Corrupt-DB path: `PRAGMA integrity_check`/`quick_check` anywhere? Open failure → recover
  (rebuild, restore, rename-aside) or crash loop?
- Backup story: online backup API / `VACUUM INTO`, never a live-file copy while a writer is open.
- SQLCipher: key handling never logged; rekey path exists; plaintext temp files
  (`temp_store=MEMORY` when contents are sensitive).
