Controls for `tests/sqlfluff_accuracy.rs`. Files carry a `.txt` suffix so repository
SQL scanners never treat deliberate parse failures as project SQL; the test copies
each to the `.sql` (or `.sqlfluff`) name inside a temporary repository.
