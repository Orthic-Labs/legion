# Issue workflow

- Search the open issues before you file a new one, and put `Checked: #<n>[, #<n>...] (search "<terms>")` (or `Checked: none found (search "<terms>")`) in the body of every `gh issue create`; `legion-hook` denies the create without it (check id `issue-search`, `engine/bins/legion-hook/src/issue_gate.rs`).
- Close a contract only after its `decision` issues are closed and each decision is written into the contract; `legion run close` refuses a complete close while an open `decision` issue carries a `Contract: <contract id>` line (`engine/bins/legion/src/commands/run.rs`, `ARC_DECISION_ISSUES_OPEN`; `--disposition archive` is not refused).
