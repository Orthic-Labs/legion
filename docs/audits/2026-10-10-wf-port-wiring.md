# wf_port wiring audit, 2026-10-10

Scope: direct child modules of `engine/crates/legion-runtime/src/wf_port/` and `engine/crates/legion-audit/src/wf_port/`. Read-only; no builds, no source edits.

Method: line counts are newline counts of every `*.rs` under each module directory. A reference is a `wf_port::X` path or `X::` path in a file that mentions `wf_port`, found by grep-style scan of all `engine/**/*.rs` (excluding `target/`), outside the module's own directory. Comment lines and `//` trailers are ignored. Brace-only `use` imports are not counted as use; the module must be used by path. Class rules: WIRED = a production reference (non-test, outside `wf_port`); TEST-ONLY = references only from `tests/` files or `#[cfg(test)]` blocks; INTERNAL = referenced only from other `wf_port` modules; UNREFERENCED = no reference at all. Rows sort by class (WIRED, TEST-ONLY, INTERNAL, UNREFERENCED), then lines descending. A `tests` reference from a file that also contains code is counted as test only when it sits in a `#[cfg(test)]` block.

| module | lines | class | first reference or referencing tests |
|---|---:|---|---|
| `runtime/r46` | 6675 | WIRED | `engine/bins/legion/src/commands/script.rs:1900` (+3 more production sites); tests: 4 sites |
| `runtime/r37` | 4749 | WIRED | `engine/bins/legion/src/commands/script.rs:2177` (+6 more production sites); tests: 4 sites |
| `runtime/w2_016` | 4615 | WIRED | `engine/bins/legion/src/commands/script.rs:660` (+1 more production sites) |
| `runtime/w2_018` | 4503 | WIRED | `engine/bins/legion/src/commands/script.rs:641`; tests: 2 sites |
| `runtime/w2_007` | 3887 | WIRED | `engine/bins/legion/src/commands/script.rs:1551` (+18 more production sites); tests: 2 sites |
| `runtime/w2_033` | 3524 | WIRED | `engine/bins/legion/src/commands/script.rs:391` (+3 more production sites); tests: 5 sites |
| `runtime/w2_020` | 3402 | WIRED | `engine/bins/legion/src/commands/script.rs:695` (+2 more production sites); tests: 4 sites |
| `runtime/w2_032` | 3402 | WIRED | `engine/bins/legion/src/commands/script.rs:427` (+5 more production sites); tests: 5 sites |
| `runtime/w2_030` | 3314 | WIRED | `engine/bins/legion/src/commands/script.rs:405` (+3 more production sites); tests: 7 sites |
| `runtime/w2_034` | 3240 | WIRED | `engine/bins/legion/src/commands/script.rs:454` (+9 more production sites); tests: 5 sites |
| `runtime/w2_031` | 2941 | WIRED | `engine/bins/legion/src/commands/script.rs:31` (+11 more production sites); tests: 2 sites |
| `runtime/r03` | 2697 | WIRED | `engine/bins/legion/src/commands/script.rs:1451` (+14 more production sites); tests: 3 sites |
| `runtime/w2_010` | 2636 | WIRED | `engine/bins/legion/src/commands/script.rs:938` (+7 more production sites); tests: 4 sites |
| `runtime/r18` | 2608 | WIRED | `engine/bins/legion/src/commands/script.rs:775`; tests: 2 sites |
| `runtime/r54` | 2512 | WIRED | `engine/bins/legion/src/commands/script.rs:2370` (+1 more production sites); tests: 7 sites |
| `runtime/w2_029` | 2373 | WIRED | `engine/bins/legion/src/commands/script.rs:513` (+10 more production sites); tests: 9 sites |
| `audit/wf010` | 2332 | WIRED | `engine/bins/legion-dev/src/generators/manifest.rs:18`; tests: 7 sites |
| `runtime/w2_044` | 2275 | WIRED | `engine/bins/legion/src/commands/script.rs:2039` (+6 more production sites); tests: 2 sites |
| `runtime/r14` | 2236 | WIRED | `engine/bins/legion/src/commands/script.rs:815` (+4 more production sites) |
| `runtime/r12` | 2209 | WIRED | `engine/bins/legion/src/commands/script.rs:785` (+1 more production sites) |
| `runtime/w2_025` | 2167 | WIRED | `engine/bins/legion/src/commands/script.rs:2612` (+4 more production sites); tests: 5 sites |
| `runtime/r24` | 2121 | WIRED | `engine/bins/legion/src/commands/script.rs:669` (+7 more production sites); tests: 2 sites |
| `runtime/w2_017` | 1953 | WIRED | `engine/bins/legion/src/commands/script.rs:716` (+1 more production sites); tests: 5 sites |
| `runtime/w2_019` | 1933 | WIRED | `engine/bins/legion/src/commands/script.rs:726` (+5 more production sites); tests: 5 sites |
| `runtime/w2_028` | 1865 | WIRED | `engine/bins/legion/src/commands/script.rs:583` (+13 more production sites); tests: 4 sites |
| `runtime/r00` | 1807 | WIRED | `engine/bins/legion/src/commands/script.rs:1252` (+16 more production sites); tests: 3 sites |
| `runtime/w2_006` | 1759 | WIRED | `engine/bins/legion/src/commands/script.rs:2299` (+5 more production sites); tests: 1 sites |
| `runtime/r02` | 1735 | WIRED | `engine/bins/legion/src/commands/script.rs:1498` (+9 more production sites); tests: 2 sites |
| `runtime/r13` | 1702 | WIRED | `engine/bins/legion/src/commands/script.rs:841` (+2 more production sites) |
| `runtime/r05` | 1700 | WIRED | `engine/bins/legion/src/commands/script.rs:1186` (+6 more production sites); tests: 2 sites |
| `runtime/r22` | 1478 | WIRED | `engine/bins/legion/src/commands/script.rs:646` (+1 more production sites); tests: 2 sites |
| `runtime/r08` | 1273 | WIRED | `engine/bins/legion/src/commands/script.rs:1166`; tests: 1 sites |
| `runtime/w2_005` | 1240 | WIRED | `engine/bins/legion/src/commands/script.rs:278` (+6 more production sites); tests: 1 sites |
| `runtime/r07` | 1060 | WIRED | `engine/bins/legion/src/commands/script.rs:1154` (+8 more production sites); tests: 6 sites |
| `runtime/r04` | 998 | WIRED | `engine/bins/legion/src/commands/script.rs:930`; tests: 2 sites |
| `runtime/r32` | 770 | WIRED | `engine/bins/legion/src/commands/script.rs:399`; tests: 1 sites |
| `runtime/w2_023` | 467 | WIRED | `engine/bins/legion/src/commands/script.rs:1087` (+5 more production sites); tests: 1 sites |
| `runtime/w2_045` | 446 | WIRED | `engine/bins/legion/src/commands/script.rs:3616`; tests: 1 sites |
| `runtime/w2_027` | 437 | WIRED | `engine/bins/legion/src/commands/script.rs:3464` (+3 more production sites); tests: 1 sites |
| `audit/wf065` | 8122 | TEST-ONLY | tests: `wf_wf065.rs:11`, `wf_wf065.rs:14` (+12 more) |
| `runtime/w2_021` | 4418 | TEST-ONLY | tests: `r24_live_server.rs:16`, `r26_live_wrap.rs:12` (+13 more); also internal from wf_port: r18, r24, w2_017, w2_019, w2_020 |
| `audit/wf064` | 4111 | TEST-ONLY | tests: `audit_conformance.rs:12`, `wf_wf064.rs:10` (+3 more); also internal from wf_port: wf010, wf065 |
| `audit/wf052` | 3722 | TEST-ONLY | tests: `wf_wf052.rs:13`, `wf_wf052.rs:14` (+3 more); also internal from wf_port: wf055, wf063 |
| `audit/wf047` | 3632 | TEST-ONLY | tests: `wf_wf047.rs:12`, `wf_wf047.rs:13` (+3 more) |
| `audit/wf066` | 3283 | TEST-ONLY | tests: `wf_wf066.rs:26`, `wf_wf066.rs:29` (+2 more) |
| `audit/wf049` | 3245 | TEST-ONLY | tests: `wf_wf049.rs:9`, `wf_wf049.rs:12` (+4 more); also internal from wf_port: wf048 |
| `runtime/w2_022` | 3150 | TEST-ONLY | tests: `wf_r31_svelte_component_fs.rs:15`, `wf_w2_022.rs:12` (+3 more); also internal from wf_port: r22, r24, w2_018, w2_020 |
| `audit/wf055` | 2737 | TEST-ONLY | tests: `wf_wf055.rs:24`, `wf_wf055.rs:27` (+3 more); also internal from wf_port: wf053 |
| `runtime/w2_012` | 2618 | TEST-ONLY | tests: `wf_w2_012.rs:5`, `wf_w2_012.rs:9` (+2 more); also internal from wf_port: r09, w2_013 |
| `runtime/w2_011` | 2606 | TEST-ONLY | tests: `wf_r06.rs:19`, `wf_w2_011.rs:9`; also internal from wf_port: r09, r14 |
| `runtime/w2_013` | 2598 | TEST-ONLY | tests: `wf_w2_013.rs:6`, `wf_w2_013.rs:7` (+3 more) |
| `audit/wf060` | 2539 | TEST-ONLY | tests: `wf_wf060.rs:27`, `wf_wf060.rs:28`; also internal from wf_port: wf063 |
| `audit/wf059` | 2499 | TEST-ONLY | tests: `wf_wf059.rs:26`, `wf_wf059.rs:27` (+5 more) |
| `audit/wf062` | 2485 | TEST-ONLY | tests: `wf_wf062.rs:33` |
| `audit/wf048` | 2329 | TEST-ONLY | tests: `wf_wf048.rs:17`, `wf_wf048.rs:18` (+2 more); also internal from wf_port: wf047 |
| `audit/wf053` | 2293 | TEST-ONLY | tests: `wf_wf053.rs:11`, `wf_wf053.rs:154` (+1 more) |
| `audit/wf063` | 2005 | TEST-ONLY | tests: `wf_wf063.rs:22`, `wf_wf063.rs:23` (+3 more) |
| `audit/wf050` | 1985 | TEST-ONLY | tests: `wf_wf050.rs:18`, `wf_wf050.rs:19` (+3 more) |
| `audit/wf061` | 1869 | TEST-ONLY | tests: `wf_wf061.rs:8` |
| `audit/wf057` | 1773 | TEST-ONLY | tests: `wf_wf057.rs:15`, `wf_wf057.rs:762` |
| `audit/wf003` | 1661 | TEST-ONLY | tests: `wf_wf003.rs:18` |
| `audit/wf005` | 1583 | TEST-ONLY | tests: `wf_wf005.rs:23` |
| `runtime/r09` | 1528 | TEST-ONLY | tests: `r09_css_cascade.rs:14`; also internal from wf_port: r11, w2_013 |
| `audit/wf054` | 1448 | TEST-ONLY | tests: `wf_wf054.rs:20`; also internal from wf_port: wf053 |
| `audit/wf011` | 1295 | TEST-ONLY | tests: `wf_wf011.rs:12` |
| `audit/wf014` | 1238 | TEST-ONLY | tests: `wf_wf014.rs:11` |
| `audit/wf056` | 1124 | TEST-ONLY | tests: `wf_wf056.rs:25`, `wf_wf056.rs:504` |
| `runtime/w2_014` | 1124 | TEST-ONLY | tests: `wf_w2_014.rs:10`, `wf_w2_014.rs:14`; also internal from wf_port: r07, r11 |
| `runtime/w2_008` | 1094 | TEST-ONLY | tests: `wf_w2_008.rs:17`, `wf_w2_008.rs:135` (+1 more); also internal from wf_port: r03 |
| `audit/wf019` | 1092 | TEST-ONLY | tests: `wf_wf019.rs:10`, `wf_wf019.rs:13`; also internal from wf_port: wf020 |
| `runtime/w2_015` | 1069 | TEST-ONLY | tests: `wf_w2_015.rs:10`; also internal from wf_port: r13, r14 |
| `audit/wf013` | 852 | TEST-ONLY | tests: `wf_wf013.rs:46`, `wf_wf013.rs:65` (+2 more) |
| `audit/wf021` | 846 | TEST-ONLY | tests: `wf_wf021.rs:17` |
| `audit/wf012` | 801 | TEST-ONLY | tests: `audit_conformance.rs:9`, `wf_wf012.rs:10` |
| `audit/wf037` | 691 | TEST-ONLY | tests: `wf_wf037.rs:11` |
| `audit/wf058` | 606 | TEST-ONLY | tests: `wf_wf058.rs:28` |
| `audit/wf038` | 563 | TEST-ONLY | tests: `wf_wf038.rs:12` |
| `audit/wf001` | 506 | TEST-ONLY | tests: `wf_wf001.rs:8` |
| `audit/wf039` | 427 | TEST-ONLY | tests: `wf_wf039.rs:5` |
| `audit/wf022` | 402 | TEST-ONLY | tests: `wf_wf022.rs:7` |
| `audit/wf009` | 362 | TEST-ONLY | tests: `wf_wf009.rs:8` |
| `audit/w2_059` | 360 | TEST-ONLY | tests: `wf_w2_059.rs:11` |
| `audit/wf004` | 346 | TEST-ONLY | tests: `wf_wf004.rs:13` |
| `runtime/q_q1` | 240 | TEST-ONLY | tests: `q_q1_paths.rs:5`; also internal from wf_port: r24 |
| `audit/w2_058` | 140 | TEST-ONLY | tests: `wf_w2_058.rs:19` |
| `audit/wf020` | 48 | TEST-ONLY | tests: `wf_wf020.rs:28` |
| `runtime/r11` | 3048 | INTERNAL | wf_port modules only: w2_013 |
| `audit/r66` | 2008 | INTERNAL | wf_port modules only: wf063 |
| `runtime/u03` | 978 | UNREFERENCED | none (no code reference outside its directory) |
| `audit/q_q6` | 307 | UNREFERENCED | none (no code reference outside its directory) |
| `audit/wf051` | 7 | UNREFERENCED | none (no code reference outside its directory) |

## Totals

| class | modules | lines |
|---|---:|---:|
| WIRED | 39 | 93041 |
| TEST-ONLY | 47 | 85465 |
| INTERNAL | 2 | 5056 |
| UNREFERENCED | 3 | 1292 |
| **all** | **91** | **184854** |

## Notes

- `runtime/r11` and `audit/r66` are INTERNAL. Their only referrers are `runtime/w2_013` (TEST-ONLY) and `audit/wf063` (TEST-ONLY), so they are not production-reachable. The TEST-ONLY chains `audit/wf019` (via wf020), `wf048` (via wf047), `wf049` (via wf048), `wf052` (via wf055, wf063), `wf054` and `wf055` (via wf053), `wf060` (via wf063) also have no production path.
- Eight TEST-ONLY modules are reached from production wf_port modules via non-test code: `runtime/q_q1` (via r24), `runtime/w2_008` (via r03), `runtime/w2_011` (via r09, r14), `runtime/w2_014` (via r07), `runtime/w2_015` (via r13, r14), `runtime/w2_021` (via r18, r24, w2_017, w2_019, w2_020), `runtime/w2_022` (via r22, r24, w2_018, w2_020), `audit/wf064` (via wf010, wf065). They are reachable from production only through a wf_port module, not referenced by `bins/` or a production crate directly.
- `audit/wf051` has a test file `engine/crates/legion-audit/tests/wf_wf051.rs` that refers to it only in prose. It is UNREFERENCED in code by design (the doc says it carries no logic).
- Most WIRED modules get their only production reference from the `use legion_runtime::wf_port::{...}` block and call sites in `engine/bins/legion/src/commands/script.rs`. `audit/wf010` is wired only by `engine/bins/legion-dev/src/generators/manifest.rs:18`. The three UNREFERENCED modules were grepped for any bare-name mention; none found outside their own directories.

