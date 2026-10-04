# Export samples & symbolicate

Inspect trace table of contents before choosing an XPath:

```sh
xcrun xctrace export --input /tmp/App.trace --toc
xcrun xctrace export --input /tmp/App.trace \
  --xpath '/trace-toc/run[@number="1"]/data/table[@schema="time-sample"]' \
  --output /tmp/time-sample.xml
```

Some Xcode releases expose `time-profile` rather than `time-sample`; use the schema shown by `--toc`, then preserve XML outside chat. Do not print large exports to terminal.

For symbolication, use binary/dSYM from exact revision/configuration that produced trace. On macOS, read runtime `__TEXT` load address from `vmmap PID`; ASLR makes a hard-coded address unsafe. On iOS device, use the process/device address reported by the capture and matching symbols. `atos -o BINARY -l LOAD_ADDRESS ADDRESS...` can symbolize batches; an unsymbolicated frame is not a hotspot claim.

Check binary identity, architecture, UUID/dSYM and load address before comparing runs. Wrong binary path, stale dSYM or wrong ASLR base can produce plausible but false names. Keep raw addresses and private symbols in local evidence.

Native Rust routes now cover reviewed export & symbolication contracts. Canonical `profile.export` accepts explicit `trace_path` and `output_path` through mobile's typed `xcrun xctrace export` route; inspect TOC/schema before selecting an export. Pure `profile.parse` uses a bounded XML reader to expand referenced `kperf-bt` stacks. `profile.symbols` filters `[load_address, load_address + __TEXT size)`, ranks address/count pairs, prepares bounded `/usr/bin/atos` argv batches, and assembles deterministic `address,count,symbol` CSV after returned symbols are matched. Canonical `symbolicate` effect remains mobile's typed route. Preserve raw XML and symbols privately, verify binary/dSYM UUID and runtime load address, and treat missing or unsymbolicated rows as evidence gaps. These routes never use shell interpolation or claim hotspot meaning without matching symbols.
