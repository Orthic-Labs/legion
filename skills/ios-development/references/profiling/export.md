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

Reusable native helper requirements: port trace-table export with TOC/schema selection and missing-output failure; port kperf stack reference expansion, `__TEXT` range filtering, bounded `atos` batches and address/count/symbol CSV. Keep upstream Python as source evidence; no executable helper is shipped until a Rust port exists.
