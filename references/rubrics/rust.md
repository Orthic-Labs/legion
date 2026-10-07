# Rubric pack: Rust (`**/*.rs`)

Loaded by `correctness`, `security`, `resilience`, and `performance` when scoped files match. Every
finding still needs a real `file:line`; a pattern below is a candidate until the surrounding code
confirms it.

## Correctness
- `unwrap()` / `expect()` / indexing / slicing on input that crosses a trust or I/O boundary. A panic
  there is a reachable crash, not style. Test code and proven-infallible constants are exempt.
- `as` casts that narrow, change sign, or go float to int on externally supplied numbers; prefer
  `try_from` and a typed error.
- Integer arithmetic on lengths, offsets, sizes, or money without `checked_*` / `saturating_*` where
  overflow changes behaviour (release builds wrap silently).
- A `Result` or `Option` discarded with `let _ =` or `.ok()` on an operation whose failure matters
  (write, rename, send, spawn, flush).
- Holding a `std::sync` lock or `RefCell` borrow across an `.await`; blocking calls (file, process,
  `std::thread::sleep`, blocking channel) inside an async task.
- `select!` / `timeout` arms that drop a future holding partially completed state (cancellation
  safety); `tokio::spawn` handles whose `JoinError` is never observed.
- Iterator or collection order assumed stable where the type is a `HashMap`/`HashSet`.

## Security
- Every `unsafe` block: is the invariant written down next to it, and is the safe wrapper actually
  sound for all inputs? `transmute`, `from_raw_parts`, `get_unchecked`, `set_len`, raw FFI pointers.
- Path joins from untrusted strings without canonicalisation and a prefix check; `..` and absolute
  components accepted by `Path::join`.
- `Command::new` with a shell (`sh -c`) or string-built arguments from external input; prefer an
  argument vector and an allow-listed program.
- Secrets in `Debug` / `Display` derives, logs, error messages, or `format!` of a whole config struct.
- Deserialisation of untrusted input into types without size, depth, or length bounds.
- Hand-rolled crypto, non-constant-time secret comparison, or a fixed/zero nonce or seed.

## Resilience and performance
- Unbounded channels, `Vec` growth, or `read_to_end` on input the caller does not size-limit.
- Retry loops with no cap, no backoff, or no cancellation.
- `.clone()` of large buffers inside loops, `String` rebuilt per iteration, `collect()` into a vector
  only to iterate it once.
- `Mutex<HashMap<..>>` on a hot path where contention is evident from the call graph.
- Temp files, child processes, or locks not cleaned up on the error path (no guard type, no `Drop`).

## Not findings
- Lints already enforced in CI (`clippy -D warnings`): cite the lint config, do not restate it.
- `unwrap()` in tests, examples, and build scripts.
