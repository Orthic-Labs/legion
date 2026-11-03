//! Port of `qa.mjs`'s `freePort()` and `waitForHttp()` (lines 218-252): pure retry/backoff logic
//! behind traits for the actual TCP connect / HTTP GET, so it is testable without real sockets.

/// Abstracts "is something already listening on 127.0.0.1:`<port>`?" (the `createConnection`
/// probe in `freePort`, qa.mjs lines 218-236: `connect` means taken, `error` means free).
pub trait PortProbe {
    fn is_taken(&mut self, port: u32) -> bool;
}

/// Port of `freePort(startAt)` (qa.mjs lines 218-236): scans `startAt..=startAt+200`, returning
/// the first free port or erroring past the range.
pub fn free_port(probe: &mut dyn PortProbe, start_at: u32) -> Result<u32, String> {
    let mut candidate = start_at;
    loop {
        if candidate > start_at + 200 {
            return Err(format!(
                "No free loopback port found from {start_at} to {}.",
                start_at + 200
            ));
        }
        if !probe.is_taken(candidate) {
            return Ok(candidate);
        }
        candidate += 1;
    }
}

/// One `fetch(url)` attempt's outcome, mirroring `waitForHttp`'s `try { const res = await
/// fetch(url); if (res.ok) return; last = ...status...; } catch (error) { last = ...; }`
/// (qa.mjs lines 238-252).
pub enum HttpAttempt {
    Ok,
    NotOk { status: u16, status_text: String },
    Error(String),
}

/// Abstracts one `fetch(url)` call plus the `wait(250)` between retries, so `wait_for_http` is
/// testable with a scripted sequence of attempts and no real clock/network.
pub trait HttpProbe {
    fn attempt(&mut self, url: &str) -> HttpAttempt;
    /// Elapsed time (ms) since the probe's own start; used in place of `Date.now() - started`.
    fn elapsed_ms(&self) -> u64;
    fn sleep(&mut self, ms: u64);
}

/// Port of `waitForHttp(url, timeoutMs = 30000)` (qa.mjs lines 238-252).
pub fn wait_for_http(probe: &mut dyn HttpProbe, url: &str, timeout_ms: u64) -> Result<(), String> {
    loop {
        let last = match probe.attempt(url) {
            HttpAttempt::Ok => return Ok(()),
            HttpAttempt::NotOk {
                status,
                status_text,
            } => format!("{status} {status_text}"),
            HttpAttempt::Error(msg) => msg,
        };
        if probe.elapsed_ms() >= timeout_ms {
            return Err(format!("Timed out waiting for {url}: {last}"));
        }
        probe.sleep(250);
    }
}
