//! Port of `qa.mjs`'s `freePort()` and `waitForHttp()` (lines 218-252): pure retry/backoff logic
//! behind traits for the actual TCP connect / HTTP GET, so it is testable without real sockets.

/// Abstracts "is something already listening on 127.0.0.1:<port>?" (the `createConnection`
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
            return Err(format!("No free loopback port found from {start_at} to {}.", start_at + 200));
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
    let mut last = String::new();
    loop {
        match probe.attempt(url) {
            HttpAttempt::Ok => return Ok(()),
            HttpAttempt::NotOk { status, status_text } => last = format!("{status} {status_text}"),
            HttpAttempt::Error(msg) => last = msg,
        }
        if probe.elapsed_ms() >= timeout_ms {
            return Err(format!("Timed out waiting for {url}: {last}"));
        }
        probe.sleep(250);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeTakenUntil(u32);
    impl PortProbe for FakeTakenUntil {
        fn is_taken(&mut self, port: u32) -> bool {
            port < self.0
        }
    }

    #[test]
    fn free_port_returns_first_untaken() {
        let mut p = FakeTakenUntil(1425);
        assert_eq!(free_port(&mut p, 1422).unwrap(), 1425);
    }

    struct AllTaken;
    impl PortProbe for AllTaken {
        fn is_taken(&mut self, _port: u32) -> bool {
            true
        }
    }

    #[test]
    fn free_port_errors_past_range() {
        let mut p = AllTaken;
        let e = free_port(&mut p, 1422).unwrap_err();
        assert_eq!(e, "No free loopback port found from 1422 to 1622.");
    }

    struct ScriptedHttp {
        attempts: Vec<HttpAttempt>,
        idx: usize,
        elapsed: u64,
    }
    impl HttpProbe for ScriptedHttp {
        fn attempt(&mut self, _url: &str) -> HttpAttempt {
            let a = self.attempts.remove(0);
            self.idx += 1;
            a
        }
        fn elapsed_ms(&self) -> u64 {
            self.elapsed
        }
        fn sleep(&mut self, ms: u64) {
            self.elapsed += ms;
        }
    }

    #[test]
    fn wait_for_http_succeeds_on_first_ok() {
        let mut p = ScriptedHttp { attempts: vec![HttpAttempt::Ok], idx: 0, elapsed: 0 };
        assert!(wait_for_http(&mut p, "http://x", 30000).is_ok());
    }

    #[test]
    fn wait_for_http_retries_then_succeeds() {
        let mut p = ScriptedHttp {
            attempts: vec![HttpAttempt::Error("ECONNREFUSED".into()), HttpAttempt::NotOk { status: 503, status_text: "Busy".into() }, HttpAttempt::Ok],
            idx: 0,
            elapsed: 0,
        };
        assert!(wait_for_http(&mut p, "http://x", 30000).is_ok());
    }

    #[test]
    fn wait_for_http_times_out_with_last_error() {
        let mut p = ScriptedHttp { attempts: vec![HttpAttempt::Error("boom".into())], idx: 0, elapsed: 30000 };
        let e = wait_for_http(&mut p, "http://x", 30000).unwrap_err();
        assert_eq!(e, "Timed out waiting for http://x: boom");
    }
}
