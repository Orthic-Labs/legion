//! The daily job's memory (`~/.legion/daily/ledger.json`): which events each
//! fingerprint had on each UTC day, and which issue each fingerprint became.
//! Events are keyed by a stable id and merged by union, so overlapping scan
//! windows and re-runs never count one event twice. A fingerprint "repeats on
//! two or more days" when this ledger holds it on two or more dates.
use super::{clock, receipts::write_atomic, transcripts::Failure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path};

const MAX_IDS_PER_DAY: usize = 2000;
const KEEP_DAYS: i64 = 90;
/// Windows that start within this many seconds of the last one's end join it.
const SCAN_JOIN_SECONDS: i64 = 120;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DayFp {
    #[serde(default)]
    pub ids: Vec<String>,
    /// The first quote (or flag detail) seen that day.
    #[serde(default)]
    pub quote: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Earliest and latest event time that day (epoch seconds, 0 when unknown).
    #[serde(default)]
    pub first: i64,
    #[serde(default)]
    pub last: i64,
}

impl DayFp {
    fn touch(&mut self, epoch: i64) {
        if self.first == 0 || epoch < self.first {
            self.first = epoch;
        }
        if epoch > self.last {
            self.last = epoch;
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct IssueNote {
    #[serde(default)]
    pub repo: String,
    #[serde(default)]
    pub number: u64,
    #[serde(default)]
    pub created: Option<String>,
    /// Run dates on which an occurrence comment was posted.
    #[serde(default)]
    pub commented: Vec<String>,
    /// Run dates on which the issue was reopened as "fix did not work".
    #[serde(default)]
    pub reopened: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Ledger {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub days: BTreeMap<String, BTreeMap<String, DayFp>>,
    #[serde(default)]
    pub issues: BTreeMap<String, IssueNote>,
    /// Merged `[since, until]` windows that were fully scanned on every host,
    /// so a day with no events is told apart from a day nobody looked at.
    #[serde(default)]
    pub scans: Vec<[i64; 2]>,
}

impl Ledger {
    /// A missing file is an empty ledger; an unreadable or corrupt one is an
    /// error, so the caller never mistakes lost history for "nothing recurred".
    pub fn load(path: &Path) -> Result<Ledger, String> {
        match fs::read_to_string(path) {
            Ok(body) => serde_json::from_str(&body)
                .map_err(|error| format!("{} is not valid: {error}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Ledger::default()),
            Err(error) => Err(format!("cannot read {}: {error}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let mut copy = self.clone();
        copy.version = 1;
        let body = serde_json::to_vec_pretty(&copy).map_err(|error| error.to_string())?;
        write_atomic(path, &body)
    }

    fn slot(&mut self, date: &str, fingerprint: &str) -> &mut DayFp {
        self.days
            .entry(date.to_owned())
            .or_default()
            .entry(fingerprint.to_owned())
            .or_default()
    }

    /// Merge one failure. Returns whether the ledger had not seen it.
    pub fn add_failure(&mut self, failure: &Failure) -> bool {
        let date = clock::date_of(failure.epoch);
        let fingerprint = failure.fingerprint();
        let slot = self.slot(&date, &fingerprint);
        if slot.ids.contains(&failure.id) || slot.ids.len() >= MAX_IDS_PER_DAY {
            return false;
        }
        slot.ids.push(failure.id.clone());
        slot.touch(failure.epoch);
        if slot.quote.is_empty() {
            slot.quote = failure.quote.clone();
        }
        if !slot.hosts.contains(&failure.host) {
            slot.hosts.push(failure.host.clone());
        }
        true
    }

    /// Merge a warmth flag: one event per fingerprint per date.
    pub fn add_flag(
        &mut self,
        fingerprint: &str,
        date: &str,
        host: &str,
        detail: &str,
        epoch: i64,
    ) -> bool {
        let id = format!("{fingerprint}@{date}");
        let slot = self.slot(date, fingerprint);
        if slot.ids.contains(&id) {
            return false;
        }
        slot.ids.push(id);
        slot.touch(epoch);
        if slot.quote.is_empty() {
            slot.quote = detail.to_owned();
        }
        if !slot.hosts.iter().any(|known| known == host) {
            slot.hosts.push(host.to_owned());
        }
        true
    }

    pub fn count_on(&self, date: &str, fingerprint: &str) -> usize {
        self.days
            .get(date)
            .and_then(|day| day.get(fingerprint))
            .map_or(0, |slot| slot.ids.len())
    }

    /// Dates (ascending) on which the fingerprint was seen.
    pub fn dates_for(&self, fingerprint: &str) -> Vec<String> {
        self.days
            .iter()
            .filter(|(_, day)| {
                day.get(fingerprint)
                    .is_some_and(|slot| !slot.ids.is_empty())
            })
            .map(|(date, _)| date.clone())
            .collect()
    }

    /// Seconds between the earliest and the latest event the ledger holds for
    /// the fingerprint, across all dates (0 when it has fewer than two times).
    pub fn span_seconds(&self, fingerprint: &str) -> i64 {
        let mut first = i64::MAX;
        let mut last = 0i64;
        for day in self.days.values() {
            if let Some(slot) = day.get(fingerprint) {
                if slot.first > 0 {
                    first = first.min(slot.first);
                }
                last = last.max(slot.last);
            }
        }
        if first == i64::MAX || last <= first {
            0
        } else {
            last - first
        }
    }

    /// Events in a bucket on a date, over every cause.
    pub fn bucket_total(&self, date: &str, bucket: &str) -> usize {
        let prefix = format!("{bucket}/");
        self.days.get(date).map_or(0, |day| {
            day.iter()
                .filter(|(fingerprint, _)| fingerprint.starts_with(&prefix))
                .map(|(_, slot)| slot.ids.len())
                .sum()
        })
    }

    /// Record a fully scanned window; overlapping or touching windows merge.
    pub fn record_scan(&mut self, since: i64, until: i64) {
        if until <= since {
            return;
        }
        let mut sorted = self.scans.clone();
        sorted.push([since, until]);
        sorted.sort();
        let mut merged: Vec<[i64; 2]> = Vec::new();
        for scan in sorted {
            let extend = merged
                .last()
                .is_some_and(|last| scan[0] <= last[1] + SCAN_JOIN_SECONDS);
            if extend {
                if let Some(last) = merged.last_mut() {
                    if scan[1] > last[1] {
                        last[1] = scan[1];
                    }
                }
            } else {
                merged.push(scan);
            }
        }
        self.scans = merged;
    }

    /// Whether the whole UTC day was inside a fully scanned window.
    pub fn covers_day(&self, date: &str) -> bool {
        let Some(start) = clock::parse_rfc3339(&format!("{date}T00:00:00Z")) else {
            return false;
        };
        let end = start + clock::DAY_SECONDS;
        self.scans
            .iter()
            .any(|scan| scan[0] <= start && scan[1] >= end)
    }

    pub fn prune(&mut self, today: &str) {
        if let Some(cutoff) = clock::shift_date(today, -KEEP_DAYS) {
            self.days.retain(|date, _| date.as_str() >= cutoff.as_str());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::daily::transcripts::Kind;

    fn failure(id: &str, epoch: i64, bucket: &'static str, cause: &str) -> Failure {
        Failure {
            id: id.to_owned(),
            host: "mac".to_owned(),
            kind: Kind::Correction,
            epoch,
            session: "s".to_owned(),
            project: "p".to_owned(),
            quote: format!("quote {id}"),
            context: String::new(),
            bucket,
            cause: cause.to_owned(),
            catch_all: false,
        }
    }

    #[test]
    fn events_merge_by_id_across_overlapping_runs() {
        let mut ledger = Ledger::default();
        let one = failure("a", 1_793_628_394, "B3", "ci-as-compiler");
        assert!(ledger.add_failure(&one));
        assert!(!ledger.add_failure(&one));
        let two = failure("b", 1_793_628_400, "B3", "ci-as-compiler");
        assert!(ledger.add_failure(&two));
        assert_eq!(ledger.count_on("2026-11-02", "B3/ci-as-compiler"), 2);
        assert_eq!(ledger.bucket_total("2026-11-02", "B3"), 2);
        assert_eq!(ledger.bucket_total("2026-11-02", "B1"), 0);
    }

    #[test]
    fn a_fingerprint_repeats_when_two_dates_hold_it() {
        let mut ledger = Ledger::default();
        ledger.add_failure(&failure("a", 1_793_628_394, "B5", "ignored-request"));
        assert_eq!(
            ledger.dates_for("B5/ignored-request"),
            vec!["2026-11-02".to_owned()]
        );
        ledger.add_failure(&failure(
            "b",
            1_793_628_394 - 86_400,
            "B5",
            "ignored-request",
        ));
        assert_eq!(
            ledger.dates_for("B5/ignored-request"),
            vec!["2026-11-01".to_owned(), "2026-11-02".to_owned()]
        );
        assert!(ledger.dates_for("B5/other").is_empty());
        assert_eq!(ledger.span_seconds("B5/ignored-request"), 86_400);
        assert_eq!(ledger.span_seconds("B5/other"), 0);
    }

    #[test]
    fn flags_count_once_per_date() {
        let mut ledger = Ledger::default();
        assert!(ledger.add_flag(
            "warmth/disk-low-mac-host",
            "2026-11-02",
            "mac",
            "9 GiB free"
        ));
        assert!(!ledger.add_flag(
            "warmth/disk-low-mac-host",
            "2026-11-02",
            "mac",
            "9 GiB free"
        ));
        assert!(ledger.add_flag(
            "warmth/disk-low-mac-host",
            "2026-11-03",
            "mac",
            "8 GiB free"
        ));
        assert_eq!(ledger.dates_for("warmth/disk-low-mac-host").len(), 2);
    }

    #[test]
    fn scanned_windows_merge_and_decide_which_days_are_covered() {
        let day = |text: &str| clock::parse_rfc3339(text).unwrap();
        let mut ledger = Ledger::default();
        ledger.record_scan(day("2026-10-31T08:00:00Z"), day("2026-11-01T08:00:00Z"));
        ledger.record_scan(day("2026-11-01T08:00:30Z"), day("2026-11-02T08:00:00Z"));
        assert_eq!(ledger.scans.len(), 1);
        assert!(ledger.covers_day("2026-11-01"));
        assert!(!ledger.covers_day("2026-10-31"));
        assert!(!ledger.covers_day("2026-11-02"));
        assert!(!ledger.covers_day("not-a-date"));
        // A gap keeps windows apart.
        ledger.record_scan(day("2026-11-04T08:00:00Z"), day("2026-11-05T08:00:00Z"));
        assert_eq!(ledger.scans.len(), 2);
        assert!(!ledger.covers_day("2026-11-03"));
        ledger.record_scan(5, 5);
        assert_eq!(ledger.scans.len(), 2);
    }

    #[test]
    fn round_trips_through_the_state_file_and_prunes_old_days() {
        let dir = std::env::temp_dir().join(format!("legion-daily-ledger-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("ledger.json");
        assert!(Ledger::load(&path).unwrap().days.is_empty());

        let mut ledger = Ledger::default();
        ledger.add_failure(&failure("a", 1_793_628_394, "B1", "ignored-stop"));
        ledger.issues.insert(
            "B1/ignored-stop".to_owned(),
            IssueNote {
                repo: "Orthic-Labs/legion".to_owned(),
                number: 7,
                ..IssueNote::default()
            },
        );
        ledger.save(&path).unwrap();
        let loaded = Ledger::load(&path).unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.count_on("2026-11-02", "B1/ignored-stop"), 1);
        assert_eq!(loaded.issues["B1/ignored-stop"].number, 7);

        let mut old = loaded;
        old.add_failure(&failure("z", 1_700_000_000, "B1", "ignored-stop"));
        old.prune("2026-11-02");
        assert_eq!(
            old.days.keys().cloned().collect::<Vec<_>>(),
            vec!["2026-11-02".to_owned()]
        );

        fs::write(&path, "{not json").unwrap();
        assert!(Ledger::load(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
