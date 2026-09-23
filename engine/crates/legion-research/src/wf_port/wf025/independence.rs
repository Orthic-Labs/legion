//! Faithful Rust port of `src/lib/research-core/independence.py`: automatic
//! source-independence clustering. Clusters duplicate URLs, redirect/origin
//! copies, identical or near-identical bodies, shared DOI/study origins,
//! explicit wire origins, and common wire-service copies. Operates on loose
//! JSON (`serde_json::Value` objects), matching the Python script's schema
//! rather than this crate's strict `EvidenceRecord` type, so field names and
//! output shape are preserved exactly.

use std::collections::{BTreeMap, HashMap, HashSet};

use regex::Regex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const WIRE_MARKERS: &[&str] = &[
    "pr newswire",
    "prnewswire",
    "business wire",
    "globe newswire",
    "associated press",
    "(ap)",
    "(reuters)",
    "accesswire",
    "newsfile corp",
];

fn tracking_re() -> Regex {
    Regex::new(r"(?i)^(utm_|fbclid$|gclid$|ref$|source$)").expect("valid regex")
}

fn word_re() -> Regex {
    Regex::new(r"[a-z0-9]{3,}").expect("valid regex")
}

/// Canonicalizes a URL: lowercases + strips a leading `www.` from the host,
/// collapses repeated slashes and trailing slash in the path, drops
/// tracking query params and sorts the rest, and normalizes the scheme to
/// `https` (or keeps `file`). Mirrors `independence.py`'s `canonical_url`.
pub fn canonical_url(url: &str) -> String {
    let url = url.trim();
    if url.is_empty() {
        return String::new();
    }
    let tracking = tracking_re();

    // Split off scheme.
    let (scheme, rest) = match url.find("://") {
        Some(idx) => (url[..idx].to_ascii_lowercase(), &url[idx + 3..]),
        None => (String::new(), url),
    };
    // Split rest into authority and path+query.
    let (authority, path_and_query) = match rest.find(|c| matches!(c, '/' | '?' | '#')) {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };
    // Host is the authority without userinfo or port.
    let host_with_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = host_with_port
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_string();

    // Split path+query on '#' (fragment is dropped entirely), then on '?'.
    let path_and_query = path_and_query.split('#').next().unwrap_or("");
    let (raw_path, raw_query) = match path_and_query.find('?') {
        Some(idx) => (&path_and_query[..idx], &path_and_query[idx + 1..]),
        None => (path_and_query, ""),
    };

    // Collapse repeated slashes, then strip a single trailing slash;
    // default to "/" when the path is empty (mirrors `p.path or '/'`).
    let mut collapsed = String::with_capacity(raw_path.len());
    let mut prev_slash = false;
    for ch in raw_path.chars() {
        if ch == '/' {
            if prev_slash {
                continue;
            }
            prev_slash = true;
        } else {
            prev_slash = false;
        }
        collapsed.push(ch);
    }
    let mut path = collapsed.trim_end_matches('/').to_string();
    if path.is_empty() {
        path = "/".to_string();
    }

    // Query: keep non-empty-value-tolerant pairs whose key isn't tracking,
    // sort by (key, value), re-encode with '+' style spaces like urlencode.
    let mut pairs: Vec<(String, String)> = Vec::new();
    if !raw_query.is_empty() {
        for kv in raw_query.split('&') {
            if kv.is_empty() {
                continue;
            }
            let mut it = kv.splitn(2, '=');
            let k = percent_decode(it.next().unwrap_or(""));
            let v = percent_decode(it.next().unwrap_or(""));
            if tracking.is_match(&k) {
                continue;
            }
            pairs.push((k, v));
        }
    }
    pairs.sort();
    let query = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let out_scheme = if scheme == "file" { "file" } else { "https" };
    let mut out = format!("{out_scheme}://{host}{path}");
    if !query.is_empty() {
        out.push('?');
        out.push_str(&query);
    }
    out
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn str_field(record: &Value, key: &str) -> String {
    record
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn body_text(record: &Value) -> String {
    for key in ["body_plain", "body", "quote_or_paraphrase"] {
        if let Some(v) = record.get(key).and_then(Value::as_str) {
            if !v.is_empty() {
                return v.to_string();
            }
        }
    }
    String::new()
}

fn shingles(text: &str, n: usize) -> HashSet<String> {
    let words: Vec<String> = word_re()
        .find_iter(&text.to_lowercase())
        .map(|m| m.as_str().to_string())
        .collect();
    if words.len() < n {
        return HashSet::new();
    }
    (0..=words.len() - n)
        .map(|i| words[i..i + n].join(" "))
        .collect()
}

fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let intersection = a.intersection(b).count();
    let union = a.union(b).count();
    intersection as f64 / union as f64
}

fn wire_signature(record: &Value) -> Option<String> {
    let body = body_text(record);
    let head: String = body.chars().take(2000).collect::<String>().to_lowercase();
    let marker = WIRE_MARKERS.iter().find(|m| head.contains(**m))?;
    let title = str_field(record, "title").to_lowercase();
    let word_re = word_re();
    let title_tokens: Vec<&str> = word_re
        .find_iter(&title)
        .map(|m| m.as_str())
        .take(8)
        .collect();
    let head_tokens: Vec<&str> = word_re.find_iter(&head).map(|m| m.as_str()).take(12).collect();
    let tokens = if title_tokens.is_empty() {
        head_tokens
    } else {
        title_tokens
    };
    Some(format!("{marker}|{}", tokens.join(" ")))
}

struct UnionFind {
    parent: HashMap<String, String>,
}

impl UnionFind {
    fn new(ids: &[String]) -> Self {
        Self {
            parent: ids.iter().map(|id| (id.clone(), id.clone())).collect(),
        }
    }

    fn find(&mut self, item: &str) -> String {
        let mut root = item.to_string();
        while self.parent.get(&root).map(String::as_str) != Some(root.as_str()) {
            root = self.parent[&root].clone();
        }
        let mut cur = item.to_string();
        while self.parent.get(&cur).map(String::as_str) != Some(cur.as_str()) {
            let next = self.parent[&cur].clone();
            self.parent.insert(cur, root.clone());
            cur = next;
        }
        root
    }

    fn union(&mut self, a: &str, b: &str) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra != rb {
            let (keep, drop) = if ra < rb { (ra, rb) } else { (rb, ra) };
            self.parent.insert(drop, keep);
        }
    }
}

pub struct ClusterRow {
    pub cluster_id: String,
    pub members: Vec<String>,
    pub reasons: Vec<String>,
}

pub struct ClusterResult {
    pub evidence: Vec<Value>,
    pub clusters: Vec<ClusterRow>,
    pub unique_voices: usize,
}

/// Ports `independence.py`'s `cluster()`. `evidence` rows must be JSON
/// objects with (at least) an `id` field; the returned `evidence` is a copy
/// of each row with `independence_cluster` set.
pub fn cluster(evidence: &[Value]) -> ClusterResult {
    cluster_with_threshold(evidence, 0.82)
}

pub fn cluster_with_threshold(evidence: &[Value], near_duplicate_threshold: f64) -> ClusterResult {
    let ids: Vec<String> = evidence
        .iter()
        .map(|e| e.get("id").map(value_to_id_string).unwrap_or_default())
        .collect();
    let mut uf = UnionFind::new(&ids);
    let by_id: HashMap<String, &Value> = ids.iter().cloned().zip(evidence.iter()).collect();
    let mut reasons: HashMap<(String, String), HashSet<String>> = HashMap::new();

    let mut merge = |uf: &mut UnionFind,
                      reasons: &mut HashMap<(String, String), HashSet<String>>,
                      a: &str,
                      b: &str,
                      reason: &str| {
        if a == b || !by_id.contains_key(a) || !by_id.contains_key(b) {
            return;
        }
        uf.union(a, b);
        let key = if a < b {
            (a.to_string(), b.to_string())
        } else {
            (b.to_string(), a.to_string())
        };
        reasons.entry(key).or_default().insert(reason.to_string());
    };

    // BTreeMap keeps deterministic (insertion-independent) key ordering,
    // though only membership order within a key matters here.
    let mut idx_url: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut idx_origin: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut idx_doi: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut idx_body_hash: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut idx_wire: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for record in evidence {
        let eid = record.get("id").map(value_to_id_string).unwrap_or_default();
        idx_url
            .entry(canonical_url(&str_field(record, "url")))
            .or_default()
            .push(eid.clone());
        let origin_raw = {
            let o = str_field(record, "origin_url");
            if !o.is_empty() {
                o
            } else {
                str_field(record, "resolved_from")
            }
        };
        let origin = canonical_url(&origin_raw);
        if !origin.is_empty() {
            idx_origin.entry(origin).or_default().push(eid.clone());
        }
        let doi = {
            let raw = str_field(record, "doi").to_lowercase();
            raw.strip_prefix("https://doi.org/")
                .unwrap_or(&raw)
                .trim()
                .to_string()
        };
        if !doi.is_empty() {
            idx_doi.entry(doi).or_default().push(eid.clone());
        }
        let mut body_hash = {
            let h = str_field(record, "content_sha256");
            if !h.is_empty() {
                h
            } else {
                str_field(record, "body_sha256")
            }
        };
        if body_hash.is_empty() {
            let text = body_text(record);
            if !text.is_empty() {
                let mut hasher = Sha256::new();
                hasher.update(text.as_bytes());
                body_hash = hex::encode(hasher.finalize());
            }
        }
        if !body_hash.is_empty() {
            idx_body_hash.entry(body_hash).or_default().push(eid.clone());
        }
        if let Some(sig) = wire_signature(record) {
            idx_wire.entry(sig).or_default().push(eid.clone());
        }
        if let Some(explicit) = record.get("wire_origin_id") {
            let explicit_id = value_to_id_string(explicit);
            if !explicit_id.is_empty() {
                merge(&mut uf, &mut reasons, &eid, &explicit_id, "explicit-origin");
            }
        }
    }

    for (kind, index) in [
        ("url", &idx_url),
        ("origin", &idx_origin),
        ("doi", &idx_doi),
        ("body_hash", &idx_body_hash),
        ("wire", &idx_wire),
    ] {
        for (key, members) in index {
            if key.is_empty() || members.len() < 2 {
                continue;
            }
            for member in &members[1..] {
                merge(&mut uf, &mut reasons, &members[0], member, kind);
            }
        }
    }

    let shingle_map: HashMap<String, HashSet<String>> = ids
        .iter()
        .map(|id| (id.clone(), shingles(&body_text(by_id[id]), 5)))
        .collect();
    for (i, a) in ids.iter().enumerate() {
        if shingle_map[a].len() < 8 {
            continue;
        }
        for b in &ids[i + 1..] {
            if uf.find(a) == uf.find(b) || shingle_map[b].len() < 8 {
                continue;
            }
            let score = jaccard(&shingle_map[a], &shingle_map[b]);
            if score >= near_duplicate_threshold {
                merge(&mut uf, &mut reasons, a, b, &format!("near-body:{score:.3}"));
            }
        }
    }

    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    for id in &ids {
        let root = uf.find(id);
        groups.entry(root).or_default().push(id.clone());
    }

    let mut sorted_groups: Vec<Vec<String>> = groups
        .into_values()
        .map(|mut members| {
            members.sort();
            members
        })
        .collect();
    sorted_groups.sort_by(|a, b| a[0].cmp(&b[0]));

    let mut cluster_rows = Vec::with_capacity(sorted_groups.len());
    let mut id_to_cluster: HashMap<String, String> = HashMap::new();
    for members in &sorted_groups {
        let mut hasher = Sha256::new();
        hasher.update(members.join("|").as_bytes());
        let digest = hex::encode(hasher.finalize());
        let cid = format!("ind:{}", &digest[..12]);
        for eid in members {
            id_to_cluster.insert(eid.clone(), cid.clone());
        }
        let mut reason_set: HashSet<String> = HashSet::new();
        for (i, a) in members.iter().enumerate() {
            for b in &members[i + 1..] {
                let key = if a < b {
                    (a.clone(), b.clone())
                } else {
                    (b.clone(), a.clone())
                };
                if let Some(r) = reasons.get(&key) {
                    reason_set.extend(r.iter().cloned());
                }
            }
        }
        let mut reason_list: Vec<String> = reason_set.into_iter().collect();
        reason_list.sort();
        cluster_rows.push(ClusterRow {
            cluster_id: cid,
            members: members.clone(),
            reasons: reason_list,
        });
    }

    let mut updated = Vec::with_capacity(evidence.len());
    for (id, record) in ids.iter().zip(evidence.iter()) {
        let mut obj: Map<String, Value> = record.as_object().cloned().unwrap_or_default();
        obj.insert(
            "independence_cluster".to_string(),
            Value::String(id_to_cluster[id].clone()),
        );
        updated.push(Value::Object(obj));
    }

    let unique_voices = cluster_rows.len();
    ClusterResult {
        evidence: updated,
        clusters: cluster_rows,
        unique_voices,
    }
}

fn value_to_id_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_url_strips_www_tracking_and_trailing_slash() {
        assert_eq!(
            canonical_url("HTTP://WWW.Example.com/a//b/?utm_source=x&z=1&a=2"),
            "https://example.com/a/b?a=2&z=1"
        );
    }

    #[test]
    fn canonical_url_empty_is_empty() {
        assert_eq!(canonical_url(""), "");
        assert_eq!(canonical_url("   "), "");
    }

    #[test]
    fn clusters_by_duplicate_url() {
        let evidence = vec![
            json!({"id": "a", "url": "https://example.com/x"}),
            json!({"id": "b", "url": "https://example.com/x?utm_source=y"}),
            json!({"id": "c", "url": "https://other.com/y"}),
        ];
        let result = cluster(&evidence);
        assert_eq!(result.unique_voices, 2);
        let a_cluster = result.evidence[0]["independence_cluster"].as_str().unwrap();
        let b_cluster = result.evidence[1]["independence_cluster"].as_str().unwrap();
        assert_eq!(a_cluster, b_cluster);
        let c_cluster = result.evidence[2]["independence_cluster"].as_str().unwrap();
        assert_ne!(a_cluster, c_cluster);
    }

    #[test]
    fn clusters_wire_service_copies() {
        let body = "PR Newswire: Acme Corp announces record results across all divisions today";
        let evidence = vec![
            json!({"id": "a", "title": "Acme announces results", "body": body}),
            json!({"id": "b", "title": "Acme announces results", "body": body}),
        ];
        let result = cluster(&evidence);
        assert_eq!(result.unique_voices, 1);
        assert!(result.clusters[0].reasons.contains(&"wire".to_string()));
    }

    #[test]
    fn explicit_wire_origin_merges() {
        let evidence = vec![
            json!({"id": "a"}),
            json!({"id": "b", "wire_origin_id": "a"}),
        ];
        let result = cluster(&evidence);
        assert_eq!(result.unique_voices, 1);
        assert!(result.clusters[0].reasons.contains(&"explicit-origin".to_string()));
    }

    #[test]
    fn distinct_sources_stay_in_separate_clusters() {
        let evidence = vec![
            json!({"id": "a", "url": "https://a.com/1", "body": "alpha content one two three"}),
            json!({"id": "b", "url": "https://b.com/2", "body": "beta content four five six"}),
        ];
        let result = cluster(&evidence);
        assert_eq!(result.unique_voices, 2);
    }
}
