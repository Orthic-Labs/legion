//! Port of `tools/research-core/independence.py`: automatic source-independence
//! clustering. Duplicate URLs, origin copies, shared DOIs, identical bodies,
//! explicit wire origins, common wire-service copies, and near-duplicate bodies
//! (5-gram Jaccard) collapse into one independence cluster. Consensus counts
//! unique clusters, never raw rows.

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use super::common::sha256_text;
use super::pyval::{py_str, py_str_or, quote_plus, truthy, unquote_plus};

pub const NEAR_DUPLICATE_THRESHOLD: f64 = 0.82;

const WIRE_MARKERS: [&str; 9] = [
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

/// Result of clustering: evidence copies with `independence_cluster` set,
/// the cluster rows, and the unique-voice count.
#[derive(Clone, Debug)]
pub struct Clustering {
    pub evidence: Vec<Value>,
    pub clusters: Vec<Value>,
    pub unique_voices: usize,
}

/// `str(record['id'])`; a missing id is an error (Python raises KeyError).
fn id_of(record: &Value) -> Result<String, String> {
    match record.get("id") {
        Some(id) => Ok(py_str(Some(id))),
        None => Err("evidence row missing id".to_string()),
    }
}

fn is_tracking_key(key: &str) -> bool {
    // TRACKING = ^(utm_|fbclid$|gclid$|ref$|source$), compiled with re.I.
    let lowered = key.to_ascii_lowercase();
    lowered.starts_with("utm_")
        || lowered == "fbclid"
        || lowered == "gclid"
        || lowered == "ref"
        || lowered == "source"
}

/// Split `scheme://netloc/path?query#fragment` the way `urlparse` does for the
/// shapes this clustering sees. Returns (scheme, netloc, path, query).
fn split_url(url: &str) -> (String, String, String, String) {
    let without_fragment = match url.find('#') {
        Some(index) => &url[..index],
        None => url,
    };
    let (scheme, rest) = match without_fragment.find(':') {
        Some(index)
            if index > 0
                && without_fragment[..index]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
                && without_fragment[..index]
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_alphabetic())
                    .unwrap_or(false) =>
        {
            (
                without_fragment[..index].to_ascii_lowercase(),
                &without_fragment[index + 1..],
            )
        }
        _ => (String::new(), without_fragment),
    };
    let (netloc, after_netloc) = if let Some(stripped) = rest.strip_prefix("//") {
        let end = stripped
            .find(|c: char| c == '/' || c == '?')
            .unwrap_or(stripped.len());
        (stripped[..end].to_string(), &stripped[end..])
    } else {
        (String::new(), rest)
    };
    let (path, query) = match after_netloc.find('?') {
        Some(index) => (
            after_netloc[..index].to_string(),
            after_netloc[index + 1..].to_string(),
        ),
        None => (after_netloc.to_string(), String::new()),
    };
    (scheme, netloc, path, query)
}

/// Lowercased hostname without userinfo or port, as `urlparse(...).hostname`.
fn hostname(netloc: &str) -> String {
    let after_user = match netloc.rfind('@') {
        Some(index) => &netloc[index + 1..],
        None => netloc,
    };
    let host = if let Some(stripped) = after_user.strip_prefix('[') {
        match stripped.find(']') {
            Some(end) => &stripped[..end],
            None => stripped,
        }
    } else {
        match after_user.find(':') {
            Some(index) => &after_user[..index],
            None => after_user,
        }
    };
    host.to_lowercase()
}

/// Port of `canonical_url`: lowercase host without `www.`, collapsed slashes,
/// tracking parameters removed, remaining query sorted, scheme folded to https
/// (file stays file), fragment dropped.
pub fn canonical_url(url: &str) -> String {
    if url.is_empty() {
        return String::new();
    }
    let (scheme, netloc, path, query) = split_url(url.trim());
    let host = hostname(&netloc);
    let host = host
        .strip_prefix("www.")
        .unwrap_or(host.as_str())
        .to_string();

    let mut collapsed = String::new();
    let mut previous_slash = false;
    for ch in path.chars() {
        if ch == '/' {
            if !previous_slash {
                collapsed.push(ch);
            }
            previous_slash = true;
        } else {
            collapsed.push(ch);
            previous_slash = false;
        }
    }
    let trimmed_path = collapsed.trim_end_matches('/');
    let clean_path = if trimmed_path.is_empty() {
        "/".to_string()
    } else {
        trimmed_path.to_string()
    };

    let mut pairs: Vec<(String, String)> = Vec::new();
    for segment in query.split('&') {
        if segment.is_empty() {
            continue;
        }
        let (name, value) = match segment.find('=') {
            Some(index) => (&segment[..index], &segment[index + 1..]),
            None => (segment, ""),
        };
        let name = unquote_plus(name);
        let value = unquote_plus(value);
        if is_tracking_key(&name) {
            continue;
        }
        pairs.push((name, value));
    }
    pairs.sort();
    let encoded_query = pairs
        .iter()
        .map(|(name, value)| format!("{}={}", quote_plus(name), quote_plus(value)))
        .collect::<Vec<String>>()
        .join("&");

    let out_scheme = if scheme == "file" { "file" } else { "https" };
    let mut result = format!("{out_scheme}://{host}{clean_path}");
    if !encoded_query.is_empty() {
        result.push('?');
        result.push_str(&encoded_query);
    }
    result
}

/// `_body_text`: first truthy of body_plain, body, quote_or_paraphrase, else ''.
pub fn body_text(record: &Value) -> String {
    for key in ["body_plain", "body", "quote_or_paraphrase"] {
        if truthy(record.get(key)) {
            return py_str(record.get(key));
        }
    }
    String::new()
}

/// `WORD_RE = [a-z0-9]{3,}` applied to already-lowercased text.
fn word_tokens(lowered: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for ch in lowered.chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            current.push(ch);
        } else {
            if current.len() >= 3 {
                out.push(current.clone());
            }
            current.clear();
        }
    }
    if current.len() >= 3 {
        out.push(current);
    }
    out
}

/// `_shingles`: set of 5-word windows over lowercased word tokens.
fn shingles(text: &str) -> BTreeSet<String> {
    let words = word_tokens(&text.to_lowercase());
    let window = 5usize;
    let mut out = BTreeSet::new();
    if words.len() >= window {
        for start in 0..=(words.len() - window) {
            out.insert(words[start..start + window].join(" "));
        }
    }
    out
}

fn jaccard(left: &BTreeSet<String>, right: &BTreeSet<String>) -> f64 {
    if left.is_empty() || right.is_empty() {
        return 0.0;
    }
    let intersection = left.intersection(right).count() as f64;
    let union = left.union(right).count() as f64;
    intersection / union
}

/// `_wire_signature`: a wire-service marker in the first 2000 body characters,
/// keyed by the marker and the title (or head) tokens.
fn wire_signature(record: &Value) -> Option<String> {
    let body = body_text(record);
    let head: String = body.chars().take(2000).collect::<String>().to_lowercase();
    let marker: &str = WIRE_MARKERS
        .iter()
        .copied()
        .find(|candidate: &&str| head.contains(*candidate))?;
    let title = py_str_or(record.get("title"), "").to_lowercase();
    let title_tokens: Vec<String> = word_tokens(&title).into_iter().take(8).collect();
    let head_tokens: Vec<String> = word_tokens(&head).into_iter().take(12).collect();
    let tokens = if title_tokens.is_empty() {
        head_tokens
    } else {
        title_tokens
    };
    Some(format!("{}|{}", marker, tokens.join(" ")))
}

/// `_jaccard`-independent DOI normalisation used for the DOI index.
fn doi_key(record: &Value) -> String {
    let lowered = py_str_or(record.get("doi"), "").to_lowercase();
    let without_prefix = lowered
        .strip_prefix("https://doi.org/")
        .unwrap_or(lowered.as_str());
    without_prefix.trim().to_string()
}

fn pair_key(left: &str, right: &str) -> (String, String) {
    if left <= right {
        (left.to_string(), right.to_string())
    } else {
        (right.to_string(), left.to_string())
    }
}

struct UnionFind {
    parent: BTreeMap<String, String>,
}

impl UnionFind {
    fn new(ids: &[String]) -> Self {
        let parent = ids.iter().map(|id| (id.clone(), id.clone())).collect();
        Self { parent }
    }

    fn parent_of(&self, item: &str) -> String {
        self.parent
            .get(item)
            .cloned()
            .unwrap_or_else(|| item.to_string())
    }

    fn find(&self, item: &str) -> String {
        let mut root = item.to_string();
        loop {
            let parent = self.parent_of(&root);
            if parent == root {
                return root;
            }
            root = parent;
        }
    }

    /// `union`: the smaller root id keeps the cluster, as in the Python.
    fn union(&mut self, left: &str, right: &str) {
        let left_root = self.find(left);
        let right_root = self.find(right);
        if left_root != right_root {
            let (keep, drop) = if left_root <= right_root {
                (left_root, right_root)
            } else {
                (right_root, left_root)
            };
            self.parent.insert(drop, keep);
        }
    }
}

struct Merger {
    uf: UnionFind,
    reasons: BTreeMap<(String, String), BTreeSet<String>>,
    known: BTreeSet<String>,
}

impl Merger {
    /// `merge`: records the reason for every merge of two known ids, even when
    /// they are already in the same cluster, exactly as the Python does.
    fn merge(&mut self, left: &str, right: &str, reason: &str) {
        if left == right || !self.known.contains(left) || !self.known.contains(right) {
            return;
        }
        self.uf.union(left, right);
        self.reasons
            .entry(pair_key(left, right))
            .or_default()
            .insert(reason.to_string());
    }
}

/// Port of `cluster(evidence, near_duplicate_threshold=...)`.
pub fn cluster(evidence: &[Value], near_duplicate_threshold: f64) -> Result<Clustering, String> {
    let mut ids: Vec<String> = Vec::with_capacity(evidence.len());
    let mut by_id: BTreeMap<String, &Value> = BTreeMap::new();
    for record in evidence {
        let eid = id_of(record)?;
        ids.push(eid.clone());
        by_id.insert(eid, record);
    }

    let mut merger = Merger {
        uf: UnionFind::new(&ids),
        reasons: BTreeMap::new(),
        known: by_id.keys().cloned().collect(),
    };

    let mut url_index: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut origin_index: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut doi_index: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut body_index: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut wire_index: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for record in evidence {
        let eid = id_of(record)?;
        let url = canonical_url(&py_str_or(record.get("url"), ""));
        url_index.entry(url).or_default().push(eid.clone());

        let origin_raw = if truthy(record.get("origin_url")) {
            py_str(record.get("origin_url"))
        } else {
            py_str_or(record.get("resolved_from"), "")
        };
        let origin = canonical_url(&origin_raw);
        if !origin.is_empty() {
            origin_index.entry(origin).or_default().push(eid.clone());
        }

        let doi = doi_key(record);
        if !doi.is_empty() {
            doi_index.entry(doi).or_default().push(eid.clone());
        }

        let mut body_hash = if truthy(record.get("content_sha256")) {
            py_str(record.get("content_sha256"))
        } else if truthy(record.get("body_sha256")) {
            py_str(record.get("body_sha256"))
        } else {
            String::new()
        };
        if body_hash.is_empty() {
            let text = body_text(record);
            if !text.is_empty() {
                body_hash = sha256_text(&text);
            }
        }
        if !body_hash.is_empty() {
            body_index.entry(body_hash).or_default().push(eid.clone());
        }

        if let Some(signature) = wire_signature(record) {
            wire_index.entry(signature).or_default().push(eid.clone());
        }

        if truthy(record.get("wire_origin_id")) {
            let explicit = py_str(record.get("wire_origin_id"));
            merger.merge(&eid, &explicit, "explicit-origin");
        }
    }

    let indexes: [(&str, &BTreeMap<String, Vec<String>>); 5] = [
        ("url", &url_index),
        ("origin", &origin_index),
        ("doi", &doi_index),
        ("body_hash", &body_index),
        ("wire", &wire_index),
    ];
    for (kind, groups) in indexes {
        for (key, members) in groups.iter() {
            if key.is_empty() || members.len() < 2 {
                continue;
            }
            let anchor = members[0].clone();
            for member in &members[1..] {
                merger.merge(&anchor, member, kind);
            }
        }
    }

    let mut shingle_map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (eid, record) in by_id.iter() {
        shingle_map.insert(eid.clone(), shingles(&body_text(record)));
    }
    for i in 0..ids.len() {
        let left = ids[i].clone();
        let left_len = shingle_map.get(&left).map_or(0, |set| set.len());
        if left_len < 8 {
            continue;
        }
        for j in (i + 1)..ids.len() {
            let right = ids[j].clone();
            let right_len = shingle_map.get(&right).map_or(0, |set| set.len());
            if merger.uf.find(&left) == merger.uf.find(&right) || right_len < 8 {
                continue;
            }
            let score = jaccard(
                shingle_map.get(&left).map_or(&BTreeSet::new(), |set| set),
                shingle_map.get(&right).map_or(&BTreeSet::new(), |set| set),
            );
            if score >= near_duplicate_threshold {
                let reason = format!("near-body:{score:.3}");
                merger.merge(&left, &right, &reason);
            }
        }
    }

    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for eid in &ids {
        let root = merger.uf.find(eid);
        groups.entry(root).or_default().push(eid.clone());
    }
    let mut ordered_groups: Vec<Vec<String>> = groups
        .into_values()
        .map(|mut members| {
            members.sort();
            members
        })
        .collect();
    ordered_groups.sort_by(|left, right| left.first().cmp(&right.first()));

    let mut cluster_rows: Vec<Value> = Vec::new();
    let mut id_to_cluster: BTreeMap<String, String> = BTreeMap::new();
    for members in &ordered_groups {
        let digest = sha256_text(&members.join("|"));
        let cluster_id = format!("ind:{}", &digest[..12]);
        for eid in members {
            id_to_cluster.insert(eid.clone(), cluster_id.clone());
        }
        let mut reason_set: BTreeSet<String> = BTreeSet::new();
        for i in 0..members.len() {
            for j in (i + 1)..members.len() {
                if let Some(reasons) = merger.reasons.get(&pair_key(&members[i], &members[j])) {
                    reason_set.extend(reasons.iter().cloned());
                }
            }
        }
        let reasons: Vec<String> = reason_set.into_iter().collect();
        cluster_rows.push(json!({
            "cluster_id": cluster_id,
            "members": members,
            "reasons": reasons,
        }));
    }

    let mut updated: Vec<Value> = Vec::with_capacity(evidence.len());
    for record in evidence {
        let eid = id_of(record)?;
        let mut copy = record.clone();
        let cluster_id = id_to_cluster.get(&eid).cloned().unwrap_or_default();
        if let Value::Object(map) = &mut copy {
            map.insert(
                "independence_cluster".to_string(),
                Value::String(cluster_id),
            );
        }
        updated.push(copy);
    }

    Ok(Clustering {
        evidence: updated,
        unique_voices: cluster_rows.len(),
        clusters: cluster_rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, url: &str) -> Value {
        json!({"id": id, "url": url, "body_plain": format!("distinct body text for {id}")})
    }

    #[test]
    fn canonical_url_drops_tracking_www_fragment_and_sorts_query() {
        assert_eq!(
            canonical_url("HTTP://www.Example.com/a//b/?utm_source=x&z=1&a=2#frag"),
            "https://example.com/a/b?a=2&z=1"
        );
        assert_eq!(canonical_url(""), "");
        assert_eq!(canonical_url("https://example.com"), "https://example.com/");
    }

    #[test]
    fn duplicate_urls_share_one_cluster_and_unique_urls_stay_apart() {
        let evidence = vec![
            row("a", "https://example.com/x"),
            row("b", "https://www.example.com/x/?utm_medium=feed"),
            row("c", "https://other.example.org/y"),
        ];
        let result = cluster(&evidence, NEAR_DUPLICATE_THRESHOLD).unwrap();
        assert_eq!(result.unique_voices, 2);
        let a = result.evidence[0]["independence_cluster"].clone();
        let b = result.evidence[1]["independence_cluster"].clone();
        let c = result.evidence[2]["independence_cluster"].clone();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(result.clusters[0]["reasons"], json!(["url"]));
    }

    #[test]
    fn explicit_origin_and_shared_doi_merge() {
        let evidence = vec![
            json!({"id": "one", "url": "https://a.test/1", "doi": "https://doi.org/10.1/ABC", "body_plain": "alpha"}),
            json!({"id": "two", "url": "https://b.test/2", "doi": "10.1/abc", "body_plain": "beta"}),
            json!({"id": "three", "url": "https://c.test/3", "wire_origin_id": "one", "body_plain": "gamma"}),
        ];
        let result = cluster(&evidence, NEAR_DUPLICATE_THRESHOLD).unwrap();
        assert_eq!(result.unique_voices, 1);
        assert_eq!(
            result.clusters[0]["reasons"],
            json!(["doi", "explicit-origin"])
        );
    }

    #[test]
    fn missing_id_is_an_error() {
        let evidence = vec![json!({"url": "https://a.test"})];
        assert!(cluster(&evidence, NEAR_DUPLICATE_THRESHOLD).is_err());
    }
}
