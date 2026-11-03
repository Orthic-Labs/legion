//! Ported from src/lib/controls/scenarios/{pairwise,constraints,compile}.mjs
//! (packet P5b-controls-config).

use super::controls_support::Value;
use std::collections::BTreeMap;

pub type Row = BTreeMap<String, Value>;
pub type Constraint = Box<dyn Fn(&Row) -> bool>;

#[derive(Debug, Clone)]
pub struct OmittedCase {
    pub row: Row,
    pub reason: String,
    pub mandatory: bool,
}

#[derive(Debug)]
pub struct PairwiseResult {
    pub rows: Vec<Row>,
    pub omitted: Vec<OmittedCase>,
    pub uncovered: Vec<Vec<(String, Value)>>,
    pub complete: bool,
}

fn stable(row: &Row) -> String {
    Value::Object(row.clone()).to_canonical_string()
}

fn allowed(row: &Row, constraints: &[Constraint]) -> bool {
    constraints.iter().all(|c| c(row))
}

/// Port of `pairwise(dimensions, { constraints, mandatory })`.
///
/// `dimensions` values are deduplicated by their canonical JSON form (a
/// faithful port of `[...new Set(dimensions[key])]`, which dedupes objects
/// by reference in JS — since our `Value` implements structural equality,
/// this instead dedupes by structural equality, which is the intent for the
/// string/number dimension values this function is used with).
pub fn pairwise(
    dimensions: &BTreeMap<String, Vec<Value>>,
    constraints: &[Constraint],
    mandatory: &[Row],
) -> Result<PairwiseResult, String> {
    let keys: Vec<String> = dimensions.keys().cloned().collect();

    let mut values: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for key in &keys {
        let mut seen: Vec<Value> = Vec::new();
        for v in dimensions.get(key).unwrap() {
            if !seen.contains(v) {
                seen.push(v.clone());
            }
        }
        seen.sort_by(|a, b| {
            Value::Array(vec![a.clone()])
                .to_canonical_string()
                .cmp(&Value::Array(vec![b.clone()]).to_canonical_string())
        });
        values.insert(key.clone(), seen);
    }

    for row in mandatory {
        let row_keys: Vec<&String> = row.keys().collect();
        let keys_ref: Vec<&String> = keys.iter().collect();
        if row_keys != keys_ref {
            return Err(
                "mandatory row must contain exactly one declared value for every dimension"
                    .to_string(),
            );
        }
        for key in &keys {
            let v = row.get(key).unwrap();
            if !values[key].contains(v) {
                return Err(
                    "mandatory row must contain exactly one declared value for every dimension"
                        .to_string(),
                );
            }
        }
    }

    let witness = |fixed: &Row| -> Option<Row> {
        let remaining: Vec<&String> = keys.iter().filter(|k| !fixed.contains_key(*k)).collect();
        fn visit(
            index: usize,
            remaining: &[&String],
            values: &BTreeMap<String, Vec<Value>>,
            row: &mut Row,
            constraints: &[Constraint],
        ) -> Option<Row> {
            if index == remaining.len() {
                return if allowed(row, constraints) {
                    Some(row.clone())
                } else {
                    None
                };
            }
            let key = remaining[index];
            for value in &values[key] {
                row.insert(key.clone(), value.clone());
                if let Some(found) = visit(index + 1, remaining, values, row, constraints) {
                    return Some(found);
                }
            }
            row.remove(key);
            None
        }
        let mut row = fixed.clone();
        visit(0, &remaining, &values, &mut row, constraints)
    };

    let mut candidates: Vec<Row> = Vec::new();
    let mut omitted: Vec<OmittedCase> = Vec::new();

    if keys.len() == 1 {
        for value in &values[&keys[0]] {
            let mut row = Row::new();
            row.insert(keys[0].clone(), value.clone());
            if allowed(&row, constraints) {
                candidates.push(row);
            } else {
                omitted.push(OmittedCase {
                    row,
                    reason: "constraint".into(),
                    mandatory: false,
                });
            }
        }
    }

    for left in 0..keys.len() {
        for right in (left + 1)..keys.len() {
            for a in &values[&keys[left]] {
                for b in &values[&keys[right]] {
                    let mut pair = Row::new();
                    pair.insert(keys[left].clone(), a.clone());
                    pair.insert(keys[right].clone(), b.clone());
                    match witness(&pair) {
                        Some(row) => candidates.push(row),
                        None => omitted.push(OmittedCase {
                            row: pair,
                            reason: "constraint".into(),
                            mandatory: false,
                        }),
                    }
                }
            }
        }
    }

    for row in mandatory {
        if allowed(row, constraints) {
            candidates.push(row.clone());
        } else {
            omitted.push(OmittedCase {
                row: row.clone(),
                reason: "constraint".into(),
                mandatory: true,
            });
        }
    }

    let mut unique_map: BTreeMap<String, Row> = BTreeMap::new();
    for row in &candidates {
        unique_map.insert(stable(row), row.clone());
    }
    let valid: Vec<Row> = unique_map.into_values().collect();

    let mut uncovered: BTreeMap<String, Vec<(String, Value)>> = BTreeMap::new();
    for left in 0..keys.len() {
        for right in (left + 1)..keys.len() {
            for a in &values[&keys[left]] {
                for b in &values[&keys[right]] {
                    let covered = valid.iter().any(|row| {
                        row.get(&keys[left]) == Some(a) && row.get(&keys[right]) == Some(b)
                    });
                    if covered {
                        let pair = vec![
                            (keys[left].clone(), a.clone()),
                            (keys[right].clone(), b.clone()),
                        ];
                        let pair_key = Value::Array(
                            pair.iter()
                                .map(|(k, v)| Value::Array(vec![Value::str(k.clone()), v.clone()]))
                                .collect(),
                        )
                        .to_canonical_string();
                        uncovered.insert(pair_key, pair);
                    }
                }
            }
        }
    }

    let mut rows: Vec<Row> = Vec::new();
    for required in mandatory {
        if allowed(required, constraints) && !rows.iter().any(|r| stable(r) == stable(required)) {
            rows.push(required.clone());
        }
    }
    let mut pool: Vec<Row> = valid
        .iter()
        .filter(|row| !rows.iter().any(|r| stable(r) == stable(row)))
        .cloned()
        .collect();

    for row in &rows {
        uncovered.retain(|_, pair| !pair.iter().all(|(k, v)| row.get(k) == Some(v)));
    }

    while !uncovered.is_empty() {
        let mut best: Option<usize> = None;
        let mut best_hits: Vec<String> = Vec::new();
        for (i, row) in pool.iter().enumerate() {
            let hits: Vec<String> = uncovered
                .iter()
                .filter(|(_, pair)| pair.iter().all(|(k, v)| row.get(k) == Some(v)))
                .map(|(key, _)| key.clone())
                .collect();
            if hits.len() > best_hits.len() {
                best = Some(i);
                best_hits = hits;
            }
        }
        match best {
            Some(i) => {
                let row = pool.remove(i);
                for hit in &best_hits {
                    uncovered.remove(hit);
                }
                rows.push(row);
            }
            None => break,
        }
    }

    if keys.len() == 1 {
        rows.extend(pool);
    }

    rows.sort_by_key(stable);

    let complete = uncovered.is_empty() && !omitted.iter().any(|o| o.mandatory);

    Ok(PairwiseResult {
        rows,
        omitted,
        uncovered: uncovered.into_values().collect(),
        complete,
    })
}

/// Port of `applyConstraints(cases, constraints)`.
pub fn apply_constraints(cases: Vec<Row>, constraints: &[Constraint]) -> Vec<Row> {
    cases
        .into_iter()
        .filter(|row| allowed(row, constraints))
        .collect()
}
