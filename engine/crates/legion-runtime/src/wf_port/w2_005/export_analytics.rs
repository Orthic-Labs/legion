//! Port of `skills/foundation/scripts/export_foundation_analytics.py`: exports
//! request-only Foundation coverage and sole-provider analytics from a validated canon table and
//! one or more mechanism-card tables.
//!
//! [`export`] is pure over the injected table text. [`run_paths`] is the thin filesystem wrapper
//! behind `legion script foundation/export-analytics`. CSV output follows Python's `csv` writer
//! defaults: `,` delimiter, `"` quoting only for fields holding `,`, `"`, CR or LF (quotes doubled),
//! and `\r\n` record terminators.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use super::validate_atom_report::{headers, parse_table, py_tuple};

/// Output file: mechanism cards, one row per validated card (mechanism-cards columns).
pub const CARDS_FILE: &str = "foundation-mechanism-cards.csv";
/// Output file: one row per canon atom with observed/unclear/not-found counts and the sole provider.
pub const SUMMARY_FILE: &str = "foundation-atom-summary.csv";
/// Output file: one row per repository with observed/unresolved counts per scope and domain.
pub const COVERAGE_FILE: &str = "foundation-coverage-matrix.csv";

/// Columns of [`SUMMARY_FILE`], in order.
pub const SUMMARY_HEADER: &[&str] = &[
    "scope",
    "domain",
    "atom_id",
    "atom",
    "observed_repositories",
    "observed_count",
    "unclear_count",
    "not_found_count",
    "sole_provider",
];

/// One exported CSV file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedFile {
    pub name: &'static str,
    pub content: String,
}

/// Result of a successful export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analytics {
    pub files: Vec<ExportedFile>,
    pub card_count: usize,
    pub atom_count: usize,
    pub sole_provider_count: usize,
}

/// One CSV record with Python `csv.writer` (QUOTE_MINIMAL) quoting and a `\r\n` terminator.
pub fn csv_line(fields: &[&str]) -> String {
    let mut line = String::new();
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            line.push(',');
        }
        if field.chars().any(|c| matches!(c, ',' | '"' | '\r' | '\n')) {
            line.push('"');
            line.push_str(&field.replace('"', "\"\""));
            line.push('"');
        } else {
            line.push_str(field);
        }
    }
    line.push_str("\r\n");
    line
}

fn csv_text(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut out = csv_line(header);
    for row in rows {
        let refs: Vec<&str> = row.iter().map(String::as_str).collect();
        out.push_str(&csv_line(&refs));
    }
    out
}

/// Parses one table into its data rows (cells in header order).
fn rows_of(text: &str, header: &[&str]) -> Result<Vec<Vec<String>>, String> {
    parse_table(text, header)
        .map(|rows| rows.into_iter().map(|(_, cells)| cells).collect())
        .map_err(|e| e.to_string())
}

fn column(header: &[&str], name: &str) -> usize {
    header
        .iter()
        .position(|h| *h == name)
        .expect("static header column")
}

/// Pure export: validates the canon and card rows, then builds the three CSV files.
///
/// Errors carry the Python `ERROR:` messages verbatim (`duplicate canon tuple`, `card references
/// unknown canon tuple`, `duplicate mechanism card`, empty inputs).
pub fn export(canon_text: &str, card_texts: &[&str]) -> Result<Analytics, String> {
    let canon_header = headers("canon").unwrap_or(&[]);
    let card_header = headers("mechanism-cards").unwrap_or(&[]);
    let canon = rows_of(canon_text, canon_header)?;
    let mut cards: Vec<Vec<String>> = Vec::new();
    for text in card_texts {
        cards.extend(rows_of(text, card_header)?);
    }
    if canon.is_empty() || cards.is_empty() {
        return Err("ERROR: canon & mechanism cards must contain data rows".to_string());
    }

    let (canon_scope, canon_domain, canon_atom_id, canon_atom) = (
        column(canon_header, "Scope"),
        column(canon_header, "Domain"),
        column(canon_header, "Atom ID"),
        column(canon_header, "Atom"),
    );
    let (card_scope, card_domain, card_atom_id) = (
        column(card_header, "Scope"),
        column(card_header, "Domain"),
        column(card_header, "Atom ID"),
    );
    let (card_repo, card_platform, card_status) = (
        column(card_header, "Repository"),
        column(card_header, "Platform"),
        column(card_header, "Status"),
    );

    let mut canon_keys: HashMap<(String, String, String), usize> = HashMap::new();
    for row in &canon {
        let key = (
            row[canon_scope].clone(),
            row[canon_domain].clone(),
            row[canon_atom_id].clone(),
        );
        if canon_keys.insert(key, canon_keys.len()).is_some() {
            return Err("ERROR: duplicate canon tuple".to_string());
        }
    }

    let mut card_keys: BTreeSet<(String, String, String, String, String)> = BTreeSet::new();
    for row in &cards {
        let atom_key = (
            row[card_scope].clone(),
            row[card_domain].clone(),
            row[card_atom_id].clone(),
        );
        if !canon_keys.contains_key(&atom_key) {
            return Err(format!(
                "ERROR: card references unknown canon tuple: {}",
                py_tuple(&[
                    atom_key.0.as_str(),
                    atom_key.1.as_str(),
                    atom_key.2.as_str()
                ])
            ));
        }
        let card_key = (
            atom_key.0.clone(),
            atom_key.1.clone(),
            atom_key.2.clone(),
            row[card_repo].clone(),
            row[card_platform].clone(),
        );
        if !card_keys.insert(card_key.clone()) {
            return Err(format!(
                "ERROR: duplicate mechanism card: {}",
                py_tuple(&[
                    card_key.0.as_str(),
                    card_key.1.as_str(),
                    card_key.2.as_str(),
                    card_key.3.as_str(),
                    card_key.4.as_str(),
                ])
            ));
        }
    }

    let mut summary_rows: Vec<Vec<String>> = Vec::new();
    let mut sole_provider_count = 0usize;
    for atom in &canon {
        let atom_cards: Vec<&Vec<String>> = cards
            .iter()
            .filter(|row| {
                row[card_scope] == atom[canon_scope]
                    && row[card_domain] == atom[canon_domain]
                    && row[card_atom_id] == atom[canon_atom_id]
            })
            .collect();
        let observed: BTreeSet<String> = atom_cards
            .iter()
            .filter(|row| row[card_status].to_uppercase() == "OBSERVED")
            .map(|row| row[card_repo].clone())
            .collect();
        let unclear = atom_cards
            .iter()
            .filter(|row| row[card_status].to_uppercase() == "UNCLEAR")
            .count();
        let not_found = atom_cards
            .iter()
            .filter(|row| row[card_status].to_uppercase() == "NOT FOUND")
            .count();
        let sole = if observed.len() == 1 {
            observed.iter().next().cloned().unwrap_or_default()
        } else {
            String::new()
        };
        if !sole.is_empty() {
            sole_provider_count += 1;
        }
        let observed_names: Vec<&str> = observed.iter().map(String::as_str).collect();
        summary_rows.push(vec![
            atom[canon_scope].clone(),
            atom[canon_domain].clone(),
            atom[canon_atom_id].clone(),
            atom[canon_atom].clone(),
            observed_names.join(";"),
            observed.len().to_string(),
            unclear.to_string(),
            not_found.to_string(),
            sole,
        ]);
    }

    let domain_keys: BTreeSet<(String, String)> = canon
        .iter()
        .map(|row| (row[canon_scope].clone(), row[canon_domain].clone()))
        .collect();
    let repositories: BTreeSet<String> = cards.iter().map(|row| row[card_repo].clone()).collect();
    let mut coverage_rows: Vec<Vec<String>> = Vec::new();
    for repo in &repositories {
        let mut values: Vec<String> = vec![repo.clone()];
        for (scope, domain) in &domain_keys {
            let matching: Vec<&Vec<String>> = cards
                .iter()
                .filter(|row| {
                    row[card_repo] == *repo
                        && row[card_scope] == *scope
                        && row[card_domain] == *domain
                })
                .collect();
            let observed = matching
                .iter()
                .filter(|row| row[card_status].to_uppercase() == "OBSERVED")
                .count();
            let unresolved = matching
                .iter()
                .filter(|row| row[card_status].to_uppercase() == "UNCLEAR")
                .count();
            values.push(observed.to_string());
            values.push(unresolved.to_string());
        }
        coverage_rows.push(values);
    }
    let mut coverage_header: Vec<String> = vec!["repository".to_string()];
    for (scope, domain) in &domain_keys {
        coverage_header.push(format!("{scope} :: {domain} observed"));
        coverage_header.push(format!("{scope} :: {domain} unresolved"));
    }
    let coverage_header_refs: Vec<&str> = coverage_header.iter().map(String::as_str).collect();

    let files = vec![
        ExportedFile {
            name: CARDS_FILE,
            content: csv_text(card_header, &cards),
        },
        ExportedFile {
            name: SUMMARY_FILE,
            content: csv_text(SUMMARY_HEADER, &summary_rows),
        },
        ExportedFile {
            name: COVERAGE_FILE,
            content: csv_text(&coverage_header_refs, &coverage_rows),
        },
    ];

    Ok(Analytics {
        files,
        card_count: cards.len(),
        atom_count: canon.len(),
        sole_provider_count,
    })
}

/// Filesystem wrapper for `legion script foundation/export-analytics`: reads the canon and card
/// tables, runs [`export`], writes the three CSV files into `out_dir`, and prints the Python
/// `PASS:` line. Returns the process exit code (0 success, 1 failure).
pub fn run_paths(canon: &Path, cards: &[PathBuf], out_dir: &Path) -> i32 {
    let canon_text = match std::fs::read_to_string(canon) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("ERROR: cannot read canon {}: {error}", canon.display());
            return 1;
        }
    };
    let mut card_texts: Vec<String> = Vec::with_capacity(cards.len());
    for path in cards {
        match std::fs::read_to_string(path) {
            Ok(text) => card_texts.push(text),
            Err(error) => {
                eprintln!("ERROR: cannot read cards {}: {error}", path.display());
                return 1;
            }
        }
    }
    let refs: Vec<&str> = card_texts.iter().map(String::as_str).collect();
    let analytics = match export(&canon_text, &refs) {
        Ok(analytics) => analytics,
        Err(message) => {
            eprintln!("{message}");
            return 1;
        }
    };
    if let Err(error) = std::fs::create_dir_all(out_dir) {
        eprintln!("ERROR: cannot create {}: {error}", out_dir.display());
        return 1;
    }
    for file in &analytics.files {
        if let Err(error) = std::fs::write(out_dir.join(file.name), file.content.as_bytes()) {
            eprintln!("ERROR: cannot write {}: {error}", file.name);
            return 1;
        }
    }
    println!(
        "PASS: exported {} cards, {} atoms, {} sole-provider atoms to {}",
        analytics.card_count,
        analytics.atom_count,
        analytics.sole_provider_count,
        out_dir.display()
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANON: &str = "\
| Scope | Domain | Atom ID | Atom | Boundary | Repository provenance |
| --- | --- | --- | --- | --- | --- |
| S1 | Paste | A-1 | Clipboard transaction | snapshot and restore | repoA:B-1 |
";

    const CARDS: &str = "\
| Scope | Domain | Atom ID | Repository | Platform | Status | Production evidence | Live consumer | Mechanism | State / fallback / safeguards | Criteria assessment |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S1 | Paste | A-1 | repoA | macOS | OBSERVED | repoA: `src/a.rs#x` | repoA: `src/b.rs#y` | copies | restores | meets |
| S1 | Paste | A-1 | repoB | macOS | UNCLEAR | n/a | n/a | unknown | unknown | not proven |
";

    fn file<'a>(analytics: &'a Analytics, name: &str) -> &'a str {
        analytics
            .files
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.content.as_str())
            .expect("exported file present")
    }

    #[test]
    fn csv_line_quotes_like_python_csv() {
        assert_eq!(
            csv_line(&["a,b", "say \"hi\"", "plain", ""]),
            "\"a,b\",\"say \"\"hi\"\"\",plain,\r\n"
        );
    }

    #[test]
    fn exports_summary_with_python_columns_and_order() {
        let analytics = export(CANON, &[CARDS]).expect("valid inputs export");
        assert_eq!(analytics.card_count, 2);
        assert_eq!(analytics.atom_count, 1);
        assert_eq!(analytics.sole_provider_count, 1);
        assert_eq!(
            file(&analytics, SUMMARY_FILE),
            "scope,domain,atom_id,atom,observed_repositories,observed_count,unclear_count,not_found_count,sole_provider\r\n\
             S1,Paste,A-1,Clipboard transaction,repoA,1,1,0,repoA\r\n"
        );
    }

    #[test]
    fn exports_coverage_matrix_per_repository_and_domain() {
        let analytics = export(CANON, &[CARDS]).expect("valid inputs export");
        assert_eq!(
            file(&analytics, COVERAGE_FILE),
            "repository,S1 :: Paste observed,S1 :: Paste unresolved\r\n\
             repoA,1,0\r\n\
             repoB,0,1\r\n"
        );
    }

    #[test]
    fn exports_card_file_with_mechanism_columns() {
        let analytics = export(CANON, &[CARDS]).expect("valid inputs export");
        let cards = file(&analytics, CARDS_FILE);
        assert!(cards.starts_with(
            "Scope,Domain,Atom ID,Repository,Platform,Status,Production evidence,Live consumer,Mechanism,State / fallback / safeguards,Criteria assessment\r\n"
        ));
        assert!(cards.contains("S1,Paste,A-1,repoA,macOS,OBSERVED,repoA: `src/a.rs#x`,repoA: `src/b.rs#y`,copies,restores,meets\r\n"));
    }

    #[test]
    fn card_with_unknown_atom_is_rejected() {
        let text = CARDS.replace("| S1 | Paste | A-1 | repoB", "| S1 | Paste | A-2 | repoB");
        let err = export(CANON, &[text.as_str()]).unwrap_err();
        assert_eq!(
            err,
            "ERROR: card references unknown canon tuple: ('S1', 'Paste', 'A-2')"
        );
    }

    #[test]
    fn duplicate_card_is_rejected() {
        let text = format!(
            "{}{}",
            CARDS, "| S1 | Paste | A-1 | repoA | macOS | OBSERVED | a | b | c | d | e |\n"
        );
        let err = export(CANON, &[text.as_str()]).unwrap_err();
        assert_eq!(
            err,
            "ERROR: duplicate mechanism card: ('S1', 'Paste', 'A-1', 'repoA', 'macOS')"
        );
    }

    #[test]
    fn empty_inputs_are_rejected() {
        let err = export(CANON, &[]).unwrap_err();
        assert_eq!(err, "ERROR: canon & mechanism cards must contain data rows");
    }
}
