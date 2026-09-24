//! Packet r57: port of
//! `src/lib/research-core/workflows/legal/india/consumer/scripts/generate_pack.py`.
//!
//! Builds a District Consumer Commission filing pack (six `.docx` files —
//! Index, Proforma, Synopsis+Dates, Memo of Parties, Consumer Complaint with
//! Affidavit, and an optional Party-in-Person Declaration) from a case YAML.
//! The generator owns STRUCTURE (headings, paragraph numbering, the six-file
//! split, cross-references); the case YAML owns SUBSTANCE. See
//! [`builders`] for the per-document layout and [`docx`] for the minimal
//! WordprocessingML writer.

pub mod builders;
pub mod docx;
pub mod yaml_case;

use std::path::{Path, PathBuf};

use serde_yaml::Value;

use docx::Doc;

/// Top-level keys `generate_pack.py`'s `validate()` requires on the case
/// YAML, in the order it reports them.
const REQUIRED_TOP_KEYS: &[&str] = &[
    "output",
    "filing",
    "commission",
    "complainant",
    "opposite_parties",
    "consumer_status",
    "money",
    "complaint_paragraphs",
    "cause_of_action",
    "limitation",
    "grounds",
    "prayer",
    "annexures",
    "synopsis",
    "dates_and_events",
    "nch",
];

/// Mirrors `validate(case)`. `Err` carries the message `sys.exit()` would
/// have printed to stderr; the caller maps that to exit code 1.
pub fn validate(case: &Value) -> Result<(), String> {
    let missing: Vec<&str> = REQUIRED_TOP_KEYS
        .iter()
        .filter(|k| case.get(*k).is_none())
        .copied()
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "Case YAML is missing required keys: {}",
            missing.join(", ")
        ));
    }
    let opposite_parties = yaml_case::seq(case, "opposite_parties");
    if opposite_parties.is_empty() {
        return Err("Case YAML has no opposite_parties.".to_string());
    }
    for (i, anx) in yaml_case::seq(case, "annexures").iter().enumerate() {
        let expected = format!("A-{}", i + 1);
        let actual = yaml_case::opt_s(anx, "id");
        if actual.as_deref() != Some(expected.as_str()) {
            return Err(format!(
                "Annexure ids must be sequential A-1, A-2, ...  found {} at position {}",
                actual
                    .map(|s| format!("'{}'", s))
                    .unwrap_or_else(|| "None".to_string()),
                i + 1
            ));
        }
    }
    Ok(())
}

/// One `(label, builder)` entry from `specs` in `main()`.
type Builder = fn(&mut Doc, &Value);

fn specs(case: &Value) -> Vec<(&'static str, Builder)> {
    let mut v: Vec<(&'static str, Builder)> = vec![
        ("Index", builders::build_index as Builder),
        ("Proforma", builders::build_proforma as Builder),
        ("Synopsis_and_Dates", builders::build_synopsis as Builder),
        ("Memo_of_Parties", builders::build_memo as Builder),
        (
            "Consumer_Complaint_with_Affidavit",
            builders::build_complaint_affidavit as Builder,
        ),
    ];
    if yaml_case::bool_or(case, "party_in_person", true) {
        v.push((
            "Party_In_Person_Declaration",
            builders::build_party_in_person as Builder,
        ));
    }
    v
}

/// Parsed CLI arguments, mirroring the `argparse` setup in `main()`.
struct Args {
    case_yaml: String,
    out: Option<String>,
}

/// Mirrors the `argparse.ArgumentParser` block in `main()`: one required
/// positional (`case_yaml`) and one optional `--out <dir>` flag.
fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut case_yaml: Option<String> = None;
    let mut out: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--out" {
            i += 1;
            let val = args
                .get(i)
                .ok_or_else(|| "argument --out: expected one argument".to_string())?;
            out = Some(val.clone());
        } else if let Some(val) = a.strip_prefix("--out=") {
            out = Some(val.to_string());
        } else if case_yaml.is_none() {
            case_yaml = Some(a.clone());
        } else {
            return Err(format!("unrecognized arguments: {}", a));
        }
        i += 1;
    }
    let case_yaml = case_yaml.ok_or_else(|| {
        "the following arguments are required: case_yaml".to_string()
    })?;
    Ok(Args { case_yaml, out })
}

/// Mirrors `main()`. Returns a process exit code: 0 on success, 1 for the
/// `sys.exit(<message>)` paths (message already written to stderr), 2 for a
/// CLI usage error (argparse's own convention).
pub fn run(args: &[String]) -> i32 {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!(
                "usage: generate_pack.py [-h] [--out OUT] case_yaml\ngenerate_pack.py: error: {}",
                msg
            );
            return 2;
        }
    };

    let text = match std::fs::read_to_string(&parsed.case_yaml) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{}: {}", parsed.case_yaml, e);
            return 1;
        }
    };
    let case: Value = match serde_yaml::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", e);
            return 1;
        }
    };

    if let Err(msg) = validate(&case) {
        eprintln!("{}", msg);
        return 1;
    }

    let out_dir_spec = parsed
        .out
        .clone()
        .unwrap_or_else(|| yaml_case::s(yaml_case::get(&case, "output"), "dir"));
    let out_dir = match std::fs::canonicalize(&out_dir_spec) {
        Ok(p) => p,
        // Mirrors os.path.abspath: works even if the directory doesn't
        // exist yet (created below).
        Err(_) => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            cwd.join(&out_dir_spec)
        }
    };
    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        eprintln!("{}", e);
        return 1;
    }
    // Re-canonicalize now that the directory is guaranteed to exist, so the
    // printed path matches what os.path.abspath + os.makedirs would show.
    let out_dir = std::fs::canonicalize(&out_dir).unwrap_or(out_dir);
    let out_dir = strip_windows_verbatim_prefix(&out_dir);

    let output = yaml_case::get(&case, "output");
    let slug = yaml_case::s(output, "case_slug");
    let start = yaml_case::i64_or(output, "start_number", 1);

    let mut written: Vec<PathBuf> = Vec::new();
    for (i, (label, builder)) in specs(&case).into_iter().enumerate() {
        let mut doc = Doc::new();
        builder(&mut doc, &case);
        let fname = format!("{:02}_{}_{}.docx", start + i as i64, slug, label);
        let path = out_dir.join(fname);
        if let Err(e) = doc.save(&path) {
            eprintln!("{}", e);
            return 1;
        }
        written.push(path);
    }

    let n = builders::complaint_para_count(&case);
    println!("Generated {} files in {}", written.len(), out_dir.display());
    for p in &written {
        println!(
            "  {}",
            p.file_name().and_then(|n| n.to_str()).unwrap_or_default()
        );
    }
    println!();
    println!("Cross-references derived by the generator:");
    println!("  complaint paragraphs: 1 to {}", n);
    println!(
        "  annexures: {}",
        builders::annexure_range(&case).unwrap_or_else(|| "None".to_string())
    );
    println!();
    println!("NEXT: verify legal substance, confirm statute citations against");
    println!("references/cp-act-2019.md, then notarise file 05 and file on e-Jagriti.");

    0
}

/// Mirrors stripping the `\\?\` extended-length prefix `Path::canonicalize`
/// adds on Windows, so printed/compared paths match the plain form
/// `os.path.abspath` produces.
fn strip_windows_verbatim_prefix(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        p.to_path_buf()
    }
}
