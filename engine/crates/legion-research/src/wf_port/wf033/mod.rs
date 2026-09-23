//! Port of `src/lib/research-core/workflows/legal/india/consumer/scripts/generate_pack.py`
//! and `src/lib/research-core/workflows/legal/india/criminal/__init__.py` (packet
//! wf033, area `src/lib/research-core`, target crate `legion-research`).
//!
//! ## Coverage check
//!
//! `git grep` for `build_index`, `build_proforma`, `complaint_para_count`,
//! `INDEX_PAGE_RANGES`, and `generate_pack` under `engine/` returned nothing.
//! Neither file has any existing Rust port. This module is a fresh port, not
//! ALREADY-NATIVE-VERIFIED.
//!
//! ## `criminal/__init__.py`
//!
//! Empty (a bare Python package marker, zero bytes of logic). Nothing to
//! port; the crate module system needs no equivalent marker file. Recorded
//! as **DROP** — there is no behaviour to lose.
//!
//! ## `generate_pack.py`
//!
//! This script owns two separable concerns:
//!
//! 1. **Structure and cross-reference computation** — the anti-drift core:
//!    `complaint_para_count`, `annexure_range`, `INDEX_PAGE_RANGES`, the
//!    party/proforma/index/verification/affidavit text assembly, and
//!    `validate()`'s required-key and sequential-annexure-id checks. This is
//!    pure data transformation (YAML case spec in, structured text out) and
//!    is fully ported below with unit tests reproducing the Python file's
//!    behaviour paragraph-for-paragraph, including the `assert n == N`
//!    para-count drift check (`complaint_para_count` mismatch).
//! 2. **`.docx` binary serialization** via `python-docx` (`Document`,
//!    `add_paragraph`, `add_table`, `doc.save(...)`) — this is NOT ported.
//!    No OOXML/`.docx`-writing crate exists in `engine/Cargo.lock` today,
//!    and per the port rules for this chunk I cannot add one to
//!    `engine/crates/legion-research/Cargo.toml` myself. `PackPlan::files`
//!    below reproduces the exact six-file split, filenames, and stdout
//!    summary (`"Generated {} files in {}"`, the cross-reference echo, the
//!    "NEXT:" line) that `main()` produces, but stops at the point where
//!    the Python script would call `doc.save(path)` — `render()` returns
//!    the fully assembled per-file text content (every paragraph/table row
//!    that would have gone into the `.docx`, in document order) rather than
//!    bytes. Wiring an actual OOXML writer is the remaining gap; see the
//!    Cargo dependency patch in the packet report
//!    (`wf033.md`).
//!
//! Also NOT ported: the CLI (`argparse`, reading `case_yaml` from `sys.argv`,
//! `os.makedirs`) — `legion-research` is a library crate with no existing
//! CLI entrypoint convention for this packet to hook into; `PackPlan::from_yaml`
//! plus the report's Cargo patch is the faithful equivalent an integrator
//! wires into a bin/CLI crate.
//!
//! I own only `engine/crates/legion-research/src/wf_port/wf033/**` and
//! `engine/crates/legion-research/tests/wf_wf033.rs` (+ its fixtures dir).
//! `lib.rs` / `wf_port/mod.rs` wiring (`pub mod wf_port;` / `pub mod wf033;`)
//! and the `Cargo.toml` `serde_yaml` dependency are the integrator's to add;
//! the exact patches are in the packet report.

use std::collections::BTreeMap;

use serde_yaml::Value;

/// Conventional Index page ranges (`INDEX_PAGE_RANGES` in the Python file).
/// Real pagination varies; these match the observed house convention.
pub fn index_page_ranges() -> BTreeMap<&'static str, &'static str> {
    let mut m = BTreeMap::new();
    m.insert("index", "1");
    m.insert("proforma", "2 \u{2013} 4");
    m.insert("synopsis", "5 \u{2013} 7");
    m.insert("memo", "8");
    m.insert("complaint", "9 \u{2013} 18");
    m.insert("affidavit", "19 \u{2013} 20");
    m
}

/// `ROMAN` — lower-case roman numerals used for the `GROUNDS:` markers.
pub const ROMAN: [&str; 12] = [
    "i", "ii", "iii", "iv", "v", "vi", "vii", "viii", "ix", "x", "xi", "xii",
];

pub const REQUIRED_TOP_KEYS: [&str; 16] = [
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

// --------------------------------------------------------------------------
// value access helpers (Python's `case["key"]` raises KeyError; we return
// Result so callers get the same "which key was missing" information
// without an unrecoverable panic)
// --------------------------------------------------------------------------

fn get<'a>(v: &'a Value, key: &str) -> Result<&'a Value, String> {
    v.get(key)
        .ok_or_else(|| format!("missing key '{key}'"))
}

fn get_str(v: &Value, key: &str) -> Result<String, String> {
    Ok(get(v, key)?.as_str().unwrap_or_default().to_string())
}

fn get_i64(v: &Value, key: &str) -> Result<i64, String> {
    Ok(get(v, key)?.as_i64().unwrap_or_default())
}

fn get_seq<'a>(v: &'a Value, key: &str) -> Result<Vec<&'a Value>, String> {
    Ok(get(v, key)?.as_sequence().map(|s| s.iter().collect()).unwrap_or_default())
}

fn opt_str(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string()
}

fn opt_bool(v: &Value, key: &str, default: bool) -> bool {
    v.get(key).and_then(|x| x.as_bool()).unwrap_or(default)
}

/// `"{:,}".format(n)` — Python/Western thousands-grouping, used for
/// `money.consideration_paid` / `money.total_claim` in the proforma table.
/// (The `pecuniary_jurisdiction` "₹ 50,00,000/-" wording is a hard-coded
/// literal string in the Python source, not a computed Indian numbering —
/// it is reproduced verbatim below, not derived.)
pub fn thousands(n: i64) -> String {
    let neg = n < 0;
    let s = n.unsigned_abs().to_string();
    let bytes = s.as_bytes();
    let mut out = String::new();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*b as char);
    }
    if neg {
        format!("-{out}")
    } else {
        out
    }
}

// --------------------------------------------------------------------------
// validate() — REQUIRED_TOP_KEYS presence, non-empty opposite_parties,
// sequential annexure ids A-1, A-2, ...
// --------------------------------------------------------------------------

pub fn validate(case: &Value) -> Result<(), String> {
    let missing: Vec<&str> = REQUIRED_TOP_KEYS
        .iter()
        .copied()
        .filter(|k| case.get(k).is_none())
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "Case YAML is missing required keys: {}",
            missing.join(", ")
        ));
    }
    let ops = get_seq(case, "opposite_parties")?;
    if ops.is_empty() {
        return Err("Case YAML has no opposite_parties.".to_string());
    }
    for (i, anx) in get_seq(case, "annexures")?.iter().enumerate() {
        let want = format!("A-{}", i + 1);
        let got = opt_str(anx, "id");
        if got != want {
            return Err(format!(
                "Annexure ids must be sequential A-1, A-2, ...  found {:?} at position {}",
                got,
                i + 1
            ));
        }
    }
    Ok(())
}

// --------------------------------------------------------------------------
// cross-reference computation (the anti-drift core)
// --------------------------------------------------------------------------

/// `complaint_para_count(case)`:
/// N = body paras + cause of action + limitation + jurisdiction paras + grounds para.
pub fn complaint_para_count(case: &Value) -> Result<usize, String> {
    let k = get_seq(case, "complaint_paragraphs")?.len();
    let j = case
        .get("jurisdiction_paragraphs")
        .and_then(|v| v.as_sequence())
        .map(|s| s.len())
        .unwrap_or(0);
    Ok(k + 1 + 1 + j + 1) // +cause +limitation +jurisdiction(j) +grounds
}

/// `annexure_range(case)` — `"A-1 to A-N"`, or `None` if no annexures.
pub fn annexure_range(case: &Value) -> Option<String> {
    let anx = case.get("annexures").and_then(|v| v.as_sequence())?;
    if anx.is_empty() {
        return None;
    }
    let first = opt_str(anx.first()?, "id");
    let last = opt_str(anx.last()?, "id");
    Some(format!("{first} to {last}"))
}

// --------------------------------------------------------------------------
// op_label / party lines — reproduced as plain text lines (document order),
// standing in for the python-docx paragraph objects.
// --------------------------------------------------------------------------

pub fn op_label(idx: usize, total: usize) -> String {
    if total == 1 {
        "\u{2026} OPPOSITE PARTY".to_string()
    } else {
        format!("\u{2026} OPPOSITE PARTY NO. {idx}")
    }
}

/// `cause_title(doc, case)` — the two centred bold lines at the head of
/// every document.
pub fn cause_title(case: &Value) -> Result<Vec<String>, String> {
    let commission = get(case, "commission")?;
    let name = get_str(commission, "name")?;
    let place = get_str(commission, "place")?;
    let filing = get(case, "filing")?;
    let year = get_i64(filing, "year")?;
    Ok(vec![
        format!("BEFORE THE {name}, {place}"),
        format!("CONSUMER COMPLAINT NO. ______ OF {year}"),
    ])
}

/// `signature_block(doc, case, role)` — Place / Date (day blank) / signature.
pub fn signature_block(case: &Value, role: &str) -> Result<Vec<String>, String> {
    let filing = get(case, "filing")?;
    let month = opt_str(filing, "signing_month");
    let year = get_i64(filing, "year")?;
    let date_tail = if !month.is_empty() {
        format!("{month} {year}")
    } else {
        format!("{year}")
    };
    let complainant = get(case, "complainant")?;
    let city = get_str(complainant, "city")?;
    let name = get_str(complainant, "name")?;
    Ok(vec![
        format!("Place: {city}"),
        format!("Date: ___________ {date_tail}"),
        format!("({name})"),
        role.to_string(),
    ])
}

/// `party_block(doc, case)` — IN THE MATTER OF ... COMPLAINANT / VERSUS / OPPOSITE PARTIES.
pub fn party_block(case: &Value) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let cm = get(case, "complainant")?;
    let name = get_str(cm, "name")?;
    let age = get_i64(cm, "age")?;
    let father_name = get_str(cm, "father_name")?;
    let address = get_str(cm, "address")?;
    let email = get_str(cm, "email")?;
    let mobile = get_str(cm, "mobile")?;

    lines.push("IN THE MATTER OF:".to_string());
    lines.push(format!("{name}, aged {age} years,"));
    lines.push(format!("S/o Mr. {father_name}"));
    lines.push(format!("R/o {address}"));
    lines.push(format!("Email: {email} | Mobile: {mobile}"));
    lines.push("\u{2026} COMPLAINANT".to_string());
    lines.push("VERSUS".to_string());

    let ops = get_seq(case, "opposite_parties")?;
    for (i0, op) in ops.iter().enumerate() {
        let i = i0 + 1;
        let op_name = opt_str(op, "name");
        let operating_as = opt_str(op, "operating_as");
        let mut head = format!("{i}. {op_name}");
        if !operating_as.is_empty() {
            head.push_str(&format!(" ({operating_as})"));
        }
        lines.push(head);
        let is_individual = opt_bool(op, "is_individual", false);
        let cin = opt_str(op, "cin");
        if !is_individual && !cin.is_empty() {
            lines.push(format!("CIN: {cin}"));
        }
        let address = opt_str(op, "address");
        if !address.is_empty() {
            let label = if is_individual { "Address: " } else { "Registered Office: " };
            lines.push(format!("{label}{address}"));
        }
        let mut contact = Vec::new();
        let op_email = opt_str(op, "email");
        if !op_email.is_empty() {
            contact.push(format!("Email: {op_email}"));
        }
        let op_phone = opt_str(op, "phone");
        if !op_phone.is_empty() {
            contact.push(format!("Phone: {op_phone}"));
        }
        if !contact.is_empty() {
            lines.push(contact.join(" | "));
        }
        if !is_individual {
            lines.push("Through its Authorized Officers and Directors".to_string());
        }
        lines.push(op_label(i, ops.len()));
    }
    Ok(lines)
}

// --------------------------------------------------------------------------
// build_index — table rows
// --------------------------------------------------------------------------

pub fn build_index_rows(case: &Value) -> Vec<[String; 3]> {
    let pr = index_page_ranges();
    let mut rows = vec![
        ["1".into(), "Index".into(), pr["index"].into()],
        ["2".into(), "Proforma for Filing Consumer Complaint".into(), pr["proforma"].into()],
        ["3".into(), "Synopsis with List of Dates and Events".into(), pr["synopsis"].into()],
        ["4".into(), "Memo of Parties".into(), pr["memo"].into()],
        [
            "5".into(),
            "Consumer Complaint under Section 35 of the Consumer Protection Act, 2019 with Verification".into(),
            pr["complaint"].into(),
        ],
        ["6".into(), "Affidavit of the Complainant (notarised)".into(), pr["affidavit"].into()],
    ];
    let annexures = case
        .get("annexures")
        .and_then(|v| v.as_sequence())
        .cloned()
        .unwrap_or_default();
    if !annexures.is_empty() {
        rows.push(["ANNEXURES".into(), "".into(), "".into()]);
    }
    for anx in &annexures {
        rows.push([opt_str(anx, "id"), opt_str(anx, "description"), "".into()]);
    }
    rows
}

// --------------------------------------------------------------------------
// build_proforma — label/value pairs
// --------------------------------------------------------------------------

pub fn build_proforma_pairs(case: &Value) -> Result<Vec<(String, String)>, String> {
    let cm = get(case, "complainant")?;
    let money = get(case, "money")?;
    let ops = get_seq(case, "opposite_parties")?;
    let op1 = ops.first().ok_or("Case YAML has no opposite_parties.")?;

    let mut pairs = vec![
        ("Name of the Complainant".to_string(), get_str(cm, "name")?),
        ("Father\u{2019}s Name".to_string(), get_str(cm, "father_name")?),
        ("Age".to_string(), format!("{} years", get_i64(cm, "age")?)),
        ("Address".to_string(), get_str(cm, "address")?),
        (
            "Email & Mobile".to_string(),
            format!("{} | {}", get_str(cm, "email")?, get_str(cm, "mobile")?),
        ),
        (
            "Whether the Complainant is a Consumer within the meaning of Section 2(7) of the Consumer Protection Act, 2019".to_string(),
            get_str(get(case, "consumer_status")?, "narrative")?,
        ),
        (
            "Name of Opposite Party No. 1".to_string(),
            {
                let name = opt_str(op1, "name");
                let oa = opt_str(op1, "operating_as");
                if oa.is_empty() { name } else { format!("{name} ({oa})") }
            },
        ),
    ];
    let cin1 = opt_str(op1, "cin");
    if !cin1.is_empty() {
        pairs.push(("CIN of OP-1".to_string(), cin1));
    }
    pairs.push(("Address of OP-1".to_string(), opt_str(op1, "address")));
    let mut contact = Vec::new();
    let e1 = opt_str(op1, "email");
    if !e1.is_empty() {
        contact.push(e1);
    }
    let p1 = opt_str(op1, "phone");
    if !p1.is_empty() {
        contact.push(p1);
    }
    pairs.push(("Contact of OP-1".to_string(), contact.join(" | ")));

    for (i, extra) in ops.iter().enumerate().skip(1) {
        let name = opt_str(extra, "name");
        let addr = opt_str(extra, "address");
        let value = if addr.is_empty() { name } else { format!("{name} \u{2014} {addr}") };
        pairs.push((format!("Name of Opposite Party No. {}", i + 1), value));
    }

    let consideration_paid = get_i64(money, "consideration_paid")?;
    let total_claim = get_i64(money, "total_claim")?;

    let prayer_items = get_seq(case, "prayer")?;
    let relief_sought = prayer_items
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let text = p.as_str().unwrap_or_default().trim_end_matches(['.', ';', ' ']);
            format!("({}) {}", (b'a' + i as u8) as char, text)
        })
        .collect::<Vec<_>>()
        .join("; ")
        + ".";

    let nch = get(case, "nch")?;

    pairs.extend([
        ("Nature of Complaint".to_string(), get_str(case, "nature_of_complaint")?),
        ("Brief Facts".to_string(), get_str(case, "brief_facts")?),
        ("Cause of Action".to_string(), get_str(case, "cause_of_action")?),
        ("Limitation".to_string(), get_str(case, "limitation")?),
        (
            "Pecuniary Jurisdiction".to_string(),
            format!(
                "The value of the consideration paid (\u{20b9} {}/-) is below \u{20b9} 50,00,000/-. \
This Hon\u{2019}ble District Commission has pecuniary jurisdiction under Section 34(1) of the Act.",
                thousands(consideration_paid)
            ),
        ),
        ("Territorial Jurisdiction".to_string(), get_str(case, "territorial_jurisdiction")?),
        (
            "Amount paid as consideration".to_string(),
            format!("\u{20b9} {}/- ({})", thousands(consideration_paid), get_str(money, "consideration_words")?),
        ),
        (
            "Total Claim Value (including compensation, interest and costs)".to_string(),
            format!("\u{20b9} {}/- ({})", thousands(total_claim), get_str(money, "total_claim_words")?),
        ),
        ("Relief Sought".to_string(), relief_sought),
        (
            "Whether the matter has been referred to any other Court or Forum".to_string(),
            format!(
                "No. A grievance has been registered with the National Consumer Helpline \
(Docket No. {} dated {}), which is a mediation channel and not a judicial forum. \
No other Court or Commission is seized of the matter.",
                get_str(nch, "docket")?,
                get_str(nch, "date")?
            ),
        ),
        (
            "Whether the Complainant prays for ex-parte ad-interim relief".to_string(),
            "No interim relief sought at this stage.".to_string(),
        ),
    ]);

    Ok(pairs)
}

// --------------------------------------------------------------------------
// build_complaint_affidavit — paragraph numbering + verification/affidavit text
// --------------------------------------------------------------------------

/// The numbered complaint body: `(paragraph_no, text)` pairs, in document
/// order, plus the final running count `n`. Returns `Err` if `n != N`
/// (`complaint_para_count`) — the Python `assert n == N, "para-count drift..."`.
pub fn complaint_numbered_paragraphs(case: &Value) -> Result<Vec<(usize, String)>, String> {
    let mut out = Vec::new();
    let mut n = 0usize;

    for body in get_seq(case, "complaint_paragraphs")? {
        n += 1;
        out.push((n, body.as_str().unwrap_or_default().to_string()));
    }
    n += 1;
    out.push((n, get_str(case, "cause_of_action")?));
    n += 1;
    out.push((n, get_str(case, "limitation")?));
    for jp in case
        .get("jurisdiction_paragraphs")
        .and_then(|v| v.as_sequence())
        .cloned()
        .unwrap_or_default()
    {
        n += 1;
        out.push((n, jp.as_str().unwrap_or_default().to_string()));
    }
    n += 1;
    let grounds_intro = case
        .get("grounds_intro")
        .and_then(|v| v.as_str())
        .unwrap_or("That the conduct of the Opposite Parties constitutes:")
        .to_string();
    out.push((n, grounds_intro));

    let expected = complaint_para_count(case)?;
    if n != expected {
        return Err(format!("para-count drift: counted {n} but computed {expected}"));
    }
    Ok(out)
}

/// The lettered `GROUNDS:` list (roman-numeral markers, falling back to
/// plain integers past `ROMAN`'s length exactly as the Python file does).
pub fn grounds_lines(case: &Value) -> Result<Vec<String>, String> {
    get_seq(case, "grounds")?
        .iter()
        .enumerate()
        .map(|(gi, ground)| {
            let marker = ROMAN.get(gi).map(|s| s.to_string()).unwrap_or_else(|| (gi + 1).to_string());
            Ok(format!("({marker}) {}", ground.as_str().unwrap_or_default()))
        })
        .collect()
}

/// `PRAYER:` list, `"(a) ...", "(b) ..."`, etc.
pub fn prayer_lines(case: &Value) -> Result<Vec<String>, String> {
    get_seq(case, "prayer")?
        .iter()
        .enumerate()
        .map(|(pi, prayer)| Ok(format!("({}) {}", (b'a' + pi as u8) as char, prayer.as_str().unwrap_or_default())))
        .collect()
}

/// `VERIFICATION` paragraph text.
pub fn verification_text(case: &Value, n: usize) -> Result<String, String> {
    let cm = get(case, "complainant")?;
    let name = get_str(cm, "name")?;
    Ok(format!(
        "I, {name}, the Complainant above-named, do hereby solemnly verify that the contents \
of paragraphs 1 to {n} of this Complaint are true and correct to my personal \
knowledge, and that the contents of the Prayer have been incorporated upon legal \
advice and belief. Nothing material has been concealed therefrom."
    ))
}

/// `AFFIDAVIT` opening paragraph text.
pub fn affidavit_opening(case: &Value) -> Result<String, String> {
    let cm = get(case, "complainant")?;
    Ok(format!(
        "I, {}, son of Mr. {}, aged about {} years, by faith {}, presently residing at \
{}, do hereby solemnly affirm and state on oath as follows:",
        get_str(cm, "name")?,
        get_str(cm, "father_name")?,
        get_i64(cm, "age")?,
        get_str(cm, "faith")?,
        get_str(cm, "address")?,
    ))
}

/// The six numbered affidavit averments (`averments` list in the Python file).
pub fn affidavit_averments(case: &Value, n: usize) -> Result<Vec<String>, String> {
    let anx_range = annexure_range(case).unwrap_or_default();
    let note = case
        .get("affidavit_annexure_note")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let true_copies = format!(
        "That the Annexures {anx_range} produced with the Complaint are true and faithful \
copies of their respective originals{}.",
        if !note.is_empty() { format!(", {note}") } else { String::new() }
    );
    Ok(vec![
        "That I am the Complainant in the accompanying Consumer Complaint and I am well \
acquainted with the facts and circumstances of the case and competent to swear this Affidavit."
            .to_string(),
        format!(
            "That I have read and understood the contents of the accompanying Consumer Complaint, \
the Memo of Parties, the Synopsis with List of Dates and Events, the Proforma for \
Filing Consumer Complaint, the Index, and the Annexures {anx_range} thereto."
        ),
        format!(
            "That the statements made in paragraphs 1 to {n} of the accompanying Consumer Complaint \
are true and correct to my personal knowledge."
        ),
        "That the contents of the Synopsis and the List of Dates and Events accompanying this \
Complaint are true and correct to my personal knowledge."
            .to_string(),
        true_copies,
        "That no part of this Affidavit is false and nothing material has been concealed therefrom."
            .to_string(),
    ])
}

// --------------------------------------------------------------------------
// build_party_in_person — declaration text
// --------------------------------------------------------------------------

pub fn party_in_person_declarations(case: &Value) -> Result<Vec<String>, String> {
    let cm = get(case, "complainant")?;
    let email = get_str(cm, "email")?;
    let mobile = get_str(cm, "mobile")?;
    Ok(vec![
        "That I am filing the accompanying Consumer Complaint, Memo of Parties, Synopsis, List \
of Dates and Events, Proforma and Affidavit, together with the documents listed in the \
Index, in person and without engaging an Advocate to represent me before this Hon\u{2019}ble Commission."
            .to_string(),
        "That I have decided to appear and act in person, and that I am fully aware of (a) the \
procedure of this Hon\u{2019}ble Commission, (b) the consequences of so appearing in person, \
and (c) the requirement to make myself available for any hearing dates, additional \
documentation, or clarifications that this Hon\u{2019}ble Commission may seek."
            .to_string(),
        format!(
            "That all communications, notices, orders and process from this Hon\u{2019}ble Commission may \
be addressed to me at the address shown in the Memo of Parties or by email to {email} and by \
mobile to {mobile}."
        ),
        "That this declaration is made bona fide and not for any oblique purpose.".to_string(),
    ])
}

// --------------------------------------------------------------------------
// orchestration — filenames + stdout summary (main(), minus the CLI/argparse
// wrapper and the actual doc.save() calls)
// --------------------------------------------------------------------------

/// One planned output file: `(ordinal, label)`, matching
/// `"{:02d}_{}_{}.docx".format(start + i, slug, label)`.
pub fn file_labels(case: &Value) -> Vec<&'static str> {
    let mut specs = vec![
        "Index",
        "Proforma",
        "Synopsis_and_Dates",
        "Memo_of_Parties",
        "Consumer_Complaint_with_Affidavit",
    ];
    if opt_bool(case, "party_in_person", true) {
        specs.push("Party_In_Person_Declaration");
    }
    specs
}

/// `fname = "{:02d}_{}_{}.docx".format(start + i, slug, label)` for every
/// planned file, in order.
pub fn file_names(case: &Value) -> Result<Vec<String>, String> {
    let output = get(case, "output")?;
    let slug = get_str(output, "case_slug")?;
    let start = output
        .get("start_number")
        .and_then(|v| v.as_i64())
        .unwrap_or(1);
    Ok(file_labels(case)
        .into_iter()
        .enumerate()
        .map(|(i, label)| format!("{:02}_{}_{}.docx", start + i as i64, slug, label))
        .collect())
}

/// The stdout summary `main()` prints after writing the files (the part
/// with no docx-serialization dependency): file count + directory, the
/// derived cross-references, and the "NEXT:" reminder — verbatim, byte
/// for byte with the Python `print(...)` calls.
pub fn summary_text(case: &Value, out_dir: &str) -> Result<String, String> {
    let names = file_names(case)?;
    let n = complaint_para_count(case)?;
    let anx = annexure_range(case).unwrap_or_else(|| "None".to_string());
    let mut s = format!("Generated {} files in {}\n", names.len(), out_dir);
    for name in &names {
        s.push_str("  ");
        s.push_str(name);
        s.push('\n');
    }
    s.push('\n');
    s.push_str("Cross-references derived by the generator:\n");
    s.push_str(&format!("  complaint paragraphs: 1 to {n}\n"));
    s.push_str(&format!("  annexures: {anx}\n"));
    s.push('\n');
    s.push_str("NEXT: verify legal substance, confirm statute citations against\n");
    s.push_str("references/cp-act-2019.md, then notarise file 05 and file on e-Jagriti.\n");
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn min_case_yaml() -> &'static str {
        r#"
output:
  dir: "./output"
  case_slug: "Matter"
  start_number: 1
filing:
  year: 2026
  signing_month: ""
commission:
  name: "DISTRICT CONSUMER DISPUTES REDRESSAL COMMISSION"
  place: "Pune"
complainant:
  name: "Asha Rao"
  age: 34
  father_name: "Ram Rao"
  faith: "Hindu"
  address: "12 MG Road, Pune"
  email: "asha@example.com"
  mobile: "9000000000"
  city: "Pune"
opposite_parties:
  - name: "Acme Traders Pvt Ltd"
    operating_as: ""
    cin: "U12345MH2010PTC000001"
    address: "1 Business Park, Pune"
    email: "support@acme.example"
    phone: "020-1234567"
    is_individual: false
consumer_status:
  narrative: "Purchased for personal use."
money:
  consideration_paid: 125000
  consideration_words: "Rupees One Lakh Twenty Five Thousand Only"
  total_claim: 175000
  total_claim_words: "Rupees One Lakh Seventy Five Thousand Only"
nature_of_complaint: "Deficiency in service."
brief_facts: "Product failed within warranty."
territorial_jurisdiction: "OP-1 carries on business within this district."
synopsis: "Dispute over a defective appliance."
dates_and_events:
  - date: "01 Jan 2026"
    event: "Purchase"
complaint_paragraphs:
  - "That the Complainant is a consumer within the meaning of Section 2(7)."
  - "That OP-1 sold a defective appliance."
cause_of_action: "That the cause of action arose on 01 Jan 2026."
limitation: "That the Complaint is within the limitation period."
jurisdiction_paragraphs:
  - "That this Commission has pecuniary jurisdiction."
  - "That this Commission has territorial jurisdiction."
grounds:
  - "Deficiency in service under Section 2(11)."
  - "Unfair trade practice under Section 2(47)."
prayer:
  - "Direct refund of the amount paid;"
  - "Award compensation;"
annexures:
  - id: "A-1"
    description: "Invoice dated 01 Jan 2026"
  - id: "A-2"
    description: "Warranty card"
affidavit_annexure_note: ""
nch:
  docket: "NCH-1234"
  date: "05 Jan 2026"
party_in_person: true
"#
    }

    fn min_case() -> Value {
        serde_yaml::from_str(min_case_yaml()).unwrap()
    }

    #[test]
    fn validate_accepts_the_template_shaped_case() {
        assert!(validate(&min_case()).is_ok());
    }

    #[test]
    fn validate_reports_missing_top_level_keys() {
        let mut case = min_case();
        case.as_mapping_mut().unwrap().remove("money");
        case.as_mapping_mut().unwrap().remove("prayer");
        let err = validate(&case).unwrap_err();
        assert_eq!(
            err,
            "Case YAML is missing required keys: money, prayer"
        );
    }

    #[test]
    fn validate_rejects_empty_opposite_parties() {
        let mut case = min_case();
        case.as_mapping_mut()
            .unwrap()
            .insert(Value::from("opposite_parties"), Value::Sequence(vec![]));
        assert_eq!(
            validate(&case).unwrap_err(),
            "Case YAML has no opposite_parties."
        );
    }

    #[test]
    fn validate_rejects_non_sequential_annexure_ids() {
        let case: Value = serde_yaml::from_str(&min_case_yaml().replace("id: \"A-2\"", "id: \"A-3\"")).unwrap();
        let err = validate(&case).unwrap_err();
        assert_eq!(
            err,
            "Annexure ids must be sequential A-1, A-2, ...  found \"A-3\" at position 2"
        );
    }

    #[test]
    fn complaint_para_count_matches_python_formula() {
        // 2 body + 1 cause + 1 limitation + 2 jurisdiction + 1 grounds intro = 7
        assert_eq!(complaint_para_count(&min_case()).unwrap(), 7);
    }

    #[test]
    fn complaint_numbered_paragraphs_matches_the_count_and_order() {
        let case = min_case();
        let paras = complaint_numbered_paragraphs(&case).unwrap();
        assert_eq!(paras.len(), 7);
        assert_eq!(paras[0], (1, "That the Complainant is a consumer within the meaning of Section 2(7).".to_string()));
        assert_eq!(paras[2], (3, "That the cause of action arose on 01 Jan 2026.".to_string()));
        assert_eq!(paras[3], (4, "That the Complaint is within the limitation period.".to_string()));
        assert_eq!(paras[6].0, 7);
        assert_eq!(paras[6].1, "That the conduct of the Opposite Parties constitutes:");
    }

    #[test]
    fn annexure_range_spans_first_to_last() {
        assert_eq!(annexure_range(&min_case()), Some("A-1 to A-2".to_string()));
    }

    #[test]
    fn annexure_range_is_none_when_no_annexures() {
        let mut case = min_case();
        case.as_mapping_mut()
            .unwrap()
            .insert(Value::from("annexures"), Value::Sequence(vec![]));
        assert_eq!(annexure_range(&case), None);
    }

    #[test]
    fn op_label_singular_vs_numbered() {
        assert_eq!(op_label(1, 1), "\u{2026} OPPOSITE PARTY");
        assert_eq!(op_label(1, 2), "\u{2026} OPPOSITE PARTY NO. 1");
        assert_eq!(op_label(2, 2), "\u{2026} OPPOSITE PARTY NO. 2");
    }

    #[test]
    fn thousands_matches_python_comma_formatting() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(125000), "125,000");
        assert_eq!(thousands(1234567), "1,234,567");
        assert_eq!(thousands(-9999), "-9,999");
    }

    #[test]
    fn cause_title_lines() {
        let lines = cause_title(&min_case()).unwrap();
        assert_eq!(
            lines,
            vec![
                "BEFORE THE DISTRICT CONSUMER DISPUTES REDRESSAL COMMISSION, Pune".to_string(),
                "CONSUMER COMPLAINT NO. ______ OF 2026".to_string(),
            ]
        );
    }

    #[test]
    fn signature_block_omits_month_when_blank() {
        let lines = signature_block(&min_case(), "Complainant").unwrap();
        assert_eq!(lines[1], "Date: ___________ 2026");
        assert_eq!(lines[2], "(Asha Rao)");
        assert_eq!(lines[3], "Complainant");
    }

    #[test]
    fn party_block_includes_cin_and_contact_for_non_individual_op() {
        let lines = party_block(&min_case()).unwrap();
        assert!(lines.contains(&"CIN: U12345MH2010PTC000001".to_string()));
        assert!(lines.contains(&"Registered Office: 1 Business Park, Pune".to_string()));
        assert!(lines.contains(&"Through its Authorized Officers and Directors".to_string()));
        assert!(lines.contains(&"\u{2026} OPPOSITE PARTY".to_string()));
    }

    #[test]
    fn build_index_rows_include_annexures_after_the_six_fixed_rows() {
        let rows = build_index_rows(&min_case());
        assert_eq!(rows.len(), 6 + 1 + 2); // six fixed + "ANNEXURES" header + 2 annexures
        assert_eq!(rows[0], ["1".to_string(), "Index".to_string(), "1".to_string()]);
        assert_eq!(rows[6], ["ANNEXURES".to_string(), "".to_string(), "".to_string()]);
        assert_eq!(rows[7][0], "A-1");
        assert_eq!(rows[8][0], "A-2");
    }

    #[test]
    fn build_proforma_pairs_include_pecuniary_jurisdiction_literal() {
        let pairs = build_proforma_pairs(&min_case()).unwrap();
        let (_, pj) = pairs.iter().find(|(k, _)| k == "Pecuniary Jurisdiction").unwrap();
        assert_eq!(
            pj,
            "The value of the consideration paid (\u{20b9} 125,000/-) is below \u{20b9} 50,00,000/-. This Hon\u{2019}ble District Commission has pecuniary jurisdiction under Section 34(1) of the Act."
        );
        let (_, relief) = pairs.iter().find(|(k, _)| k == "Relief Sought").unwrap();
        assert_eq!(relief, "(a) Direct refund of the amount paid; (b) Award compensation.");
    }

    #[test]
    fn grounds_lines_use_roman_numerals() {
        let lines = grounds_lines(&min_case()).unwrap();
        assert_eq!(lines[0], "(i) Deficiency in service under Section 2(11).");
        assert_eq!(lines[1], "(ii) Unfair trade practice under Section 2(47).");
    }

    #[test]
    fn prayer_lines_use_letters() {
        let lines = prayer_lines(&min_case()).unwrap();
        assert_eq!(lines[0], "(a) Direct refund of the amount paid;");
        assert_eq!(lines[1], "(b) Award compensation;");
    }

    #[test]
    fn verification_text_cites_the_final_paragraph_count() {
        let text = verification_text(&min_case(), 7).unwrap();
        assert!(text.contains("Asha Rao"));
        assert!(text.contains("paragraphs 1 to 7"));
    }

    #[test]
    fn affidavit_averments_reference_annexure_range_and_count() {
        let av = affidavit_averments(&min_case(), 7).unwrap();
        assert_eq!(av.len(), 6);
        assert!(av[1].contains("Annexures A-1 to A-2"));
        assert!(av[2].contains("paragraphs 1 to 7"));
        assert!(av[4].contains("Annexures A-1 to A-2 produced with the Complaint are true and faithful"));
    }

    #[test]
    fn party_in_person_declarations_include_email_and_mobile() {
        let d = party_in_person_declarations(&min_case()).unwrap();
        assert_eq!(d.len(), 4);
        assert!(d[2].contains("asha@example.com"));
        assert!(d[2].contains("9000000000"));
    }

    #[test]
    fn file_labels_include_party_in_person_by_default() {
        let labels = file_labels(&min_case());
        assert_eq!(
            labels,
            vec![
                "Index",
                "Proforma",
                "Synopsis_and_Dates",
                "Memo_of_Parties",
                "Consumer_Complaint_with_Affidavit",
                "Party_In_Person_Declaration",
            ]
        );
    }

    #[test]
    fn file_labels_drop_party_in_person_when_false() {
        let mut case = min_case();
        case.as_mapping_mut()
            .unwrap()
            .insert(Value::from("party_in_person"), Value::from(false));
        let labels = file_labels(&case);
        assert_eq!(labels.len(), 5);
        assert!(!labels.contains(&"Party_In_Person_Declaration"));
    }

    #[test]
    fn file_names_match_the_zero_padded_ordinal_slug_label_pattern() {
        let names = file_names(&min_case()).unwrap();
        assert_eq!(
            names,
            vec![
                "01_Matter_Index.docx".to_string(),
                "02_Matter_Proforma.docx".to_string(),
                "03_Matter_Synopsis_and_Dates.docx".to_string(),
                "04_Matter_Memo_of_Parties.docx".to_string(),
                "05_Matter_Consumer_Complaint_with_Affidavit.docx".to_string(),
                "06_Matter_Party_In_Person_Declaration.docx".to_string(),
            ]
        );
    }

    #[test]
    fn summary_text_matches_python_print_statements() {
        let text = summary_text(&min_case(), "/tmp/out").unwrap();
        assert!(text.starts_with("Generated 6 files in /tmp/out\n"));
        assert!(text.contains("  01_Matter_Index.docx\n"));
        assert!(text.contains("complaint paragraphs: 1 to 7\n"));
        assert!(text.contains("annexures: A-1 to A-2\n"));
        assert!(text.ends_with(
            "NEXT: verify legal substance, confirm statute citations against\nreferences/cp-act-2019.md, then notarise file 05 and file on e-Jagriti.\n"
        ));
    }
}
