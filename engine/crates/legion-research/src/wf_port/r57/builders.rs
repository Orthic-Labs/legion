//! Packet r57: the six document builders from `generate_pack.py`, ported
//! paragraph-for-paragraph so headings, numbering and cross-references stay
//! byte-identical to the Python house style.

use serde_yaml::Value;

use super::docx::{para, Align, Doc};
use super::yaml_case as yc;

pub const ROMAN: [&str; 12] = [
    "i", "ii", "iii", "iv", "v", "vi", "vii", "viii", "ix", "x", "xi", "xii",
];

pub struct IndexPageRanges;

impl IndexPageRanges {
    pub fn get(key: &str) -> &'static str {
        match key {
            "index" => "1",
            "proforma" => "2 – 4",
            "synopsis" => "5 – 7",
            "memo" => "8",
            "complaint" => "9 – 18",
            "affidavit" => "19 – 20",
            other => panic!("KeyError: '{}'", other),
        }
    }
}

// --------------------------------------------------------------------------
// low-level docx helpers
// --------------------------------------------------------------------------

/// Mirrors `cause_title(doc, case)`.
pub fn cause_title(doc: &mut Doc, case: &Value) {
    let commission = yc::get(case, "commission");
    let line1 = format!(
        "BEFORE THE {}, {}",
        yc::s(commission, "name"),
        yc::s(commission, "place")
    );
    doc.para(para(line1).bold(true).align(Align::Center).space_after(2));
    let filing = yc::get(case, "filing");
    doc.para(
        para(format!(
            "CONSUMER COMPLAINT NO. ______ OF {}",
            yc::s(filing, "year")
        ))
        .bold(true)
        .align(Align::Center)
        .space_after(12),
    );
}

/// Mirrors `signature_block(doc, case, role="Complainant")`.
pub fn signature_block(doc: &mut Doc, case: &Value, role: &str) {
    let filing = yc::get(case, "filing");
    let month = yc::truthy_s(filing, "signing_month").unwrap_or_default();
    let year = yc::s(filing, "year");
    let date_tail = if !month.is_empty() {
        format!("{} {}", month, year)
    } else {
        year
    };
    let complainant = yc::get(case, "complainant");
    doc.para(para(format!("Place: {}", yc::s(complainant, "city"))).space_after(2));
    doc.para(para(format!("Date: ___________ {}", date_tail)).space_after(12));
    doc.para(
        para(format!("({})", yc::s(complainant, "name")))
            .align(Align::Right)
            .space_after(0),
    );
    doc.para(para(role.to_string()).align(Align::Right).space_after(6));
}

/// Mirrors `op_label(idx, total)`.
pub fn op_label(idx: usize, total: usize) -> String {
    if total == 1 {
        "… OPPOSITE PARTY".to_string()
    } else {
        format!("… OPPOSITE PARTY NO. {}", idx)
    }
}

/// Mirrors `party_block(doc, case)`.
pub fn party_block(doc: &mut Doc, case: &Value) {
    let cm = yc::get(case, "complainant");
    doc.para(para("IN THE MATTER OF:").bold(true).space_after(8));
    doc.para(para(format!("{}, aged {} years,", yc::s(cm, "name"), yc::s(cm, "age"))).space_after(0));
    doc.para(para(format!("S/o Mr. {}", yc::s(cm, "father_name"))).space_after(0));
    doc.para(para(format!("R/o {}", yc::s(cm, "address"))).space_after(0));
    doc.para(
        para(format!(
            "Email: {} | Mobile: {}",
            yc::s(cm, "email"),
            yc::s(cm, "mobile")
        ))
        .space_after(0),
    );
    doc.para(
        para("… COMPLAINANT")
            .bold(true)
            .align(Align::Right)
            .space_after(6),
    );
    doc.para(para("VERSUS").bold(true).space_after(6));

    let ops = yc::seq(case, "opposite_parties");
    let total = ops.len();
    for (i, op) in ops.iter().enumerate() {
        let idx = i + 1;
        let mut head = format!("{}. {}", idx, yc::s(op, "name"));
        if let Some(operating_as) = yc::truthy_s(op, "operating_as") {
            head.push_str(&format!(" ({})", operating_as));
        }
        doc.para(para(head).space_after(0));
        let is_individual = yc::bool_or(op, "is_individual", false);
        if !is_individual {
            if let Some(cin) = yc::truthy_s(op, "cin") {
                doc.para(para(format!("CIN: {}", cin)).space_after(0));
            }
        }
        if let Some(address) = yc::truthy_s(op, "address") {
            let label = if is_individual {
                "Address: "
            } else {
                "Registered Office: "
            };
            doc.para(para(format!("{}{}", label, address)).space_after(0));
        }
        let mut contact = Vec::new();
        if let Some(email) = yc::truthy_s(op, "email") {
            contact.push(format!("Email: {}", email));
        }
        if let Some(phone) = yc::truthy_s(op, "phone") {
            contact.push(format!("Phone: {}", phone));
        }
        if !contact.is_empty() {
            doc.para(para(contact.join(" | ")).space_after(0));
        }
        if !is_individual {
            doc.para(para("Through its Authorized Officers and Directors").space_after(0));
        }
        doc.para(
            para(op_label(idx, total))
                .bold(true)
                .align(Align::Right)
                .space_after(6),
        );
    }
}

// --------------------------------------------------------------------------
// cross-reference computation (the anti-drift core)
// --------------------------------------------------------------------------

/// Mirrors `complaint_para_count(case)`.
pub fn complaint_para_count(case: &Value) -> usize {
    let k = yc::seq(case, "complaint_paragraphs").len();
    let j = yc::seq(case, "jurisdiction_paragraphs").len();
    k + 1 + 1 + j + 1
}

/// Mirrors `annexure_range(case)`.
pub fn annexure_range(case: &Value) -> Option<String> {
    let anx = yc::seq(case, "annexures");
    if anx.is_empty() {
        return None;
    }
    let first = yc::s(anx.first().unwrap(), "id");
    let last = yc::s(anx.last().unwrap(), "id");
    Some(format!("{} to {}", first, last))
}

// --------------------------------------------------------------------------
// the six builders
// --------------------------------------------------------------------------

/// Mirrors `build_index(doc, case)`.
pub fn build_index(doc: &mut Doc, case: &Value) {
    cause_title(doc, case);
    doc.para(para("INDEX").bold(true).align(Align::Center).space_after(10));
    let mut rows = vec![
        vec!["1".to_string(), "Index".to_string(), IndexPageRanges::get("index").to_string()],
        vec![
            "2".to_string(),
            "Proforma for Filing Consumer Complaint".to_string(),
            IndexPageRanges::get("proforma").to_string(),
        ],
        vec![
            "3".to_string(),
            "Synopsis with List of Dates and Events".to_string(),
            IndexPageRanges::get("synopsis").to_string(),
        ],
        vec!["4".to_string(), "Memo of Parties".to_string(), IndexPageRanges::get("memo").to_string()],
        vec![
            "5".to_string(),
            "Consumer Complaint under Section 35 of the Consumer Protection Act, 2019 with Verification"
                .to_string(),
            IndexPageRanges::get("complaint").to_string(),
        ],
        vec![
            "6".to_string(),
            "Affidavit of the Complainant (notarised)".to_string(),
            IndexPageRanges::get("affidavit").to_string(),
        ],
    ];
    let annexures = yc::seq(case, "annexures");
    if !annexures.is_empty() {
        rows.push(vec!["ANNEXURES".to_string(), String::new(), String::new()]);
    }
    for anx in &annexures {
        rows.push(vec![yc::s(anx, "id"), yc::s(anx, "description"), String::new()]);
    }
    doc.table(
        Some(vec![
            "S.NO.".to_string(),
            "PARTICULARS OF DOCUMENT".to_string(),
            "PAGE NO.".to_string(),
        ]),
        rows,
    );
    doc.para(para("").space_after(2));
    signature_block(doc, case, "Complainant");
}

/// Mirrors `build_proforma(doc, case)`.
pub fn build_proforma(doc: &mut Doc, case: &Value) {
    cause_title(doc, case);
    doc.para(
        para("PROFORMA FOR FILING CONSUMER COMPLAINT")
            .bold(true)
            .align(Align::Center)
            .space_after(10),
    );
    let cm = yc::get(case, "complainant");
    let m = yc::get(case, "money");
    let ops = yc::seq(case, "opposite_parties");
    let op1 = ops.first().expect("opposite_parties is non-empty (validated)");

    let mut pairs: Vec<(String, String)> = vec![
        ("Name of the Complainant".to_string(), yc::s(cm, "name")),
        ("Father’s Name".to_string(), yc::s(cm, "father_name")),
        ("Age".to_string(), format!("{} years", yc::s(cm, "age"))),
        ("Address".to_string(), yc::s(cm, "address")),
        (
            "Email & Mobile".to_string(),
            format!("{} | {}", yc::s(cm, "email"), yc::s(cm, "mobile")),
        ),
        (
            "Whether the Complainant is a Consumer within the meaning of Section 2(7) of the Consumer Protection Act, 2019"
                .to_string(),
            yc::s(yc::get(case, "consumer_status"), "narrative"),
        ),
        (
            "Name of Opposite Party No. 1".to_string(),
            {
                let mut name = yc::s(op1, "name");
                if let Some(operating_as) = yc::truthy_s(op1, "operating_as") {
                    name.push_str(&format!(" ({})", operating_as));
                }
                name
            },
        ),
    ];
    if let Some(cin) = yc::truthy_s(op1, "cin") {
        pairs.push(("CIN of OP-1".to_string(), cin));
    }
    pairs.push(("Address of OP-1".to_string(), yc::s_or(op1, "address", "")));
    let mut contact = Vec::new();
    if let Some(email) = yc::truthy_s(op1, "email") {
        contact.push(email);
    }
    if let Some(phone) = yc::truthy_s(op1, "phone") {
        contact.push(phone);
    }
    pairs.push(("Contact of OP-1".to_string(), contact.join(" | ")));
    for (i, extra) in ops.iter().enumerate().skip(1) {
        let mut val = yc::s(extra, "name");
        if let Some(address) = yc::truthy_s(extra, "address") {
            val.push_str(&format!(" — {}", address));
        }
        pairs.push((format!("Name of Opposite Party No. {}", i + 1), val));
    }

    let consideration_paid = yc::i64_(m, "consideration_paid");
    let total_claim = yc::i64_(m, "total_claim");
    let prayer = yc::seq(case, "prayer");
    let nch = yc::get(case, "nch");

    pairs.extend(vec![
        ("Nature of Complaint".to_string(), yc::s(case, "nature_of_complaint")),
        ("Brief Facts".to_string(), yc::s(case, "brief_facts")),
        ("Cause of Action".to_string(), yc::s(case, "cause_of_action")),
        ("Limitation".to_string(), yc::s(case, "limitation")),
        (
            "Pecuniary Jurisdiction".to_string(),
            format!(
                "The value of the consideration paid (₹ {}/-) is below ₹ 50,00,000/-. This Hon’ble District Commission has pecuniary jurisdiction under Section 34(1) of the Act.",
                yc::comma_int(consideration_paid)
            ),
        ),
        ("Territorial Jurisdiction".to_string(), yc::s(case, "territorial_jurisdiction")),
        (
            "Amount paid as consideration".to_string(),
            format!(
                "₹ {}/- ({})",
                yc::comma_int(consideration_paid),
                yc::s(m, "consideration_words")
            ),
        ),
        (
            "Total Claim Value (including compensation, interest and costs)".to_string(),
            format!("₹ {}/- ({})", yc::comma_int(total_claim), yc::s(m, "total_claim_words")),
        ),
        (
            "Relief Sought".to_string(),
            {
                let parts: Vec<String> = prayer
                    .iter()
                    .enumerate()
                    .map(|(i, p)| {
                        let text = yc::scalar_pub(p);
                        format!("({}) {}", (b'a' + i as u8) as char, text.trim_end_matches(['.', ' ', ';']))
                    })
                    .collect();
                format!("{}.", parts.join("; "))
            },
        ),
        (
            "Whether the matter has been referred to any other Court or Forum".to_string(),
            format!(
                "No. A grievance has been registered with the National Consumer Helpline (Docket No. {} dated {}), which is a mediation channel and not a judicial forum. No other Court or Commission is seized of the matter.",
                yc::s(nch, "docket"),
                yc::s(nch, "date")
            ),
        ),
        (
            "Whether the Complainant prays for ex-parte ad-interim relief".to_string(),
            "No interim relief sought at this stage.".to_string(),
        ),
    ]);

    let rows: Vec<Vec<String>> = pairs
        .into_iter()
        .enumerate()
        .map(|(i, (label, value))| vec![(i + 1).to_string(), label, value])
        .collect();
    doc.table(
        Some(vec!["S.NO.".to_string(), "PARTICULARS".to_string(), "DETAILS".to_string()]),
        rows,
    );
    doc.para(para("").space_after(2));
    signature_block(doc, case, "Complainant");
}

/// Mirrors `build_synopsis(doc, case)`.
pub fn build_synopsis(doc: &mut Doc, case: &Value) {
    cause_title(doc, case);
    doc.para(para("SYNOPSIS").bold(true).align(Align::Center).space_after(10));
    doc.para(
        para(yc::s(case, "synopsis"))
            .align(Align::Justify)
            .space_after(12),
    );
    doc.para(
        para("LIST OF DATES AND EVENTS")
            .bold(true)
            .align(Align::Center)
            .space_after(10),
    );
    let rows: Vec<Vec<String>> = yc::seq(case, "dates_and_events")
        .iter()
        .map(|d| vec![yc::s(d, "date"), yc::s(d, "event")])
        .collect();
    doc.table(Some(vec!["DATE".to_string(), "EVENT".to_string()]), rows);
    doc.para(para("").space_after(2));
    signature_block(doc, case, "Complainant");
}

/// Mirrors `build_memo(doc, case)`.
pub fn build_memo(doc: &mut Doc, case: &Value) {
    cause_title(doc, case);
    doc.para(
        para("MEMO OF PARTIES")
            .bold(true)
            .align(Align::Center)
            .space_after(10),
    );
    party_block(doc, case);
    doc.para(para("").space_after(2));
    signature_block(doc, case, "Complainant");
}

/// Mirrors `build_complaint_affidavit(doc, case)`.
pub fn build_complaint_affidavit(doc: &mut Doc, case: &Value) {
    let cm = yc::get(case, "complainant");
    let n_total = complaint_para_count(case);
    let anx_range = annexure_range(case);

    cause_title(doc, case);
    party_block(doc, case);
    doc.para(
        para("CONSUMER COMPLAINT UNDER SECTION 35 OF THE CONSUMER PROTECTION ACT, 2019")
            .bold(true)
            .align(Align::Center)
            .space_after(10),
    );
    doc.para(para("RESPECTFULLY SHOWETH:").bold(true).space_after(6));

    let mut n: usize = 0;
    for body in yc::seq(case, "complaint_paragraphs") {
        n += 1;
        doc.para(para(format!("{}. {}", n, yc::scalar_pub(&body))).align(Align::Justify));
    }

    doc.para(para("CAUSE OF ACTION:").bold(true).space_after(4));
    n += 1;
    doc.para(para(format!("{}. {}", n, yc::s(case, "cause_of_action"))).align(Align::Justify));

    doc.para(para("LIMITATION:").bold(true).space_after(4));
    n += 1;
    doc.para(para(format!("{}. {}", n, yc::s(case, "limitation"))).align(Align::Justify));

    doc.para(para("JURISDICTION:").bold(true).space_after(4));
    for jp in yc::seq(case, "jurisdiction_paragraphs") {
        n += 1;
        doc.para(para(format!("{}. {}", n, yc::scalar_pub(&jp))).align(Align::Justify));
    }

    doc.para(para("GROUNDS:").bold(true).space_after(4));
    n += 1;
    let grounds_intro = yc::s_or(
        case,
        "grounds_intro",
        "That the conduct of the Opposite Parties constitutes:",
    );
    doc.para(para(format!("{}. {}", n, grounds_intro)).align(Align::Justify));
    for (gi, ground) in yc::seq(case, "grounds").iter().enumerate() {
        let marker = ROMAN.get(gi).map(|s| s.to_string()).unwrap_or_else(|| (gi + 1).to_string());
        doc.para(para(format!("({}) {}", marker, yc::scalar_pub(ground))).align(Align::Justify));
    }

    assert_eq!(
        n, n_total,
        "para-count drift: counted {} but computed {}",
        n, n_total
    );

    doc.para(para("PRAYER:").bold(true).space_after(4));
    doc.para(
        para("In the premises aforesaid, the Complainant most respectfully prays that this Hon’ble Commission may be pleased to:")
            .align(Align::Justify),
    );
    for (pi, prayer) in yc::seq(case, "prayer").iter().enumerate() {
        doc.para(
            para(format!("({}) {}", (b'a' + pi as u8) as char, yc::scalar_pub(prayer)))
                .align(Align::Justify),
        );
    }
    doc.para(
        para("AND FOR THIS ACT OF KINDNESS THE COMPLAINANT, AS IN DUTY BOUND, SHALL EVER PRAY.")
            .space_after(12),
    );
    signature_block(doc, case, "Complainant");

    doc.para(
        para("VERIFICATION")
            .bold(true)
            .align(Align::Center)
            .space_after(6),
    );
    doc.para(
        para(format!(
            "I, {}, the Complainant above-named, do hereby solemnly verify that the contents of paragraphs 1 to {} of this Complaint are true and correct to my personal knowledge, and that the contents of the Prayer have been incorporated upon legal advice and belief. Nothing material has been concealed therefrom.",
            yc::s(cm, "name"),
            n_total
        ))
        .align(Align::Justify),
    );
    let filing = yc::get(case, "filing");
    let month = {
        let m = yc::truthy_s(filing, "signing_month");
        m.unwrap_or_else(|| "__________".to_string())
    };
    doc.para(
        para(format!(
            "Verified at {} on this _____ day of {}, {}.",
            yc::s(cm, "city"),
            month,
            yc::s(filing, "year")
        ))
        .space_after(12),
    );
    doc.para(
        para(format!("({})", yc::s(cm, "name")))
            .align(Align::Right)
            .space_after(0),
    );
    doc.para(para("Complainant").align(Align::Right).space_after(6));

    doc.page_break();
    cause_title(doc, case);
    doc.para(
        para("AFFIDAVIT")
            .bold(true)
            .align(Align::Center)
            .space_after(10),
    );
    doc.para(
        para(format!(
            "I, {}, son of Mr. {}, aged about {} years, by faith {}, presently residing at {}, do hereby solemnly affirm and state on oath as follows:",
            yc::s(cm, "name"),
            yc::s(cm, "father_name"),
            yc::s(cm, "age"),
            yc::s(cm, "faith"),
            yc::s(cm, "address")
        ))
        .align(Align::Justify),
    );

    let note = yc::opt_s(case, "affidavit_annexure_note").unwrap_or_default();
    let anx_range_str = anx_range.clone().unwrap_or_default();
    let true_copies = format!(
        "That the Annexures {} produced with the Complaint are true and faithful copies of their respective originals{}.",
        anx_range_str,
        if !note.is_empty() {
            format!(", {}", note)
        } else {
            String::new()
        }
    );
    let averments = vec![
        "That I am the Complainant in the accompanying Consumer Complaint and I am well acquainted with the facts and circumstances of the case and competent to swear this Affidavit.".to_string(),
        format!(
            "That I have read and understood the contents of the accompanying Consumer Complaint, the Memo of Parties, the Synopsis with List of Dates and Events, the Proforma for Filing Consumer Complaint, the Index, and the Annexures {} thereto.",
            anx_range_str
        ),
        format!(
            "That the statements made in paragraphs 1 to {} of the accompanying Consumer Complaint are true and correct to my personal knowledge.",
            n_total
        ),
        "That the contents of the Synopsis and the List of Dates and Events accompanying this Complaint are true and correct to my personal knowledge.".to_string(),
        true_copies,
        "That no part of this Affidavit is false and nothing material has been concealed therefrom.".to_string(),
    ];
    for (i, av) in averments.iter().enumerate() {
        doc.para(para(format!("{}. {}", i + 1, av)).align(Align::Justify));
    }
    signature_block(doc, case, "DEPONENT");

    doc.para(
        para("VERIFICATION OF AFFIDAVIT")
            .bold(true)
            .align(Align::Center)
            .space_after(6),
    );
    doc.para(
        para(format!(
            "Verified at {} on this _____ day of {}, {}, that the contents of the above Affidavit are true and correct to my personal knowledge, no part of it is false, and nothing material has been concealed therefrom.",
            yc::s(cm, "city"),
            month,
            yc::s(filing, "year")
        ))
        .space_after(12),
    );
    doc.para(
        para(format!("({})", yc::s(cm, "name")))
            .align(Align::Right)
            .space_after(0),
    );
    doc.para(para("DEPONENT").align(Align::Right).space_after(12));
    doc.para(para("Identified by me:").space_after(18));
    doc.para(para("Advocate / Notary Stamp & Seal Below:").space_after(0));
}

/// Mirrors `build_party_in_person(doc, case)`.
pub fn build_party_in_person(doc: &mut Doc, case: &Value) {
    let cm = yc::get(case, "complainant");
    cause_title(doc, case);
    doc.para(para("IN THE MATTER OF:").bold(true).space_after(8));
    doc.para(para(yc::s(cm, "name")).space_after(0));
    doc.para(para(format!("R/o {}", yc::s(cm, "address"))).space_after(0));
    doc.para(
        para("… COMPLAINANT")
            .bold(true)
            .align(Align::Right)
            .space_after(6),
    );
    doc.para(para("VERSUS").bold(true).space_after(6));
    let ops = yc::seq(case, "opposite_parties");
    for (i, op) in ops.iter().enumerate() {
        let idx = i + 1;
        let mut line = format!("{}. {}", idx, yc::s(op, "name"));
        if let Some(operating_as) = yc::truthy_s(op, "operating_as") {
            line.push_str(&format!(" ({})", operating_as));
        }
        doc.para(para(line).space_after(0));
        if let Some(cin) = yc::truthy_s(op, "cin") {
            doc.para(para(format!("   CIN: {}", cin)).space_after(0));
        }
        if let Some(address) = yc::truthy_s(op, "address") {
            doc.para(para(format!("   {}", address)).space_after(4));
        }
    }
    doc.para(
        para(format!(
            "… OPPOSITE {}",
            if ops.len() == 1 { "PARTY" } else { "PARTIES" }
        ))
        .bold(true)
        .align(Align::Right)
        .space_after(8),
    );
    doc.para(
        para("DECLARATION OF PARTY-IN-PERSON")
            .bold(true)
            .align(Align::Center)
            .space_after(10),
    );
    doc.para(
        para(format!(
            "I, {}, the Complainant above-named, do hereby declare as follows:",
            yc::s(cm, "name")
        ))
        .space_after(6),
    );
    let decls = vec![
        "That I am filing the accompanying Consumer Complaint, Memo of Parties, Synopsis, List of Dates and Events, Proforma and Affidavit, together with the documents listed in the Index, in person and without engaging an Advocate to represent me before this Hon’ble Commission.".to_string(),
        "That I have decided to appear and act in person, and that I am fully aware of (a) the procedure of this Hon’ble Commission, (b) the consequences of so appearing in person, and (c) the requirement to make myself available for any hearing dates, additional documentation, or clarifications that this Hon’ble Commission may seek.".to_string(),
        format!(
            "That all communications, notices, orders and process from this Hon’ble Commission may be addressed to me at the address shown in the Memo of Parties or by email to {} and by mobile to {}.",
            yc::s(cm, "email"),
            yc::s(cm, "mobile")
        ),
        "That this declaration is made bona fide and not for any oblique purpose.".to_string(),
    ];
    for (i, d) in decls.iter().enumerate() {
        doc.para(para(format!("{}. {}", i + 1, d)).align(Align::Justify));
    }
    signature_block(doc, case, "Complainant, In Person");
}
