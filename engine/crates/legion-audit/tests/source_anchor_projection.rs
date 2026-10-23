//! A14 canonical source-anchor fixtures (RULE-FIXTURES ANCHOR-01..09) & safe
//! PR projection, exercised on production entry points:
//! `legion_contracts::position_anchor_canonical`, the `source_anchor`
//! validation/projection helpers, `ReportV2` v1/v2 round-trips &
//! `legion_report::render_github_review`.
//!
//! Authored under the edit-only worker rules; root integration executes.

use std::collections::BTreeMap;

use legion_contracts::source_anchor::{
    build_evidence, derive_position, line_byte_range, locate_span, project_to_pr, propose_reanchor,
    safe_snapshot_path, validate_evidence_against_bytes, AnchorValidation, ByteRange, PrDiff,
    PrDiffFile, PrProjection, PrProjectionReason, ReanchorOutcome, SourceSide, SpanLocation,
};
use legion_contracts::{
    position_anchor_canonical, DiffTag, Finding, FindingId, LiftContext, LineRange, Report,
    ReportId, ReportScope, ReportStatus, ReportV2,
};
use serde_json::{json, Value};

fn lines(start: u32, end: u32) -> LineRange {
    LineRange { start, end }
}

fn evidence_for(path: &str, side: SourceSide, bytes: &[u8], range: LineRange) -> legion_contracts::source_anchor::SourceAnchorEvidence {
    build_evidence(
        path,
        side,
        Some("repo"),
        Some("snap-1"),
        bytes,
        line_byte_range(bytes, range).unwrap(),
    )
    .unwrap()
}

fn diff(head: &str, files: Vec<PrDiffFile>) -> PrDiff {
    PrDiff {
        head_oid: head.into(),
        files,
    }
}

fn file(base: Option<&str>, head: Option<&str>, base_hunks: Vec<LineRange>, head_hunks: Vec<LineRange>) -> PrDiffFile {
    PrDiffFile {
        base_path: base.map(Into::into),
        head_path: head.map(Into::into),
        base_hunks,
        head_hunks,
    }
}

// ANCHOR-01: correct path/range but wrong blob or snapshot rejects; no rebase.
#[test]
fn anchor01_wrong_snapshot_or_blob_is_rejected() {
    let bytes = b"alpha\nbeta\ngamma\n";
    let evidence = evidence_for("src/a.rs", SourceSide::Selected, bytes, lines(2, 2));
    assert_eq!(
        validate_evidence_against_bytes(&evidence, Some("snap-1"), Some(bytes)),
        AnchorValidation::Validated
    );
    assert_eq!(
        validate_evidence_against_bytes(&evidence, Some("snap-2"), Some(bytes)),
        AnchorValidation::SnapshotMismatch
    );
    let wrong_blob = validate_evidence_against_bytes(
        &evidence,
        Some("snap-1"),
        Some(b"alpha\nBETA\ngamma\n"),
    );
    assert_eq!(wrong_blob, AnchorValidation::FileDigestMismatch);
    // The mismatched-bytes result cannot project inline.
    assert_eq!(
        project_to_pr(
            &evidence,
            wrong_blob,
            "head",
            &diff("head", vec![file(Some("src/a.rs"), Some("src/a.rs"), vec![], vec![lines(1, 3)])]),
        ),
        PrProjection::SummaryOnly {
            reason: PrProjectionReason::NotValidated
        }
    );
}

// ANCHOR-02: byte range outside file, reversed, or splitting the encoding.
#[test]
fn anchor02_invalid_byte_ranges_are_rejected() {
    let bytes = "caf\u{e9}\nnext\n".as_bytes();
    for (range, expected) in [
        (ByteRange { start: 0, end: 10_000 }, AnchorValidation::ByteRangeOutOfBounds),
        (ByteRange { start: 5, end: 2 }, AnchorValidation::ReversedRange),
        // Byte 4 splits "é" (bytes 3..5).
        (ByteRange { start: 4, end: 5 }, AnchorValidation::InvalidUtf8Boundary),
    ] {
        assert_eq!(derive_position(bytes, range), Err(expected), "{range:?}");
        assert_eq!(
            build_evidence("src/a.rs", SourceSide::Selected, None, None, bytes, range),
            Err(expected)
        );
    }
    assert_eq!(
        derive_position(b"\xff\x00\xfe", ByteRange { start: 0, end: 1 }),
        Err(AnchorValidation::NonUtf8File)
    );
}

// ANCHOR-03: same quoted snippet in several functions needs stronger identity.
#[test]
fn anchor03_repeated_snippet_is_ambiguous() {
    let bytes = b"fn a() {\n    check();\n}\nfn b() {\n    check();\n}\n";
    assert_eq!(
        locate_span(bytes, b"check();"),
        SpanLocation::Ambiguous { occurrences: 2 }
    );
    let original = evidence_for("src/a.rs", SourceSide::Selected, bytes, lines(2, 2));
    let padded = b"// new header\nfn a() {\n    check();\n}\nfn b() {\n    check();\n}\n";
    assert_eq!(
        propose_reanchor(&original, None, Some("snap-2"), Some(padded), b"    check();"),
        ReanchorOutcome::Ambiguous { occurrences: 2 },
        "relocation must not pick the first of two identical spans"
    );
    // Byte-exact identity still anchors the first span when its bytes and
    // offset are what is claimed, via position (not text search).
    let (anchor, canonical) = position_anchor_canonical(
        "src/a.rs",
        2,
        2,
        None,
        Some(bytes),
        Some(DiffTag::InDiff),
        SourceSide::Selected,
        None,
        Some("snap-1"),
    );
    assert!(!anchor.failed());
    assert_eq!(canonical.unwrap().byte_range.start, 9);
}

// ANCHOR-04: multibyte text, CRLF, tabs & column conventions derive from bytes.
#[test]
fn anchor04_columns_derive_from_original_bytes() {
    // Bytes: tab=0, "é"=1..3, "中"=3..6, CRLF=6..8, x=8, LF=9, end=10.
    let bytes = "\t\u{e9}\u{4e2d}\r\nx\nend".as_bytes();
    let first = derive_position(bytes, ByteRange { start: 0, end: 6 }).unwrap();
    assert_eq!(first.lines, lines(1, 1));
    assert_eq!(
        (first.start_column, first.end_column),
        (1, 4),
        "tab + 2 scalars = 3 columns wide, however many bytes they take"
    );
    let second = derive_position(bytes, ByteRange { start: 8, end: 9 }).unwrap();
    assert_eq!(second.lines, lines(2, 2));
    // A span across the CRLF keeps the original terminator bytes in its
    // digest (no newline normalization), while its line hash peer in the
    // legacy anchor normalizes CRLF (existing position_anchor behaviour).
    let across = line_byte_range(bytes, lines(1, 2)).unwrap();
    assert_eq!(&bytes[across.start as usize..across.end as usize], "\t\u{e9}\u{4e2d}\r\nx".as_bytes());
    // BOM + no final newline.
    let bom = b"\xef\xbb\xbffn main() {}";
    let derived = derive_position(bom, line_byte_range(bom, lines(1, 1)).unwrap()).unwrap();
    assert_eq!(derived.lines, lines(1, 1));
    assert_eq!((derived.start_column, derived.end_column), (1, 13));
}

// ANCHOR-05: rename/deletion keeps correct side identity & historical path.
#[test]
fn anchor05_rename_and_deletion_keep_side_identity() {
    let base_bytes = b"keep\nremoved();\n";
    let evidence = evidence_for("src/old.rs", SourceSide::Base, base_bytes, lines(2, 2));
    let renamed = file(
        Some("src/old.rs"),
        Some("src/new.rs"),
        vec![lines(1, 2)],
        vec![lines(1, 2)],
    );
    assert_eq!(
        project_to_pr(&evidence, AnchorValidation::Validated, "h", &diff("h", vec![renamed])),
        PrProjection::Inline {
            path: "src/old.rs".into(),
            side: SourceSide::Base,
            line: 2,
            start_line: None,
        }
    );
    let deleted = file(Some("src/old.rs"), None, vec![lines(1, 2)], vec![]);
    assert!(matches!(
        project_to_pr(&evidence, AnchorValidation::Validated, "h", &diff("h", vec![deleted])),
        PrProjection::Inline { side: SourceSide::Base, .. }
    ));
}

// ANCHOR-06: valid finding in an unchanged caller stays a summary finding.
#[test]
fn anchor06_beyond_diff_finding_remains_in_summary() {
    let report = canonical_report("src/caller.rs:2", b"fn caller() {\n    target();\n}\n");
    // Caller unchanged in the PR: no prDiff entry for it at all.
    let payload: Value =
        serde_json::from_str(&legion_report::render_github_review(&report).unwrap()).unwrap();
    assert_eq!(payload["comments"].as_array().unwrap().len(), 0);
    let body = payload["body"].as_str().unwrap();
    assert!(body.contains("canonical fixture finding"), "finding retained in main report");
    assert!(body.contains("src/caller.rs"));
    // And with a diff that does not cover the caller lines: still summary.
    let evidence = report.findings[0].source_anchor_evidence().unwrap().unwrap();
    assert_eq!(
        project_to_pr(
            &evidence,
            AnchorValidation::Validated,
            "head-1",
            &diff("head-1", vec![file(Some("src/other.rs"), Some("src/other.rs"), vec![], vec![lines(1, 9)])]),
        ),
        PrProjection::SummaryOnly {
            reason: PrProjectionReason::PathNotInDiff
        }
    );
}

// ANCHOR-07: generated artifact without a source map is cited as itself.
#[test]
fn anchor07_generated_artifact_is_cited_without_guessed_source() {
    let generated = b"// @generated\nfunction a(){return b()}\n";
    let evidence = evidence_for(
        "dist/bundle.min.js",
        SourceSide::Selected,
        generated,
        lines(2, 2),
    );
    assert_eq!(evidence.path, "dist/bundle.min.js");
    assert_eq!(
        validate_evidence_against_bytes(&evidence, Some("snap-1"), Some(generated)),
        AnchorValidation::Validated
    );
    // Projection uses the artifact path only; nothing remaps it to an
    // invented original source location.
    assert_eq!(
        project_to_pr(
            &evidence,
            AnchorValidation::Validated,
            "h",
            &diff("h", vec![file(Some("dist/bundle.min.js"), Some("dist/bundle.min.js"), vec![], vec![lines(1, 2)])]),
        ),
        PrProjection::Inline {
            path: "dist/bundle.min.js".into(),
            side: SourceSide::Selected,
            line: 2,
            start_line: None,
        }
    );
}

// ANCHOR-08: location validation is independent of the behavioral claim.
// (Semantic rejection belongs to the verifier; the anchor layer must neither
// confirm a false claim nor fail a true position because of message text.)
#[test]
fn anchor08_location_validation_ignores_claim_text() {
    let bytes = b"fn checked() {\n    return;\n}\n";
    let mut report = canonical_report("src/a.rs:2", bytes);
    report.findings[0].message = "this line reads from the network".into();
    let evidence = report.findings[0].source_anchor_evidence().unwrap().unwrap();
    assert_eq!(
        validate_evidence_against_bytes(&evidence, Some("snap-1"), Some(bytes)),
        AnchorValidation::Validated,
        "position is exactly as claimed even though the claim is false"
    );
    report.validate().unwrap();
}

// ANCHOR-09: traversal / outside-snapshot paths reject, never read elsewhere.
#[test]
fn anchor09_traversal_and_outside_snapshot_reject() {
    for bad in ["../secret.rs", "/etc/passwd", "src/../../x", "src\\win.rs"] {
        assert!(!safe_snapshot_path(bad), "{bad}");
        assert_eq!(
            build_evidence(bad, SourceSide::Selected, None, None, b"x\n", ByteRange { start: 0, end: 1 }),
            Err(AnchorValidation::UnsafePath)
        );
    }
    let evidence = evidence_for("src/a.rs", SourceSide::Selected, b"x\n", lines(1, 1));
    assert_eq!(
        validate_evidence_against_bytes(&evidence, Some("snap-1"), None),
        AnchorValidation::MissingFile,
        "outside the snapshot is a failure, not a pass"
    );
    // A report carrying a traversal canonical path does not validate.
    let mut report = canonical_report("src/a.rs:1", b"x\n");
    let mut forged = report.findings[0].source_anchor_evidence().unwrap().unwrap();
    forged.path = "../secret.rs".into();
    report.findings[0].set_source_anchor_evidence(&forged).unwrap();
    assert!(report.validate().is_err());
}

// Acceptance extras: changed head & noncontiguous ranges never inline;
// re-anchoring proposes lineage without moving a confirmed finding.
#[test]
fn acceptance_head_contiguity_and_reanchor_lineage() {
    let bytes = b"1\n2\n3\n4\n5\n";
    let evidence = evidence_for("src/a.rs", SourceSide::Selected, bytes, lines(2, 4));
    let split = file(
        Some("src/a.rs"),
        Some("src/a.rs"),
        vec![],
        vec![lines(1, 2), lines(3, 5)],
    );
    assert_eq!(
        project_to_pr(&evidence, AnchorValidation::Validated, "head-a", &diff("head-b", vec![split.clone()])),
        PrProjection::SummaryOnly {
            reason: PrProjectionReason::HeadMismatch
        }
    );
    assert_eq!(
        project_to_pr(&evidence, AnchorValidation::Validated, "head", &diff("head", vec![split])),
        PrProjection::SummaryOnly {
            reason: PrProjectionReason::LinesNonContiguousInDiff
        }
    );

    let before = b"head\ntarget();\ntail\n";
    let original = evidence_for("src/a.rs", SourceSide::Selected, before, lines(2, 2));
    let original_range = original.byte_range;
    match propose_reanchor(&original, None, Some("snap-2"), Some(b"inserted\nhead\ntarget();\ntail\n"), b"target();") {
        ReanchorOutcome::Candidate { candidate, previous_byte_range, .. } => {
            assert_eq!(candidate.lines, lines(3, 3));
            assert_eq!(previous_byte_range, original_range);
        }
        other => panic!("expected lineage candidate, got {other:?}"),
    }
    assert_eq!(original.byte_range, original_range, "confirmed anchor never moves in place");
    // Changed source text at the old span: reverify fails, recorded as such.
    assert_eq!(
        validate_evidence_against_bytes(&original, Some("snap-1"), Some(b"head\nchanged();\ntail\n")),
        AnchorValidation::FileDigestMismatch
    );
    assert_eq!(
        propose_reanchor(&original, None, Some("snap-2"), Some(b"head\nchanged();\ntail\n"), b"target();"),
        ReanchorOutcome::NotFound
    );
}

// Builds a validated v2 report whose single finding carries canonical
// evidence for `location` against `bytes` (production lift path).
fn canonical_report(location: &str, bytes: &[u8]) -> ReportV2 {
    let path = location.rsplit_once(':').unwrap().0.to_owned();
    let owned = bytes.to_vec();
    let resolve = move |candidate: &str| (candidate == path.as_str()).then(|| owned.clone());
    let scope = ReportScope {
        spec: "whole".into(),
        base_ref_oid: None,
        merge_base_oid: None,
        head: "head-1".into(),
        snapshot_key: Some("snap-1".into()),
        index_schema_version: Some(1),
    };
    let diff_tag = |_: &str, _: u32, _: u32| DiffTag::InDiff;
    let mut context = LiftContext::new(scope, &resolve);
    context.diff_tag = Some(&diff_tag);
    let v1 = Report {
        schema_version: 1,
        report_id: ReportId::new("anchor-fixture").unwrap(),
        status: ReportStatus::Findings,
        findings: vec![Finding {
            id: FindingId::new("f-1").unwrap(),
            severity: "high".into(),
            title: "canonical fixture finding".into(),
            message: "fixture".into(),
            provider: Some("security.source".into()),
            locations: vec![location.into()],
            evidence: BTreeMap::new(),
        }],
        gaps: Vec::new(),
        claims: BTreeMap::new(),
        targets: vec!["repo".into()],
        extensions: BTreeMap::new(),
    };
    let mut report = ReportV2::from_v1_with(&v1, &context).unwrap();
    let anchor = report.findings[0].anchor.clone().expect("lifted anchor");
    assert!(!anchor.failed(), "fixture location must position: {location}");
    let (_, canonical) = position_anchor_canonical(
        &anchor.path,
        anchor.range.start,
        anchor.range.end,
        Some(&anchor.line_hash),
        Some(bytes),
        Some(DiffTag::InDiff),
        SourceSide::Selected,
        Some("repo"),
        Some("snap-1"),
    );
    report.findings[0]
        .set_source_anchor_evidence(&canonical.expect("canonical evidence"))
        .unwrap();
    report.validate().unwrap();
    report
}

#[test]
fn canonical_report_round_trips_and_review_stays_local_json() {
    let report = canonical_report("src/caller.rs:2", b"fn caller() {\n    target();\n}\n");
    for schema in [1, 2] {
        let wire = report.to_value_for_schema(schema).unwrap();
        assert_eq!(Report::read_any(&wire).unwrap(), report, "schema {schema}");
    }
    // Local JSON only: the payload is the review-request shape rendered to
    // a string; nothing here posts or installs anything.
    let rendered = legion_report::render_github_review(&report).unwrap();
    let payload: Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(payload["event"], json!("COMMENT"));
    let review = legion_report::render_review(&report).unwrap();
    assert!(review.contains("Canonical anchor:"));
    assert!(review.contains("side `selected`"));
}
