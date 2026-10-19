//! Negative parser controls only; no browser acquisition or qualification claim.
use super::{parse_qa_output, verified_load};

#[test]
fn completed_action_output_cannot_hide_failed_or_missing_load_evidence() {
    for load in [
        "[qa] 1:eval value {\"ok\":false,\"href\":\"chrome-error://chromewebdata/\"}\n",
        "",
        "[qa] 1:eval value {\"ok\":true\n",
        "[qa] 1:eval value {\"href\":\"http://127.0.0.1/\"}\n",
        "[qa] 1:eval value {\"ok\":\"true\"}\n",
    ] {
        let output = format!(
            "{load}[qa] screenshot /scratch/shot.png\n[qa] 2:screenshot ok\n\
             [qa] actions complete /scratch/actions.json\n\
             [qa] no console errors or warnings\n"
        );
        let qa = parse_qa_output(&output);
        assert!(qa.actions_complete);
        assert!(qa.screenshot.is_some());
        let mut gaps = Vec::new();
        assert!(!verified_load(&qa, "entry", &mut gaps), "{output}");
        assert_eq!(gaps, ["runtime-surface-load-failed:entry"]);
    }
}

#[test]
fn successful_load_action_output_does_not_add_a_load_failure_gap() {
    let qa = parse_qa_output(
        "[qa] 1:eval value {\"ok\":true,\"href\":\"http://127.0.0.1/\",\"status\":200}\n\
         [qa] actions complete /scratch/actions.json\n",
    );
    let mut gaps = Vec::new();
    assert!(verified_load(&qa, "entry", &mut gaps));
    assert!(gaps.is_empty());
}
