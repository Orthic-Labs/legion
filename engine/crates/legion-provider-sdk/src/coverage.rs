use legion_contracts::Coverage;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageAssessment {
    pub coverage: Coverage,
    pub complete: bool,
    pub gaps: Vec<String>,
}

impl CoverageAssessment {
    pub fn is_complete(&self) -> bool {
        self.complete
    }
}

pub fn normalize_coverage(
    reported: Option<&Coverage>,
    denominator_digest: impl Into<String>,
    expected: u64,
) -> CoverageAssessment {
    let denominator_digest = denominator_digest.into();
    let (examined, mut gaps) = match reported {
        Some(value) => (value.examined, value.gaps.clone()),
        None => (0, vec!["provider-denominator-unreported".into()]),
    };
    if let Some(value) = reported {
        if value.expected != expected {
            gaps.push(format!(
                "provider-denominator-mismatch:{}/{}",
                value.expected, expected
            ));
        }
    }
    if examined < expected {
        gaps.push(format!(
            "provider-denominator-incomplete:{}/{}",
            examined, expected
        ));
    }
    gaps.sort();
    gaps.dedup();
    let coverage = Coverage {
        denominator_digest,
        expected,
        examined,
        gaps: gaps.clone(),
    };
    CoverageAssessment {
        complete: gaps.is_empty() && examined >= expected,
        coverage,
        gaps,
    }
}
