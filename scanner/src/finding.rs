use serde::Serialize;

/// How bad a finding is. Ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// One problem a rule found. Rules build these with [`Rule::finding`](crate::Rule::finding), which fills the
/// rule-level fields so they cannot disagree with the rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    /// Path relative to the scanned directory, `/`-separated.
    pub file: String,
    /// 1-based.
    pub line: usize,
    /// 1-based, in characters.
    pub column: usize,
    /// The code item at fault, such as `Escrow::on_release`.
    pub item: String,
    pub message: String,
    /// How to fix it; the same text for every finding of a rule.
    pub help: &'static str,
}
