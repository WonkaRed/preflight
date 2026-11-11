use serde::Serialize;

use super::snapshot::Snapshot;
use crate::finding::Severity;

/// One observation about a deployed contract. Same idea as a source [`Finding`](crate::Finding), but located by
/// what was read from the chain rather than by file and line, and it carries what that read does and does not
/// prove, because a reader of a published scan has no other way to know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    /// What the finding is about: the account, a key, or a group of exports.
    pub item: String,
    /// What was observed. Facts only.
    pub message: String,
    /// The RPC reads this finding rests on; the same text for every finding of a check.
    pub read: &'static str,
    /// What this finding does not prove; the same text for every finding of a check.
    pub limits: &'static str,
    /// What the contract's owner can do about it; the same text for every finding of a check.
    pub help: &'static str,
}

/// A check that could not reach a verdict. Reported, so a missing finding is never mistaken for a pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NotEvaluated {
    pub rule_id: &'static str,
    pub reason: String,
}

/// A check over a [`Snapshot`]. Implement it in `src/deployed/checks/pfwNN_<slug>.rs` and list it in
/// `checks::ALL`.
pub(crate) trait Check: Sync {
    /// Stable id, `PFW` and two digits. Never reused for a different check.
    fn id(&self) -> &'static str;
    fn title(&self) -> &'static str;
    fn read(&self) -> &'static str;
    fn limits(&self) -> &'static str;
    fn help(&self) -> &'static str;
    fn check(&self, snapshot: &Snapshot) -> Result<Vec<Finding>, NotEvaluated>;

    fn finding(&self, severity: Severity, item: impl Into<String>, message: impl Into<String>) -> Finding
    where
        Self: Sized,
    {
        Finding {
            rule_id: self.id(),
            title: self.title(),
            severity,
            item: item.into(),
            message: message.into(),
            read: self.read(),
            limits: self.limits(),
            help: self.help(),
        }
    }

    fn not_evaluated(&self, reason: impl Into<String>) -> NotEvaluated
    where
        Self: Sized,
    {
        NotEvaluated { rule_id: self.id(), reason: reason.into() }
    }
}
