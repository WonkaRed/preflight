//! PFW04: initialization method exported, no contract state stored.

use crate::deployed::check::{Check, Finding, NotEvaluated};
use crate::deployed::snapshot::{Snapshot, StateProbe};
use crate::finding::Severity;

pub(crate) static CHECK: NeverInitialized = NeverInitialized;

pub(crate) struct NeverInitialized;

const INIT_EXPORTS: &[&str] = &["new", "init", "initialize", "new_default_meta"];

impl Check for NeverInitialized {
    fn id(&self) -> &'static str {
        "PFW04"
    }

    fn title(&self) -> &'static str {
        "Initialization method exported and no contract state"
    }

    fn read(&self) -> &'static str {
        "RPC query view_code (export names) and RPC query view_state for the key STATE (the key near-sdk stores \
         the contract's state struct under) and, if that is missing, for the first key of any kind, at the block \
         shown in the report"
    }

    fn limits(&self) -> &'static str {
        "An account with no stored state at all does not prove the contract was never initialized: one that keeps \
         no state, or only writes it on first use, looks the same. An account that has state but no STATE key is \
         not judged, since it may use its own storage layout. It does not show that the initialization method is \
         callable by anyone, and it is true only at the block shown."
    }

    fn help(&self) -> &'static str {
        "Call the initialization method from the owner account, in the same transaction as the deploy, and mark \
         it #[private] or otherwise restrict who may call it"
    }

    fn check(&self, snapshot: &Snapshot) -> Result<Vec<Finding>, NotEvaluated> {
        let Some(init) = INIT_EXPORTS.iter().find(|name| snapshot.exports.contains(**name)) else {
            return Ok(Vec::new());
        };
        match &snapshot.state {
            StateProbe::StateKey => Ok(Vec::new()),
            StateProbe::Unknown(why) => Err(self.not_evaluated(why.clone())),
            StateProbe::OtherKeys => Err(self.not_evaluated(
                "the account has state but no STATE key, so it may use its own storage layout and initialization \
                 cannot be judged from the keys",
            )),
            StateProbe::Empty => Ok(vec![self.finding(
                Severity::Medium,
                &snapshot.account_id,
                format!(
                    "the contract exports `{init}` and the account stores no state at all, which is what a contract \
                     looks like before its initialization method has run"
                ),
            )]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_state_means_no_finding() {
        assert_eq!(CHECK.check(&Snapshot::sample()).unwrap(), []);
    }

    #[test]
    fn an_init_export_with_no_state_at_all_is_a_finding() {
        let mut snapshot = Snapshot::sample();
        snapshot.state = StateProbe::Empty;
        let findings = CHECK.check(&snapshot).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("exports `new` and the account stores no state at all"));
    }

    #[test]
    fn state_under_other_keys_is_not_evaluated_never_a_finding() {
        let mut snapshot = Snapshot::sample();
        snapshot.state = StateProbe::OtherKeys;
        let not_evaluated = CHECK.check(&snapshot).unwrap_err();
        assert_eq!(not_evaluated.rule_id, "PFW04");
        assert!(not_evaluated.reason.contains("own storage layout"));
    }

    #[test]
    fn no_state_without_an_init_export_is_not_a_finding() {
        let mut snapshot = Snapshot::sample();
        snapshot.state = StateProbe::Empty;
        snapshot.exports.clear();
        snapshot.exports.insert("ft_total_supply".to_owned());
        assert_eq!(CHECK.check(&snapshot).unwrap(), []);
    }

    #[test]
    fn an_unreadable_state_is_not_evaluated_never_a_finding() {
        let mut snapshot = Snapshot::sample();
        snapshot.state = StateProbe::Unknown("the node refused to read the state: TOO_LARGE_CONTRACT_STATE".into());
        let not_evaluated = CHECK.check(&snapshot).unwrap_err();
        assert_eq!(not_evaluated.rule_id, "PFW04");
        assert!(not_evaluated.reason.contains("TOO_LARGE_CONTRACT_STATE"));
    }

    #[test]
    fn an_unreadable_state_in_a_contract_without_an_init_export_needs_no_note() {
        let mut snapshot = Snapshot::sample();
        snapshot.state = StateProbe::Unknown("x".into());
        snapshot.exports.clear();
        assert_eq!(CHECK.check(&snapshot).unwrap(), []);
    }
}
