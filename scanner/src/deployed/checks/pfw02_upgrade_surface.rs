//! PFW02: exported methods whose names suggest the code or the owner can be changed.

use crate::deployed::check::{Check, Finding, NotEvaluated};
use crate::deployed::display::list;
use crate::deployed::snapshot::Snapshot;
use crate::finding::Severity;

pub(crate) static CHECK: UpgradeSurface = UpgradeSurface;

pub(crate) struct UpgradeSurface;

const EXACT: &[&str] = &["upgrade", "update_contract", "migrate", "state_migrate"];
const PREFIX: &str = "set_owner";

impl Check for UpgradeSurface {
    fn id(&self) -> &'static str {
        "PFW02"
    }

    fn title(&self) -> &'static str {
        "Exports named like upgrade or ownership methods"
    }

    fn read(&self) -> &'static str {
        "RPC query view_code: the names in the wasm export section, nothing else from the code"
    }

    fn limits(&self) -> &'static str {
        "A name proves nothing about what the function does or who may call it, and many contracts have these on \
         purpose. A method under another name is not matched. A contract can also be replaced through a \
         full-access key (PFW01) without exporting any of these."
    }

    fn help(&self) -> &'static str {
        "Check in the contract's source that each of these methods is restricted to an owner or a governance \
         contract, and say so in the documentation"
    }

    fn check(&self, snapshot: &Snapshot) -> Result<Vec<Finding>, NotEvaluated> {
        let names: Vec<&str> = snapshot
            .exports
            .iter()
            .map(String::as_str)
            .filter(|name| EXACT.contains(name) || name.starts_with(PREFIX))
            .collect();
        if names.is_empty() {
            return Ok(Vec::new());
        }
        Ok(vec![self.finding(
            Severity::Info,
            &snapshot.account_id,
            format!(
                "the contract exports {} method{} named like upgrade or ownership methods: {}. Only the names were read",
                names.len(),
                if names.len() == 1 { "" } else { "s" },
                list(&names, 10),
            ),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_contract_without_such_exports_has_no_finding() {
        assert_eq!(CHECK.check(&Snapshot::sample()).unwrap(), []);
    }

    #[test]
    fn a_name_that_only_contains_a_matching_word_is_not_matched() {
        let mut snapshot = Snapshot::sample();
        snapshot.exports.extend(["reset_ownership_request", "get_upgrade_status", "migrated"].map(str::to_owned));
        assert_eq!(CHECK.check(&snapshot).unwrap(), []);
    }

    #[test]
    fn matching_names_are_listed_as_information() {
        let mut snapshot = Snapshot::sample();
        snapshot.exports.extend(["upgrade", "migrate", "set_owner_id", "set_owners_x", "update"].map(str::to_owned));
        let findings = CHECK.check(&snapshot).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(
            findings[0].message.contains(
                "4 methods named like upgrade or ownership methods: migrate, set_owner_id, set_owners_x, upgrade"
            ),
            "{}",
            findings[0].message
        );
    }
}
