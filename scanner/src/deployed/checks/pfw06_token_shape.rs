//! PFW06: NEP-141 shape, judged from export names.

use crate::deployed::check::{Check, Finding, NotEvaluated};
use crate::deployed::snapshot::Snapshot;
use crate::finding::Severity;

pub(crate) static CHECK: TokenShape = TokenShape;

pub(crate) struct TokenShape;

impl Check for TokenShape {
    fn id(&self) -> &'static str {
        "PFW06"
    }

    fn title(&self) -> &'static str {
        "Fungible token missing a standard method"
    }

    fn read(&self) -> &'static str {
        "RPC query view_code: the names in the wasm export section, nothing else from the code"
    }

    fn limits(&self) -> &'static str {
        "Only export names are compared. NEP-141 lets the resolver have any name, so a resolver renamed to \
         something without \"resolve\" is not recognised, and NEP-141 leaves storage registration to a separate \
         standard (NEP-145), so a token without it can still conform. Whether an exported method is implemented \
         correctly is not examined."
    }

    fn help(&self) -> &'static str {
        "Export a resolver for ft_transfer_call (conventionally ft_resolve_transfer) that refunds the sender when \
         the receiver call fails, and export storage_deposit so accounts can register before receiving tokens"
    }

    fn check(&self, snapshot: &Snapshot) -> Result<Vec<Finding>, NotEvaluated> {
        let mut findings = Vec::new();
        if snapshot.exports.contains("ft_transfer_call")
            && !snapshot.exports.iter().any(|name| name.contains("resolve"))
        {
            findings.push(self.finding(
                Severity::Low,
                &snapshot.account_id,
                "the contract exports ft_transfer_call but no export has \"resolve\" in its name. NEP-141 requires \
                 a resolver that settles a failed transfer-and-call, though it may be named anything",
            ));
        }
        if snapshot.exports.contains("ft_transfer") && !snapshot.exports.contains("storage_deposit") {
            findings.push(self.finding(
                Severity::Info,
                &snapshot.account_id,
                "the contract exports ft_transfer but not storage_deposit (NEP-145), so receivers cannot register \
                 through NEP-145; the token may register them another way or not need registration",
            ));
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exports(names: &[&str]) -> Snapshot {
        let mut snapshot = Snapshot::sample();
        snapshot.exports = names.iter().map(|n| (*n).to_owned()).collect();
        snapshot
    }

    #[test]
    fn a_complete_token_has_no_finding() {
        assert_eq!(CHECK.check(&Snapshot::sample()).unwrap(), []);
    }

    #[test]
    fn a_contract_that_is_not_a_token_has_no_finding() {
        assert_eq!(CHECK.check(&exports(&["new", "get_greeting"])).unwrap(), []);
    }

    #[test]
    fn transfer_call_without_any_resolve_export_is_low() {
        let findings = CHECK.check(&exports(&["ft_transfer_call", "ft_transfer", "storage_deposit"])).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
        assert!(findings[0].message.contains("ft_transfer_call but no export has \"resolve\""));
    }

    #[test]
    fn a_renamed_resolver_containing_resolve_satisfies_the_check() {
        let snapshot = exports(&["ft_transfer_call", "ft_transfer", "storage_deposit", "on_ft_resolve"]);
        assert_eq!(CHECK.check(&snapshot).unwrap(), []);
    }

    #[test]
    fn transfer_without_storage_deposit_is_information() {
        let findings = CHECK.check(&exports(&["ft_transfer", "ft_resolve_transfer"])).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].message.contains("ft_transfer but not storage_deposit"));
    }
}
