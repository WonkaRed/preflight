//! PFW01: access keys on the contract's account.

use crate::deployed::check::{Check, Finding, NotEvaluated};
use crate::deployed::display::list;
use crate::deployed::snapshot::{Permission, Snapshot};
use crate::finding::Severity;

pub(crate) static CHECK: AccessKeys = AccessKeys;

pub(crate) struct AccessKeys;

impl Check for AccessKeys {
    fn id(&self) -> &'static str {
        "PFW01"
    }

    fn title(&self) -> &'static str {
        "Access keys that can change the contract"
    }

    fn read(&self) -> &'static str {
        "RPC query view_access_key_list for the account (every page), at the block shown in the report"
    }

    fn limits(&self) -> &'static str {
        "It shows that a key exists, not who holds it or how it is guarded: a multisig, a DAO or a timelock may \
         sit behind it. A contract can be upgradable through such a key or through its own methods (see PFW02), \
         and it reads no code."
    }

    fn help(&self) -> &'static str {
        "If the contract must not change, delete the full-access keys so the account holds no key that can \
         deploy code; if it must, say who holds the key and keep it in a multisig or governance contract"
    }

    fn check(&self, snapshot: &Snapshot) -> Result<Vec<Finding>, NotEvaluated> {
        let account = &snapshot.account_id;
        let full_access: Vec<&str> = snapshot
            .keys
            .iter()
            .filter(|key| matches!(key.permission, Permission::FullAccess))
            .map(|key| key.public_key.as_str())
            .collect();
        // A function-call key restricted to the contract's own account with no method list may call every
        // method, including ones guarded only by `#[private]`: the caller of such a call is the account itself.
        let self_any_method: Vec<&str> = snapshot
            .keys
            .iter()
            .filter(|key| {
                matches!(&key.permission, Permission::FunctionCall { receiver_id, method_names }
                    if receiver_id == account && method_names.is_empty())
            })
            .map(|key| key.public_key.as_str())
            .collect();

        let mut findings = Vec::new();
        if !full_access.is_empty() {
            findings.push(self.finding(
                Severity::Medium,
                account,
                format!(
                    "this account has {} full-access key{}: {}. Whoever holds one can replace the contract's code, \
                     delete the account, or add more keys",
                    full_access.len(),
                    if full_access.len() == 1 { "" } else { "s" },
                    list(&full_access, 5),
                ),
            ));
        }
        if !self_any_method.is_empty() {
            findings.push(self.finding(
                Severity::Medium,
                account,
                format!(
                    "this account has {} function-call key{} with {account} as the receiver and an empty method list: {}. \
                     Such a key can call, with no attached deposit, any method on the contract, including methods \
                     guarded only by checking that the caller is the contract itself (`#[private]`)",
                    self_any_method.len(),
                    if self_any_method.len() == 1 { "" } else { "s" },
                    list(&self_any_method, 5),
                ),
            ));
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployed::snapshot::AccessKey;

    fn key(public_key: &str, permission: Permission) -> AccessKey {
        AccessKey { public_key: public_key.to_owned(), permission }
    }

    fn function_call(receiver: &str, methods: &[&str]) -> Permission {
        Permission::FunctionCall {
            receiver_id: receiver.to_owned(),
            method_names: methods.iter().map(|m| (*m).to_owned()).collect(),
        }
    }

    #[test]
    fn an_account_with_no_keys_has_no_finding() {
        assert_eq!(CHECK.check(&Snapshot::sample()).unwrap(), []);
    }

    #[test]
    fn full_access_keys_are_counted_and_named_without_accusation() {
        let mut snapshot = Snapshot::sample();
        snapshot.keys = vec![key("ed25519:AAA", Permission::FullAccess), key("ed25519:BBB", Permission::FullAccess)];
        let findings = CHECK.check(&snapshot).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(
            findings[0].message,
            "this account has 2 full-access keys: ed25519:AAA, ed25519:BBB. Whoever holds one can replace the \
             contract's code, delete the account, or add more keys"
        );
    }

    #[test]
    fn a_function_call_key_on_the_contract_with_an_empty_method_list_is_a_finding() {
        let mut snapshot = Snapshot::sample();
        snapshot.keys = vec![key("ed25519:CCC", function_call("token.example.near", &[]))];
        let findings = CHECK.check(&snapshot).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("1 function-call key with token.example.near as the receiver"));
        assert!(findings[0].message.contains("ed25519:CCC"));
    }

    #[test]
    fn restricted_or_foreign_function_call_keys_are_not_findings() {
        let mut snapshot = Snapshot::sample();
        snapshot.keys = vec![
            key("ed25519:A", function_call("token.example.near", &["execute_intents"])),
            key("ed25519:B", function_call("other.near", &[])),
        ];
        assert_eq!(CHECK.check(&snapshot).unwrap(), []);
    }

    #[test]
    fn both_kinds_are_reported_separately() {
        let mut snapshot = Snapshot::sample();
        snapshot.keys =
            vec![key("ed25519:A", Permission::FullAccess), key("ed25519:B", function_call("token.example.near", &[]))];
        assert_eq!(CHECK.check(&snapshot).unwrap().len(), 2);
    }

    #[test]
    fn a_long_key_list_is_cut() {
        let mut snapshot = Snapshot::sample();
        snapshot.keys = (0..8).map(|i| key(&format!("ed25519:K{i}"), Permission::FullAccess)).collect();
        let message = CHECK.check(&snapshot).unwrap().remove(0).message;
        assert!(message.contains("8 full-access keys") && message.contains("(and 3 more)"), "{message}");
    }
}
