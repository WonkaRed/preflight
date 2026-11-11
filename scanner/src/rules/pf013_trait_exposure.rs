//! PF013: a privileged method exported through a `#[near]` trait impl, with no caller check.
//!
//! The `#[near]` macro exports every method of a trait impl as a public contract method (near-sdk-macros 5.30.1,
//! `ImplItemMethodInfo::new`: `impl_trait.is_some() || vis == pub`), whatever its visibility, because a trait
//! method has none. A trait written to organise the contract's internals (`Pausable`, `Mintable`) becomes a public
//! API the moment its impl carries `#[near]`, and a method that was meant to be called by the contract's own code
//! can be called by anyone. Docs: https://sigmaprime.io/blog/near-accounts-and-access-control/
//!
//! A method is reported when all of these hold:
//! - it is in an `impl Trait for Type` carrying `#[near]` / `#[near_bindgen]`, and `Trait` is defined in the same
//!   crate (a `trait Name` item in any file, matched by the last path segment);
//! - it takes `&mut self` and is not `#[private]`, and carries no attribute macro the scanner does not know
//!   (`#[payable]`, `#[handle_result]`, `#[result_serializer]`, `#[init]`, `#[allow]`, `#[doc]`, `#[inline]`,
//!   `#[must_use]` and `#[cfg]` are known; an unknown one may be an access guard);
//! - its name is privileged: it has a word in [`PRIVILEGED_WORDS`] (`pause`, `toggle_pause`, `mint`,
//!   `transfer_ownership`, `add_admin`, `withdraw`, ...), or it starts with `set_` and is handed the new value
//!   (`set_fee(fee)`); `set_to_zero(&mut self)` only resets a counter;
//! - neither it nor a same-crate function it reaches looks at the caller (`guards::Guards`: it mentions
//!   `predecessor_account_id` or `signer_account_id` on every path, or carries `#[private]` or a near-plugins
//!   attribute). A guard called by name (`assert_owner()`, `require_role`) counts only through a body the crate
//!   defines; one from another crate is not seen, so the method is reported.
//!
//! Knowingly missed: a trait defined in another crate (a standards trait such as `FungibleTokenCore` is one);
//! privileged methods under other names; a guard that lives in a dependency (it is not seen, so the method
//! is reported); a trait method that is intentionally public yet named like an
//! administrative action and checks nothing. Inherent `pub` methods are not this rule's business.
//!
//! Relation to PF007: that rule flags an unguarded method that writes an access-control field (one some method
//! compares with the caller), changes the contract's account, or is a migration. PF013 needs none of that: it
//! looks at the privileged name and at the export, so `pause` flipping a plain `paused` flag is PF013 only. A trait
//! method that does both, such as one assigning `self.owner`, is reported by both.

use std::collections::BTreeSet;

use proc_macro2::Span;
use syn::visit::{self, Visit};
use syn::{Attribute, ImplItem, ItemImpl, ItemTrait};

use super::pf007_unguarded_admin::{is_near_attr, type_name};
use crate::finding::{Finding, Severity};
use crate::guards::Guards;
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf013TraitExposure;

pub static RULE: Pf013TraitExposure = Pf013TraitExposure;

impl Rule for Pf013TraitExposure {
    fn id(&self) -> &'static str {
        "PF013"
    }

    fn title(&self) -> &'static str {
        "Privileged trait method exported by #[near] without a caller check"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn help(&self) -> &'static str {
        "check the caller inside the method, or move it out of the #[near] trait impl, which exports every method"
    }

    fn check(&self, krate: &Crate) -> Vec<Finding> {
        let scans: Vec<FileScan> = krate
            .files
            .iter()
            .map(|file| {
                let mut scan = FileScan::default();
                scan.visit_file(&file.ast);
                scan
            })
            .collect();
        let local_traits: BTreeSet<&str> = scans.iter().flat_map(|scan| scan.traits.iter().map(String::as_str)).collect();
        let guards = Guards::new(krate);

        let mut findings = Vec::new();
        for (index, (file, scan)) in krate.files.iter().zip(&scans).enumerate() {
            for export in &scan.exports {
                if !local_traits.contains(export.trait_name.as_str())
                    || !export.mut_self
                    || export.shielded
                    || !is_privileged(&export.name, export.takes_input)
                    || guards.of(index, export.span).looks_at_caller()
                {
                    continue;
                }
                let name = format!("{}::{}", export.owner, export.name);
                findings.push(self.finding(
                    file,
                    export.span,
                    name.clone(),
                    format!(
                        "`{name}` is in `#[near] impl {} for {}`, so it is exported as a public contract method, and it never checks who the caller is, so any account can call it",
                        export.trait_name, export.owner
                    ),
                ));
            }
        }
        findings
    }
}

/// Words that mark an administrative or value-moving action when they appear in a method name.
const PRIVILEGED_WORDS: [&str; 17] = [
    "pause", "unpause", "resume", "freeze", "unfreeze", "owner", "ownership", "admin", "mint", "burn", "upgrade",
    "migrate", "withdraw", "sweep", "rescue", "drain", "blacklist",
];

/// Attributes on a method that the scanner knows are not access guards.
const KNOWN_ATTRS: [&str; 9] =
    ["payable", "handle_result", "result_serializer", "init", "allow", "doc", "inline", "must_use", "cfg"];

/// A setter is configuration when it is handed the new value; `set_to_zero(&mut self)` only resets a counter.
fn is_privileged(name: &str, takes_input: bool) -> bool {
    (takes_input && name.starts_with("set_")) || name.split('_').any(|word| PRIVILEGED_WORDS.contains(&word))
}

/// A method of a `#[near]` trait impl.
struct Export {
    owner: String,
    trait_name: String,
    name: String,
    span: Span,
    mut_self: bool,
    /// Has a parameter besides the receiver.
    takes_input: bool,
    /// `#[private]`, or an attribute macro that may be an access guard.
    shielded: bool,
}

#[derive(Default)]
struct FileScan {
    /// Names of the traits defined in the file.
    traits: Vec<String>,
    exports: Vec<Export>,
}

/// `#[private]`, or an attribute macro outside [`KNOWN_ATTRS`].
fn shields_method(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().segments.last().is_none_or(|segment| !KNOWN_ATTRS.iter().any(|known| segment.ident == *known))
    })
}

impl<'ast> Visit<'ast> for FileScan {
    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        if item.attrs.iter().any(is_near_attr)
            && let Some((_, trait_path, _)) = &item.trait_
        {
            let owner = type_name(&item.self_ty);
            let trait_name = trait_path.segments.last().map_or_else(String::new, |segment| segment.ident.to_string());
            for member in &item.items {
                if let ImplItem::Fn(method) = member {
                    self.exports.push(Export {
                        owner: owner.clone(),
                        trait_name: trait_name.clone(),
                        name: method.sig.ident.to_string(),
                        span: method.sig.ident.span(),
                        mut_self: method.sig.receiver().is_some_and(|r| r.reference.is_some() && r.mutability.is_some()),
                        takes_input: method.sig.inputs.len() > 1,
                        shielded: shields_method(&method.attrs),
                    });
                }
            }
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_item_trait(&mut self, item: &'ast ItemTrait) {
        self.traits.push(item.ident.to_string());
        visit::visit_item_trait(self, item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(sources: &[(&str, &str)]) -> Vec<Finding> {
        let krate = Crate::from_sources(sources.iter().copied()).unwrap();
        RULE.check(&krate)
    }

    fn one(source: &str) -> Vec<Finding> {
        check(&[("src/lib.rs", source)])
    }

    fn items(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|finding| finding.item.as_str()).collect()
    }

    const VAULT: &str = r#"
        pub trait Pausable {
            fn is_paused(&self) -> bool;
            fn pause(&mut self);
        }

        #[near]
        impl Pausable for Vault {
            fn is_paused(&self) -> bool {
                self.paused
            }
            fn pause(&mut self) {
                self.paused = true;
            }
        }
    "#;

    /// The vault with `pause` replaced by a method named `name` whose body is `body`.
    fn vault_with(name: &str, body: &str) -> String {
        VAULT.replace("fn pause(&mut self);", &format!("fn {name}(&mut self);")).replace(
            "fn pause(&mut self) {\n                self.paused = true;\n            }",
            &format!("fn {name}(&mut self) {{ {body} }}"),
        )
    }

    #[test]
    fn flags_an_unguarded_privileged_method_of_a_near_trait_impl_and_locates_it() {
        let findings = one(VAULT);
        assert_eq!(items(&findings), ["Vault::pause"]);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF013", Severity::High));
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 12, 16));
        assert!(finding.message.contains("`#[near] impl Pausable for Vault`"), "{}", finding.message);
    }

    #[test]
    fn accepts_both_near_spellings() {
        for attr in ["#[near_bindgen]", "#[near_sdk::near]", "#[near(contract_state)]"] {
            let source = VAULT.replace("#[near]", attr);
            assert_eq!(items(&one(&source)), ["Vault::pause"], "{attr}");
        }
    }

    #[test]
    fn flags_privileged_names() {
        for name in [
            "pause", "unpause", "toggle_pause", "resume", "mint", "burn_all", "transfer_ownership",
            "add_admin", "change_owner", "upgrade", "migrate", "withdraw_fees", "sweep", "rescue_funds", "drain",
        ] {
            let source = vault_with(name, "self.paused = !self.paused;");
            assert_eq!(items(&one(&source)), [format!("Vault::{name}")], "{name}");
        }
    }

    #[test]
    fn ordinary_names_are_not_privileged() {
        for name in ["increment", "deposit", "settle", "reset", "setup", "paused_since", "unrelated", "set_to_zero"] {
            assert!(one(&vault_with(name, "self.count += 1;")).is_empty(), "{name}");
        }
    }

    #[test]
    fn a_trait_defined_in_another_file_of_the_crate_counts() {
        let definition = "trait Pausable { fn pause(&mut self); }";
        let implementation = "#[near] impl crate::pausable::Pausable for Vault { fn pause(&mut self) { self.paused = true; } }";
        assert_eq!(items(&check(&[("src/pausable.rs", definition), ("src/lib.rs", implementation)])), ["Vault::pause"]);
    }

    #[test]
    fn a_trait_from_a_dependency_is_not_reported() {
        let source = "#[near] impl FungibleTokenCore for Token { fn ft_mint(&mut self) { self.supply += 1; } fn pause(&mut self) {} }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn a_method_that_checks_the_caller_is_clean() {
        for body in [
            "require!(env::predecessor_account_id() == self.owner, \"only the owner\"); self.paused = true;",
            "assert_eq!(near_sdk::env::predecessor_account_id(), self.owner); self.paused = true;",
            "if env::signer_account_id() != self.owner { env::panic_str(\"no\"); } self.paused = true;",
            "let caller = predecessor_account_id(); self.paused = caller == self.owner;",
        ] {
            assert!(one(&vault_with("pause", body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn a_guard_in_a_same_crate_helper_is_followed() {
        let guarded = "impl Vault { fn flip(&mut self) { self.check(); self.paused = true; } fn check(&self) { require!(env::predecessor_account_id() == self.owner); } }";
        let source = vault_with("pause", "self.flip();");
        assert!(check(&[("src/lib.rs", &source), ("src/helpers.rs", guarded)]).is_empty());

        let unguarded = "impl Vault { fn flip(&mut self) { self.paused = true; } }";
        assert_eq!(items(&check(&[("src/lib.rs", &source), ("src/helpers.rs", unguarded)])), ["Vault::pause"]);
    }

    #[test]
    fn a_helper_cycle_terminates() {
        let source = vault_with("pause", "ping();") + "fn ping() { pong(); } fn pong() { ping(); }";
        assert_eq!(items(&one(&source)), ["Vault::pause"]);
    }

    #[test]
    fn private_methods_and_unknown_attribute_macros_are_trusted() {
        for attr in ["#[private]", "#[only(owner)]", "#[access_control_any(roles(Role::Pauser))]"] {
            let source = VAULT.replace("fn pause(&mut self) {", &format!("{attr}\n fn pause(&mut self) {{"));
            assert!(one(&source).is_empty(), "{attr}");
        }
        for attr in ["#[payable]", "#[handle_result]", "#[allow(unused)]", "/// docs", "#[inline]", "#[cfg(not(test))]"] {
            let source = VAULT.replace("fn pause(&mut self) {", &format!("{attr}\n fn pause(&mut self) {{"));
            assert_eq!(items(&one(&source)), ["Vault::pause"], "{attr}");
        }
    }

    #[test]
    fn views_and_by_value_methods_are_ignored() {
        for receiver in ["&self", "self", "mut self"] {
            let source = VAULT.replace("fn pause(&mut self) {", &format!("fn pause({receiver}) {{"));
            assert!(one(&source).is_empty(), "{receiver}");
        }
        assert!(one(&VAULT.replace("fn pause(&mut self) {", "fn pause() {")).is_empty());
    }

    #[test]
    fn impls_the_near_macro_does_not_export_are_ignored() {
        assert!(one(&VAULT.replace("#[near]", "")).is_empty());
        assert!(one(&VAULT.replace("#[near]", "#[derive(Debug)]")).is_empty());
        let inherent = "#[near] impl Vault { pub fn pause(&mut self) { self.paused = true; } }";
        assert!(one(inherent).is_empty(), "inherent pub methods are another rule's business");
    }

    #[test]
    fn reports_each_method_once_and_names_the_impl() {
        let source = VAULT.replace(
            "fn is_paused(&self) -> bool {",
            "fn resume(&mut self) { self.paused = false; }\n fn is_paused(&self) -> bool {",
        ) + "#[near] impl Pausable for Other { fn pause(&mut self) {} }";
        assert_eq!(items(&one(&source)), ["Vault::resume", "Vault::pause", "Other::pause"]);
    }

    #[test]
    fn a_setter_that_is_handed_no_value_is_a_reset_not_configuration() {
        let reset = "trait Zeroable { fn set_to_zero(&mut self); fn set_fee(&mut self, fee: u32); }
            #[near] impl Zeroable for Vault { fn set_to_zero(&mut self) { self.n = 0; } fn set_fee(&mut self, fee: u32) { self.fee = fee; } }";
        let found: Vec<String> = check(&[("src/lib.rs", reset)]).into_iter().map(|finding| finding.item).collect();
        assert_eq!(found, ["Vault::set_fee"]);
    }

    #[test]
    fn a_near_plugins_attribute_is_a_caller_check_and_a_role_check_by_name_is_not() {
        for name in ["<Self as Rbac>::require_role(&Role::Admin);", "self.assert_manager();", "common::assert_owner(self);"] {
            let source = format!(
                "trait Pausable {{ fn pause(&mut self); }}
                 #[near] impl Pausable for Vault {{ fn pause(&mut self) {{ {name} self.paused = true; }} }}"
            );
            assert_eq!(check(&[("src/lib.rs", &source)]).len(), 1, "{name}");
        }
        let guarded = "trait Pausable { fn pause(&mut self); }
            #[near] impl Pausable for Vault { #[access_control_any(roles(Role::Dao))] fn pause(&mut self) { self.paused = true; } }";
        assert!(check(&[("src/lib.rs", guarded)]).is_empty());
        let unrelated = "trait Pausable { fn pause(&mut self); }
            #[near] impl Pausable for Vault { fn pause(&mut self) { assert!(!self.paused); self.paused = true; } }";
        assert_eq!(check(&[("src/lib.rs", unrelated)]).len(), 1);
    }

    /// A no-op `check_owner` defined in the crate guards nothing; the one that checks does.
    #[test]
    fn a_no_op_owner_check_defined_in_the_crate_is_not_a_guard() {
        let noop = vault_with("pause", "self.check_owner(); self.paused = true;") + "impl Vault { fn check_owner(&self) {} }";
        assert_eq!(items(&one(&noop)), ["Vault::pause"]);
        let real = vault_with("pause", "self.check_owner(); self.paused = true;")
            + "impl Vault { fn check_owner(&self) { require!(env::predecessor_account_id() == self.owner); } }";
        assert!(one(&real).is_empty());
    }
}
