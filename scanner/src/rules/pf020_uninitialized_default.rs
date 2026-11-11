//! PF020: contract state that can be built by `Default` while the contract also has an `#[init]` method.
//!
//! near-sdk runs every method on `state_read().unwrap_or_default()`: before the contract is initialized, a call
//! does not fail, it runs on the state type's `Default`, and a `&mut self` call writes that state back, so the
//! later `#[init]` method panics with "The contract has already been initialized". Whoever calls first fixes the
//! state; when `Default` builds an owner from the caller, that is the attacker. `#[derive(PanicOnDefault)]` makes
//! every method panic until `#[init]` has run. Docs: https://docs.near.org/smart-contracts/anatomy/anatomy#initialization-method
//!
//! A struct is reported when all of these hold in the crate: it is contract state (`#[near_bindgen]`, or
//! `#[near(contract_state)]` on the struct); it has a `Default` (`#[derive(Default)]` or an `impl Default for` it,
//! outside test code); it does not derive `PanicOnDefault`; and an impl of it annotated with `#[near]` or
//! `#[near_bindgen]` has an `#[init]` method that checks the state is empty (that is, not `ignore_state`). The `#[init]`
//! method is the author saying the contract must be configured first, and `Default` lets callers skip it.
//!
//! Two shapes are not reported because nothing can be fixed by the first caller: a state type with no fields, and a
//! hand-written `impl Default` whose `default` always panics (for example `env::panic(b"not initialized")`),
//! which is `PanicOnDefault` written out.
//!
//! Knowingly missed: contract state with `Default` and no `#[init]` method (the author never asked for a setup
//! step); a state type whose `Default` comes from a macro or a blanket impl; and `#[init(ignore_state)]` migration
//! methods, which are not the setup step. Knowingly over-reported: a `#[derive(Default)]` state whose zero values
//! are harmless before `#[init]` runs.

use std::collections::BTreeMap;

use proc_macro2::Span;
use syn::visit::{self, Visit};
use syn::{Attribute, ImplItem, ImplItemFn, ItemEnum, ItemImpl, ItemMod, ItemStruct, Meta};

use super::pf007_unguarded_admin::{is_near_attr, last_segment_is_one_of, tokens_contain, type_name};
use crate::finding::{Finding, Severity};
use crate::guards::always_panics;
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf020UninitializedDefault;

pub static RULE: Pf020UninitializedDefault = Pf020UninitializedDefault;

impl Rule for Pf020UninitializedDefault {
    fn id(&self) -> &'static str {
        "PF020"
    }

    fn title(&self) -> &'static str {
        "Contract state has Default, so calls before init run on default state"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn help(&self) -> &'static str {
        "derive `PanicOnDefault` instead of implementing `Default`, so no method runs until the `#[init]` method has"
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
        let init_methods: BTreeMap<&str, &str> = scans
            .iter()
            .flat_map(|scan| scan.init_methods.iter())
            .map(|(owner, method)| (owner.as_str(), method.as_str()))
            .collect();
        let manual_defaults: BTreeMap<&str, &ManualDefault> = scans
            .iter()
            .flat_map(|scan| scan.manual_defaults.iter())
            .map(|default| (default.owner.as_str(), default))
            .collect();

        let mut findings = Vec::new();
        for (file, scan) in krate.files.iter().zip(&scans) {
            for state in &scan.states {
                let (Some(init), true) = (init_methods.get(state.name.as_str()), !state.panics_on_default) else {
                    continue;
                };
                let manual = manual_defaults.get(state.name.as_str());
                if manual.is_some_and(|default| default.panics) || !state.derives_default && manual.is_none() {
                    continue;
                }
                let name = &state.name;
                let message = if manual.is_some_and(|default| default.reads_caller) {
                    format!(
                        "`{name}` implements `Default` by reading the caller, so a call made before `{init}` has run \
                         builds the state from whoever calls first, and `{init}` then panics because the state exists"
                    )
                } else {
                    format!(
                        "`{name}` has `Default` and an `#[init]` method `{init}`, so a call made before `{init}` has run \
                         uses default state instead of failing, and `{init}` then panics because the state exists"
                    )
                };
                findings.push(self.finding(file, state.span, name.clone(), message));
            }
        }
        findings
    }
}

/// A contract state type declared in a file.
struct State {
    name: String,
    span: Span,
    derives_default: bool,
    panics_on_default: bool,
}

/// An `impl Default for T`.
struct ManualDefault {
    owner: String,
    reads_caller: bool,
    /// Every call of the `default` function ends in a panic.
    panics: bool,
}

#[derive(Default)]
struct FileScan {
    states: Vec<State>,
    manual_defaults: Vec<ManualDefault>,
    /// `(type, #[init] method)` for every setup method in a `#[near]` impl.
    init_methods: Vec<(String, String)>,
}

fn tokens_mention(meta: &Meta, ident: &str) -> bool {
    matches!(meta, Meta::List(list) if tokens_contain(&list.tokens, &[ident]))
}

/// `#[near_bindgen]` or `#[near(contract_state)]` on a type declaration marks the contract state.
fn is_contract_state_attr(attr: &Attribute) -> bool {
    last_segment_is_one_of(attr, &["near_bindgen"])
        || last_segment_is_one_of(attr, &["near"]) && tokens_mention(&attr.meta, "contract_state")
}

/// The last path segments of everything named in `#[derive(..)]` attributes.
fn derived(attrs: &[Attribute]) -> Vec<String> {
    let mut names = Vec::new();
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("derive")) {
        let _ = attr.parse_nested_meta(|meta| {
            names.extend(meta.path.segments.last().map(|segment| segment.ident.to_string()));
            Ok(())
        });
    }
    names
}

fn is_test_code(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || attr.path().is_ident("cfg") && attr.parse_args::<syn::Ident>().is_ok_and(|arg| arg == "test")
    })
}

/// Whether a `#[init]` attribute is on `method` and the init checks that the state is empty.
fn is_setup_init(method: &ImplItemFn) -> bool {
    method.attrs.iter().any(|attr| attr.path().is_ident("init") && !tokens_mention(&attr.meta, "ignore_state"))
}

/// Finds `env::predecessor_account_id()` and `env::signer_account_id()` calls.
#[derive(Default)]
struct ReadsCaller(bool);

impl<'ast> Visit<'ast> for ReadsCaller {
    fn visit_ident(&mut self, ident: &'ast proc_macro2::Ident) {
        self.0 |= ident == "predecessor_account_id" || ident == "signer_account_id";
    }
}

impl FileScan {
    fn state(&mut self, attrs: &[Attribute], ident: &syn::Ident, has_fields: bool) {
        if has_fields && attrs.iter().any(is_contract_state_attr) {
            let derives = derived(attrs);
            self.states.push(State {
                name: ident.to_string(),
                span: ident.span(),
                derives_default: derives.iter().any(|name| name == "Default"),
                panics_on_default: derives.iter().any(|name| name == "PanicOnDefault"),
            });
        }
    }
}

impl<'ast> Visit<'ast> for FileScan {
    fn visit_item_struct(&mut self, item: &'ast ItemStruct) {
        self.state(&item.attrs, &item.ident, !item.fields.is_empty());
    }

    fn visit_item_enum(&mut self, item: &'ast ItemEnum) {
        self.state(&item.attrs, &item.ident, true);
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        if is_test_code(&item.attrs) {
            return;
        }
        let owner = type_name(&item.self_ty);
        match &item.trait_ {
            Some((_, path, _)) if path.segments.last().is_some_and(|segment| segment.ident == "Default") => {
                let mut caller = ReadsCaller::default();
                caller.visit_item_impl(item);
                let panics = item.items.iter().any(|member| {
                    matches!(member, ImplItem::Fn(method) if method.sig.ident == "default" && always_panics(&method.block))
                });
                self.manual_defaults.push(ManualDefault { owner, reads_caller: caller.0, panics });
            }
            _ if item.attrs.iter().any(is_near_attr) => {
                for member in &item.items {
                    if let ImplItem::Fn(method) = member
                        && is_setup_init(method)
                    {
                        self.init_methods.push((owner.clone(), method.sig.ident.to_string()));
                    }
                }
            }
            _ => {}
        }
    }

    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        if !is_test_code(&item.attrs) {
            visit::visit_item_mod(self, item);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(sources: &[(&str, &str)]) -> Vec<Finding> {
        RULE.check(&Crate::from_sources(sources.iter().copied()).unwrap())
    }

    fn items(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|finding| finding.item.as_str()).collect()
    }

    const INIT: &str = "#[near] impl Treasury { #[init] pub fn new(owner_id: AccountId) -> Self { todo!() } }";

    #[test]
    fn flags_contract_state_with_a_derived_default_and_an_init_method() {
        let source = format!("#[near(contract_state)] #[derive(Default)] pub struct Treasury {{ fee: u128 }} {INIT}");
        let findings = check(&[("src/lib.rs", &source)]);
        assert_eq!(items(&findings), ["Treasury"]);
        assert!(findings[0].message.contains("`Treasury` has `Default` and an `#[init]` method `new`"), "{}", findings[0].message);
    }

    #[test]
    fn flags_a_manual_default_and_says_so_when_it_reads_the_caller() {
        let source = format!(
            "#[near(contract_state)] pub struct Treasury {{ owner_id: AccountId }}
            impl Default for Treasury {{ fn default() -> Self {{ Self {{ owner_id: env::predecessor_account_id() }} }} }}
            {INIT}"
        );
        let findings = check(&[("src/lib.rs", &source)]);
        assert_eq!(items(&findings), ["Treasury"]);
        assert!(findings[0].message.contains("by reading the caller"), "{}", findings[0].message);
    }

    #[test]
    fn a_manual_default_that_ignores_the_caller_is_still_flagged_with_the_general_message() {
        let source = format!(
            "#[near(contract_state)] pub struct Treasury {{ fee: u128 }}
            impl Default for Treasury {{ fn default() -> Self {{ Self {{ fee: 30 }} }} }}
            {INIT}"
        );
        let findings = check(&[("src/lib.rs", &source)]);
        assert_eq!(items(&findings), ["Treasury"]);
        assert!(!findings[0].message.contains("reading the caller"));
    }

    #[test]
    fn accepts_near_bindgen_path_qualified_attributes_and_enums() {
        for state in [
            "#[near_bindgen] #[derive(Default)] pub struct Treasury { n: u64 }",
            "#[near_sdk::near_bindgen] #[derive(Default)] pub struct Treasury { n: u64 }",
            "#[near_sdk::near(contract_state)] #[derive(Default)] pub struct Treasury { n: u64 }",
            "#[near(contract_state, serializers = [borsh])] #[derive(Debug, std::default::Default)] pub struct Treasury { n: u64 }",
            "#[near(contract_state)] #[derive(Default)] pub enum Treasury { #[default] Open }",
        ] {
            let source = format!("{state} #[near_bindgen] impl Treasury {{ #[init] pub fn new() -> Self {{ todo!() }} }}");
            assert_eq!(items(&check(&[("src/lib.rs", &source)])), ["Treasury"], "{state}");
        }
    }

    #[test]
    fn follows_the_type_across_files() {
        let findings = check(&[
            ("src/lib.rs", "#[near(contract_state)] #[derive(Default)] pub struct Treasury { n: u64 }"),
            ("src/default.rs", INIT),
        ]);
        assert_eq!(items(&findings), ["Treasury"]);
        assert_eq!(findings[0].file, "src/lib.rs");
    }

    #[test]
    fn panic_on_default_is_the_fix() {
        let source = format!("#[near(contract_state)] #[derive(PanicOnDefault)] pub struct Treasury {{ n: u64 }} {INIT}");
        assert!(check(&[("src/lib.rs", &source)]).is_empty());
        let source = format!("#[near(contract_state)] #[derive(near_sdk::PanicOnDefault)] pub struct Treasury {{ n: u64 }} {INIT}");
        assert!(check(&[("src/lib.rs", &source)]).is_empty());
    }

    #[test]
    fn default_without_an_init_method_is_not_flagged() {
        let source = "#[near(contract_state)] #[derive(Default)] pub struct Counter { n: u64 }
            #[near] impl Counter { pub fn bump(&mut self) { self.n += 1; } }";
        assert!(check(&[("src/lib.rs", source)]).is_empty());
    }

    #[test]
    fn a_migration_that_ignores_state_is_not_the_setup_step() {
        let source = "#[near(contract_state)] #[derive(Default)] pub struct Counter { n: u64 }
            #[near] impl Counter { #[private] #[init(ignore_state)] pub fn migrate() -> Self { todo!() } }";
        assert!(check(&[("src/lib.rs", source)]).is_empty());
    }

    #[test]
    fn a_type_that_is_not_contract_state_is_not_flagged() {
        let source = format!(
            "#[near(serializers = [json])] #[derive(Default)] pub struct Treasury {{ n: u64 }}
            #[derive(Default)] pub struct Plain {{ n: u64 }} {INIT}"
        );
        assert!(check(&[("src/lib.rs", &source)]).is_empty());
    }

    #[test]
    fn an_init_method_of_another_type_or_outside_a_near_impl_does_not_count() {
        let source = "#[near(contract_state)] #[derive(Default)] pub struct Treasury { n: u64 }
            #[near] impl Other { #[init] pub fn new() -> Self { todo!() } }
            impl Treasury { #[init] pub fn new() -> Self { todo!() } }";
        assert!(check(&[("src/lib.rs", source)]).is_empty());
    }

    #[test]
    fn a_default_in_test_code_is_ignored() {
        let source = format!(
            "#[near(contract_state)] pub struct Treasury {{ n: u64 }} {INIT}
            #[cfg(test)] mod tests {{ impl Default for Treasury {{ fn default() -> Self {{ Self {{}} }} }} }}"
        );
        assert!(check(&[("src/lib.rs", &source)]).is_empty());
    }

    #[test]
    fn reports_each_state_type_once() {
        let source = "#[near(contract_state)] #[derive(Default)] pub struct A { n: u64 } #[near_bindgen] #[derive(Default)] pub struct B { n: u64 }
            #[near] impl A { #[init] pub fn new() -> Self { todo!() } #[init] pub fn again() -> Self { todo!() } }
            #[near] impl B { #[init] pub fn new() -> Self { todo!() } }";
        assert_eq!(items(&check(&[("src/lib.rs", source)])), ["A", "B"]);
    }

    /// A common shape in deployed code: `PanicOnDefault` written by hand.
    #[test]
    fn a_default_that_always_panics_is_panic_on_default_written_out() {
        for body in ["env::panic(b\"not initialized\")", "env::panic_str(\"no default\");", "panic!(\"not initialized\")", "unreachable!()"] {
            let source = format!(
                "#[near_bindgen] pub struct Treasury {{ n: u64 }}
                impl Default for Treasury {{ fn default() -> Self {{ {body} }} }}
                {INIT}"
            );
            assert!(check(&[("src/lib.rs", &source)]).is_empty(), "{body}");
        }
    }

    #[test]
    fn a_default_that_does_anything_besides_panic_is_still_flagged() {
        for body in ["Self { n: 0 }", "env::log_str(\"default\"); Self { n: 0 }", "if cheap() { env::panic_str(\"no\") } Self { n: 0 }"] {
            let source = format!(
                "#[near_bindgen] pub struct Treasury {{ n: u64 }}
                impl Default for Treasury {{ fn default() -> Self {{ {body} }} }}
                {INIT}"
            );
            assert_eq!(items(&check(&[("src/lib.rs", &source)])), ["Treasury"], "{body}");
        }
    }

    /// A common shape in deployed code, a stub state `Prover {}`: with no field there is no state for the first caller to fix.
    #[test]
    fn a_state_with_no_fields_is_not_flagged_but_a_state_with_fields_is() {
        for state in ["pub struct Treasury {}", "pub struct Treasury;", "pub struct Treasury();"] {
            let source = format!("#[near_bindgen] #[derive(Default)] {state} {INIT}");
            assert!(check(&[("src/lib.rs", &source)]).is_empty(), "{state}");
        }
        for state in ["pub struct Treasury { n: u64 }", "pub struct Treasury(u64);"] {
            let source = format!("#[near_bindgen] #[derive(Default)] {state} {INIT}");
            assert_eq!(items(&check(&[("src/lib.rs", &source)])), ["Treasury"], "{state}");
        }
    }
}
