//! PF001: a callback exported without `#[private]`.
//!
//! A NEAR callback must be a public contract method so the runtime can call it, but it must only be callable by
//! the contract itself. Without `#[private]` any account can call it directly and feed it forged arguments or a
//! forged promise result. Docs: https://docs.near.org/smart-contracts/security/cross-contract-calls/callbacks
//!
//! A method is a callback when it takes a callback argument (`#[callback_result]`, `#[callback_unwrap]`,
//! `#[callback_vec]`, `#[callback]`) or when the crate schedules it as the continuation of a promise:
//! `Self::ext(env::current_account_id()).method(..)` written in a `.then(..)`, in a local, bare, or in a helper
//! function that makes the call (a helper that only returns the builder, `fn me() -> Contract { Self::ext(..) }`, is
//! not followed). Only methods the `#[near]` macro exports are considered: `pub` methods of an inherent impl, and
//! every method of a trait impl.
//!
//! Only `#[private]` on the method itself counts. A callback guarded by hand (`assert_self()`, the caller compared
//! with the current account) is reported too: the rule does not read bodies, and a check it cannot see is not one it
//! can trust.

use std::collections::BTreeSet;

use proc_macro2::Span;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, ExprCall, ExprMethodCall, FnArg, ImplItem, ImplItemFn, ItemImpl, Visibility};

use super::pf007_unguarded_admin::{is_near_attr, type_name};
use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf001Callback;

pub static RULE: Pf001Callback = Pf001Callback;

impl Rule for Pf001Callback {
    fn id(&self) -> &'static str {
        "PF001"
    }

    fn title(&self) -> &'static str {
        "Callback not marked #[private]"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn help(&self) -> &'static str {
        "add #[private] to the callback so only the contract itself can call it"
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
        let self_scheduled: BTreeSet<&str> =
            scans.iter().flat_map(|scan| scan.self_scheduled.iter().map(String::as_str)).collect();

        let mut findings = Vec::new();
        for (file, scan) in krate.files.iter().zip(&scans) {
            for method in scan.exported.iter().filter(|method| !method.private) {
                let reason = if method.has_callback_arg {
                    "takes a callback argument".to_owned()
                } else if self_scheduled.contains(method.name.as_str()) {
                    "is scheduled on the contract itself with `ext(..)`".to_owned()
                } else {
                    continue;
                };
                findings.push(self.finding(
                    file,
                    method.span,
                    format!("{}::{}", method.owner, method.name),
                    format!(
                        "`{}::{}` {reason} but is not marked `#[private]`, so any account can call it directly",
                        method.owner, method.name
                    ),
                ));
            }
        }
        findings
    }
}

/// A method the `#[near]` macro exports.
struct Exported {
    owner: String,
    name: String,
    span: Span,
    private: bool,
    has_callback_arg: bool,
}

/// What one file contributes: its exported methods, and the method names it schedules on the contract itself.
#[derive(Default)]
struct FileScan {
    exported: Vec<Exported>,
    self_scheduled: BTreeSet<String>,
}

const CALLBACK_ARG_ATTRS: [&str; 4] = ["callback", "callback_unwrap", "callback_result", "callback_vec"];

fn has_helper_attr(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident(name))
}

impl<'ast> Visit<'ast> for FileScan {
    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        if item.attrs.iter().any(is_near_attr) {
            let owner = type_name(&item.self_ty);
            let is_trait_impl = item.trait_.is_some();
            for member in &item.items {
                if let ImplItem::Fn(method) = member
                    && (is_trait_impl || matches!(method.vis, Visibility::Public(_)))
                {
                    self.exported.push(exported(&owner, method));
                }
            }
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if let Some(names) = names_called_on_self_ext(call) {
            self.self_scheduled.extend(names);
        }
        visit::visit_expr_method_call(self, call);
    }
}

fn exported(owner: &str, method: &ImplItemFn) -> Exported {
    let has_callback_arg = method.sig.inputs.iter().any(|arg| match arg {
        FnArg::Typed(arg) => CALLBACK_ARG_ATTRS.iter().any(|name| has_helper_attr(&arg.attrs, name)),
        FnArg::Receiver(_) => false,
    });
    Exported {
        owner: owner.to_owned(),
        name: method.sig.ident.to_string(),
        span: method.sig.ident.span(),
        private: has_helper_attr(&method.attrs, "private"),
        has_callback_arg,
    }
}

/// For a chain like `Self::ext(env::current_account_id()).with_static_gas(g).on_done(x)`, the method names in the
/// chain. `None` unless the chain starts at `Self::ext(..)`, or at `Type::ext(env::current_account_id())`, which
/// is how a contract schedules its own methods; `ext(..)` on another contract's type schedules that contract's.
fn names_called_on_self_ext(call: &ExprMethodCall) -> Option<Vec<String>> {
    let mut names = vec![call.method.to_string()];
    let mut receiver = &*call.receiver;
    loop {
        match receiver {
            Expr::MethodCall(inner) => {
                names.push(inner.method.to_string());
                receiver = &inner.receiver;
            }
            Expr::Call(root) => return is_self_ext(root).then_some(names),
            _ => return None,
        }
    }
}

fn is_self_ext(call: &ExprCall) -> bool {
    let Expr::Path(func) = &*call.func else { return false };
    let mut segments = func.path.segments.iter().rev();
    let (Some(last), Some(owner)) = (segments.next(), segments.next()) else { return false };
    last.ident == "ext" && (owner.ident == "Self" || first_arg_is_current_account(call))
}

fn first_arg_is_current_account(call: &ExprCall) -> bool {
    matches!(
        call.args.first(),
        Some(Expr::Call(arg)) if matches!(
            &*arg.func,
            Expr::Path(path) if path.path.segments.last().is_some_and(|s| s.ident == "current_account_id")
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(sources: &[(&str, &str)]) -> Vec<Finding> {
        let krate = Crate::from_sources(sources.iter().copied()).unwrap();
        RULE.check(&krate)
    }

    fn items(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|finding| finding.item.as_str()).collect()
    }

    const SCHEDULED_PUBLIC: &str = r#"
        #[near]
        impl Escrow {
            pub fn release(&mut self, id: u64) -> Promise {
                Promise::new(self.seller.clone())
                    .transfer(self.amount)
                    .then(Self::ext(env::current_account_id()).with_static_gas(GAS).on_release(id))
            }
            pub fn on_release(&mut self, id: u64) {}
        }
    "#;

    #[test]
    fn flags_a_callback_scheduled_on_self_and_locates_it() {
        let findings = check(&[("src/lib.rs", SCHEDULED_PUBLIC)]);
        assert_eq!(items(&findings), ["Escrow::on_release"]);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF001", Severity::High));
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 9, 20));
    }

    #[test]
    fn private_callback_is_clean() {
        let source = SCHEDULED_PUBLIC.replace("pub fn on_release", "#[private]\n pub fn on_release");
        assert!(check(&[("src/lib.rs", &source)]).is_empty());
    }

    #[test]
    fn flags_every_callback_argument_attribute() {
        for attr in ["callback", "callback_unwrap", "callback_result", "callback_vec"] {
            let source = format!("#[near] impl C {{ pub fn done(&mut self, #[{attr}] r: u64) {{}} }}");
            assert_eq!(items(&check(&[("src/lib.rs", &source)])), ["C::done"], "#[{attr}]");
        }
    }

    #[test]
    fn private_callback_with_a_callback_argument_is_clean() {
        let source = "#[near] impl C { #[private] pub fn done(&mut self, #[callback_result] r: Result<u64, PromiseError>) {} }";
        assert!(check(&[("src/lib.rs", source)]).is_empty());
    }

    #[test]
    fn finds_a_callback_scheduled_through_an_ext_contract_trait() {
        let source = "#[near] impl C { pub fn go(&self) { ext_self::ext(env::current_account_id()).done(); } pub fn done(&mut self) {} }";
        assert_eq!(items(&check(&[("src/lib.rs", source)])), ["C::done"]);
    }

    #[test]
    fn follows_a_callback_scheduled_in_another_file_of_the_crate() {
        let definition = "#[near] impl C { pub fn done(&mut self) {} }";
        let scheduling = "fn go() { Self::ext(env::current_account_id()).done(); }";
        let findings = check(&[("src/lib.rs", scheduling), ("src/callbacks.rs", definition)]);
        assert_eq!(items(&findings), ["C::done"]);
        assert_eq!(findings[0].file, "src/callbacks.rs");
    }

    #[test]
    fn calls_on_another_contract_do_not_make_a_local_method_a_callback() {
        let source = "#[near] impl C {
            pub fn ft_transfer(&mut self, to: AccountId) {}
            pub fn pay(&self) { ext_ft::ext(token()).ft_transfer(to); Promise::new(a).function_call(); }
        }";
        assert!(check(&[("src/lib.rs", source)]).is_empty());
    }

    #[test]
    fn methods_the_near_macro_does_not_export_are_ignored() {
        let source = "
            impl NotNear { pub fn done(&mut self, #[callback_result] r: u64) {} }
            #[near] impl C {
                fn hidden(&mut self, #[callback_result] r: u64) {}
                pub(crate) fn crate_only(&mut self, #[callback_result] r: u64) {}
            }";
        assert!(check(&[("src/lib.rs", source)]).is_empty());
    }

    #[test]
    fn every_method_of_a_trait_impl_is_exported() {
        let source = "#[near] impl Callbacks for C { fn done(&mut self, #[callback_result] r: u64) {} }";
        assert_eq!(items(&check(&[("src/lib.rs", source)])), ["C::done"]);
    }

    #[test]
    fn accepts_near_bindgen_and_path_qualified_near() {
        for attr in ["#[near_bindgen]", "#[near_sdk::near]", "#[near(contract_state)]"] {
            let source = format!("{attr} impl C {{ pub fn done(&mut self, #[callback_unwrap] r: u64) {{}} }}");
            assert_eq!(items(&check(&[("src/lib.rs", &source)])), ["C::done"], "{attr}");
        }
    }

    #[test]
    fn reports_each_callback_once_per_definition() {
        let source = "#[near] impl C {
            pub fn a(&mut self, #[callback_result] r: u64) {}
            pub fn b(&mut self, #[callback_result] r: u64) {}
            pub fn go(&self) { Self::ext(me()).a(); Self::ext(me()).a(); }
        }";
        assert_eq!(items(&check(&[("src/lib.rs", source)])), ["C::a", "C::b"]);
    }

    /// A bare `Self::ext(..).step()` may be scheduled behind a promise by the caller of the helper that makes it.
    #[test]
    fn a_self_call_written_bare_or_in_a_helper_is_a_callback() {
        for go in [
            "pub fn go(&self) { Self::ext(env::current_account_id()).step(); }",
            "pub fn go(&self, p: Promise) -> Promise { p.then(self.settle()) } fn settle(&self) -> Promise { Self::ext(env::current_account_id()).step() }",
        ] {
            let source = format!("#[near] impl C {{ {go} pub fn step(&mut self) {{}} }}");
            assert_eq!(items(&check(&[("src/lib.rs", &source)])), ["C::step"], "{go}");
        }
    }

    /// A common shape in deployed code: the callback is chosen in an `if`, bound to a local, then continued with.
    #[test]
    fn a_callback_chosen_into_a_local_and_continued_with_is_scheduled() {
        let source = "#[near] impl C {
            pub fn go(&self, near: bool) -> Promise {
                let callback = if near { Self::ext(env::current_account_id()).resolve_near() } else { Self::ext(env::current_account_id()).resolve_ft() };
                transfer.then(callback)
            }
            pub fn resolve_near(&mut self) {}
            pub fn resolve_ft(&mut self) {}
            pub fn other(&mut self) {}
        }";
        assert_eq!(items(&check(&[("src/lib.rs", source)])), ["C::resolve_near", "C::resolve_ft"]);
    }

    #[test]
    fn both_the_receiver_and_the_argument_of_then_are_self_calls() {
        let source = "#[near] impl C {
            pub fn go(&self) -> Promise { Self::ext(env::current_account_id()).first().then(Self::ext(env::current_account_id()).second()) }
            pub fn first(&mut self) {}
            pub fn second(&mut self) {}
        }";
        assert_eq!(items(&check(&[("src/lib.rs", source)])), ["C::first", "C::second"]);
    }

    /// Only `#[private]` counts: a check written by hand is reported, whatever it is. (Re-audit HIGH snippets: a payout
    /// through a trait call, through another type's method, a guard that is no guard, a payout before the guard.)
    #[test]
    fn a_callback_without_private_is_reported_however_it_is_guarded_by_hand() {
        for (name, body) in [
            ("trait_call_payout", "Refund::refund(self, to);"),
            ("method_of_another_type_pays", "self.ledger.pay(to);"),
            ("guard_that_can_pass_for_anyone", "require!(self.n < 10 || env::predecessor_account_id() == env::current_account_id());"),
            ("payout_before_the_guard", "Promise::new(to).transfer(amount); if self.n > 0 { return; } assert_self();"),
            ("assert_self", "assert_self();"),
            ("caller_is_the_current_account", "require!(env::predecessor_account_id() == env::current_account_id());"),
        ] {
            let source = format!(
                "#[near] impl C {{ pub fn go(&self) -> Promise {{ Promise::new(a).then(Self::ext(env::current_account_id()).on_done(to, amount)) }}
                    pub fn on_done(&mut self, to: AccountId, amount: NearToken) {{ {body} }} }}"
            );
            assert_eq!(items(&check(&[("src/lib.rs", &source)])), ["C::on_done"], "{name}");
        }
    }

    /// The scheduling is found when the helper that makes the call is not the method that schedules it, but a helper
    /// that only returns the builder is not followed: a documented limit, not a guarantee.
    #[test]
    fn a_helper_that_only_returns_the_builder_is_not_followed() {
        let source = "#[near] impl C { fn me() -> Contract { Self::ext(env::current_account_id()) } pub fn go(&self) -> Promise { p.then(Self::me().step()) } pub fn step(&mut self) {} }";
        assert!(check(&[("src/lib.rs", source)]).is_empty());
    }
}
