//! PF003: a callback that never looks at the result of the promise it follows.
//!
//! A callback runs whether the cross-contract call it follows succeeded or failed. If it never reads the result,
//! it treats a failed call (no balance, a panicking token, an unregistered account) as a success and goes on to
//! grant the item, credit the balance or mark the order paid. Docs:
//! https://docs.near.org/smart-contracts/security/cross-contract-calls/callbacks
//!
//! A method is a callback when the `#[near]` macro exports it (`pub` method of an inherent impl, or any method of
//! a trait impl) and it takes a callback argument (`#[callback]`, `#[callback_unwrap]`, `#[callback_result]`,
//! `#[callback_vec]`), or the crate schedules it as the continuation of a promise:
//! `.then(Self::ext(env::current_account_id()).with_static_gas(g).method(..))`.
//!
//! A callback looks at the result when it takes `#[callback]`, `#[callback_unwrap]` or `#[callback_vec]` (they
//! panic on a failed call), or `#[callback_result]` bound to a name that does not start with `_`, or when its body
//! calls `env::promise_result_checked`, `env::promise_result`, `is_promise_success` or `promise_result_as_success`,
//! or a wrapper whose name starts with `promise_result` or ends with `promise_success`
//! (`promise_result_checked_json`, `is_withdraw_promise_success`).
//! A call counts when it is in the callback or in any same-crate function it reaches, found by name
//! (a free function, an inherent method or a trait method, in any file of the crate), including calls written
//! inside macro arguments such as `require!(is_promise_success(), ..)`.
//!
//! `env::promise_results_count` alone does not count: it says how many promises the callback follows, not whether
//! they succeeded.
//!
//! Knowingly missed: a callback scheduled with a promise held in a variable (`.then(promise)`) or by a trait
//! default method, since neither names the method in the same call chain; a result read that is then ignored
//! (`let _ = is_promise_success();`); a callback whose same-named helper in the crate is unrelated to the one it
//! calls (the name match is lenient, so it errs towards silence).

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{Span, TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{
    Attribute, Block, Expr, ExprCall, ExprMethodCall, FnArg, Ident, ImplItem, ImplItemFn, ItemFn, ItemImpl, Pat,
    TraitItemFn, Type, Visibility,
};

use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf003PromiseResult;

pub static RULE: Pf003PromiseResult = Pf003PromiseResult;

impl Rule for Pf003PromiseResult {
    fn id(&self) -> &'static str {
        "PF003"
    }

    fn title(&self) -> &'static str {
        "Callback ignores the promise result"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn help(&self) -> &'static str {
        "read the result with #[callback_result] or env::promise_result_checked and stop when the call failed"
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
        let scheduled: BTreeSet<&str> =
            scans.iter().flat_map(|scan| scan.scheduled.iter().map(String::as_str)).collect();
        let by_name = functions_by_name(&scans);

        let mut findings = Vec::new();
        for (file, scan) in krate.files.iter().zip(&scans) {
            for func in &scan.functions {
                let Some(export) = &func.export else { continue };
                let how = if export.has_callback_arg {
                    "takes a callback argument"
                } else if scheduled.contains(func.name.as_str()) {
                    "is scheduled with `.then(Self::ext(..)..)`"
                } else {
                    continue;
                };
                if export.arg_reads_result || reaches_a_result_read(func, &by_name) {
                    continue;
                }
                findings.push(self.finding(
                    file,
                    export.span,
                    format!("{}::{}", export.owner, func.name),
                    format!(
                        "`{}::{}` {how} but never reads the promise result, so a failed cross-contract call is treated as a success",
                        export.owner, func.name
                    ),
                ));
            }
        }
        findings
    }
}

/// Whether a call named `name` reads a promise result: the functions of near-sdk (`env::promise_result`,
/// `promise_result_checked`, `is_promise_success`, `promise_result_as_success`) and the wrappers projects write
/// around them (`promise_result_checked_json`, `is_withdraw_promise_success`). Counting the results reads nothing.
fn reads_promise_result(name: &str) -> bool {
    name != "promise_results_count" && (name == "promise_result" || name.starts_with("promise_result_") || name.ends_with("promise_success"))
}

/// Arguments the macro fills from the promise result; all but `callback_result` panic when the call failed.
const PANICKING_CALLBACK_ARGS: [&str; 3] = ["callback", "callback_unwrap", "callback_vec"];

/// What the scan keeps of one function: the names its body calls, and whether it reads a promise result itself.
#[derive(Default)]
struct Func {
    name: String,
    calls: BTreeSet<String>,
    reads_result: bool,
    /// Set when the `#[near]` macro exports the function.
    export: Option<Export>,
}

struct Export {
    owner: String,
    span: Span,
    has_callback_arg: bool,
    /// True when a callback argument already looks at the result (see the module docs).
    arg_reads_result: bool,
}

#[derive(Default)]
struct FileScan {
    /// Every function with a body in the file, exported or not.
    functions: Vec<Func>,
    /// Names scheduled as the continuation of a promise on the contract itself.
    scheduled: BTreeSet<String>,
}

fn functions_by_name(scans: &[FileScan]) -> BTreeMap<&str, Vec<&Func>> {
    let mut by_name: BTreeMap<&str, Vec<&Func>> = BTreeMap::new();
    for func in scans.iter().flat_map(|scan| &scan.functions) {
        by_name.entry(func.name.as_str()).or_default().push(func);
    }
    by_name
}

/// Whether `start` or a same-crate function it calls, transitively, reads a promise result.
fn reaches_a_result_read(start: &Func, by_name: &BTreeMap<&str, Vec<&Func>>) -> bool {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut stack = vec![start];
    while let Some(func) = stack.pop() {
        if func.reads_result {
            return true;
        }
        for call in &func.calls {
            if let Some((name, defined)) = by_name.get_key_value(call.as_str())
                && seen.insert(name)
            {
                stack.extend(defined);
            }
        }
    }
    false
}

fn has_helper_attr(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident(name))
}

/// `#[near]`, `#[near(..)]` or `#[near_bindgen]`, possibly path-qualified (`#[near_sdk::near]`).
fn is_near_attr(attr: &Attribute) -> bool {
    attr.path().segments.last().is_some_and(|segment| segment.ident == "near" || segment.ident == "near_bindgen")
}

impl<'ast> Visit<'ast> for FileScan {
    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        let near = item.attrs.iter().any(is_near_attr);
        let owner = type_name(&item.self_ty);
        for member in &item.items {
            if let ImplItem::Fn(method) = member {
                let mut func = func_of(&method.sig.ident, &method.block);
                if near && (item.trait_.is_some() || matches!(method.vis, Visibility::Public(_))) {
                    func.export = Some(export_of(&owner, method));
                }
                self.functions.push(func);
            }
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.functions.push(func_of(&item.sig.ident, &item.block));
        visit::visit_item_fn(self, item);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast TraitItemFn) {
        if let Some(block) = &item.default {
            self.functions.push(func_of(&item.sig.ident, block));
        }
        visit::visit_trait_item_fn(self, item);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if call.method == "then"
            && let Some(Expr::MethodCall(continuation)) = call.args.first()
            && is_rooted_at_self_ext(continuation)
        {
            self.scheduled.insert(continuation.method.to_string());
        }
        visit::visit_expr_method_call(self, call);
    }
}

fn type_name(ty: &Type) -> String {
    match ty {
        Type::Path(path) => path.path.segments.last().map_or_else(String::new, |segment| segment.ident.to_string()),
        _ => "<unnamed type>".to_owned(),
    }
}

fn func_of(name: &Ident, block: &Block) -> Func {
    let mut body = BodyScan::default();
    body.visit_block(block);
    Func { name: name.to_string(), calls: body.calls, reads_result: body.reads_result, export: None }
}

fn export_of(owner: &str, method: &ImplItemFn) -> Export {
    let mut has_callback_arg = false;
    let mut arg_reads_result = false;
    for arg in &method.sig.inputs {
        let FnArg::Typed(arg) = arg else { continue };
        if PANICKING_CALLBACK_ARGS.iter().any(|name| has_helper_attr(&arg.attrs, name)) {
            has_callback_arg = true;
            arg_reads_result = true;
        } else if has_helper_attr(&arg.attrs, "callback_result") {
            has_callback_arg = true;
            arg_reads_result |= !is_ignored_binding(&arg.pat);
        }
    }
    Export { owner: owner.to_owned(), span: method.sig.ident.span(), has_callback_arg, arg_reads_result }
}

/// `_` or a name starting with `_`: the argument is bound only to be dropped.
fn is_ignored_binding(pat: &Pat) -> bool {
    match pat {
        Pat::Wild(_) => true,
        Pat::Ident(ident) => ident.ident.to_string().starts_with('_'),
        _ => false,
    }
}

/// The calls in one function body, including calls written inside macro arguments.
#[derive(Default)]
struct BodyScan {
    calls: BTreeSet<String>,
    reads_result: bool,
}

impl BodyScan {
    fn call(&mut self, name: String) {
        self.reads_result |= reads_promise_result(&name);
        self.calls.insert(name);
    }

    /// `name(..)` inside a macro's tokens: an identifier directly followed by a parenthesised group.
    fn calls_in_tokens(&mut self, tokens: TokenStream) {
        let mut previous: Option<String> = None;
        for tree in tokens {
            match tree {
                TokenTree::Ident(ident) => previous = Some(ident.to_string()),
                TokenTree::Group(group) => {
                    if group.delimiter() == proc_macro2::Delimiter::Parenthesis
                        && let Some(name) = previous.take()
                    {
                        self.call(name);
                    }
                    previous = None;
                    self.calls_in_tokens(group.stream());
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => previous = None,
            }
        }
    }
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(func) = &*call.func
            && let Some(last) = func.path.segments.last()
        {
            self.call(last.ident.to_string());
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        self.call(call.method.to_string());
        visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.calls_in_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// Whether the chain `Self::ext(..).with_static_gas(g).method(..)` starts at `Self::ext(..)`, or at
/// `Type::ext(env::current_account_id())`, which is how a contract schedules its own methods; `ext(..)` on
/// another contract's type schedules that contract's methods.
fn is_rooted_at_self_ext(call: &ExprMethodCall) -> bool {
    let mut receiver = &*call.receiver;
    loop {
        match receiver {
            Expr::MethodCall(inner) => receiver = &inner.receiver,
            Expr::Call(root) => return is_self_ext(root),
            _ => return false,
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

    fn one(source: &str) -> Vec<Finding> {
        check(&[("src/lib.rs", source)])
    }

    const SHOP: &str = r#"
        #[near]
        impl Shop {
            pub fn buy(&mut self, item: u64) -> Promise {
                ledger::ext(self.ledger.clone())
                    .charge(env::predecessor_account_id(), PRICE)
                    .then(Self::ext(env::current_account_id()).with_static_gas(GAS).on_charged(item))
            }
            #[private]
            pub fn on_charged(&mut self, item: u64) {
                self.owned.insert(item);
            }
        }
    "#;

    #[test]
    fn flags_a_scheduled_callback_that_never_reads_the_result_and_locates_it() {
        let findings = one(SHOP);
        assert_eq!(items(&findings), ["Shop::on_charged"]);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF003", Severity::High));
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 10, 20));
        assert!(finding.message.contains("`Shop::on_charged`") && finding.message.contains("never reads"));
    }

    #[test]
    fn flags_a_callback_result_argument_the_body_ignores() {
        for binding in ["_paid", "_"] {
            let source = format!(
                "#[near] impl C {{ #[private] pub fn done(&mut self, #[callback_result] {binding}: Result<u64, PromiseError>) {{}} }}"
            );
            assert_eq!(items(&one(&source)), ["C::done"], "{binding}");
        }
    }

    #[test]
    fn flags_a_callback_that_only_counts_the_promise_results() {
        let source = SHOP.replace("self.owned.insert(item);", "require!(env::promise_results_count() == 1);");
        assert_eq!(items(&one(&source)), ["Shop::on_charged"]);
    }

    #[test]
    fn every_way_of_reading_the_result_is_clean() {
        let reads = [
            "require!(is_promise_success(), \"payment failed\");",
            "require!(near_sdk::is_promise_success());",
            "if env::promise_result_checked(0, 64).is_err() { env::panic_str(\"failed\"); }",
            "if let PromiseResult::Failed = env::promise_result(0) { return; }",
            "let Some(_) = near_sdk::utils::promise_result_as_success() else { return };",
            "assert!(is_promise_success());",
        ];
        for read in reads {
            let source = SHOP.replace("self.owned.insert(item);", &format!("{read} self.owned.insert(item);"));
            assert!(one(&source).is_empty(), "{read}");
        }
    }

    #[test]
    fn every_result_taking_argument_attribute_is_clean() {
        for attr in ["callback", "callback_unwrap", "callback_vec", "callback_result"] {
            let source = format!("#[near] impl C {{ #[private] pub fn done(&mut self, #[{attr}] paid: u64) {{}} }}");
            assert!(one(&source).is_empty(), "#[{attr}]");
        }
    }

    #[test]
    fn a_panicking_callback_argument_counts_even_when_named_with_an_underscore() {
        let source = "#[near] impl C { #[private] pub fn done(&mut self, #[callback_unwrap] _r: u64) {} }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn a_helper_in_the_crate_that_reads_the_result_is_followed() {
        let source = SHOP.replace("self.owned.insert(item);", "self.require_paid(); self.owned.insert(item);");
        assert_eq!(items(&one(&source)), ["Shop::on_charged"], "an undefined helper reads nothing");

        let helper = "impl Shop { fn require_paid(&self) { Self::assert_charged(); } } fn assert_charged() { require!(is_promise_success()); }";
        let findings = check(&[("src/lib.rs", &source), ("src/helpers.rs", helper)]);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn a_helper_cycle_terminates() {
        let source = SHOP.replace("self.owned.insert(item);", "ping();")
            + "fn ping() { pong(); } fn pong() { ping(); }";
        assert_eq!(items(&one(&source)), ["Shop::on_charged"]);
    }

    #[test]
    fn a_trait_default_method_helper_is_followed() {
        let source = SHOP.replace("self.owned.insert(item);", "self.require_paid();")
            + "trait Paid { fn require_paid(&self) { require!(is_promise_success()); } }";
        assert!(one(&source).is_empty());
    }

    #[test]
    fn flags_a_trait_impl_callback_and_both_near_spellings() {
        for attr in ["#[near_bindgen]", "#[near_sdk::near]", "#[near(contract_state)]", "#[near]"] {
            let source = format!(
                "{attr} impl Callbacks for C {{ fn done(&mut self) {{}} }}
                 fn go() {{ p.then(Self::ext(env::current_account_id()).done()); }}"
            );
            assert_eq!(items(&one(&source)), ["C::done"], "{attr}");
        }
    }

    #[test]
    fn follows_a_callback_scheduled_in_another_file_of_the_crate() {
        let definition = "#[near] impl C { pub fn done(&mut self) {} }";
        let scheduling = "fn go() { p.then(Self::ext(env::current_account_id()).done()); }";
        let findings = check(&[("src/lib.rs", scheduling), ("src/callbacks.rs", definition)]);
        assert_eq!(items(&findings), ["C::done"]);
        assert_eq!(findings[0].file, "src/callbacks.rs");
    }

    #[test]
    fn a_method_called_on_self_but_not_as_a_continuation_is_not_a_callback() {
        let source = "#[near] impl C {
            pub fn go(&self) -> Promise { Self::ext(env::current_account_id()).stage_two().then(other()) }
            pub fn stage_two(&mut self) {}
        }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn a_continuation_on_another_contract_is_not_a_local_callback() {
        let source = "#[near] impl C {
            pub fn go(&self) -> Promise { a::ext(token()).ft_transfer(x).then(b::ext(other()).done()) }
            pub fn done(&mut self) {}
        }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn methods_the_near_macro_does_not_export_are_ignored() {
        let source = "
            impl NotNear { pub fn done(&mut self) {} }
            #[near] impl C {
                fn hidden(&mut self) {}
                pub(crate) fn crate_only(&mut self) {}
                pub fn go(&self) { p.then(Self::ext(me()).hidden()); p.then(Self::ext(me()).crate_only()); }
            }
            fn free() { p.then(Self::ext(env::current_account_id()).done()); }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn reports_each_callback_once() {
        let source = format!("{SHOP} #[near] impl Other {{ pub fn go(&self) {{ p.then(Self::ext(me()).on_charged(1)); p.then(Self::ext(me()).on_charged(2)); }} }}");
        assert_eq!(items(&one(&source)), ["Shop::on_charged"]);
    }

    /// A common shape in deployed code: `promise_result_checked_void(0)` wraps `env::promise_result_checked`.
    #[test]
    fn a_wrapper_named_for_the_result_read_counts() {
        for call in ["promise_result_checked_void(0).is_ok()", "promise_result_checked_json(0).is_ok()", "is_withdraw_promise_success()"] {
            let source = SHOP.replace("self.owned.insert(item);", &format!("require!({call}); self.owned.insert(item);"));
            assert!(one(&source).is_empty(), "{call}");
        }
        let unrelated = SHOP.replace("self.owned.insert(item);", "require!(promise_resulting()); self.owned.insert(item);");
        assert_eq!(items(&one(&unrelated)), ["Shop::on_charged"]);
    }
}
