//! PF018: a callback that panics when the call it follows failed, after a method that already debited a balance.
//!
//! A method that pays out debits the user's balance first and sends the value in a promise; the callback is the
//! only place that can put the balance back when that promise failed. The callback runs whether the call
//! succeeded or failed, but a callback argument marked `#[callback_unwrap]` (or `#[callback]`, `#[callback_vec]`)
//! makes the macro panic when the result is a failure, so the callback's own receipt fails, its refund never
//! runs, and the debit made by the first method stays: the funds are locked. The same happens when the body
//! unwraps the result by hand. Docs:
//! https://docs.near.org/smart-contracts/security/cross-contract-calls/callback-failures
//!
//! A callback is reported when all four hold:
//! 1. It is exported by the `#[near]` / `#[near_bindgen]` macro (`pub` in an inherent impl, any method of a trait
//!    impl) and the crate schedules it as the continuation of a promise on another contract,
//!    `Promise::new(..)` / `Other::ext(..)` `.then(Self::ext(env::current_account_id()).with_static_gas(g).callback(..))`,
//!    inside an exported method (not a `burn*` method, not a `*_on_transfer` hook) that debits.
//! 2. That method debits: `place -= ..`, `place = <expression with a subtraction>`, `.insert(..)` / `.set(..)`
//!    with a subtraction in its arguments, or `.remove(..)`, where `place` is rooted at `self` or at a name bound
//!    to a mutable handle into it (`let b = self.balances.entry(id).or_default();`), directly or in a function
//!    it calls on `self`, found by name and followed through helpers.
//! 3. The callback panics when the call failed: it has a callback argument marked `#[callback_unwrap]`,
//!    `#[callback]` or `#[callback_vec]`, or its body reads the result only by unwrapping it:
//!    `env::promise_result_checked(..).unwrap()` / `.expect(..)` (also `promise_result_as_success`), or
//!    `.unwrap()` / `.expect(..)` on a `#[callback_result]` argument that is mentioned nowhere else, so no
//!    branch handles the failure.
//! 4. It writes contract state, directly or through helpers: it looks like it restores the debit, but the
//!    failure path never reaches that code. A callback that writes nothing is PF015's case, not this one.
//!
//! Silent by design: a callback that reads the result with `#[callback_result]` and handles the error, one that
//! tests `is_promise_success()` or `.is_err()` first, and an initiator that debits nothing (a callback that only
//! credits what a successful call returned).
//!
//! Knowingly missed or approximated: a debit made in a method the initiator does not call on `self`; a promise
//! held in a variable before `.then(..)`; a callback that panics through `require!(is_promise_success())` or a
//! `match` on `PromiseResult`; a refund path elsewhere (a `claim_failed` method the user can call) that makes the
//! lock recoverable; a callback defined in another crate. Methods are matched by name only, since the scanner
//! resolves no types.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{Span, TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{
    Attribute, BinOp, Block, Expr, ExprAssign, ExprBinary, ExprCall, ExprMethodCall, FnArg, ImplItem, ImplItemFn,
    ItemImpl, Local, Type, Visibility,
};

use super::pf017_ft_receiver_return::{Index, aliases, bound_name, rooted_at_self};
use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf018CallbackUnwrapLock;

pub static RULE: Pf018CallbackUnwrapLock = Pf018CallbackUnwrapLock;

/// Callback arguments whose macro panics when the promise failed.
const PANICKING_ARGS: [&str; 3] = ["callback", "callback_unwrap", "callback_vec"];

/// Calls that read how the previous promise ended.
const RESULT_READS: [&str; 4] = ["promise_result_checked", "promise_result", "is_promise_success", "promise_result_as_success"];

/// Reads whose value is an `Option` or `Result` that `unwrap` / `expect` turn into a panic on failure.
const UNWRAPPABLE_READS: [&str; 2] = ["promise_result_checked", "promise_result_as_success"];

/// Collection methods that take a value out of `self`.
const REMOVALS: [&str; 3] = ["remove", "swap_remove", "remove_entry"];

/// How far helper calls are followed when looking for a debit.
const MAX_DEPTH: usize = 4;

impl Rule for Pf018CallbackUnwrapLock {
    fn id(&self) -> &'static str {
        "PF018"
    }

    fn title(&self) -> &'static str {
        "Callback panics on a failed call, so the debit is never restored"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn help(&self) -> &'static str {
        "take the result with #[callback_result] as a Result, credit the balance back on Err, and never unwrap it"
    }

    fn check(&self, krate: &Crate) -> Vec<Finding> {
        let index = Index::build(krate);
        let scans: Vec<FileScan> = krate
            .files
            .iter()
            .map(|file| {
                let mut scan = FileScan::default();
                scan.visit_file(&file.ast);
                scan
            })
            .collect();

        // Callback name -> the exported method that debits and then schedules it.
        let mut initiators: BTreeMap<String, String> = BTreeMap::new();
        for method in scans.iter().flat_map(|scan| &scan.exported) {
            let name = method.method.sig.ident.to_string();
            if name.starts_with("burn") || name.ends_with("_on_transfer") || !debits(&method.method.block, &index, 0) {
                continue;
            }
            for callback in scheduled_callbacks(&method.method.block) {
                initiators.entry(callback).or_insert_with(|| format!("{}::{name}", method.owner));
            }
        }

        let mut findings = Vec::new();
        for (file, scan) in krate.files.iter().zip(&scans) {
            for callback in &scan.exported {
                let name = callback.method.sig.ident.to_string();
                let Some(initiator) = initiators.get(&name) else { continue };
                let Some(how) = panics_on_failure(callback.method) else { continue };
                if !index.writes_state(&callback.method.block) {
                    continue;
                }
                let item = format!("{}::{name}", callback.owner);
                let message = format!(
                    "`{item}` is scheduled by `{initiator}`, which debits a balance before the call it follows, but \
                     {how}, so when that call fails the callback panics before it can credit the debit back and the \
                     funds stay locked"
                );
                findings.push(self.finding(file, callback.span(), item, message));
            }
        }
        findings
    }
}

/// A method the `#[near]` macro exports, with the type that implements it.
struct Exported<'a> {
    owner: String,
    method: &'a ImplItemFn,
}

impl Exported<'_> {
    fn span(&self) -> Span {
        self.method.sig.ident.span()
    }
}

#[derive(Default)]
struct FileScan<'a> {
    exported: Vec<Exported<'a>>,
}

impl<'ast> Visit<'ast> for FileScan<'ast> {
    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        if item.attrs.iter().any(is_near_attr) {
            let owner = type_name(&item.self_ty);
            let is_trait_impl = item.trait_.is_some();
            for member in &item.items {
                if let ImplItem::Fn(method) = member
                    && (is_trait_impl || matches!(method.vis, Visibility::Public(_)))
                {
                    self.exported.push(Exported { owner: owner.clone(), method });
                }
            }
        }
        visit::visit_item_impl(self, item);
    }
}

/// `#[near]`, `#[near(..)]` or `#[near_bindgen]`, possibly path-qualified (`#[near_sdk::near]`).
fn is_near_attr(attr: &Attribute) -> bool {
    attr.path().segments.last().is_some_and(|segment| segment.ident == "near" || segment.ident == "near_bindgen")
}

fn type_name(ty: &Type) -> String {
    match ty {
        Type::Path(path) => path.path.segments.last().map_or_else(String::new, |segment| segment.ident.to_string()),
        _ => "<unnamed type>".to_owned(),
    }
}

/// Whether the body debits a balance of `self`, directly or in a method it calls on `self`.
fn debits(body: &Block, index: &Index, depth: usize) -> bool {
    let mut debits = Debits { index, aliases: aliases(body), depth, found: false };
    debits.visit_block(body);
    debits.found
}

struct Debits<'i, 'a> {
    index: &'i Index<'a>,
    aliases: BTreeSet<String>,
    depth: usize,
    found: bool,
}

impl<'ast> Visit<'ast> for Debits<'_, '_> {
    fn visit_expr_assign(&mut self, assign: &'ast ExprAssign) {
        self.found |= rooted_at_self(&assign.left, &self.aliases) && subtracts(&assign.right);
        visit::visit_expr_assign(self, assign);
    }

    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        self.found |= matches!(binary.op, BinOp::SubAssign(_)) && rooted_at_self(&binary.left, &self.aliases);
        visit::visit_expr_binary(self, binary);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let method = call.method.to_string();
        if rooted_at_self(&call.receiver, &self.aliases) {
            let stores = matches!(method.as_str(), "insert" | "set") && call.args.iter().any(subtracts);
            self.found |= stores || REMOVALS.contains(&method.as_str());
        }
        if matches!(&*call.receiver, Expr::Path(path) if path.path.is_ident("self"))
            && self.depth < MAX_DEPTH
            && self.index.bodies(&method).iter().any(|body| debits(body, self.index, self.depth + 1))
        {
            self.found = true;
        }
        visit::visit_expr_method_call(self, call);
    }
}

/// Whether the expression subtracts: `a - b`, `a.checked_sub(b)`, `a.saturating_sub(b)`.
fn subtracts(expr: &Expr) -> bool {
    struct Subtracts(bool);
    impl<'ast> Visit<'ast> for Subtracts {
        fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
            self.0 |= matches!(binary.op, BinOp::Sub(_));
            visit::visit_expr_binary(self, binary);
        }

        fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
            self.0 |= matches!(call.method.to_string().as_str(), "checked_sub" | "saturating_sub");
            visit::visit_expr_method_call(self, call);
        }
    }
    let mut found = Subtracts(false);
    found.visit_expr(expr);
    found.0
}

/// The names this body schedules on the contract itself as the continuation of a promise on another contract.
fn scheduled_callbacks(body: &Block) -> BTreeSet<String> {
    #[derive(Default)]
    struct Schedules(BTreeSet<String>);
    impl<'ast> Visit<'ast> for Schedules {
        fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
            if call.method == "then"
                && let Some(root) = chain_root(&call.receiver)
                && (ends_with(root, &["Promise", "new"]) || (ends_with(root, &["ext"]) && !is_self_ext(root)))
                && let Some(callback) = call.args.first().and_then(callback_name)
            {
                self.0.insert(callback);
            }
            visit::visit_expr_method_call(self, call);
        }
    }
    let mut found = Schedules::default();
    found.visit_block(body);
    found.0
}

/// The call at the start of a method chain: `Promise::new(to)` in `Promise::new(to).transfer(x).then(cb)`.
fn chain_root(expr: &Expr) -> Option<&ExprCall> {
    match expr {
        Expr::MethodCall(call) => chain_root(&call.receiver),
        Expr::Call(call) => Some(call),
        Expr::Paren(inner) => chain_root(&inner.expr),
        _ => None,
    }
}

/// Whether the called path ends with `tail`: `Self::ext` ends with `["Self", "ext"]` and with `["ext"]`.
fn ends_with(call: &ExprCall, tail: &[&str]) -> bool {
    let Expr::Path(func) = &*call.func else { return false };
    let segments = &func.path.segments;
    segments.len() >= tail.len() && segments.iter().rev().zip(tail.iter().rev()).all(|(segment, name)| segment.ident == name)
}

/// `Self::ext(..)`, or `Type::ext(env::current_account_id())`, which is how a contract schedules its own methods;
/// `ext(..)` on another contract's type schedules that contract's methods.
fn is_self_ext(root: &ExprCall) -> bool {
    ends_with(root, &["Self", "ext"])
        || (ends_with(root, &["ext"])
            && matches!(root.args.first(), Some(Expr::Call(arg)) if ends_with(arg, &["current_account_id"])))
}

/// The method a `.then(..)` argument schedules on the contract itself: `Self::ext(..).with_static_gas(g).done(..)`
/// is `done`; `None` for a continuation on another contract.
fn callback_name(arg: &Expr) -> Option<String> {
    let Expr::MethodCall(call) = arg else { return None };
    let name = call.method.to_string();
    if name.starts_with("with_") { callback_name(&call.receiver) } else { is_self_ext(chain_root(&call.receiver)?).then_some(name) }
}

/// How the callback panics when the promise it follows failed, as a clause of the finding message; `None` when
/// it does not.
fn panics_on_failure(method: &ImplItemFn) -> Option<String> {
    let mut result_args = BTreeSet::new();
    for arg in &method.sig.inputs {
        let FnArg::Typed(arg) = arg else { continue };
        if let Some(attr) = PANICKING_ARGS.iter().find(|name| arg.attrs.iter().any(|attr| attr.path().is_ident(name))) {
            return Some(format!("it takes a `#[{attr}]` argument, which panics on a failed result"));
        }
        if arg.attrs.iter().any(|attr| attr.path().is_ident("callback_result"))
            && let Some(name) = bound_name(&arg.pat)
        {
            result_args.insert(name);
        }
    }
    let mut uses = ResultUse { args: result_args, unwrapped: 0, handled: 0 };
    uses.visit_block(&method.block);
    (uses.unwrapped > 0 && uses.handled == 0).then(|| "it only ever unwraps the result, which panics on a failure".to_owned())
}

/// Counts the places a callback unwraps the promise result and the places it looks at it any other way.
struct ResultUse {
    /// The names of `#[callback_result]` arguments, until a `let` rebinds one.
    args: BTreeSet<String>,
    unwrapped: usize,
    handled: usize,
}

impl ResultUse {
    /// An argument, or a read whose value is an `Option` or `Result`, as the receiver of `unwrap` / `expect`.
    fn is_unwrappable(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Path(path) => path.path.get_ident().is_some_and(|ident| self.args.contains(&ident.to_string())),
            Expr::Call(call) => matches!(&*call.func, Expr::Path(func)
                if func.path.segments.last().is_some_and(|last| UNWRAPPABLE_READS.iter().any(|name| last.ident == name))),
            Expr::Paren(inner) => self.is_unwrappable(&inner.expr),
            _ => false,
        }
    }

    fn tokens(&mut self, tokens: TokenStream) {
        for tree in tokens {
            match tree {
                TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    self.handled += usize::from(self.args.contains(&name) || RESULT_READS.contains(&name.as_str()));
                }
                TokenTree::Group(group) => self.tokens(group.stream()),
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for ResultUse {
    fn visit_local(&mut self, local: &'ast Local) {
        if let Some(init) = &local.init {
            self.visit_expr(&init.expr);
        }
        if let Some(name) = bound_name(&local.pat) {
            self.args.remove(&name);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if (call.method == "unwrap" || call.method == "expect") && self.is_unwrappable(&call.receiver) {
            self.unwrapped += 1;
            call.args.iter().for_each(|arg| self.visit_expr(arg));
        } else {
            visit::visit_expr_method_call(self, call);
        }
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(func) = &*call.func
            && func.path.segments.last().is_some_and(|last| RESULT_READS.iter().any(|name| last.ident == name))
        {
            self.handled += 1;
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.handled += usize::from(path.path.get_ident().is_some_and(|ident| self.args.contains(&ident.to_string())));
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
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

    fn one(source: &str) -> Vec<Finding> {
        check(&[("src/lib.rs", source)])
    }

    /// A vault whose `withdraw` runs `debit`, then sends tokens and schedules `on_done`, defined by `callback`.
    fn vault(debit: &str, callback: &str) -> String {
        format!(
            "#[near] impl Vault {{
                #[payable] pub fn withdraw(&mut self, receiver_id: AccountId, amount: U128) -> Promise {{
                    let account = env::predecessor_account_id();
                    {debit}
                    ext_ft::ext(self.token.clone()).ft_transfer_call(receiver_id, amount, None, String::new())
                        .then(Self::ext(env::current_account_id()).with_static_gas(GAS).on_done(account, amount))
                }}
                {callback}
            }}"
        )
    }

    const DEBIT: &str = "*self.balances.get_mut(&account).unwrap() -= amount.0;";
    const UNWRAPPING: &str = "#[private] pub fn on_done(&mut self, account: AccountId, amount: U128, #[callback_unwrap] used: U128) -> U128 {
        *self.balances.entry(account).or_insert(0) += amount.0 - used.0;
        used
    }";
    const HANDLING: &str = "#[private] pub fn on_done(&mut self, account: AccountId, amount: U128, #[callback_result] used: Result<U128, PromiseError>) -> U128 {
        let used = used.map_or(0, |used| used.0);
        *self.balances.entry(account).or_insert(0) += amount.0 - used;
        U128(used)
    }";

    #[test]
    fn flags_a_callback_that_panics_on_failure_after_a_debit_and_locates_it() {
        let findings = one(&vault(DEBIT, UNWRAPPING));
        assert_eq!(items(&findings), ["Vault::on_done"]);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF018", Severity::High));
        assert_eq!((finding.file.as_str(), finding.line), ("src/lib.rs", 8));
        assert!(finding.message.contains("`Vault::on_done` is scheduled by `Vault::withdraw`"));
        assert!(finding.message.contains("`#[callback_unwrap]`"));
    }

    #[test]
    fn the_same_vault_with_a_handled_result_is_silent() {
        assert!(one(&vault(DEBIT, HANDLING)).is_empty());
    }

    #[test]
    fn flags_each_argument_attribute_that_panics_on_failure() {
        for attr in ["callback_unwrap", "callback", "callback_vec"] {
            let callback = UNWRAPPING.replace("callback_unwrap", attr);
            assert_eq!(items(&one(&vault(DEBIT, &callback))), ["Vault::on_done"], "{attr}");
        }
    }

    #[test]
    fn flags_a_body_that_only_unwraps_the_result() {
        for read in [
            "env::promise_result_checked(0, 64).expect(\"transfer failed\");",
            "let used = env::promise_result_checked(0, 64).unwrap();",
            "promise_result_as_success().expect(\"failed\");",
        ] {
            let callback = format!(
                "#[private] pub fn on_done(&mut self, account: AccountId, amount: U128) {{ {read} self.balances.insert(account, amount.0); }}"
            );
            assert_eq!(items(&one(&vault(DEBIT, &callback))), ["Vault::on_done"], "{read}");
        }
        let unwrapped_argument = "#[private] pub fn on_done(&mut self, account: AccountId, amount: U128, #[callback_result] used: Result<U128, PromiseError>) { let used = used.unwrap(); self.balances.insert(account, amount.0 - used.0); }";
        assert_eq!(items(&one(&vault(DEBIT, unwrapped_argument))), ["Vault::on_done"]);
    }

    #[test]
    fn an_unwrap_that_a_check_of_the_result_guards_is_not_reported() {
        for body in [
            "if used.is_err() { self.balances.insert(account, amount.0); return; } let used = used.unwrap();",
            "if let Ok(used) = used { self.total = used.0; } else { self.balances.insert(account, amount.0); } let _ = used.unwrap();",
            "if !is_promise_success() { self.balances.insert(account, amount.0); return; } let used = env::promise_result_checked(0, 64).unwrap();",
            "match env::promise_result(0) { PromiseResult::Failed => self.balances.insert(account, amount.0), _ => None }; let used = env::promise_result_checked(0, 64).unwrap();",
        ] {
            let callback = format!(
                "#[private] pub fn on_done(&mut self, account: AccountId, amount: U128, #[callback_result] used: Result<U128, PromiseError>) {{ {body} }}"
            );
            assert!(one(&vault(DEBIT, &callback)).is_empty(), "{body}");
        }
    }

    #[test]
    fn recognises_each_kind_of_debit() {
        for debit in [
            "*self.balances.get_mut(&account).unwrap() -= amount.0;",
            "let balance = self.balances.entry(account.clone()).or_default(); *balance -= amount.0;",
            "self.total = self.total - amount.0;",
            "self.balances.insert(account.clone(), self.balances.get(&account).copied().unwrap_or(0) - amount.0);",
            "self.balances.insert(account.clone(), held.saturating_sub(amount.0));",
            "self.stakes.remove(&account);",
            "self.take(&account, amount.0);",
        ] {
            let source = format!(
                "{} impl Vault {{ fn take(&mut self, id: &AccountId, n: u128) {{ *self.balances.get_mut(id).unwrap() -= n; }} }}",
                vault(debit, UNWRAPPING)
            );
            assert_eq!(items(&one(&source)), ["Vault::on_done"], "{debit}");
        }
    }

    #[test]
    fn an_initiator_that_debits_nothing_is_not_reported() {
        assert!(one(&vault("self.calls += 1;", UNWRAPPING)).is_empty());
        assert!(one(&vault("", UNWRAPPING)).is_empty());
        let credits_on_success = vault("*self.balances.entry(account.clone()).or_insert(0) += amount.0;", UNWRAPPING);
        assert!(one(&credits_on_success).is_empty());
    }

    #[test]
    fn a_callback_that_writes_nothing_is_pf015s_case() {
        let callback = "#[private] pub fn on_done(&mut self, account: AccountId, amount: U128, #[callback_unwrap] used: U128) -> U128 { used }";
        assert!(one(&vault(DEBIT, callback)).is_empty());
    }

    #[test]
    fn follows_a_debit_through_two_helpers() {
        let source = format!(
            "{} impl Vault {{ fn take(&mut self, id: &AccountId, n: u128) {{ self.book(id, n); }} fn book(&mut self, id: &AccountId, n: u128) {{ *self.balances.get_mut(id).unwrap() -= n; }} }}",
            vault("self.take(&account, amount.0);", UNWRAPPING)
        );
        assert_eq!(items(&one(&source)), ["Vault::on_done"]);
    }

    #[test]
    fn recognises_native_transfers_and_the_ext_of_the_current_account() {
        let native = "#[near] impl Vault {
            pub fn withdraw(&mut self, to: AccountId, amount: U128) -> Promise {
                self.balances.remove(&env::predecessor_account_id());
                Promise::new(to).transfer(NearToken::from_yoctonear(amount.0)).then(Self::ext(env::current_account_id()).on_done(amount))
            }
            #[private] pub fn on_done(&mut self, amount: U128, #[callback_unwrap] ok: bool) { self.total += amount.0; }
        }";
        assert_eq!(items(&one(native)), ["Vault::on_done"]);
        let explicit = native.replace("Self::ext(env::current_account_id())", "Vault::ext(env::current_account_id())");
        assert_eq!(items(&one(&explicit)), ["Vault::on_done"]);
    }

    #[test]
    fn a_continuation_that_is_not_on_this_contract_or_not_after_another_one_is_ignored() {
        let elsewhere = vault(DEBIT, UNWRAPPING).replace("Self::ext(env::current_account_id())", "other::ext(self.dex.clone())");
        assert!(one(&elsewhere).is_empty());
        let own_step = vault(DEBIT, UNWRAPPING).replace("ext_ft::ext(self.token.clone())", "Self::ext(env::current_account_id())");
        assert!(one(&own_step).is_empty());
    }

    #[test]
    fn burning_methods_and_receiver_hooks_are_exempt_initiators() {
        let burning = vault(DEBIT, UNWRAPPING).replace("pub fn withdraw", "pub fn burn_and_bridge");
        assert!(one(&burning).is_empty());
        let hook = vault(DEBIT, UNWRAPPING).replace("pub fn withdraw", "pub fn ft_on_transfer");
        assert!(one(&hook).is_empty());
    }

    #[test]
    fn methods_the_near_macro_does_not_export_are_ignored() {
        let hidden = vault(DEBIT, UNWRAPPING).replace("pub fn on_done", "fn on_done");
        assert!(one(&hidden).is_empty());
        let plain = vault(DEBIT, UNWRAPPING).replace("#[near] impl", "impl");
        assert!(one(&plain).is_empty());
    }

    #[test]
    fn accepts_near_bindgen_and_finds_a_callback_defined_in_another_file() {
        let initiator = vault(DEBIT, "").replace("#[near] impl", "#[near_bindgen] impl");
        let callback = format!("#[near_bindgen] impl Vault {{ {UNWRAPPING} }}");
        let findings = check(&[("src/lib.rs", &initiator), ("src/callbacks.rs", &callback)]);
        assert_eq!(items(&findings), ["Vault::on_done"]);
        assert_eq!(findings[0].file, "src/callbacks.rs");
    }

    #[test]
    fn reports_a_callback_once_however_many_methods_schedule_it() {
        let second = "#[near] impl Vault { pub fn withdraw_all(&mut self, r: AccountId) -> Promise { self.balances.remove(&env::predecessor_account_id()); ext_ft::ext(self.token.clone()).ft_transfer_call(r, a, None, s).then(Self::ext(me()).on_done(x, y)) } }";
        let findings = check(&[("src/lib.rs", &vault(DEBIT, UNWRAPPING)), ("src/more.rs", second)]);
        assert_eq!(items(&findings), ["Vault::on_done"]);
    }
}
