//! PF019: a token's `ft_resolve_transfer` refunds whatever amount the receiver reports as unused.
//!
//! In `ft_transfer_call` the token calls the receiver's `ft_on_transfer`, which returns the amount it did not
//! use, and then runs its own resolver, which moves that amount from the receiver back to the sender. The value
//! comes from the receiver's contract, so it is attacker input whenever the receiver is. A resolver that refunds
//! it without capping it at the `amount` that was sent, and at what the receiver still holds, refunds tokens
//! the sender never spent: the sender is credited and the receiver is debited only as far as its balance goes.
//! near-contract-standards takes `min(unused, amount)` and then `min(receiver_balance, unused)`. Docs:
//! https://docs.near.org/smart-contracts/security/cross-contract-calls/ft-transfer-call and
//! https://nomicon.io/Standards/Tokens/FungibleToken/Core
//!
//! A resolver is a method the `#[near]` / `#[near_bindgen]` macro exports (`pub` in an inherent impl, any method
//! of a trait impl) that is named `ft_resolve_transfer`, or that the crate schedules right after an
//! `ft_on_transfer` call: `.ft_on_transfer(..).then(Self::ext(..).with_static_gas(g).my_resolver(..))`. It is
//! reported when all three hold:
//! 1. It reads the receiver's result: a callback argument (`#[callback_unwrap]`, `#[callback_result]`,
//!    `#[callback]`, `#[callback_vec]`) or a call of `env::promise_result_checked`, `env::promise_result`,
//!    `is_promise_success` or `promise_result_as_success`.
//! 2. It writes contract state: an assignment or compound assignment to a place rooted at `self`, or a call of
//!    `insert`, `set`, `push`, ... on one, directly or in a method of the crate it calls on `self`.
//! 3. Nothing in it bounds the amount: no call of `min`, `clamp` or `checked_sub` and no comparison (`<`, `<=`,
//!    `>`, `>=`, including inside `require!` / `assert!`) in the resolver or in any same-crate function it
//!    reaches, found by name (a free function, an inherent or a trait method, in any file of the crate).
//!
//! Silent by design: a resolver that hands the work to another crate (`self.token.internal_ft_resolve_transfer(..)`
//! reads no result in this crate), one that caps the refund, and any resolver that never reads the result.
//!
//! Knowingly missed or approximated: any bound counts, even one on another quantity, so a comparison unrelated
//! to the refund silences the rule; a refund capped only by a `checked_sub` that reverts is accepted (it cannot
//! mint, but it still lets the receiver's other tokens be taken); `saturating_sub` is not a bound; resolvers of
//! NEP-171 / NEP-245 (`nft_resolve_transfer`, `mt_resolve_transfer`) and resolvers scheduled with a promise held
//! in a variable are not recognised. Methods are matched by name only, since the scanner resolves no types.

use std::collections::BTreeSet;

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{
    Attribute, BinOp, Expr, ExprBinary, ExprCall, ExprMethodCall, FnArg, ImplItem, ImplItemFn, ItemImpl, Type,
    Visibility,
};

use super::pf017_ft_receiver_return::Index;
use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf019ResolveRefund;

pub static RULE: Pf019ResolveRefund = Pf019ResolveRefund;

/// The resolver NEP-141 names; a contract may rename it, so a method scheduled after `ft_on_transfer` counts too.
const RESOLVER: &str = "ft_resolve_transfer";

/// Calls that read how the receiver's promise ended.
const RESULT_READS: [&str; 4] = ["promise_result_checked", "promise_result", "is_promise_success", "promise_result_as_success"];

/// Calls that cap one number by another (`checked_sub` reverts when the refund exceeds what is there).
const BOUNDS: [&str; 3] = ["min", "clamp", "checked_sub"];

const CALLBACK_ARGS: [&str; 4] = ["callback", "callback_unwrap", "callback_result", "callback_vec"];

impl Rule for Pf019ResolveRefund {
    fn id(&self) -> &'static str {
        "PF019"
    }

    fn title(&self) -> &'static str {
        "ft_resolve_transfer refunds an unbounded amount"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn help(&self) -> &'static str {
        "cap the refund at min(min(unused, amount), receiver balance) before moving any tokens"
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
        let index = Index::build(krate);

        let mut findings = Vec::new();
        for (file, scan) in krate.files.iter().zip(&scans) {
            for (owner, method) in &scan.exported {
                let name = method.sig.ident.to_string();
                if name != RESOLVER && !scheduled.contains(name.as_str()) {
                    continue;
                }
                let reach = Reach::of(method, &index);
                if !(reach.reads_result && !reach.bounded && index.writes_state(&method.block)) {
                    continue;
                }
                let item = format!("{owner}::{name}");
                let message = format!(
                    "`{item}` reads the unused amount the receiver reports and moves that much back to the sender with no \
                     cap (`min`, a comparison) against the amount sent or the receiver's balance, so a receiver that \
                     reports more than it was sent is refunded tokens the sender never spent"
                );
                findings.push(self.finding(file, method.sig.ident.span(), item, message));
            }
        }
        findings
    }
}

/// What one file contributes: its exported methods, and the names it schedules right after an `ft_on_transfer`.
#[derive(Default)]
struct FileScan<'a> {
    exported: Vec<(String, &'a ImplItemFn)>,
    scheduled: BTreeSet<String>,
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
                    self.exported.push((owner.clone(), method));
                }
            }
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if call.method == "then"
            && follows_a_hook_call(&call.receiver)
            && let Some(callback) = call.args.first().and_then(callback_name)
        {
            self.scheduled.insert(callback);
        }
        visit::visit_expr_method_call(self, call);
    }
}

/// Whether the promise chain contains a call of `ft_on_transfer`.
fn follows_a_hook_call(chain: &Expr) -> bool {
    match chain {
        Expr::MethodCall(call) => call.method == "ft_on_transfer" || follows_a_hook_call(&call.receiver),
        Expr::Paren(inner) => follows_a_hook_call(&inner.expr),
        _ => false,
    }
}

/// The method a `.then(..)` argument schedules on the contract itself: `Self::ext(..).with_static_gas(g).resolve(..)`
/// is `resolve`; `None` for a continuation on another contract.
fn callback_name(arg: &Expr) -> Option<String> {
    let Expr::MethodCall(call) = arg else { return None };
    let name = call.method.to_string();
    if name.starts_with("with_") { callback_name(&call.receiver) } else { is_self_ext(&call.receiver).then_some(name) }
}

/// Whether the chain starts at `Self::ext(..)`, or at `Type::ext(env::current_account_id())`, which is how a
/// contract schedules its own methods; `ext(..)` on another contract's type schedules that contract's methods.
fn is_self_ext(chain: &Expr) -> bool {
    match chain {
        Expr::MethodCall(call) => is_self_ext(&call.receiver),
        Expr::Call(root) => {
            ends_with(root, &["Self", "ext"])
                || (ends_with(root, &["ext"])
                    && matches!(root.args.first(), Some(Expr::Call(arg)) if ends_with(arg, &["current_account_id"])))
        }
        _ => false,
    }
}

/// Whether the called path ends with `tail`: `Self::ext` ends with `["Self", "ext"]` and with `["ext"]`.
fn ends_with(call: &ExprCall, tail: &[&str]) -> bool {
    let Expr::Path(func) = &*call.func else { return false };
    let segments = &func.path.segments;
    segments.len() >= tail.len() && segments.iter().rev().zip(tail.iter().rev()).all(|(segment, name)| segment.ident == name)
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

/// What the resolver and the same-crate functions it reaches do with the result and with the amount.
struct Reach {
    reads_result: bool,
    bounded: bool,
}

impl Reach {
    fn of(resolver: &ImplItemFn, index: &Index) -> Self {
        let mut reach = Self {
            reads_result: resolver.sig.inputs.iter().any(|arg| {
                matches!(arg, FnArg::Typed(arg)
                    if arg.attrs.iter().any(|attr| CALLBACK_ARGS.iter().any(|name| attr.path().is_ident(name))))
            }),
            bounded: false,
        };
        let mut seen = BTreeSet::new();
        let mut pending = vec![&resolver.block];
        while let Some(body) = pending.pop() {
            let mut facts = Facts::default();
            facts.visit_block(body);
            reach.reads_result |= facts.reads_result;
            reach.bounded |= facts.bounded;
            for call in facts.calls {
                if seen.insert(call.clone()) {
                    pending.extend(index.bodies(&call).iter().copied());
                }
            }
        }
        reach
    }
}

/// The calls in one body, and whether it reads a promise result or bounds a number.
#[derive(Default)]
struct Facts {
    calls: BTreeSet<String>,
    reads_result: bool,
    bounded: bool,
}

impl Facts {
    fn call(&mut self, name: String) {
        self.reads_result |= RESULT_READS.contains(&name.as_str());
        self.bounded |= BOUNDS.contains(&name.as_str());
        self.calls.insert(name);
    }

    /// Calls and comparisons written inside a macro's tokens, such as `require!(unused <= amount.0)`.
    fn tokens(&mut self, tokens: TokenStream) {
        let mut previous: Option<String> = None;
        for tree in tokens {
            match tree {
                TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    self.reads_result |= RESULT_READS.contains(&name.as_str());
                    self.bounded |= BOUNDS.contains(&name.as_str());
                    previous = Some(name);
                }
                TokenTree::Group(group) => {
                    if group.delimiter() == Delimiter::Parenthesis
                        && let Some(name) = previous.take()
                    {
                        self.calls.insert(name);
                    }
                    previous = None;
                    self.tokens(group.stream());
                }
                TokenTree::Punct(punct) => {
                    self.bounded |= matches!(punct.as_char(), '<' | '>');
                    previous = None;
                }
                TokenTree::Literal(_) => previous = None,
            }
        }
    }
}

impl<'ast> Visit<'ast> for Facts {
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

    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        self.bounded |= matches!(binary.op, BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_));
        visit::visit_expr_binary(self, binary);
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

    /// A resolver with `body` between its signature and a final `U128(0)`.
    fn resolver(body: &str) -> String {
        format!(
            "#[near] impl Token {{ #[private] pub fn ft_resolve_transfer(&mut self, sender_id: AccountId, receiver_id: AccountId, amount: U128) -> U128 {{ {body} U128(0) }} }}"
        )
    }

    const UNBOUNDED: &str = "
        let unused = env::promise_result_checked(0, 64).ok().and_then(|v| serde_json::from_slice::<U128>(&v).ok()).map_or(amount.0, |u| u.0);
        let held = self.balances.get(&receiver_id).copied().unwrap_or(0);
        self.balances.insert(receiver_id, held.saturating_sub(unused));
        *self.balances.entry(sender_id).or_insert(0) += unused;";

    #[test]
    fn flags_a_resolver_that_refunds_the_reported_amount_uncapped_and_locates_it() {
        let findings = one(&resolver(UNBOUNDED));
        assert_eq!(items(&findings), ["Token::ft_resolve_transfer"]);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF019", Severity::Critical));
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 1, 40));
        assert!(finding.message.contains("`Token::ft_resolve_transfer`") && finding.message.contains("no cap"));
    }

    #[test]
    fn flags_each_way_of_reading_the_result() {
        for read in [
            "let unused = env::promise_result_checked(0, 64).map_or(0, |v| v.len() as u128);",
            "let unused = match env::promise_result(0) { PromiseResult::Successful(v) => v.len() as u128, _ => 0 };",
            "let unused = if is_promise_success() { 1 } else { 2 };",
            "let unused = promise_result_as_success().map_or(0, |v| v.len() as u128);",
        ] {
            let body = format!("{read} *self.balances.entry(sender_id).or_insert(0) += unused;");
            assert_eq!(items(&one(&resolver(&body))), ["Token::ft_resolve_transfer"], "{read}");
        }
        let callback = "#[near] impl Token { #[private] pub fn ft_resolve_transfer(&mut self, sender_id: AccountId, receiver_id: AccountId, amount: U128, #[callback_unwrap] unused: U128) -> U128 { self.balances.insert(sender_id, unused.0); U128(0) } }";
        assert_eq!(items(&one(callback)), ["Token::ft_resolve_transfer"]);
    }

    #[test]
    fn a_saturating_subtraction_is_not_a_bound() {
        assert!(!one(&resolver(UNBOUNDED)).is_empty());
        assert!(one(&resolver(&UNBOUNDED.replace("saturating_sub", "wrapping_sub"))).len() == 1);
    }

    #[test]
    fn follows_the_refund_into_a_helper_and_across_files() {
        let resolver = "#[near] impl Token { #[private] pub fn ft_resolve_transfer(&mut self, s: AccountId, r: AccountId, amount: U128) -> U128 { let unused = env::promise_result_checked(0, 64).map_or(0, |v| v.len() as u128); self.refund(&s, &r, unused); U128(0) } }";
        let helper = "impl Token { fn refund(&mut self, s: &AccountId, r: &AccountId, n: u128) { self.balances.insert(s.clone(), n); } }";
        assert_eq!(items(&check(&[("src/lib.rs", resolver), ("src/refund.rs", helper)])), ["Token::ft_resolve_transfer"]);
    }

    #[test]
    fn recognises_a_renamed_resolver_scheduled_after_ft_on_transfer() {
        let source = "#[near] impl Token {
            #[payable] pub fn send(&mut self, r: AccountId, amount: U128, msg: String) -> Promise {
                ext_receiver::ext(r.clone()).with_unused_gas_weight(1).ft_on_transfer(me(), amount, msg)
                    .then(Self::ext(env::current_account_id()).with_static_gas(GAS).settle(me(), r, amount))
            }
            #[private] pub fn settle(&mut self, s: AccountId, r: AccountId, amount: U128) -> U128 {
                let unused = env::promise_result_checked(0, 64).map_or(0, |v| v.len() as u128);
                *self.balances.entry(s).or_insert(0) += unused;
                U128(0)
            }
        }";
        assert_eq!(items(&one(source)), ["Token::settle"]);
    }

    #[test]
    fn a_method_that_is_not_a_resolver_is_ignored() {
        let source = "#[near] impl Token {
            pub fn go(&mut self, r: AccountId) -> Promise { ext_other::ext(r).ping().then(Self::ext(env::current_account_id()).done()) }
            #[private] pub fn done(&mut self) { let unused = env::promise_result_checked(0, 64).map_or(0, |v| v.len() as u128); self.total += unused; }
            pub fn nft_resolve_transfer(&mut self) { let ok = is_promise_success(); self.total += 1; }
        }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn a_resolver_scheduled_on_another_contract_is_not_this_contracts() {
        let source = "#[near] impl Router {
            pub fn go(&mut self, r: AccountId) -> Promise { ext_receiver::ext(r).ft_on_transfer(a, b, c).then(other::ext(self.dex.clone()).settle()) }
            pub fn settle(&mut self) { let unused = env::promise_result_checked(0, 64).map_or(0, |v| v.len() as u128); self.total += unused; }
        }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn a_bound_on_the_refund_silences_the_rule() {
        for bound in [
            "let unused = unused.min(amount.0);",
            "let unused = std::cmp::min(unused, amount.0);",
            "let unused = unused.clamp(0, amount.0);",
            "let unused = amount.0.checked_sub(unused).expect(\"over\");",
            "if unused > amount.0 { env::panic_str(\"over\"); }",
            "require!(unused <= amount.0, \"over\");",
            "assert!(amount.0 >= unused);",
            "if held < unused { return U128(0); }",
        ] {
            let body = format!(
                "let unused = env::promise_result_checked(0, 64).map_or(0, |v| v.len() as u128); let held = 0u128; {bound} *self.balances.entry(sender_id).or_insert(0) += unused;"
            );
            assert!(one(&resolver(&body)).is_empty(), "{bound}");
        }
    }

    #[test]
    fn a_bound_in_a_helper_the_resolver_reaches_silences_the_rule() {
        let resolver = "#[near] impl Token { #[private] pub fn ft_resolve_transfer(&mut self, s: AccountId, r: AccountId, amount: U128) -> U128 { let unused = env::promise_result_checked(0, 64).map_or(0, |v| v.len() as u128); self.refund(&s, capped(unused, amount.0)); U128(0) } }";
        let helper = "fn capped(unused: u128, amount: u128) -> u128 { unused.min(amount) } impl Token { fn refund(&mut self, s: &AccountId, n: u128) { self.balances.insert(s.clone(), n); } }";
        assert!(check(&[("src/lib.rs", resolver), ("src/refund.rs", helper)]).is_empty());
    }

    #[test]
    fn a_resolver_that_delegates_to_the_standard_implementation_is_silent() {
        let source = "#[near] impl FungibleTokenResolver for Token { #[private] fn ft_resolve_transfer(&mut self, sender_id: AccountId, receiver_id: AccountId, amount: U128) -> U128 { let (used, _burned) = self.token.internal_ft_resolve_transfer(&sender_id, receiver_id, amount); used.into() } }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn a_resolver_that_never_reads_the_result_or_writes_nothing_is_silent() {
        assert!(one(&resolver("self.balances.insert(sender_id, amount.0);")).is_empty());
        assert!(one(&resolver("let unused = env::promise_result_checked(0, 64).map_or(0, |v| v.len() as u128); env::log_str(\"resolved\");")).is_empty());
    }

    #[test]
    fn accepts_near_bindgen_trait_impls_and_ignores_what_the_macro_does_not_export() {
        let body = "let unused = env::promise_result_checked(0, 64).map_or(0, |v| v.len() as u128); self.total += unused;";
        let sig = "(&mut self, s: AccountId, r: AccountId, amount: U128) -> U128";
        assert_eq!(items(&one(&format!("#[near_bindgen] impl FungibleTokenResolver for Token {{ fn ft_resolve_transfer{sig} {{ {body} U128(0) }} }}"))), ["Token::ft_resolve_transfer"]);
        assert!(one(&format!("impl Token {{ pub fn ft_resolve_transfer{sig} {{ {body} U128(0) }} }}")).is_empty());
        assert!(one(&format!("#[near] impl Token {{ fn ft_resolve_transfer{sig} {{ {body} U128(0) }} }}")).is_empty());
    }
}
