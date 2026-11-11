//! PF002: a method that moves assets without requiring one yoctoNEAR.
//!
//! A function-call access key cannot attach a deposit, so a method that demands exactly 1 yoctoNEAR
//! (`assert_one_yocto()`) can only be reached with a full-access key, which means a wallet confirmation. Without
//! it, any app or agent holding a function-call key for the contract on the victim's account can move the
//! victim's assets silently. Docs: https://docs.near.org/smart-contracts/security/one_yocto
//!
//! A method is checked when the `#[near]` macro exports it (`pub` method of an inherent impl, or any method of a
//! trait impl), it takes `&mut self` and it is not `#[private]`. It is reported when it moves assets and neither
//! it nor a same-crate function it reaches requires a deposit.
//!
//! Moves assets, either of:
//! - its name is a NEP interface method that moves tokens or grants rights over them: `ft_transfer`,
//!   `ft_transfer_call`, `nft_transfer`, `nft_transfer_call`, `nft_approve`, `nft_revoke`, `nft_revoke_all`,
//!   `mt_transfer`, `mt_batch_transfer`, `mt_transfer_call`, `mt_batch_transfer_call`, `mt_approve`, `mt_revoke`,
//!   `mt_revoke_all`, `storage_withdraw`, `storage_unregister` (each standard requires the yocto);
//! - it hands value to another account: it uses `env::predecessor_account_id()` as the account to debit,
//!   subtracts and adds (`-`, `-=`, `checked_sub`, ... and `+`, `+=`, `checked_add`, ...) or pays out
//!   (`.transfer(..)`, `ft_transfer(..)` and the other NEP transfer calls), and takes an `AccountId` parameter
//!   that its body uses. A caller that is only compared (`require!(env::predecessor_account_id() == self.shop)`,
//!   `if env::predecessor_account_id() != owner`) is an access check, not the account being debited.
//!
//! Never reported: the NEP receiver hooks, by exact name (`ft_on_transfer`, `nft_on_transfer`, `mt_on_transfer`,
//! `nft_on_approve`, `mt_on_approve`: the token contract, which is the caller, already demanded the yocto on
//! `ft_transfer_call` or `nft_approve`; `vault_on_transfer` is an ordinary method); a method every call of which ends
//! in a panic (`self.assert_live(); env::panic_str("not supported")`: a failed call changes nothing); and delegation to `internal_<name>` of a library
//! (`self.token.internal_storage_unregister(..)`, which asserts the yocto itself) when the crate does not define
//! that name. A call found by name is followed through a bare or path call, a macro (also a crate-local
//! `macro_rules!`, and a `#[macro_export]` one of a crate this one depends on by `path` inside the scan) and a method called on `self` or on a field of it (`self.ledger.f(..)`), not through a method
//! called on any other value (`validator.withdraw(..)` is that validator's method).
//!
//! Requires a deposit: a call to `assert_one_yocto`, `assert_at_least_one_yocto` or `env::attached_deposit` (a
//! method that reads the deposit has decided what to demand). A call counts when it is in the method or in any
//! same-crate function it reaches, found by name (free function, inherent or trait method, any file of the
//! crate), including calls written inside macro arguments such as `require!(env::attached_deposit() == ..)`.
//! A method named like a NEP method that calls a method of the same name on something else, as in
//! `self.token.ft_transfer(..)`, is delegating to a library implementation (near-contract-standards asserts the
//! yocto itself) and is not reported, unless the crate defines that name a second time.
//!
//! Knowingly missed: ownership changes and approvals under custom names; transfers whose debit and credit sit in
//! a method with no `AccountId` parameter (for example a receiver taken as `String`); assets moved by an
//! `impl_*!` macro, which the scanner cannot see; a deposit read that accepts zero, and in general any read of
//! `attached_deposit` counts as the check, whatever is done with the value (it is logged, compared with the wrong
//! bound, or ignored); a macro of a path dependency is imported by its bare name, so a crate that never imports it,
//! or imports it under another name, gets that macro's deposit check (or its absence) all the same.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{Delimiter, Span, TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{
    Attribute, BinOp, Block, Expr, ExprBinary, ExprCall, ExprMethodCall, ExprPath, FnArg, Ident, ImplItem,
    ImplItemFn, ItemFn, ItemImpl, ItemMacro, Pat, TraitItemFn, Type, Visibility,
};

use crate::finding::{Finding, Severity};
use crate::guards::{field_path, always_panics};
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf002OneYocto;

pub static RULE: Pf002OneYocto = Pf002OneYocto;

impl Rule for Pf002OneYocto {
    fn id(&self) -> &'static str {
        "PF002"
    }

    fn title(&self) -> &'static str {
        "Asset-moving method without assert_one_yocto"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn help(&self) -> &'static str {
        "mark the method #[payable] and call assert_one_yocto() first, so only a full-access key can call it"
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
        // Macros of path dependencies are definitions to follow, after the crate's own functions: nothing in them is reported.
        let imported: Vec<FileScan> = krate
            .imported_macros
            .iter()
            .map(|item| {
                let mut scan = FileScan::default();
                scan.visit_item_macro(item);
                scan
            })
            .collect();
        let functions: Vec<&Func> = scans.iter().chain(&imported).flat_map(|scan| &scan.functions).collect();
        let mut by_name: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (index, func) in functions.iter().enumerate() {
            by_name.entry(func.name.as_str()).or_default().push(index);
        }

        let mut findings = Vec::new();
        let mut next = 0;
        for (file, scan) in krate.files.iter().zip(&scans) {
            for func in &scan.functions {
                let index = next;
                next += 1;
                let Some(export) = &func.export else { continue };
                if export.private || !export.mut_self || func.always_panics || is_receiver_hook(&func.name) {
                    continue;
                }
                let reached = reach(index, &functions, &by_name);
                if reached.requires_deposit {
                    continue;
                }
                let name = format!("{}::{}", export.owner, func.name);
                let why = if NEP_ASSET_METHODS.contains(&func.name.as_str()) {
                    let internal = format!("internal_{}", func.name);
                    let delegates = (func.called.contains(&func.name) && by_name[func.name.as_str()].len() == 1)
                        || (func.called.contains(&internal) && !by_name.contains_key(internal.as_str()));
                    if delegates {
                        continue;
                    }
                    "is a NEP method that moves tokens or grants rights over them".to_owned()
                } else if let Some(receiver) = export.account_params.iter().find(|param| func.mentions.contains(*param))
                    && reached.caller
                    && reached.debit
                    && reached.credit
                {
                    format!("debits the caller's balance and credits or pays `{receiver}`")
                } else {
                    continue;
                };
                findings.push(self.finding(
                    file,
                    export.span,
                    name.clone(),
                    format!(
                        "`{name}` {why} but never requires an attached deposit, so a function-call access key can call it without a wallet confirmation"
                    ),
                ));
            }
        }
        findings
    }
}

/// NEP interface methods that move tokens or grant rights over them; each standard requires 1 yoctoNEAR.
const NEP_ASSET_METHODS: [&str; 16] = [
    "ft_transfer",
    "ft_transfer_call",
    "nft_transfer",
    "nft_transfer_call",
    "nft_approve",
    "nft_revoke",
    "nft_revoke_all",
    "mt_transfer",
    "mt_batch_transfer",
    "mt_transfer_call",
    "mt_batch_transfer_call",
    "mt_approve",
    "mt_revoke",
    "mt_revoke_all",
    "storage_withdraw",
    "storage_unregister",
];

/// The NEP receiver hooks, called by the token contract, which already demanded the yocto. Exact names only: a method
/// that merely ends in `_on_transfer` (`vault_on_transfer`) is an ordinary entry point anyone can call.
const RECEIVER_HOOKS: [&str; 5] = ["ft_on_transfer", "nft_on_transfer", "mt_on_transfer", "nft_on_approve", "mt_on_approve"];

fn is_receiver_hook(name: &str) -> bool {
    RECEIVER_HOOKS.contains(&name)
}

/// Calls that demand or inspect the attached deposit.
const DEPOSIT_CHECKS: [&str; 3] = ["assert_one_yocto", "assert_at_least_one_yocto", "attached_deposit"];

/// Method calls that pay an account or ask another contract to move tokens.
const PAYOUTS: [&str; 9] = [
    "transfer",
    "ft_transfer",
    "ft_transfer_call",
    "nft_transfer",
    "nft_transfer_call",
    "mt_transfer",
    "mt_batch_transfer",
    "mt_transfer_call",
    "mt_batch_transfer_call",
];

/// Macros whose arguments are a condition to check, so a caller read inside one is an access check.
const GUARD_MACROS: [&str; 6] = ["require", "assert", "assert_eq", "assert_ne", "debug_assert", "debug_assert_eq"];

const SUBTRACTIONS: [&str; 4] = ["sub", "checked_sub", "saturating_sub", "wrapping_sub"];
const ADDITIONS: [&str; 4] = ["add", "checked_add", "saturating_add", "wrapping_add"];

/// What one function body does itself.
#[derive(Default, Clone, Copy)]
struct Facts {
    requires_deposit: bool,
    caller: bool,
    debit: bool,
    credit: bool,
}

impl Facts {
    fn merge(&mut self, other: Facts) {
        self.requires_deposit |= other.requires_deposit;
        self.caller |= other.caller;
        self.debit |= other.debit;
        self.credit |= other.credit;
    }
}

/// What the scan keeps of one function: what its body does, the names it calls and the plain names it uses.
#[derive(Default)]
struct Func {
    name: String,
    facts: Facts,
    /// Names it calls that the scan follows to a same-crate function.
    calls: BTreeSet<String>,
    /// Every method it calls, on any receiver.
    called: BTreeSet<String>,
    mentions: BTreeSet<String>,
    always_panics: bool,
    /// Set when the `#[near]` macro exports the function.
    export: Option<Export>,
}

struct Export {
    owner: String,
    span: Span,
    mut_self: bool,
    private: bool,
    /// Parameters of type `AccountId`.
    account_params: Vec<String>,
}

#[derive(Default)]
struct FileScan {
    /// Every function with a body in the file, exported or not.
    functions: Vec<Func>,
}

/// The facts of `start` and of every same-crate function it reaches by name, transitively.
fn reach(start: usize, functions: &[&Func], by_name: &BTreeMap<&str, Vec<usize>>) -> Facts {
    let mut facts = Facts::default();
    let mut seen = BTreeSet::from([start]);
    let mut stack = vec![start];
    while let Some(index) = stack.pop() {
        facts.merge(functions[index].facts);
        for call in &functions[index].calls {
            for &callee in by_name.get(call.as_str()).into_iter().flatten() {
                if seen.insert(callee) {
                    stack.push(callee);
                }
            }
        }
    }
    facts
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

    /// A crate-local `macro_rules!` is followed like a function of the same name: `assert_deposit!(..)` reaches
    /// the `attached_deposit()` in its body.
    fn visit_item_macro(&mut self, item: &'ast ItemMacro) {
        if let (Some(name), true) = (&item.ident, item.mac.path.is_ident("macro_rules")) {
            let mut body = BodyScan::default();
            body.names_in_tokens(item.mac.tokens.clone());
            self.functions.push(Func { name: name.to_string(), facts: body.facts, calls: body.calls, called: body.called, mentions: body.mentions, ..Func::default() });
        }
        visit::visit_item_macro(self, item);
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
    Func {
        name: name.to_string(),
        facts: body.facts,
        calls: body.calls,
        called: body.called,
        mentions: body.mentions,
        always_panics: always_panics(block),
        export: None,
    }
}

fn export_of(owner: &str, method: &ImplItemFn) -> Export {
    let mut_self = method.sig.receiver().is_some_and(|receiver| receiver.reference.is_some() && receiver.mutability.is_some());
    let account_params = method
        .sig
        .inputs
        .iter()
        .filter_map(|arg| match arg {
            FnArg::Typed(arg) if type_name(&arg.ty) == "AccountId" => match &*arg.pat {
                Pat::Ident(ident) => Some(ident.ident.to_string()),
                _ => None,
            },
            _ => None,
        })
        .collect();
    Export {
        owner: owner.to_owned(),
        span: method.sig.ident.span(),
        mut_self,
        private: has_helper_attr(&method.attrs, "private"),
        account_params,
    }
}

/// The facts, calls and plain names of one function body, including those written inside macro arguments.
#[derive(Default)]
struct BodyScan {
    /// Greater than zero while visiting an access check: an `==`/`!=` operand or a guard macro's arguments.
    in_check: usize,
    facts: Facts,
    calls: BTreeSet<String>,
    called: BTreeSet<String>,
    mentions: BTreeSet<String>,
}

impl BodyScan {
    /// Notes a call. `follow` says whether it can only mean a function of this crate: a bare call, a path call,
    /// a macro or a method on `self`.
    fn call(&mut self, name: String, follow: bool) {
        self.facts.requires_deposit |= DEPOSIT_CHECKS.contains(&name.as_str());
        self.facts.caller |= name == "predecessor_account_id" && self.in_check == 0;
        self.facts.debit |= SUBTRACTIONS.contains(&name.as_str());
        self.facts.credit |= ADDITIONS.contains(&name.as_str()) || PAYOUTS.contains(&name.as_str());
        self.called.insert(name.clone());
        if follow {
            self.calls.insert(name);
        }
    }

    /// Identifiers in a macro's tokens: `name(..)` is a call, any other identifier is a plain name.
    fn names_in_tokens(&mut self, tokens: TokenStream) {
        let mut previous: Option<String> = None;
        for tree in tokens {
            match tree {
                TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    self.mentions.insert(name.clone());
                    previous = Some(name);
                }
                TokenTree::Group(group) => {
                    if group.delimiter() == Delimiter::Parenthesis
                        && let Some(name) = previous.take()
                    {
                        self.call(name, true);
                    }
                    previous = None;
                    self.names_in_tokens(group.stream());
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
            self.call(last.ident.to_string(), true);
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let on_self = matches!(&*call.receiver, Expr::Path(path) if path.path.is_ident("self"))
            || field_path(&call.receiver).is_some();
        self.call(call.method.to_string(), on_self);
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        match binary.op {
            BinOp::Sub(_) | BinOp::SubAssign(_) => self.facts.debit = true,
            BinOp::Add(_) | BinOp::AddAssign(_) => self.facts.credit = true,
            _ => {}
        }
        let is_comparison = matches!(binary.op, BinOp::Eq(_) | BinOp::Ne(_));
        self.in_check += usize::from(is_comparison);
        visit::visit_expr_binary(self, binary);
        self.in_check -= usize::from(is_comparison);
    }

    fn visit_expr_path(&mut self, path: &'ast ExprPath) {
        if let Some(ident) = path.path.get_ident() {
            self.mentions.insert(ident.to_string());
        }
        visit::visit_expr_path(self, path);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let is_guard = mac.path.segments.last().is_some_and(|name| GUARD_MACROS.contains(&name.ident.to_string().as_str()));
        self.in_check += usize::from(is_guard);
        if let Some(name) = mac.path.segments.last() {
            self.call(name.ident.to_string(), true);
        }
        self.names_in_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
        self.in_check -= usize::from(is_guard);
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

    const LEDGER: &str = r#"
        #[near]
        impl Arcade {
            pub fn transfer(&mut self, receiver_id: AccountId, amount: U128) {
                let sender = env::predecessor_account_id();
                let balance = self.credits.get(&sender).copied().unwrap_or(0);
                require!(balance >= amount.0, "not enough credits");
                self.credits.insert(sender, balance - amount.0);
                let held = self.credits.get(&receiver_id).copied().unwrap_or(0);
                self.credits.insert(receiver_id, held + amount.0);
            }
        }
    "#;

    #[test]
    fn flags_a_transfer_between_internal_balances_and_locates_it() {
        let findings = one(LEDGER);
        assert_eq!(items(&findings), ["Arcade::transfer"]);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF002", Severity::High));
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 4, 20));
        assert!(finding.message.contains("credits or pays `receiver_id`"), "{}", finding.message);
    }

    #[test]
    fn flags_a_payable_method_that_never_reads_the_deposit() {
        let source = LEDGER.replace("pub fn transfer", "#[payable]\n pub fn transfer");
        assert_eq!(items(&one(&source)), ["Arcade::transfer"]);
    }

    #[test]
    fn flags_a_withdrawal_to_another_account() {
        let source = "#[near] impl V { pub fn withdraw_to(&mut self, to: AccountId, amount: u128) -> Promise {
            let from = env::predecessor_account_id();
            let held = self.balances.get(&from).unwrap();
            self.balances.insert(from, held.checked_sub(amount).unwrap());
            Promise::new(to).transfer(NearToken::from_yoctonear(amount))
        } }";
        assert_eq!(items(&one(source)), ["V::withdraw_to"]);
    }

    #[test]
    fn flags_a_transfer_whose_debit_and_credit_are_in_a_helper() {
        let source = "#[near] impl V {
            pub fn send(&mut self, to: AccountId, amount: u128) { self.move_credits(env::predecessor_account_id(), &to, amount); }
        }
        impl V { fn move_credits(&mut self, from: AccountId, to: &AccountId, amount: u128) { *self.c.entry(from).or_default() -= amount; *self.c.entry(to.clone()).or_default() += amount; } }";
        assert_eq!(items(&one(source)), ["V::send"]);
    }

    #[test]
    fn flags_every_nep_asset_method_by_name() {
        for name in NEP_ASSET_METHODS {
            let source = format!("#[near] impl C {{ pub fn {name}(&mut self) {{ self.stuff(); }} }}");
            assert_eq!(items(&one(&source)), [format!("C::{name}")], "{name}");
        }
    }

    #[test]
    fn flags_a_trait_impl_method_and_both_near_spellings() {
        for attr in ["#[near_bindgen]", "#[near_sdk::near]", "#[near(contract_state)]", "#[near]"] {
            let source = format!("{attr} impl FungibleTokenCore for C {{ fn ft_transfer(&mut self, r: AccountId) {{ self.move_it(r); }} }}");
            assert_eq!(items(&one(&source)), ["C::ft_transfer"], "{attr}");
        }
    }

    #[test]
    fn a_method_that_requires_one_yocto_is_clean() {
        for check in ["assert_one_yocto();", "near_sdk::assert_one_yocto();", "assert_at_least_one_yocto();"] {
            let source = LEDGER.replace("let sender", &format!("{check} let sender"));
            assert!(one(&source).is_empty(), "{check}");
        }
    }

    #[test]
    fn reading_the_attached_deposit_counts_as_demanding_one() {
        for check in [
            "require!(env::attached_deposit() == NearToken::from_yoctonear(1));",
            "let paid = near_sdk::env::attached_deposit();",
            "assert_eq!(attached_deposit().as_yoctonear(), 1);",
        ] {
            let source = LEDGER.replace("let sender", &format!("{check} let sender"));
            assert!(one(&source).is_empty(), "{check}");
        }
    }

    #[test]
    fn a_helper_in_the_crate_that_requires_one_yocto_is_followed() {
        let source = LEDGER.replace("let sender", "self.confirm(); let sender");
        assert_eq!(items(&one(&source)), ["Arcade::transfer"], "an undefined helper requires nothing");

        let helper = "impl Arcade { fn confirm(&self) { guard(); } } fn guard() { assert_one_yocto(); }";
        assert!(check(&[("src/lib.rs", &source), ("src/guards.rs", helper)]).is_empty());
    }

    #[test]
    fn a_helper_cycle_terminates() {
        let source = LEDGER.replace("let sender", "ping(); let sender") + "fn ping() { pong(); } fn pong() { ping(); }";
        assert_eq!(items(&one(&source)), ["Arcade::transfer"]);
    }

    #[test]
    fn delegating_to_a_library_implementation_of_the_same_method_is_clean() {
        let source = "#[near] impl FungibleTokenCore for C {
            fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) { self.token.ft_transfer(receiver_id, amount, memo) }
        }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn delegating_to_a_second_definition_in_the_crate_follows_that_definition() {
        let delegating = "#[near] impl FungibleTokenCore for C {
            fn ft_transfer(&mut self, receiver_id: AccountId) { self.token.ft_transfer(receiver_id) }
        }";
        let own_ledger = "impl Ledger { fn ft_transfer(&mut self, receiver_id: AccountId) {} }";
        assert_eq!(items(&check(&[("src/lib.rs", delegating), ("src/ledger.rs", own_ledger)])), ["C::ft_transfer"]);
        let checked = "impl Ledger { fn ft_transfer(&mut self, receiver_id: AccountId) { assert_one_yocto(); } }";
        assert!(check(&[("src/lib.rs", delegating), ("src/ledger.rs", checked)]).is_empty());
    }

    #[test]
    fn private_views_and_unexported_methods_are_ignored() {
        for (name, replacement) in [
            ("private", LEDGER.replace("pub fn transfer", "#[private]\n pub fn transfer")),
            ("view", LEDGER.replace("&mut self", "&self")),
            ("by value", LEDGER.replace("&mut self", "self")),
            ("not pub", LEDGER.replace("pub fn transfer", "fn transfer")),
            ("pub(crate)", LEDGER.replace("pub fn transfer", "pub(crate) fn transfer")),
            ("not near", LEDGER.replace("#[near]", "")),
        ] {
            assert!(one(&replacement).is_empty(), "{name}");
        }
    }

    #[test]
    fn paying_the_caller_itself_is_not_handing_value_to_another_account() {
        let source = "#[near] impl V { pub fn cash_out(&mut self, amount: u128) -> Promise {
            let from = env::predecessor_account_id();
            let held = self.balances.get(&from).unwrap();
            self.balances.insert(from.clone(), held - amount);
            Promise::new(from).transfer(NearToken::from_yoctonear(amount))
        } }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn a_caller_that_is_only_checked_is_not_the_account_being_debited() {
        for check in [
            "require!(env::predecessor_account_id() == self.shop, \"only the shop\");",
            "assert_eq!(near_sdk::env::predecessor_account_id(), self.shop);",
            "if env::predecessor_account_id() != self.shop { env::panic_str(\"only the shop\"); }",
        ] {
            let source = LEDGER.replace("let sender = env::predecessor_account_id();", &format!("{check} let sender = self.payer.clone();"));
            assert!(one(&source).is_empty(), "{check}");
        }
    }

    #[test]
    fn bookkeeping_with_an_account_parameter_is_not_a_transfer() {
        for body in [
            "require!(env::predecessor_account_id() == self.owner); self.members.remove(&member); self.count -= 1;",
            "let sender = env::predecessor_account_id(); self.counts.insert(member, self.counts.len() + 1);",
            "self.count -= 1; self.members.insert(member);",
            "let sender = env::predecessor_account_id(); self.stake += 1; self.members.insert(sender);",
        ] {
            let source = format!("#[near] impl C {{ pub fn update(&mut self, member: AccountId) {{ {body} }} }}");
            assert!(one(&source).is_empty(), "{body}");
        }
    }

    #[test]
    fn a_debit_and_credit_without_a_used_account_parameter_is_not_reported() {
        let source = LEDGER.replace("receiver_id: AccountId", "receiver_id: String").replace("self.credits.insert(receiver_id, held", "self.credits.insert(receiver_id.parse().unwrap(), held");
        assert!(one(&source).is_empty());
        let unused = LEDGER.replace("self.credits.get(&receiver_id)", "self.credits.get(&sender)").replace("self.credits.insert(receiver_id,", "self.credits.insert(sender,");
        assert!(one(&unused).is_empty());
    }

    #[test]
    fn reports_each_method_once_and_names_the_impl() {
        let source = format!("{LEDGER} #[near] impl Other {{ pub fn ft_transfer(&mut self) {{}} }}");
        assert_eq!(items(&one(&source)), ["Arcade::transfer", "Other::ft_transfer"]);
    }

    #[test]
    fn nep_receiver_hooks_and_always_panicking_methods_are_clean() {
        let hook = "#[near] impl Receiver for C { fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> U128 { self.credit(sender_id, amount); amount } }";
        assert!(one(hook).is_empty());
        let nft_hook = hook.replace("ft_on_transfer", "nft_on_approve");
        assert!(one(&nft_hook).is_empty());
        let panics = "#[near] impl StorageManagement for C { #[payable] fn storage_unregister(&mut self, force: Option<bool>) -> bool { env::panic_str(\"no\"); } }";
        assert!(one(panics).is_empty());
        // A common shape in deployed code: a check, then the panic.
        let checked = "#[near] impl StorageManagement for C { #[payable] fn storage_unregister(&mut self, force: Option<bool>) -> bool { self.assert_live(); self.remove(); env::panic_str(\"no\"); } }";
        assert!(one(checked).is_empty());
        // A way out before the panic is a call that completes.
        let escapes = "#[near] impl StorageManagement for C { fn storage_unregister(&mut self, force: Option<bool>) -> bool { self.remove(); if force.is_some() { return true; } env::panic_str(\"no\"); } }";
        assert_eq!(items(&one(escapes)), ["C::storage_unregister"]);
        let conditional = "#[near] impl StorageManagement for C { fn storage_unregister(&mut self, force: Option<bool>) -> bool { self.remove(); if force.is_none() { env::panic_str(\"no\"); } true } }";
        assert_eq!(items(&one(conditional)), ["C::storage_unregister"]);
        let moves = "#[near] impl StorageManagement for C { fn storage_unregister(&mut self, force: Option<bool>) -> bool { self.remove(); true } }";
        assert_eq!(items(&one(moves)), ["C::storage_unregister"]);
        let transfer = "#[near] impl C { fn on_transfer_all(&mut self, to: AccountId) { Promise::new(to).transfer(1); } }";
        assert_eq!(items(&one(transfer)).len(), 0);
    }

    /// Only the exact NEP hook names are the token contract's call; a suffix match let any method opt out.
    #[test]
    fn a_method_that_only_ends_in_on_transfer_is_not_a_receiver_hook() {
        for name in ["ft_on_transfer", "nft_on_transfer", "mt_on_transfer", "nft_on_approve", "mt_on_approve"] {
            assert!(one(&LEDGER.replace("fn transfer", &format!("fn {name}"))).is_empty(), "{name}");
        }
        for name in ["vault_on_transfer", "pay_on_approve", "ft_on_transfer_all"] {
            assert_eq!(items(&one(&LEDGER.replace("fn transfer", &format!("fn {name}")))), [format!("Arcade::{name}")], "{name}");
        }
    }

    /// An unknown macro may return, so a method ending in one is not a method that always panics.
    #[test]
    fn a_method_ending_in_an_unknown_macro_is_not_an_always_panic() {
        let source = "#[near] impl StorageManagement for C { fn storage_unregister(&mut self, force: Option<bool>) -> bool { self.remove(); finish!(\"no\") } }";
        assert_eq!(items(&one(source)), ["C::storage_unregister"]);
        assert!(one(&source.replace("finish!(\"no\")", "panic!(\"no\")")).is_empty());
    }

    #[test]
    fn delegating_to_an_internal_function_of_a_library_is_clean_unless_the_crate_defines_it() {
        let delegating = "#[near] impl StorageManagement for C {
            fn storage_unregister(&mut self, force: Option<bool>) -> bool { self.token.internal_storage_unregister(force).is_some() }
        }";
        assert!(one(delegating).is_empty());
        let own = "impl Ledger { fn internal_storage_unregister(&mut self, force: Option<bool>) -> Option<bool> { None } }";
        assert_eq!(items(&check(&[("src/lib.rs", delegating), ("src/ledger.rs", own)])), ["C::storage_unregister"]);
    }

    #[test]
    fn a_crate_local_macro_that_reads_the_deposit_is_followed() {
        let source = "macro_rules! assert_deposit { ($r:expr) => { if env::attached_deposit() < $r { env::panic_str(\"deposit\") } } }
            #[near] impl Approvals for C { fn nft_approve(&mut self, token_id: TokenId, account_id: AccountId) { assert_deposit!(1); self.approve(token_id, account_id); } }";
        assert!(one(source).is_empty());
        assert_eq!(items(&one(&source.replace("assert_deposit!(1);", "assert_nothing!(1);"))), ["C::nft_approve"]);
    }

    /// A common shape in deployed code: `validator.withdraw(..)` is the validator's method, not this contract's debiting `withdraw`.
    #[test]
    fn a_method_called_on_another_value_is_not_followed_by_name() {
        let source = "#[near] impl C {
            pub fn epoch_withdraw(&mut self, to: AccountId, amount: u128) { validator.withdraw(to, amount); }
            fn withdraw(&mut self, to: AccountId, amount: u128) { let who = env::predecessor_account_id(); self.balances[who] -= amount; self.balances[to] += amount; }
        }";
        assert!(one(source).is_empty());
        let on_self = source.replace("validator.withdraw", "self.withdraw");
        assert_eq!(items(&one(&on_self)), ["C::epoch_withdraw"]);
    }

    /// A common shape in deployed code: a deposit-check macro lives in a path dependency that is part of the scan.
    #[test]
    fn a_macro_exported_by_a_path_dependency_that_reads_the_deposit_is_followed() {
        let common = "#[macro_export] macro_rules! assert_deposit { ($r:expr) => { if env::attached_deposit() < $r { env::panic_str(\"deposit\") } } }";
        let app = |call: &str| {
            format!("#[near] impl Approvals for C {{ fn nft_approve(&mut self, token_id: TokenId, account_id: AccountId) {{ {call}(1); self.approve(token_id, account_id); }} }}")
        };
        let manifest = |name: &str, dependencies: &str| {
            crate::source::Manifest::parse(&format!("[package]\nname = \"{name}\"\n[dependencies]\n{dependencies}"), "[workspace]").unwrap()
        };
        let scan = |call: &str, dependencies: &str, common: &str| {
            let mut crates = [
                Crate::from_sources([("app/src/lib.rs", app(call).as_str())]).unwrap().with_manifest(manifest("app", dependencies)),
                Crate::from_sources([("common/src/lib.rs", common)]).unwrap().with_manifest(manifest("common", "")),
            ];
            crate::source::link_macros(&mut crates);
            RULE.check(&crates[0]).into_iter().map(|finding| finding.item).collect::<Vec<_>>()
        };
        assert!(scan("assert_deposit!", "common = { path = \"../common\" }", common).is_empty());
        // Not that macro, not a path dependency, not exported, or a name the crate cannot tell from another one.
        for (call, dependencies, common) in [
            ("assert_nothing!", "common = { path = \"../common\" }", common),
            ("assert_deposit!", "common = \"1\"", common),
            ("assert_deposit!", "other = { path = \"../common\" }", common),
            ("assert_deposit!", "common = { path = \"../common\" }", &common.replace("#[macro_export] ", "")),
        ] {
            assert_eq!(scan(call, dependencies, common), ["C::nft_approve"], "{call} {dependencies}");
        }
    }
}
