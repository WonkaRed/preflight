//! PF015: a method that debits a balance, sends value, and has no way to restore the debit if the send fails.
//!
//! A transfer can fail after the method has already returned: the receiver account does not exist, the token
//! contract refuses an unregistered account or is paused. A method that lowers the user's balance first and then
//! sends the value must therefore restore the balance in a callback that checks the result; otherwise the funds
//! stay in the contract and the user's record says they are gone. Docs:
//! https://docs.near.org/smart-contracts/security/checklist (callbacks) and
//! https://docs.near.org/smart-contracts/security/reentrancy
//!
//! A method is checked when the `#[near]` macro exports it (`pub` method of an inherent impl, or any method of a
//! trait impl) and its name does not start with `burn` (a burn-on-withdraw bridge means to keep the debit).
//!
//! Debit, in the method body: `place -= amount`, `place = .. - amount` (or `checked_sub`, `saturating_sub`),
//! `.insert(..)` / `.set(..)` with a subtraction in its arguments, or `.remove(..)`, where `place` is rooted at
//! `self` or at a name bound by `let b = self.<..>.get_mut(..)` (also `entry`, `as_mut`, `&mut self.<..>`).
//!
//! Send, after a debit: `Promise::new(..).transfer(..)` to a recipient that is not the caller itself
//! (`env::predecessor_account_id()`, or a name bound to it: a transfer to the account that is making the call
//! cannot fail in practice), or `ext(..).ft_transfer(..)` and the other NEP transfer calls (`ft_transfer_call`,
//! `nft_transfer`, `nft_transfer_call`, `mt_transfer`, `mt_transfer_call`, `mt_batch_transfer`,
//! `mt_batch_transfer_call`). The send must be related to the debit: the debited amount and the send's arguments
//! share a variable (`*balance -= amount; ..transfer(amount)`), or the debit is a `.remove(..)`, which takes the
//! whole record. A debit that is unrelated to the payment, such as `self.stock -= qty` followed by a refund of the
//! excess deposit, is not reported.
//!
//! Nothing restores the debit when the method has no `.then(..)` at all, or when every `.then(..)` schedules a
//! callback on the contract itself (`Self::ext(..)`, or `Type::ext(env::current_account_id())`) and none of those
//! callbacks, nor a same-crate function they reach by name, credits anything: `+=`, `.insert(..)`, `.set(..)`,
//! `.checked_add(..)`, `.saturating_add(..)` or another send. The callback need not do it only on failure; PF003
//! covers a callback that never looks at the result.
//!
//! Knowingly missed: a debit made in a helper the method calls; a payout amount first stored in a variable that
//! shares nothing with the debit (`let payout = amount - fee; ..transfer(payout)`); a `.then(..)` on another
//! contract, on a promise held in a variable, or on a callback defined outside the crate (the method is then not
//! reported); a callback that credits on success instead of failure; a native transfer to the caller.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{Span, TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{
    BinOp, Expr, ExprAssign, ExprBinary, ExprCall, ExprMethodCall, ImplItem, ItemFn, ItemImpl, Local, Pat, TraitItemFn,
    Type, Visibility,
};

use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf015NoRollback;

pub static RULE: Pf015NoRollback = Pf015NoRollback;

impl Rule for Pf015NoRollback {
    fn id(&self) -> &'static str {
        "PF015"
    }

    fn title(&self) -> &'static str {
        "Balance debited before a transfer with no rollback"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn help(&self) -> &'static str {
        "send the value with a .then(..) callback that reads the result and credits the balance back when the transfer failed"
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
        let mut by_name: BTreeMap<&str, Vec<&Func>> = BTreeMap::new();
        for func in scans.iter().flat_map(|scan| &scan.functions) {
            by_name.entry(func.name.as_str()).or_default().push(func);
        }

        let mut findings = Vec::new();
        for (file, scan) in krate.files.iter().zip(&scans) {
            for func in &scan.functions {
                let (Some(export), Some(send)) = (&func.export, &func.body.send) else { continue };
                if func.name.starts_with("burn") {
                    continue;
                }
                let Some(why) = unrecovered(&func.body, &by_name) else { continue };
                let name = format!("{}::{}", export.owner, func.name);
                findings.push(self.finding(
                    file,
                    export.span,
                    name.clone(),
                    format!(
                        "`{name}` debits a balance and then sends value with `{send}`, but {why}, so a failed transfer loses the funds"
                    ),
                ));
            }
        }
        findings
    }
}

/// Why the debit survives a failed send, or `None` when a callback may restore it or the method cannot be judged.
fn unrecovered(body: &BodyScan, by_name: &BTreeMap<&str, Vec<&Func>>) -> Option<String> {
    if body.thens == 0 {
        return Some("no callback follows the send".to_owned());
    }
    if body.callbacks.len() != body.thens {
        return None;
    }
    for callback in &body.callbacks {
        let defined = by_name.get(callback.as_str())?;
        if reaches_a_credit(defined, by_name) {
            return None;
        }
    }
    let names: Vec<String> = body.callbacks.iter().map(|callback| format!("`{callback}`")).collect();
    Some(format!("its callback {} never credits anything back", names.join(", ")))
}

/// Whether one of `start`, or a same-crate function reached from them by name, credits something.
fn reaches_a_credit(start: &[&Func], by_name: &BTreeMap<&str, Vec<&Func>>) -> bool {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut stack: Vec<&Func> = start.to_vec();
    while let Some(func) = stack.pop() {
        if func.body.credits {
            return true;
        }
        for call in &func.body.calls {
            if let Some((name, defined)) = by_name.get_key_value(call.as_str())
                && seen.insert(name)
            {
                stack.extend(defined);
            }
        }
    }
    false
}

struct Func {
    name: String,
    body: BodyScan,
    /// Set when the `#[near]` macro exports the function.
    export: Option<Export>,
}

struct Export {
    owner: String,
    span: Span,
}

#[derive(Default)]
struct FileScan {
    /// Every function with a body in the file, exported or not.
    functions: Vec<Func>,
}

impl<'ast> Visit<'ast> for FileScan {
    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        let near = item.attrs.iter().any(is_near_attr);
        let owner = type_name(&item.self_ty);
        for member in &item.items {
            if let ImplItem::Fn(method) = member {
                let export = (near && (item.trait_.is_some() || matches!(method.vis, Visibility::Public(_))))
                    .then(|| Export { owner: owner.clone(), span: method.sig.ident.span() });
                self.functions.push(func_of(&method.sig.ident, &method.block, export));
            }
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.functions.push(func_of(&item.sig.ident, &item.block, None));
        visit::visit_item_fn(self, item);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast TraitItemFn) {
        if let Some(block) = &item.default {
            self.functions.push(func_of(&item.sig.ident, block, None));
        }
        visit::visit_trait_item_fn(self, item);
    }
}

fn func_of(name: &syn::Ident, block: &syn::Block, export: Option<Export>) -> Func {
    let mut body = BodyScan::default();
    body.visit_block(block);
    Func { name: name.to_string(), body, export }
}

/// `#[near]`, `#[near(..)]` or `#[near_bindgen]`, possibly path-qualified (`#[near_sdk::near]`).
fn is_near_attr(attr: &syn::Attribute) -> bool {
    attr.path().segments.last().is_some_and(|segment| segment.ident == "near" || segment.ident == "near_bindgen")
}

fn type_name(ty: &Type) -> String {
    match ty {
        Type::Path(path) => path.path.segments.last().map_or_else(String::new, |segment| segment.ident.to_string()),
        _ => "<unnamed type>".to_owned(),
    }
}

/// NEP interface methods that send tokens to another account.
const TOKEN_SENDS: [&str; 8] = [
    "ft_transfer",
    "ft_transfer_call",
    "nft_transfer",
    "nft_transfer_call",
    "mt_transfer",
    "mt_transfer_call",
    "mt_batch_transfer",
    "mt_batch_transfer_call",
];

/// Methods that give something back to a balance.
const CREDITS: [&str; 4] = ["insert", "set", "checked_add", "saturating_add"];

/// Methods that subtract: `a.checked_sub(b)` takes `b` away from `a`.
const SUBTRACTIONS: [&str; 3] = ["checked_sub", "saturating_sub", "wrapping_sub"];

/// Methods that borrow part of the contract state mutably.
const MUTABLE_BORROWS: [&str; 5] = ["get_mut", "entry", "or_insert", "or_default", "as_mut"];

/// What one function body does, in source order (a node is judged after its children).
#[derive(Default)]
struct BodyScan {
    /// Names of the functions and methods the body calls.
    calls: BTreeSet<String>,
    /// The body adds to something, inserts into a collection or sends value.
    credits: bool,
    /// Names bound to the caller's account id.
    callers: BTreeSet<String>,
    /// Names bound to a mutable borrow of contract state.
    borrows: BTreeSet<String>,
    /// The variables of each debit's amount; `None` for a `.remove(..)`, which takes the whole record.
    debits: Vec<Option<BTreeSet<String>>>,
    /// The first send of value related to a debit that came before it.
    send: Option<String>,
    /// How many `.then(..)` calls the body makes, and which same-contract callbacks they schedule.
    thens: usize,
    callbacks: Vec<String>,
}

impl BodyScan {
    fn is_state(&self, expr: &Expr) -> bool {
        root_name(expr).is_some_and(|root| root == "self" || self.borrows.contains(&root))
    }

    fn is_caller(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Call(call) => path_ends_with(call, &["predecessor_account_id"]) || path_ends_with(call, &["signer_account_id"]),
            Expr::Path(path) => path.path.get_ident().is_some_and(|name| self.callers.contains(&name.to_string())),
            Expr::MethodCall(call) if call.method == "clone" => self.is_caller(&call.receiver),
            Expr::Reference(inner) => self.is_caller(&inner.expr),
            Expr::Paren(inner) => self.is_caller(&inner.expr),
            _ => false,
        }
    }

    /// The label of a send of value that is not to the caller itself, or `None` when `call` is not one.
    fn send_label(&self, call: &ExprMethodCall) -> Option<String> {
        let send = send_of(call)?;
        (!send.recipient.is_some_and(|recipient| self.is_caller(recipient))).then_some(send.label)
    }

    fn related_to_a_debit(&self, call: &ExprMethodCall) -> bool {
        let args = idents(call.args.iter());
        self.debits.iter().any(|debit| debit.as_ref().is_none_or(|amount| !amount.is_disjoint(&args)))
    }
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_local(&mut self, local: &'ast Local) {
        if let (Some(name), Some(init)) = (bound_name(&local.pat), &local.init) {
            if self.is_caller(&init.expr) {
                self.callers.insert(name.clone());
            }
            if borrows_mutably(&init.expr) {
                self.borrows.insert(name);
            }
        }
        visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(func) = &*call.func
            && let Some(last) = func.path.segments.last()
        {
            self.calls.insert(last.ident.to_string());
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        visit::visit_expr_binary(self, binary);
        match binary.op {
            BinOp::SubAssign(_) if self.is_state(&binary.left) => self.debits.push(Some(idents([&*binary.right]))),
            BinOp::AddAssign(_) => self.credits = true,
            _ => {}
        }
    }

    fn visit_expr_assign(&mut self, assign: &'ast ExprAssign) {
        visit::visit_expr_assign(self, assign);
        if self.is_state(&assign.left)
            && let Some(amount) = subtracted(&assign.right)
        {
            self.debits.push(Some(amount));
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        // Children first: a debit written inside the arguments of a send comes before the send.
        visit::visit_expr_method_call(self, call);
        let method = call.method.to_string();
        self.calls.insert(method.clone());
        self.credits |= CREDITS.contains(&method.as_str());
        match method.as_str() {
            "remove" if self.is_state(&call.receiver) => self.debits.push(None),
            "insert" | "set" if self.is_state(&call.receiver) => {
                if let Some(amount) = call.args.iter().filter_map(subtracted).reduce(|all, next| &all | &next) {
                    self.debits.push(Some(amount));
                }
            }
            "then" => {
                self.thens += 1;
                if let Some(Expr::MethodCall(callback)) = call.args.first()
                    && chain_root(&callback.receiver).is_some_and(is_self_ext)
                {
                    self.callbacks.push(callback.method.to_string());
                }
            }
            _ => {}
        }
        if let Some(send) = self.send_label(call) {
            self.credits = true;
            if self.send.is_none() && self.related_to_a_debit(call) {
                self.send = Some(send);
            }
        }
    }
}

/// The identifier a place expression starts from: `self` in `self.balances.get_mut(&id).unwrap()`.
pub(super) fn root_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
        Expr::Field(inner) => root_name(&inner.base),
        Expr::Index(inner) => root_name(&inner.expr),
        Expr::MethodCall(inner) => root_name(&inner.receiver),
        Expr::Unary(inner) => root_name(&inner.expr),
        Expr::Paren(inner) => root_name(&inner.expr),
        Expr::Reference(inner) => root_name(&inner.expr),
        Expr::Try(inner) => root_name(&inner.expr),
        _ => None,
    }
}

/// Whether `expr` borrows part of `self` mutably: `self.balances.get_mut(&id).unwrap()`, `&mut self.total`.
fn borrows_mutably(expr: &Expr) -> bool {
    match expr {
        Expr::Reference(inner) => (inner.mutability.is_some() && root_name(&inner.expr).is_some_and(|root| root == "self")) || borrows_mutably(&inner.expr),
        Expr::MethodCall(call) => {
            (MUTABLE_BORROWS.contains(&call.method.to_string().as_str()) && root_name(&call.receiver).is_some_and(|root| root == "self"))
                || borrows_mutably(&call.receiver)
        }
        Expr::Try(inner) => borrows_mutably(&inner.expr),
        Expr::Paren(inner) => borrows_mutably(&inner.expr),
        _ => false,
    }
}

fn bound_name(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(ident) => Some(ident.ident.to_string()),
        Pat::Type(typed) => bound_name(&typed.pat),
        _ => None,
    }
}

/// The call at the start of a method chain: `Promise::new(to)` in `Promise::new(to).transfer(x).then(cb)`.
pub(super) fn chain_root(expr: &Expr) -> Option<&ExprCall> {
    match expr {
        Expr::MethodCall(call) => chain_root(&call.receiver),
        Expr::Call(call) => Some(call),
        Expr::Paren(inner) => chain_root(&inner.expr),
        _ => None,
    }
}

/// Whether the called path ends with `tail`: `Promise::new` ends with `["Promise", "new"]` and with `["new"]`.
pub(super) fn path_ends_with(call: &ExprCall, tail: &[&str]) -> bool {
    let Expr::Path(func) = &*call.func else { return false };
    let segments = &func.path.segments;
    segments.len() >= tail.len() && segments.iter().rev().zip(tail.iter().rev()).all(|(segment, name)| segment.ident == name)
}

/// `Self::ext(..)`, or `Type::ext(env::current_account_id())`, which is how a contract schedules its own methods;
/// `ext(..)` on another contract's type schedules that contract's methods.
fn is_self_ext(root: &ExprCall) -> bool {
    path_ends_with(root, &["Self", "ext"])
        || (path_ends_with(root, &["ext"])
            && matches!(root.args.first(), Some(Expr::Call(arg)) if path_ends_with(arg, &["current_account_id"])))
}

/// The variables of every subtraction in `expr`: `x` for `a - x` and for `a.checked_sub(x)`; `None` without one.
pub(super) fn subtracted(expr: &Expr) -> Option<BTreeSet<String>> {
    #[derive(Default)]
    struct Subtractions(Option<BTreeSet<String>>);

    impl<'ast> Visit<'ast> for Subtractions {
        fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
            if matches!(binary.op, BinOp::Sub(_)) {
                self.0.get_or_insert_default().extend(idents([&*binary.right]));
            }
            visit::visit_expr_binary(self, binary);
        }

        fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
            if SUBTRACTIONS.contains(&call.method.to_string().as_str()) {
                self.0.get_or_insert_default().extend(idents(call.args.iter()));
            }
            visit::visit_expr_method_call(self, call);
        }
    }

    let mut found = Subtractions::default();
    found.visit_expr(expr);
    found.0
}

/// A send of value: `Promise::new(to).transfer(..)` or `ext(..).ft_transfer(..)` and the other NEP transfer calls.
pub(super) struct ValueSend<'a> {
    pub(super) label: String,
    /// The account of `Promise::new(..)`; `None` for a token send.
    pub(super) recipient: Option<&'a Expr>,
}

pub(super) fn send_of(call: &ExprMethodCall) -> Option<ValueSend<'_>> {
    let root = chain_root(&call.receiver)?;
    if call.method == "transfer" && path_ends_with(root, &["Promise", "new"]) {
        return Some(ValueSend { label: "Promise::new(..).transfer(..)".to_owned(), recipient: Some(root.args.first()?) });
    }
    let name = call.method.to_string();
    (TOKEN_SENDS.contains(&name.as_str()) && path_ends_with(root, &["ext"]) && !path_ends_with(root, &["Self", "ext"]))
        .then(|| ValueSend { label: format!("{name}(..)"), recipient: None })
}

/// Every identifier below the visited node, `self` excluded, including those written inside macro arguments.
#[derive(Default)]
pub(super) struct Names(pub(super) BTreeSet<String>);

impl Names {
    fn tokens(&mut self, tokens: TokenStream) {
        for tree in tokens {
            match tree {
                TokenTree::Ident(ident) => self.name(&ident),
                TokenTree::Group(group) => self.tokens(group.stream()),
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }

    fn name(&mut self, ident: &syn::Ident) {
        if ident != "self" {
            self.0.insert(ident.to_string());
        }
    }
}

impl<'ast> Visit<'ast> for Names {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        self.name(ident);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.tokens(mac.tokens.clone());
    }
}

pub(super) fn idents<'a>(exprs: impl IntoIterator<Item = &'a Expr>) -> BTreeSet<String> {
    let mut names = Names::default();
    for expr in exprs {
        names.visit_expr(expr);
    }
    names.0
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

    /// A vault whose `withdraw_to` debits first and forwards the value with no callback.
    const NO_CALLBACK: &str = r#"
        #[near]
        impl Vault {
            pub fn withdraw_to(&mut self, to: AccountId, amount: U128) -> Promise {
                assert_one_yocto();
                let caller = env::predecessor_account_id();
                let balance = self.balances.get_mut(&caller).unwrap();
                require!(*balance >= amount.0, "not enough");
                *balance -= amount.0;
                Promise::new(to).transfer(NearToken::from_yoctonear(amount.0))
            }
        }
    "#;

    #[test]
    fn flags_a_debit_then_a_transfer_with_no_callback_and_locates_it() {
        let findings = one(NO_CALLBACK);
        assert_eq!(items(&findings), ["Vault::withdraw_to"]);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF015", Severity::High));
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 4, 20));
        assert!(finding.message.contains("`Vault::withdraw_to`") && finding.message.contains("no callback follows"));
    }

    const LOGGING_CALLBACK: &str = r#"
        #[near]
        impl Vault {
            pub fn withdraw_to(&mut self, to: AccountId, amount: U128) -> Promise {
                *self.balances.get_mut(&env::predecessor_account_id()).unwrap() -= amount.0;
                Promise::new(to)
                    .transfer(NearToken::from_yoctonear(amount.0))
                    .then(Self::ext(env::current_account_id()).on_withdrawn(amount))
            }
            #[private]
            pub fn on_withdrawn(&mut self, amount: U128, #[callback_result] sent: Result<(), PromiseError>) {
                if sent.is_err() {
                    env::log_str("transfer failed");
                }
            }
        }
    "#;

    #[test]
    fn flags_a_callback_that_reads_the_result_but_never_credits_back() {
        let findings = one(LOGGING_CALLBACK);
        assert_eq!(items(&findings), ["Vault::withdraw_to"]);
        assert!(findings[0].message.contains("its callback `on_withdrawn` never credits anything back"));
    }

    #[test]
    fn a_callback_that_credits_back_is_silent() {
        let restoring = LOGGING_CALLBACK.replace(
            r#"env::log_str("transfer failed");"#,
            "*self.balances.entry(account).or_insert(0) += amount.0;",
        );
        assert!(one(&restoring).is_empty());
        for credit in ["self.balances.insert(account, amount.0);", "self.refund(amount);"] {
            let source = LOGGING_CALLBACK.replace(r#"env::log_str("transfer failed");"#, credit)
                + "#[near] impl Vault { fn refund(&mut self, amount: U128) { self.total.set(amount.0); } }";
            assert!(one(&source).is_empty(), "{credit}");
        }
    }

    #[test]
    fn a_callback_that_pays_the_value_back_is_silent() {
        let source = LOGGING_CALLBACK.replace(
            r#"env::log_str("transfer failed");"#,
            "Promise::new(account).transfer(NearToken::from_yoctonear(amount.0));",
        );
        assert!(one(&source).is_empty());
    }

    #[test]
    fn a_callback_that_credits_through_a_same_crate_helper_is_silent() {
        let source = LOGGING_CALLBACK.replace(r#"env::log_str("transfer failed");"#, "restore(self, amount);")
            + "fn restore(vault: &mut Vault, amount: U128) { vault.total += amount.0; }";
        assert!(one(&source).is_empty());
    }

    #[test]
    fn a_continuation_that_cannot_be_judged_is_silent() {
        let source = r#"#[near] impl Vault {
            pub fn out(&mut self, to: AccountId, amount: u128) -> Promise {
                self.balances.insert(me(), old - amount);
                Promise::new(to).transfer(amount).then(Self::ext(env::current_account_id()).defined_elsewhere(amount))
            }
            pub fn out_other(&mut self, to: AccountId, amount: u128) -> Promise {
                self.balances.insert(me(), old - amount);
                Promise::new(to).transfer(amount).then(other::ext(registry()).settle(amount))
            }
            pub fn out_var(&mut self, to: AccountId, amount: u128, next: Promise) -> Promise {
                self.balances.insert(me(), old - amount);
                Promise::new(to).transfer(amount).then(next)
            }
        }"#;
        assert!(one(source).is_empty());
    }

    #[test]
    fn a_callback_defined_in_another_file_is_resolved() {
        let method = r#"#[near] impl Vault {
            pub fn out(&mut self, to: AccountId, amount: u128) -> Promise {
                self.total -= amount;
                Promise::new(to).transfer(amount).then(Self::ext(env::current_account_id()).on_out())
            }
        }"#;
        let log_only = "#[near] impl Vault { #[private] pub fn on_out(&mut self) { env::log_str(\"x\"); } }";
        let credits = "#[near] impl Vault { #[private] pub fn on_out(&mut self) { self.total += 1; } }";
        assert_eq!(items(&check(&[("src/lib.rs", method), ("src/cb.rs", log_only)])), ["Vault::out"]);
        assert!(check(&[("src/lib.rs", method), ("src/cb.rs", credits)]).is_empty());
    }

    #[test]
    fn flags_every_debit_form() {
        for debit in [
            "self.total -= amount;",
            "self.total = self.total - amount;",
            "self.total = self.total.checked_sub(amount).unwrap();",
            "self.total = self.total.saturating_sub(amount);",
            "self.balances.insert(who, old - amount);",
            "self.balances.set(who, old.checked_sub(amount).unwrap());",
            "let held = self.balances.remove(&who);",
            "let slot = &mut self.total; *slot -= amount;",
            "let slot = self.balances.entry(who).or_insert(0); *slot -= amount;",
        ] {
            let source = format!(
                "#[near] impl V {{ pub fn out(&mut self, to: AccountId, amount: u128) -> Promise {{ {debit} Promise::new(to).transfer(amount) }} }}"
            );
            assert_eq!(items(&one(&source)), ["V::out"], "{debit}");
        }
    }

    #[test]
    fn flags_every_token_send() {
        for send in ["ft_transfer", "ft_transfer_call", "nft_transfer", "mt_transfer", "mt_batch_transfer_call"] {
            let source = format!(
                "#[near] impl V {{ pub fn out(&mut self, to: AccountId, amount: u128) -> Promise {{
                    self.total -= amount;
                    ext_token::ext(self.token.clone()).with_attached_deposit(ONE_YOCTO).{send}(to, amount.into())
                }} }}"
            );
            assert_eq!(items(&one(&source)), ["V::out"], "{send}");
        }
    }

    #[test]
    fn flags_a_token_send_to_the_caller_but_not_a_native_transfer_to_the_caller() {
        let template = |recipient: &str, send: &str| {
            format!(
                "#[near] impl V {{ pub fn out(&mut self, amount: u128) -> Promise {{
                    let caller = env::predecessor_account_id();
                    let again = caller.clone();
                    self.total -= amount;
                    {send}
                }} }}"
            )
            .replace("RECIPIENT", recipient)
        };
        let native = "Promise::new(RECIPIENT).transfer(amount)";
        let token = "ext_token::ext(self.token.clone()).ft_transfer(RECIPIENT, amount.into())";
        for recipient in ["caller", "again", "caller.clone()", "&caller", "env::predecessor_account_id()", "near_sdk::env::signer_account_id()"] {
            assert!(one(&template(recipient, native)).is_empty(), "native to {recipient}");
            assert_eq!(items(&one(&template(recipient, token))), ["V::out"], "token to {recipient}");
        }
        assert_eq!(items(&one(&template("self.beneficiary.clone()", native))), ["V::out"]);
    }

    #[test]
    fn a_debit_unrelated_to_the_payment_is_silent() {
        let source = "#[near] impl Shop { #[payable] pub fn buy(&mut self, qty: u128, to: AccountId) -> Promise {
            self.stock -= qty;
            let change = env::attached_deposit().as_yoctonear() - self.price * qty;
            Promise::new(to).transfer(change)
        } }";
        assert!(one(source).is_empty());
        let related = source.replace("transfer(change)", "transfer(qty * self.price)");
        assert_eq!(items(&one(&related)), ["Shop::buy"]);
    }

    #[test]
    fn a_send_before_the_debit_is_silent() {
        let source = "#[near] impl V { pub fn out(&mut self, to: AccountId, amount: u128) {
            Promise::new(to).transfer(amount);
            self.total -= amount;
        } }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn a_debit_that_is_not_contract_state_is_silent() {
        let source = "#[near] impl V { pub fn out(&mut self, to: AccountId, mut amount: u128) -> Promise {
            let mut fee = amount / 100;
            fee -= 1;
            amount -= fee;
            let mut copy = self.accounts.get(&to).cloned().unwrap();
            copy.balance -= amount;
            Promise::new(to).transfer(amount)
        } }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn burn_methods_and_methods_the_macro_does_not_export_are_silent() {
        let burn = NO_CALLBACK.replace("withdraw_to", "burn_to_withdraw");
        assert!(one(&burn).is_empty());
        let private = NO_CALLBACK.replace("pub fn", "fn");
        assert!(one(&private).is_empty());
        let not_near = NO_CALLBACK.replace("#[near]", "");
        assert!(one(&not_near).is_empty());
    }

    #[test]
    fn a_transfer_to_another_contract_without_ext_is_silent() {
        let source = "#[near] impl V { pub fn out(&mut self, to: AccountId, amount: u128) {
            self.total -= amount;
            self.token.ft_transfer(to, amount);
            wallet.transfer(amount);
            Payment::new(to).transfer(amount);
            Self::ext(env::current_account_id()).ft_transfer(to, amount);
        } }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn accepts_near_bindgen_and_trait_impls_and_reports_each_method_once() {
        for attr in ["#[near_bindgen]", "#[near_sdk::near]", "#[near(contract_state)]"] {
            let source = NO_CALLBACK.replace("#[near]", attr);
            assert_eq!(items(&one(&source)), ["Vault::withdraw_to"], "{attr}");
        }
        let in_trait = NO_CALLBACK.replace("impl Vault", "impl Payout for Vault").replace("pub fn", "fn");
        assert_eq!(items(&one(&in_trait)), ["Vault::withdraw_to"]);
        let two_sends = "#[near] impl V { pub fn out(&mut self, a: AccountId, b: AccountId, x: u128) {
            self.total -= x;
            Promise::new(a).transfer(x);
            Promise::new(b).transfer(x);
        } }";
        assert_eq!(one(two_sends).len(), 1);
    }
}
