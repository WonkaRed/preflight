//! PF026: a function schedules a transfer and then panics on the same path, so the transfer is discarded.
//!
//! A panic fails the whole receipt: its state changes are rolled back and every promise it created is dropped,
//! the transfer included. A contract that logs that a refund is queued, schedules the refund and
//! then calls `env::panic_str` therefore refunds nobody. In a callback the money came in an earlier receipt that
//! succeeded, so it stays in the contract. In a plain method the runtime hands the attached deposit of a failed call
//! back to the caller by itself, so what is left is a message that claims a transfer which never happened. Docs:
//! https://docs.near.org/smart-contracts/security/callbacks and https://docs.near.org/protocol/transaction-anatomy
//!
//! Every function with a body is checked (methods of any impl, free functions, default trait methods; code under
//! `#[cfg(test)]` and `#[test]` is not).
//!
//! A send of value is `Promise::new(..).transfer(..)`, a call on `ext(..)` or `ext_<name>::ext(..)` to one of the
//! NEP token methods (`ft_transfer`, `ft_transfer_call`, `nft_transfer`, `nft_transfer_call`, `mt_transfer`,
//! `mt_transfer_call`, `mt_batch_transfer`, `mt_batch_transfer_call`; PF015's `send_of`), or a `function_call` whose
//! method name is a string literal naming one of those methods.
//!
//! A guaranteed panic is `env::panic_str(..)`, `env::abort()`, `env::panic(..)`, `panic!`, `unreachable!`, `todo!`,
//! `unimplemented!`, `require!(false, ..)` or `assert!(false, ..)`; a call to a same-crate function that panics on
//! every path (`fail(..)`, `Self::fail(..)`, `self.fail(..)`, found by name and only when every definition of that
//! name panics on every path, `-> !` or not); an `if`/`else` or `match` whose branches all panic; and a block
//! that reaches one of these without any `return`, `break` or `continue` before it.
//!
//! "On the same path" means: the send is created in a statement of some block, on a path that falls through to the
//! end of that statement (a send followed by `return` inside a branch does not count), and a later statement of the
//! same block is a guaranteed panic. The send may sit deeper, inside a branch, loop body or argument of that earlier
//! statement; the panic must be a statement of the block itself, so it runs on every path that gets past the
//! send. Where several sends precede it, the first is named. A function with several such panics gets one finding,
//! at its first send, which counts the others.
//!
//! A function is a callback when it is marked `#[private]`, takes a `#[callback]`, `#[callback_unwrap]`,
//! `#[callback_result]` or `#[callback_vec]` argument, or mentions `promise_result`, `promise_results_count`,
//! `promise_result_checked`, `promise_result_as_success` or `is_promise_success` (the funds it sends came in an
//! earlier receipt). The finding is high for a callback and medium for any other function.
//!
//! Knowingly silent: a panic that is itself conditional after the send (`require!(cond, ..)`, `assert!(cond)`,
//! `if bad { panic!() }`, which may or may not run, so the send could be intended to survive; a send and a panic
//! in different branches of one `if`; a send made in another function the panicking one calls (`self.refund(..);
//! env::panic_str(..)`); a send inside a closure; a send followed by `break` or `continue` in a loop body; a transfer
//! whose promise is held in a variable (`let p = Promise::new(..); p.transfer(..)`); an `Err` returned from a
//! `#[handle_result]` method, which the SDK turns into a panic; an `.unwrap()` or `.expect(..)` that happens to
//! fail; a helper that sends and then panics, which is reported on its own as a non-callback (medium) even when a
//! callback calls it.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{Span, TokenTree};
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::token::Comma;
use syn::{Attribute, Block, Expr, ExprCall, ExprMethodCall, FnArg, ImplItem, ItemFn, ItemImpl, ItemMod, Lit, Macro, Stmt, TraitItemFn};

use super::pf007_unguarded_admin::type_name;
use super::pf015_no_rollback::{Names, path_ends_with, send_of};
use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf026RefundThenPanic;

pub static RULE: Pf026RefundThenPanic = Pf026RefundThenPanic;

impl Rule for Pf026RefundThenPanic {
    fn id(&self) -> &'static str {
        "PF026"
    }

    fn title(&self) -> &'static str {
        "Refund scheduled and then discarded by a panic"
    }

    /// The highest severity a finding of this rule has; a function that is not a callback gets medium.
    fn severity(&self) -> Severity {
        Severity::High
    }

    fn help(&self) -> &'static str {
        "return normally after scheduling the transfer so the receipt succeeds and the promise runs, or panic without scheduling it; a panic discards every promise the receipt created"
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
        let diverging = diverging_names(scans.iter().flat_map(|scan| &scan.functions));

        let mut findings = Vec::new();
        for (file, scan) in krate.files.iter().zip(&scans) {
            for func in &scan.functions {
                let mut walk = Walk::new(&diverging);
                walk.block(func.body);
                let mut hits = walk.hits;
                hits.sort_by_key(|hit| (hit.send.span.start().line, hit.send.span.start().column));
                let Some(first) = hits.first() else { continue };

                let item = func.item();
                let more = match hits.len() - 1 {
                    0 => String::new(),
                    1 => " (and 1 more such path in this function)".to_owned(),
                    n => format!(" (and {n} more such paths in this function)"),
                };
                let effect = if func.callback {
                    "It is a callback: the funds arrived in an earlier receipt that already succeeded, so the panic does \
                     not refund them; they stay in the contract while the message or log says they were returned"
                } else {
                    "It is not a callback: the runtime refunds a deposit attached to a failed call by itself, so the \
                     effect is a message that claims a transfer which never happened, not a loss of funds (funds that \
                     came in an earlier receipt would be lost if a callback reaches this code)"
                };
                let mut finding = self.finding(
                    file,
                    first.send.span,
                    item.clone(),
                    format!(
                        "`{item}` schedules `{}` and then reaches `{}` on the same path, so the promise is dropped with the failed receipt and nothing is sent{more}. {effect}",
                        first.send.label, first.panic
                    ),
                );
                if !func.callback {
                    finding.severity = Severity::Medium;
                }
                findings.push(finding);
            }
        }
        findings
    }
}

/// Names of the functions that panic on every path, for every definition of the name in the crate. Calling one is a
/// guaranteed panic. Grown to a fixed point, so a helper that calls a helper counts.
fn diverging_names<'a>(functions: impl Iterator<Item = &'a Func<'a>>) -> BTreeSet<String> {
    let mut by_name: BTreeMap<&str, Vec<&Func>> = BTreeMap::new();
    for func in functions {
        by_name.entry(func.name.as_str()).or_default().push(func);
    }
    let mut diverging = BTreeSet::new();
    loop {
        let next: BTreeSet<String> = by_name
            .iter()
            .filter(|(_, definitions)| definitions.iter().all(|func| Walk::new(&diverging).block(func.body).all_panic()))
            .map(|(name, _)| (*name).to_owned())
            .collect();
        if next == diverging {
            return diverging;
        }
        diverging = next;
    }
}

struct Func<'ast> {
    name: String,
    /// The impl's type, for a method.
    owner: Option<String>,
    callback: bool,
    body: &'ast Block,
}

impl Func<'_> {
    fn item(&self) -> String {
        self.owner.as_ref().map_or_else(|| self.name.clone(), |owner| format!("{owner}::{}", self.name))
    }
}

#[derive(Default)]
struct FileScan<'ast> {
    functions: Vec<Func<'ast>>,
}

impl<'ast> FileScan<'ast> {
    fn push(
        &mut self,
        name: &syn::Ident,
        owner: Option<&str>,
        attrs: &[Attribute],
        inputs: &Punctuated<FnArg, Comma>,
        body: &'ast Block,
    ) {
        if !is_test_only(attrs) {
            let callback = is_callback(attrs, inputs, body);
            self.functions.push(Func { name: name.to_string(), owner: owner.map(str::to_owned), callback, body });
        }
    }
}

impl<'ast> Visit<'ast> for FileScan<'ast> {
    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        if !is_test_only(&item.attrs) {
            visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        if is_test_only(&item.attrs) {
            return;
        }
        let owner = type_name(&item.self_ty);
        for member in &item.items {
            if let ImplItem::Fn(method) = member {
                self.push(&method.sig.ident, Some(&owner), &method.attrs, &method.sig.inputs, &method.block);
            }
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        if !is_test_only(&item.attrs) {
            self.push(&item.sig.ident, None, &item.attrs, &item.sig.inputs, &item.block);
            visit::visit_item_fn(self, item);
        }
    }

    fn visit_trait_item_fn(&mut self, item: &'ast TraitItemFn) {
        if let Some(block) = &item.default {
            self.push(&item.sig.ident, None, &item.attrs, &item.sig.inputs, block);
        }
        visit::visit_trait_item_fn(self, item);
    }
}

/// `#[cfg(test)]` or `#[test]`.
fn is_test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test") || attr.path().is_ident("cfg") && attr.parse_args::<syn::Ident>().is_ok_and(|ident| ident == "test")
    })
}

const CALLBACK_ARG_ATTRS: [&str; 4] = ["callback", "callback_unwrap", "callback_result", "callback_vec"];

/// Host and SDK functions that read what an earlier receipt produced.
const PROMISE_RESULT_READS: [&str; 5] =
    ["promise_result", "promise_results_count", "promise_result_checked", "promise_result_as_success", "is_promise_success"];

/// NEP transfer methods; the `function_call` form names one of them as a string. The same list as PF015's
/// `TOKEN_SENDS`, which that rule keeps private.
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

fn has_attr(attrs: &[Attribute], names: &[&str]) -> bool {
    attrs.iter().any(|attr| attr.path().segments.last().is_some_and(|segment| names.iter().any(|name| segment.ident == name)))
}

fn is_callback(attrs: &[Attribute], inputs: &Punctuated<FnArg, Comma>, body: &Block) -> bool {
    has_attr(attrs, &["private"])
        || inputs.iter().any(|arg| matches!(arg, FnArg::Typed(typed) if has_attr(&typed.attrs, &CALLBACK_ARG_ATTRS)))
        || {
            let mut names = Names::default();
            names.visit_block(body);
            PROMISE_RESULT_READS.iter().any(|read| names.0.contains(*read))
        }
}

/// A send of value, where it is written.
#[derive(Clone)]
struct Send {
    label: String,
    span: Span,
}

/// A send that a later guaranteed panic discards.
struct Hit {
    send: Send,
    panic: String,
}

/// What running a piece of code can do, over every path through it. The paths that fall out of the end are
/// `completes`; the others leave (`return`, `break`, `continue`) or panic.
struct Out {
    /// The first send created on a path that completes. Always `None` when nothing completes.
    send: Option<Send>,
    completes: bool,
    /// Some path leaves with `return`, `break` or `continue`.
    leaves: bool,
    /// A path panics, and how.
    panic: Option<String>,
}

impl Out {
    fn completing() -> Self {
        Self { send: None, completes: true, leaves: false, panic: None }
    }

    fn sending(send: Send) -> Self {
        Self { send: Some(send), ..Self::completing() }
    }

    fn leaving() -> Self {
        Self { completes: false, leaves: true, ..Self::completing() }
    }

    fn panicking(panic: String) -> Self {
        Self { completes: false, panic: Some(panic), ..Self::completing() }
    }

    /// The code of `self`, and then, on the paths that complete, the code of `next`.
    fn then(self, next: Self) -> Self {
        if !self.completes {
            return self;
        }
        Self {
            send: if next.completes { self.send.or(next.send) } else { None },
            completes: next.completes,
            leaves: self.leaves || next.leaves,
            panic: self.panic.or(next.panic),
        }
    }

    /// One of two alternative branches runs.
    fn either(self, other: Self) -> Self {
        Self {
            send: self.send.or(other.send),
            completes: self.completes || other.completes,
            leaves: self.leaves || other.leaves,
            panic: self.panic.or(other.panic),
        }
    }

    /// Every path panics: none falls through and none leaves.
    fn all_panic(&self) -> bool {
        !self.completes && !self.leaves && self.panic.is_some()
    }
}

struct Walk<'a> {
    diverging: &'a BTreeSet<String>,
    hits: Vec<Hit>,
}

impl<'a> Walk<'a> {
    fn new(diverging: &'a BTreeSet<String>) -> Self {
        Self { diverging, hits: Vec::new() }
    }

    /// Runs the statements in order; a statement that panics on every path while an earlier statement of the same
    /// block has created a send on a completing path is a hit.
    fn block(&mut self, block: &Block) -> Out {
        let mut total = Out::completing();
        for stmt in &block.stmts {
            let out = self.stmt(stmt);
            if out.all_panic()
                && let (Some(send), Some(panic)) = (&total.send, &out.panic)
            {
                self.hits.push(Hit { send: send.clone(), panic: panic.clone() });
            }
            total = total.then(out);
            if !total.completes {
                break;
            }
        }
        total
    }

    fn stmt(&mut self, stmt: &Stmt) -> Out {
        match stmt {
            Stmt::Local(local) => match &local.init {
                None => Out::completing(),
                Some(init) => {
                    let out = self.expr(&init.expr);
                    if let Some((_, diverge)) = &init.diverge {
                        self.expr(diverge);
                    }
                    out
                }
            },
            Stmt::Expr(expr, _) => self.expr(expr),
            Stmt::Macro(stmt) => panic_macro(&stmt.mac).map_or_else(Out::completing, Out::panicking),
            Stmt::Item(_) => Out::completing(),
        }
    }

    fn expr(&mut self, expr: &Expr) -> Out {
        match expr {
            Expr::If(branch) => {
                let cond = self.expr(&branch.cond);
                let then = self.block(&branch.then_branch);
                let otherwise = match &branch.else_branch {
                    Some((_, expr)) => self.expr(expr),
                    None => Out::completing(),
                };
                cond.then(then.either(otherwise))
            }
            Expr::Match(branch) => {
                let scrutinee = self.expr(&branch.expr);
                let mut arms: Option<Out> = None;
                for arm in &branch.arms {
                    if let Some((_, guard)) = &arm.guard {
                        self.expr(guard);
                    }
                    let body = self.expr(&arm.body);
                    arms = Some(match arms {
                        Some(earlier) => earlier.either(body),
                        None => body,
                    });
                }
                scrutinee.then(arms.unwrap_or_else(Out::completing))
            }
            Expr::Block(block) => self.block(&block.block),
            Expr::Unsafe(block) => self.block(&block.block),
            Expr::While(looped) => {
                let cond = self.expr(&looped.cond);
                let body = self.block(&looped.body);
                cond.then(Out { send: body.send, ..Out::completing() })
            }
            Expr::ForLoop(looped) => {
                let iterated = self.expr(&looped.expr);
                let body = self.block(&looped.body);
                iterated.then(Out { send: body.send, ..Out::completing() })
            }
            Expr::Loop(looped) => {
                let body = self.block(&looped.body);
                Out { send: body.send, ..Out::completing() }
            }
            Expr::Closure(closure) => {
                // Not run here: its sends and panics belong to whoever calls it.
                self.expr(&closure.body);
                Out::completing()
            }
            Expr::Return(ret) => {
                if let Some(value) = &ret.expr {
                    self.expr(value);
                }
                Out::leaving()
            }
            Expr::Break(brk) => {
                if let Some(value) = &brk.expr {
                    self.expr(value);
                }
                Out::leaving()
            }
            Expr::Continue(_) => Out::leaving(),
            Expr::Macro(mac) => panic_macro(&mac.mac).map_or_else(Out::completing, Out::panicking),
            Expr::Call(call) => {
                let mut out = self.expr(&call.func);
                for arg in &call.args {
                    out = out.then(self.expr(arg));
                }
                match self.panic_call(call) {
                    Some(panic) => out.then(Out::panicking(panic)),
                    None => out,
                }
            }
            Expr::MethodCall(call) => {
                let mut out = self.expr(&call.receiver);
                for arg in &call.args {
                    out = out.then(self.expr(arg));
                }
                if let Some(label) = send_label(call) {
                    out.then(Out::sending(Send { label, span: call.method.span() }))
                } else if let Some(panic) = self.panic_method(call) {
                    out.then(Out::panicking(panic))
                } else {
                    out
                }
            }
            _ => {
                let mut children = Children(Vec::new());
                visit::visit_expr(&mut children, expr);
                children.0.into_iter().fold(Out::completing(), |out, child| out.then(self.expr(child)))
            }
        }
    }

    /// `env::panic_str(..)` and the like, or a call to a same-crate function that always panics.
    fn panic_call(&self, call: &ExprCall) -> Option<String> {
        if path_ends_with(call, &["panic_str"]) {
            return Some("env::panic_str(..)".to_owned());
        }
        for name in ["abort", "panic"] {
            if path_ends_with(call, &["env", name]) {
                return Some(format!("env::{name}(..)"));
            }
        }
        let Expr::Path(func) = &*call.func else { return None };
        let segments: Vec<String> = func.path.segments.iter().map(|segment| segment.ident.to_string()).collect();
        let name = match segments.as_slice() {
            [name] => name,
            [owner, name] if owner == "Self" => name,
            _ => return None,
        };
        self.diverging.contains(name).then(|| format!("{name}(..)"))
    }

    /// `self.fail(..)` where `fail` always panics.
    fn panic_method(&self, call: &ExprMethodCall) -> Option<String> {
        let on_self = matches!(&*call.receiver, Expr::Path(path) if path.path.is_ident("self"));
        let name = call.method.to_string();
        (on_self && self.diverging.contains(&name)).then(|| format!("self.{name}(..)"))
    }
}

/// The immediate sub-expressions of an expression, in source order.
struct Children<'ast>(Vec<&'ast Expr>);

impl<'ast> Visit<'ast> for Children<'ast> {
    fn visit_expr(&mut self, expr: &'ast Expr) {
        self.0.push(expr);
    }
}

/// A macro that panics whenever it runs: `panic!`, `unreachable!`, `todo!`, `unimplemented!`, and `require!` or
/// `assert!` whose condition is the literal `false`.
fn panic_macro(mac: &Macro) -> Option<String> {
    let name = mac.path.segments.last()?.ident.to_string();
    match name.as_str() {
        "panic" | "unreachable" | "todo" | "unimplemented" => Some(format!("{name}!(..)")),
        "require" | "assert" if starts_with_false(mac) => Some(format!("{name}!(false, ..)")),
        _ => None,
    }
}

fn starts_with_false(mac: &Macro) -> bool {
    let mut tokens = mac.tokens.clone().into_iter();
    matches!(tokens.next(), Some(TokenTree::Ident(first)) if first == "false")
        && tokens.next().is_none_or(|next| matches!(next, TokenTree::Punct(comma) if comma.as_char() == ','))
}

/// How a send of value is written: PF015's `Promise::new(..).transfer(..)` and NEP token sends, or a
/// `function_call("ft_transfer", ..)`.
fn send_label(call: &ExprMethodCall) -> Option<String> {
    if let Some(send) = send_of(call) {
        return Some(send.label);
    }
    if call.method != "function_call" && call.method != "function_call_weight" {
        return None;
    }
    let method = string_literal(call.args.first()?)?;
    TOKEN_SENDS.contains(&method.as_str()).then(|| format!("function_call(\"{method}\", ..)"))
}

/// The text of `"name"`, `"name".to_string()`, `"name".into()` and `&"name"`.
fn string_literal(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Lit(lit) => match &lit.lit {
            Lit::Str(text) => Some(text.value()),
            _ => None,
        },
        Expr::MethodCall(call) if call.args.is_empty() => string_literal(&call.receiver),
        Expr::Reference(inner) => string_literal(&inner.expr),
        Expr::Paren(inner) => string_literal(&inner.expr),
        _ => None,
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

    /// A plain method: the refund is scheduled and the panic follows in the same block.
    fn plain(body: &str) -> String {
        format!("#[near] impl Desk {{ pub fn reject(&mut self, buyer: AccountId, deposit: u128) {{ {body} }} }}")
    }

    const REFUND: &str = "Promise::new(buyer).transfer(NearToken::from_yoctonear(deposit));";

    /// The shape the rule targets: a callback that refunds and panics on two paths.
    const CALLBACK: &str = r#"
        #[near]
        impl Desk {
            #[private]
            pub fn on_seat_checked(&mut self, buyer_id: AccountId, deposit: U128, #[callback_result] seat_result: Result<bool, PromiseError>) {
                if seat_result.is_err() {
                    log!("refund of {} yocto queued for {}", deposit.0, buyer_id);
                    Promise::new(buyer_id).transfer(deposit.0);
                    env::panic_str("Seat check failed. A refund is queued for the buyer.");
                }
                let seat_free = seat_result.unwrap();
                if !seat_free {
                    Promise::new(buyer_id).transfer(deposit.0);
                    env::panic_str("Seat is taken. A refund is queued for the buyer.");
                }
                self.paid += deposit.0;
            }
        }
    "#;

    #[test]
    fn flags_a_callback_that_refunds_and_panics_once_per_function_and_locates_the_first_send() {
        let findings = one(CALLBACK);
        assert_eq!(items(&findings), ["Desk::on_seat_checked"]);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF026", Severity::High));
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 8, 44));
        for text in [
            "`Desk::on_seat_checked` schedules `Promise::new(..).transfer(..)`",
            "`env::panic_str(..)`",
            "(and 1 more such path in this function)",
            "It is a callback",
            "stay in the contract",
        ] {
            assert!(finding.message.contains(text), "{text}: {}", finding.message);
        }
    }

    #[test]
    fn a_plain_method_is_medium_and_the_message_says_nothing_is_lost() {
        let findings = one(&plain(&format!("{REFUND} env::panic_str(\"returned\");")));
        assert_eq!(items(&findings), ["Desk::reject"]);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("It is not a callback"), "{}", findings[0].message);
        assert!(findings[0].message.contains("refunds a deposit attached to a failed call"), "{}", findings[0].message);
        assert!(findings[0].message.contains("not a loss of funds"), "{}", findings[0].message);
    }

    #[test]
    fn every_callback_marker_makes_it_high() {
        let body = format!("{REFUND} env::panic_str(\"returned\");");
        let variants = [
            format!("#[private] pub fn reject(&mut self, buyer: AccountId, deposit: u128) {{ {body} }}"),
            format!("pub fn reject(&mut self, buyer: AccountId, deposit: u128, #[callback_result] r: Result<bool, PromiseError>) {{ {body} }}"),
            format!("pub fn reject(&mut self, buyer: AccountId, deposit: u128, #[callback_unwrap] ok: bool) {{ {body} }}"),
            format!("pub fn reject(&mut self, buyer: AccountId, deposit: u128) {{ let r = env::promise_result(0); {body} }}"),
            format!("pub fn reject(&mut self, buyer: AccountId, deposit: u128) {{ require!(is_promise_success(), \"x\"); {body} }}"),
            format!("pub fn reject(&mut self, buyer: AccountId, deposit: u128) {{ let n = near_sdk::env::promise_results_count(); {body} }}"),
        ];
        for method in variants {
            let findings = one(&format!("#[near] impl Desk {{ {method} }}"));
            assert_eq!(items(&findings), ["Desk::reject"], "{method}");
            assert_eq!(findings[0].severity, Severity::High, "{method}");
        }
    }

    #[test]
    fn flags_every_panic_form() {
        for panic in [
            "env::panic_str(\"returned\");",
            "near_sdk::env::panic_str(\"returned\");",
            "panic_str(\"returned\");",
            "env::abort();",
            "near_sdk::env::abort();",
            "env::panic(b\"returned\");",
            "panic!(\"returned {}\", buyer);",
            "std::panic!(\"returned\");",
            "unreachable!();",
            "todo!();",
            "unimplemented!();",
            "require!(false, \"returned\");",
            "near_sdk::require!(false, \"returned\");",
            "require!(false);",
            "assert!(false, \"returned\");",
            "env::panic_str(\"returned\")",
            "panic!(\"returned\")",
        ] {
            let findings = one(&plain(&format!("{REFUND} {panic}")));
            assert_eq!(items(&findings), ["Desk::reject"], "{panic}");
        }
    }

    #[test]
    fn flags_every_send_form() {
        for send in [
            "Promise::new(buyer).transfer(NearToken::from_yoctonear(deposit));",
            "Promise::new(buyer).transfer(NearToken::from_yoctonear(deposit)).detach();",
            "near_sdk::Promise::new(buyer).transfer(deposit).then(Self::ext(env::current_account_id()).done());",
            "Promise::new(buyer).create_account().transfer(deposit);",
            "ext_token::ext(self.token.clone()).with_attached_deposit(ONE_YOCTO).ft_transfer(buyer, deposit.into(), None);",
            "ext_token::ext(self.token.clone()).ft_transfer_call(buyer, deposit.into(), None, msg);",
            "ext_nft::ext(self.nft.clone()).nft_transfer(buyer, id, None, None);",
            "ext(self.token.clone()).mt_batch_transfer_call(buyer, ids, amounts, None, None, msg);",
            "Promise::new(token).function_call(\"ft_transfer\".to_string(), args, ONE_YOCTO, GAS);",
            "Promise::new(token).function_call(\"nft_transfer_call\".into(), args, ONE_YOCTO, GAS);",
            "Promise::new(token).function_call(String::from(\"ft_transfer\"), args, ONE_YOCTO, GAS);",
            "Promise::new(token).function_call_weight(\"ft_transfer\".to_owned(), args, ONE_YOCTO, GAS, GasWeight(1));",
            "let refund = Promise::new(buyer).transfer(deposit);",
            "let _ = Promise::new(buyer).transfer(deposit);",
        ] {
            // `String::from("ft_transfer")` is not a literal: it is checked below as a miss.
            let expected = if send.contains("String::from") { 0 } else { 1 };
            let findings = one(&plain(&format!("{send} env::panic_str(\"returned\");")));
            assert_eq!(findings.len(), expected, "{send}");
        }
    }

    #[test]
    fn flags_a_send_in_a_branch_followed_by_a_panic_in_the_enclosing_block() {
        let source = plain(&format!(
            "if deposit > 0 {{ {REFUND} }} else {{ log!(\"nothing\"); }}
             env::panic_str(\"returned\");"
        ));
        assert_eq!(items(&one(&source)), ["Desk::reject"]);
        let in_match = plain(&format!(
            "match deposit {{ 0 => {{}}, _ => {{ {REFUND} }} }}
             env::panic_str(\"returned\");"
        ));
        assert_eq!(items(&one(&in_match)), ["Desk::reject"]);
        let in_loop = plain(&format!("for _ in 0..2 {{ {REFUND} }} env::panic_str(\"returned\");"));
        assert_eq!(items(&one(&in_loop)), ["Desk::reject"]);
        let in_block = plain(&format!("{{ {REFUND} }} env::panic_str(\"returned\");"));
        assert_eq!(items(&one(&in_block)), ["Desk::reject"]);
    }

    #[test]
    fn flags_a_send_and_a_panic_inside_the_same_inner_block_and_inside_a_let_else_or_closure() {
        let in_if = plain(&format!("if deposit > 0 {{ {REFUND} env::panic_str(\"returned\"); }}"));
        assert_eq!(items(&one(&in_if)), ["Desk::reject"]);
        let in_else = plain(&format!("let Some(x) = deposit.checked_add(1) else {{ {REFUND} env::panic_str(\"returned\"); }};"));
        assert_eq!(items(&one(&in_else)), ["Desk::reject"]);
        let in_closure = plain(&format!("let fail = |_e| {{ {REFUND} env::panic_str(\"returned\") }};"));
        assert_eq!(items(&one(&in_closure)), ["Desk::reject"]);
    }

    #[test]
    fn flags_a_panic_that_every_branch_reaches_and_a_helper_that_always_panics() {
        let both = plain(&format!("{REFUND} if deposit > 0 {{ panic!(\"a\") }} else {{ env::panic_str(\"b\") }}"));
        assert_eq!(items(&one(&both)), ["Desk::reject"]);
        let arms = plain(&format!("{REFUND} match deposit {{ 0 => panic!(\"a\"), _ => unreachable!() }}"));
        assert_eq!(items(&one(&arms)), ["Desk::reject"]);
        let block = plain(&format!("{REFUND} {{ log!(\"x\"); env::panic_str(\"b\") }}"));
        assert_eq!(items(&one(&block)), ["Desk::reject"]);

        let helpers = [
            ("fail(\"x\")", "fn fail(message: &str) -> ! { env::panic_str(message) }"),
            ("fail(\"x\")", "fn fail(message: &str) { env::panic_str(message); }"),
            ("Self::fail(\"x\")", "impl Desk { fn fail(message: &str) -> ! { panic!(\"{}\", message) } }"),
            ("self.fail(\"x\")", "impl Desk { fn fail(&self, message: &str) { log!(\"x\"); env::abort() } }"),
            ("fail(\"x\")", "fn fail(message: &str) { stop(message) } fn stop(message: &str) { env::panic_str(message) }"),
        ];
        for (call, definition) in helpers {
            let source = format!("{} {definition}", plain(&format!("{REFUND} {call};")));
            assert_eq!(items(&one(&source)), ["Desk::reject"], "{call} with {definition}");
        }
    }

    #[test]
    fn a_helper_that_does_not_always_panic_is_not_a_panic() {
        for definition in [
            "fn fail(message: &str) { if message.is_empty() { env::panic_str(message) } }",
            "fn fail(message: &str) { if message.is_empty() { return; } env::panic_str(message) }",
            "fn fail(message: &str) -> u32 { env::panic_str(message) } impl Other { fn fail(&self) { log!(\"x\"); } }",
            "fn fail(message: &str) { log!(\"x\") }",
        ] {
            let source = format!("{} {definition}", plain(&format!("{REFUND} fail(\"x\");")));
            assert!(one(&source).is_empty(), "{definition}");
        }
        // A method of another type with the same name as an always-panicking free function still counts, because
        // calls are resolved by name only: this is the documented limit, and one definition that returns breaks it.
        let ambiguous = format!(
            "{} fn fail() {{ panic!() }} impl Other {{ fn fail() {{}} }}",
            plain(&format!("{REFUND} fail();"))
        );
        assert!(one(&ambiguous).is_empty());
    }

    #[test]
    fn a_helper_reaching_the_panic_across_files_is_resolved() {
        let method = plain(&format!("{REFUND} abort_with(\"x\");"));
        let helper = "fn abort_with(message: &str) { env::panic_str(message) }";
        assert_eq!(items(&check(&[("src/lib.rs", &method), ("src/util.rs", helper)])), ["Desk::reject"]);
        assert!(check(&[("src/lib.rs", &method)]).is_empty());
    }

    #[test]
    fn flags_free_functions_and_default_trait_methods() {
        let free = "fn settle(buyer: AccountId, deposit: u128) { Promise::new(buyer).transfer(deposit); env::panic_str(\"x\") }";
        assert_eq!(items(&one(free)), ["settle"]);
        let default = "trait Settle { fn settle(&self, buyer: AccountId, deposit: u128) { Promise::new(buyer).transfer(deposit); panic!(\"x\"); } }";
        assert_eq!(items(&one(default)), ["settle"]);
    }

    #[test]
    fn counts_every_path_of_a_function_but_reports_it_once() {
        let source = plain(&format!(
            "if deposit == 1 {{ {REFUND} env::panic_str(\"a\"); }}
             if deposit == 2 {{ {REFUND} env::panic_str(\"b\"); }}
             if deposit == 3 {{ {REFUND} env::panic_str(\"c\"); }}"
        ));
        let findings = one(&source);
        assert_eq!(items(&findings), ["Desk::reject"]);
        assert!(findings[0].message.contains("(and 2 more such paths in this function)"), "{}", findings[0].message);
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn a_promise_then_a_normal_return_is_silent() {
        for body in [
            REFUND.to_owned(),
            format!("{REFUND} log!(\"returned\");"),
            format!("{REFUND} return;"),
            format!("if deposit > 0 {{ {REFUND} return; }} env::panic_str(\"x\");"),
            format!("if deposit > 0 {{ {REFUND} log!(\"x\"); return; }} else {{ return; }}"),
            format!("{REFUND} return; env::panic_str(\"unreachable in practice\");"),
        ] {
            assert!(one(&plain(&body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn a_panic_before_the_promise_is_silent() {
        let before = plain(&format!("env::panic_str(\"x\"); {REFUND}"));
        assert!(one(&before).is_empty());
        let guarded = plain(&format!("require!(deposit > 0, \"x\"); if deposit > 9 {{ panic!(\"big\") }} {REFUND}"));
        assert!(one(&guarded).is_empty());
    }

    #[test]
    fn a_conditional_panic_after_the_promise_is_silent() {
        for check_after in [
            "require!(deposit > 0, \"x\");",
            "require!(deposit > 0);",
            "near_sdk::require!(self.open, \"closed\");",
            "assert!(deposit > 0);",
            "assert_eq!(deposit, 1);",
            "if deposit == 0 { env::panic_str(\"x\"); }",
            "if deposit == 0 { panic!(\"x\"); } else { log!(\"fine\"); }",
            "match deposit { 0 => panic!(\"x\"), _ => {} }",
            "let _ = deposit.checked_sub(1).unwrap();",
            "let _ = deposit.checked_sub(1).expect(\"underflow\");",
            "deposit.checked_sub(1).unwrap_or_else(|| env::panic_str(\"x\"));",
            "debug_assert!(false);",
        ] {
            assert!(one(&plain(&format!("{REFUND} {check_after}"))).is_empty(), "{check_after}");
        }
    }

    #[test]
    fn a_promise_and_a_panic_in_exclusive_branches_are_silent() {
        for body in [
            format!("if deposit > 0 {{ {REFUND} }} else {{ env::panic_str(\"x\"); }}"),
            format!("if deposit > 0 {{ env::panic_str(\"x\"); }} else {{ {REFUND} }}"),
            format!("match deposit {{ 0 => env::panic_str(\"x\"), _ => {{ {REFUND} }} }}"),
            format!("if deposit > 0 {{ {REFUND} }} else if deposit == 0 {{ panic!(\"x\") }} else {{ unreachable!() }}"),
            format!("if deposit > 0 {{ {REFUND} return; }} panic!(\"nothing to return\");"),
        ] {
            assert!(one(&plain(&body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn a_send_in_a_closure_or_another_function_is_not_followed() {
        let closure = plain(&format!("let later = |buyer: AccountId| {{ {REFUND} }}; env::panic_str(\"x\");"));
        assert!(one(&closure).is_empty());
        let other = format!(
            "{} impl Desk {{ fn refund(&self, buyer: AccountId, deposit: u128) {{ Promise::new(buyer).transfer(deposit).detach(); }} }}",
            plain("self.refund(buyer, deposit); env::panic_str(\"x\");")
        );
        assert!(one(&other).is_empty());
    }

    #[test]
    fn calls_that_are_not_sends_or_panics_are_silent() {
        for body in [
            "wallet.transfer(deposit); env::panic_str(\"x\");",
            "Payment::new(buyer).transfer(deposit); env::panic_str(\"x\");",
            "Self::ext(env::current_account_id()).ft_transfer(buyer, deposit); env::panic_str(\"x\");",
            "self.token.ft_transfer(buyer, deposit); env::panic_str(\"x\");",
            "ext_token::ext(t).ft_balance_of(buyer); env::panic_str(\"x\");",
            "Promise::new(token).function_call(\"ft_balance_of\".to_string(), a, 0, g); env::panic_str(\"x\");",
            "Promise::new(token).function_call(method, a, 0, g); env::panic_str(\"x\");",
            "Promise::new(buyer).create_account(); env::panic_str(\"x\");",
            "log!(\"x\"); env::panic_str(\"x\");",
            "Promise::new(buyer).transfer(deposit); abort(); env_log();",
            "Promise::new(buyer).transfer(deposit); panic(\"x\");",
            "Promise::new(buyer).transfer(deposit); self.panic(\"x\");",
        ] {
            assert!(one(&plain(body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn test_code_is_silent() {
        let body = format!("{REFUND} env::panic_str(\"x\");");
        let test_mod = format!("#[cfg(test)] mod tests {{ fn refund(buyer: AccountId, deposit: u128) {{ {body} }} }}");
        assert!(one(&test_mod).is_empty());
        let test_fn = format!("#[test] fn refunds(buyer: AccountId, deposit: u128) {{ {body} }}");
        assert!(one(&test_fn).is_empty());
        let test_impl = format!("#[cfg(test)] impl Desk {{ fn refund(&self, buyer: AccountId, deposit: u128) {{ {body} }} }}");
        assert!(one(&test_impl).is_empty());
        let helper_in_test = format!(
            "{} #[cfg(test)] mod tests {{ fn fail() {{ panic!() }} }}",
            plain(&format!("{REFUND} fail();"))
        );
        assert!(one(&helper_in_test).is_empty());
        let not_test = format!("#[cfg(not_test)] fn refund(buyer: AccountId, deposit: u128) {{ {body} }}");
        assert_eq!(items(&one(&not_test)), ["refund"]);
    }

    #[test]
    fn a_nested_function_is_checked_on_its_own() {
        let source = "fn outer() { fn inner(buyer: AccountId, deposit: u128) { Promise::new(buyer).transfer(deposit); panic!(\"x\"); } inner(a, 1); }";
        assert_eq!(items(&one(source)), ["inner"]);
        let calm = "fn outer(buyer: AccountId, deposit: u128) { Promise::new(buyer).transfer(deposit); fn inner() { panic!(\"x\"); } }";
        assert!(one(calm).is_empty());
    }

    #[test]
    fn works_without_the_near_macro_and_in_trait_impls() {
        let source = "impl Settle for Desk { fn settle(&mut self, buyer: AccountId, deposit: u128) { Promise::new(buyer).transfer(deposit); env::panic_str(\"x\"); } }";
        assert_eq!(items(&one(source)), ["Desk::settle"]);
    }
}
