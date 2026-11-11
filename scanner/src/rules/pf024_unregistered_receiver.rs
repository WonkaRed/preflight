//! PF024: a transfer that creates a record for any receiver, so the contract pays the storage of every new one.
//!
//! A token contract keeps one record per holder, and each record locks part of the contract's own balance. NEP-145
//! has a holder register (and pay for the record) with `storage_deposit` first, and `near-contract-standards`
//! panics with "The account .. is not registered" when a transfer names a receiver that has no record. A hand-written
//! `ft_transfer` that reads a missing receiver balance as zero and then writes it back instead creates the record
//! itself: for 1 yoctoNEAR a sender can name any number of fresh accounts and the contract's balance pays for each.
//! Docs: https://github.com/near/NEPs/blob/master/neps/nep-0145.md and Rustle's `unregistered-receiver` detector.
//!
//! A crate is only looked at when it exports a method named `storage_deposit`, the NEP-145 call by which a holder
//! registers: that is the contract saying records are paid for up front, so a transfer that skips it is the hole.
//! A token with no registration (a ledger that creates accounts lazily by design) has no promise to break here.
//!
//! The rule looks at the methods the `#[near]` / `#[near_bindgen]` macro exports (`pub` methods of an inherent
//! impl, every method of a trait impl) that take `&mut self`, are not `#[private]` or `#[init]`, and have the word
//! `transfer` in their name, split at `_` (`ft_transfer`, `transfer`, `mt_batch_transfer_call`; not the receivers
//! `ft_on_transfer` and `ft_resolve_transfer`). It reports one that, for a parameter `receiver: AccountId`:
//! - reads a collection on `self` at that key with a default: `self.balances.get(&receiver)` followed by
//!   `.unwrap_or(..)`, `.unwrap_or_default()`, `.unwrap_or_else(..)` with a closure that does not panic,
//!   `.map_or(..)`, or `self.balances.entry(receiver).or_insert(..)` / `.or_default()` / `.or_insert_with(..)`
//!   (a `.copied()`, `.cloned()`, `.map(..)` or `.as_ref()` in between does not matter), and
//! - writes that collection at the same key, `self.balances.insert(receiver, ..)`, `.set(receiver, ..)` or the
//!   `entry(..)` call itself, and
//! - never reads that collection at that key without a default, which is how a method requires the record to exist:
//!   `self.balances.contains_key(&receiver)`, `.get(&receiver).expect(..)`, `.unwrap()`, `.ok_or(..)`,
//!   `.is_some()`, `match`, `[&receiver]`, `.get_mut(&receiver)`. Any read at the key that has no default counts, so
//!   a method that handles the missing record in its own way is not reported.
//!
//! The reads and writes may sit in a same-crate function the method calls (found by name through bare calls,
//! `Self::f` / `Type::f` paths and method calls) up to three calls deep, as in the usual
//! `let held = self.balance(&receiver); self.balances.insert(receiver, held + amount)`: the key is followed from
//! the argument at the call to the callee's parameter. A local bound to a parameter (`let to = receiver.clone()`)
//! is the same key.
//!
//! Not the defect, so never reported: a method that pays for storage, meaning it or a function it reaches mentions
//! `attached_deposit`, `storage_usage`, `storage_byte_cost`, `refund_deposit` or `refund_deposit_to_account` (a
//! deposit the method demands may be larger than the 1 yoctoNEAR its standard asks for); and a method restricted to
//! one privileged account, which compares the caller with a field of `self` using `==` (`require!(env::predecessor_
//! account_id() == self.treasury)`, `assert_eq!`, `if`): only that account can create records.
//!
//! Relation to PF008: that rule reports a method that stores caller data and is neither `#[payable]` nor accounts
//! for storage, so a non-payable `transfer` that creates records is reported by both, each truthfully. The
//! `#[payable]` `ft_transfer` the standard asks for (it takes 1 yoctoNEAR) is skipped by PF008 and caught here.
//!
//! Knowingly missed: a token that registers holders under another name than `storage_deposit`; a key that is not a
//! plain parameter (a tuple `(token, receiver)`, a computed key); a record created with
//! `match map.get(&k) { Some(..) => .., None => map.insert(..) }` or `if let`, which is a read with no default; a
//! read of a missing receiver through a helper that the rule cannot resolve; a receiver whose type is not named
//! `AccountId`; and a transfer to an account that is validated in another contract.
//! Knowingly noisy: a token that exports `storage_deposit` yet deliberately creates the receiver's record on a
//! transfer and is paid for it in a way the rule cannot see.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::Span;
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Attribute, BinOp, Expr, ExprBinary, ExprCall, ExprMethodCall, ExprPath, FnArg, ImplItemFn, ItemFn, ItemImpl, Local,
    Macro, Signature, Token, TraitItemFn, Type, Visibility,
};

use super::pf007_unguarded_admin::{
    CALLER_FNS, CallRef, bound_ident, call_ref, field_path, is_call_to, is_near_attr, peel, tokens_contain, type_name,
};
use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::Crate;

/// The NEP-145 method a holder calls to register, and pay for, its record.
const REGISTRATION_METHOD: &str = "storage_deposit";

pub struct Pf024UnregisteredReceiver;

pub static RULE: Pf024UnregisteredReceiver = Pf024UnregisteredReceiver;

impl Rule for Pf024UnregisteredReceiver {
    fn id(&self) -> &'static str {
        "PF024"
    }

    fn title(&self) -> &'static str {
        "Transfer creates a record for an unregistered receiver"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn help(&self) -> &'static str {
        "panic when the receiver has no record, so a record is only created by storage_deposit, which the new holder pays for"
    }

    fn check(&self, krate: &Crate) -> Vec<Finding> {
        let mut collector = Collector::default();
        for (index, file) in krate.files.iter().enumerate() {
            collector.file = index;
            collector.visit_file(&file.ast);
        }
        let fns = collector.fns;
        if !fns.iter().any(|function| function.export.is_some() && function.name == REGISTRATION_METHOD) {
            return Vec::new();
        }

        let mut findings = Vec::new();
        for (id, function) in fns.iter().enumerate() {
            let Some(export) = &function.export else { continue };
            if !export.mut_self || export.private || export.init || !is_transfer(&function.name) {
                continue;
            }
            if reachable(&fns, id)
                .into_iter()
                .any(|reached| fns[reached].accounts_storage || fns[reached].restricts_caller)
            {
                continue;
            }
            let ops = effective_ops(&fns, id, CALL_DEPTH);
            let Some((receiver, field)) = credited_without_record(&ops, &export.accounts) else { continue };
            let item = format!("{}::{}", function.owner.as_deref().unwrap_or_default(), function.name);
            let message = format!(
                "`{item}` credits `{receiver}` in `self.{field}`, treating a missing record as zero and writing one, \
                 and never requires `{receiver}` to be registered, so any account name it is given gets a record \
                 that the contract's own balance pays the storage for"
            );
            findings.push(self.finding(&krate.files[function.file], export.span, item, message));
        }
        findings
    }
}

/// The `(receiver, collection)` that `ops` credit from a default and write back, with no read that requires a record.
fn credited_without_record(ops: &[Op], receivers: &[String]) -> Option<(String, String)> {
    let fields: BTreeSet<&String> = ops.iter().map(|op| &op.field).collect();
    for receiver in receivers {
        let key = Key::Name(receiver.clone());
        for field in &fields {
            // An operation at the receiver's key; with `any_key`, also one at a key the rule cannot read, which may be it.
            let has = |kind: Kind, any_key: bool| {
                ops.iter().any(|op| {
                    op.kind == kind && op.field == **field && (op.key == key || (any_key && op.key == Key::Unknown))
                })
            };
            if has(Kind::Upsert, false) && has(Kind::DefaultRead, false) && !has(Kind::Presence, true) {
                return Some((receiver.clone(), (*field).clone()));
            }
        }
    }
    None
}

/// How many calls deep a read or write is followed from the exported method.
const CALL_DEPTH: usize = 3;

/// Names whose mention means the method looks at what it stores or what was paid for it.
const ACCOUNTING_FNS: [&str; 5] =
    ["attached_deposit", "storage_usage", "storage_byte_cost", "refund_deposit", "refund_deposit_to_account"];

/// Methods that give a missing record a value.
const DEFAULTING: [&str; 5] = ["unwrap_or", "unwrap_or_default", "unwrap_or_else", "map_or", "map_or_else"];

/// `entry(..)` followers that insert the entry when it is missing.
const ENTRY_ADDERS: [&str; 3] = ["or_insert", "or_insert_with", "or_default"];

/// Methods that change a value without changing whether it is there, so a read through them is still the read.
const TRANSPARENT: [&str; 7] = ["copied", "cloned", "map", "as_ref", "as_deref", "and_modify", "inspect"];

/// Whether `name` is a transfer: the word `transfer` and not the receiving or settling side of one.
fn is_transfer(name: &str) -> bool {
    let words: Vec<&str> = name.split('_').collect();
    words.contains(&"transfer") && !words.contains(&"on") && !words.contains(&"resolve")
}

struct Export {
    span: Span,
    private: bool,
    init: bool,
    mut_self: bool,
    /// The parameters of type `AccountId`, possibly behind a reference.
    accounts: Vec<String>,
}

/// What a function does with a collection on `self`, keyed by one of its names.
#[derive(Clone, PartialEq, Eq)]
enum Kind {
    /// `get(k)` or `entry(k)` with a default for a missing record.
    DefaultRead,
    /// Any other read at `k`: `contains_key`, `get(k).expect(..)`, `get_mut(k)`.
    Presence,
    /// `insert(k, ..)`, `set(k, ..)`, or an `entry(k)` that inserts.
    Upsert,
}

/// The key of an operation, in the scope of the function that names it.
#[derive(Clone, PartialEq, Eq)]
enum Key {
    /// A parameter, or a local bound to one (resolved), or any other local.
    Name(String),
    /// A local of a called function: matches nothing in the caller.
    Foreign,
    /// An expression that is not a plain name.
    Unknown,
}

#[derive(Clone)]
struct Op {
    field: String,
    key: Key,
    kind: Kind,
}

/// A call to a function that may be in the crate, with the plain names it passes.
struct Call {
    target: CallRef,
    /// The name each argument is, or `None` for an argument that is not a plain name; for a method call, the
    /// receiver is not among them.
    args: Vec<Option<String>>,
}

#[derive(Default)]
struct FnFacts {
    file: usize,
    name: String,
    owner: Option<String>,
    /// Parameter names in order, the receiver as `self`; empty for a pattern that is not a plain identifier.
    inputs: Vec<String>,
    has_receiver: bool,
    export: Option<Export>,
    accounts_storage: bool,
    /// Compares the caller with a field of `self` using `==`: only that account gets through.
    restricts_caller: bool,
    calls: Vec<Call>,
    ops: Vec<Op>,
}

#[derive(Default)]
struct Frame {
    facts: FnFacts,
    /// Locals bound to a parameter, mapped to it.
    aliases: BTreeMap<String, String>,
    caller_locals: BTreeSet<String>,
    /// The `get` / `entry` calls already recorded as a read with a default, by address.
    defaulted: BTreeSet<usize>,
}

impl Frame {
    fn key_of(&self, expr: &Expr) -> Key {
        match plain_name(expr) {
            Some(name) => Key::Name(self.aliases.get(&name).cloned().unwrap_or(name)),
            None => Key::Unknown,
        }
    }

    fn is_caller(&self, expr: &Expr) -> bool {
        match peel(expr) {
            Expr::Call(call) => is_call_to(call, &CALLER_FNS),
            Expr::MethodCall(call) => call.args.is_empty() && CALLER_FNS.iter().any(|name| call.method == name),
            Expr::Path(path) => {
                path.path.get_ident().is_some_and(|name| self.caller_locals.contains(&name.to_string()))
            }
            _ => false,
        }
    }

    fn compare(&mut self, left: &Expr, right: &Expr) {
        let caller_and_field = |caller: &Expr, field: &Expr| self.is_caller(caller) && field_path(field).is_some();
        if caller_and_field(left, right) || caller_and_field(right, left) {
            self.facts.restricts_caller = true;
        }
    }

    fn operate(&mut self, field: String, key: Key, kind: Kind) {
        self.facts.ops.push(Op { field, key, kind });
    }

    /// Notes `<read>.unwrap_or(..)` and its kin: the read of `self.<field>` at a key that gives a missing record a value.
    fn note_default(&mut self, call: &ExprMethodCall) {
        let name = call.method.to_string();
        let defaults = match name.as_str() {
            "unwrap_or_else" | "map_or_else" => call.args.first().is_some_and(|closure| !diverges(closure)),
            _ => DEFAULTING.contains(&name.as_str()) || ENTRY_ADDERS.contains(&name.as_str()),
        };
        if !defaults {
            return;
        }
        let Some((source, field)) = read_source(&call.receiver) else { return };
        let Some(key) = source.args.first().map(|key| self.key_of(key)) else { return };
        self.defaulted.insert(std::ptr::from_ref(source) as usize);
        self.operate(field.clone(), key.clone(), Kind::DefaultRead);
        if source.method == "entry" {
            self.operate(field, key, Kind::Upsert);
        }
    }
}

/// The `get(k)` or `entry(k)` call on a field of `self` at the bottom of a read, and that field: the part of
/// `self.balances.get(&k).copied()` that `.unwrap_or(0)` gives a default to.
fn read_source(expr: &Expr) -> Option<(&ExprMethodCall, String)> {
    let mut expr = expr;
    loop {
        match expr {
            Expr::MethodCall(call) if call.method == "get" || call.method == "entry" => {
                return field_path(&call.receiver).map(|field| (call, field.join(".")));
            }
            Expr::MethodCall(call) if TRANSPARENT.iter().any(|adapter| call.method == adapter) => expr = &call.receiver,
            Expr::Paren(inner) => expr = &inner.expr,
            _ => return None,
        }
    }
}

/// Whether a closure ends the call by panicking, so it supplies no value: `|| env::panic_str("..")`, `|| panic!(..)`.
fn diverges(closure: &Expr) -> bool {
    struct Panics(bool);
    impl<'ast> Visit<'ast> for Panics {
        fn visit_macro(&mut self, mac: &'ast Macro) {
            self.0 |= mac.path.segments.last().is_some_and(|segment| {
                ["panic", "unreachable", "todo", "unimplemented"].iter().any(|name| segment.ident == name)
            });
        }

        fn visit_expr_call(&mut self, call: &'ast ExprCall) {
            self.0 |= is_call_to(call, &["panic_str", "panic", "abort", "panic_utf8"]);
            visit::visit_expr_call(self, call);
        }
    }
    let mut panics = Panics(false);
    panics.visit_expr(closure);
    panics.0
}

/// The identifier `expr` is, ignoring borrows and clones: `receiver`, `&receiver`, `receiver.clone()`.
fn plain_name(expr: &Expr) -> Option<String> {
    match peel(expr) {
        Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
        _ => None,
    }
}

/// Whether a parameter type is `AccountId`, possibly behind a reference.
fn is_account_id(ty: &Type) -> bool {
    match ty {
        Type::Reference(reference) => is_account_id(&reference.elem),
        Type::Paren(paren) => is_account_id(&paren.elem),
        Type::Path(path) => path.path.segments.last().is_some_and(|segment| segment.ident == "AccountId"),
        _ => false,
    }
}

struct ImplContext {
    owner: String,
    exports: bool,
    is_trait_impl: bool,
}

#[derive(Default)]
struct Collector {
    file: usize,
    fns: Vec<FnFacts>,
    frames: Vec<Frame>,
    impl_context: Option<ImplContext>,
}

impl Collector {
    fn begin_fn(&mut self, sig: &Signature, attrs: &[Attribute], exported: bool) {
        let has_attr = |name: &str| attrs.iter().any(|attr| attr.path().is_ident(name));
        let inputs = sig
            .inputs
            .iter()
            .map(|arg| match arg {
                FnArg::Receiver(_) => "self".to_owned(),
                FnArg::Typed(arg) => bound_ident(&arg.pat).unwrap_or_default(),
            })
            .collect();
        let accounts = sig
            .inputs
            .iter()
            .filter_map(|arg| match arg {
                FnArg::Typed(arg) if is_account_id(&arg.ty) => bound_ident(&arg.pat),
                _ => None,
            })
            .collect();
        let export = exported.then(|| Export {
            span: sig.ident.span(),
            private: has_attr("private"),
            init: has_attr("init"),
            mut_self: sig
                .receiver()
                .is_some_and(|receiver| receiver.reference.is_some() && receiver.mutability.is_some()),
            accounts,
        });
        self.frames.push(Frame {
            facts: FnFacts {
                file: self.file,
                name: sig.ident.to_string(),
                owner: self.impl_context.as_ref().map(|context| context.owner.clone()),
                inputs,
                has_receiver: sig.receiver().is_some(),
                export,
                ..FnFacts::default()
            },
            ..Frame::default()
        });
    }

    fn end_fn(&mut self) {
        if let Some(frame) = self.frames.pop() {
            self.fns.push(frame.facts);
        }
    }

    /// Runs `walk` over a free or trait function, which is never in an impl even when nested inside one.
    fn in_free_fn(&mut self, sig: &Signature, attrs: &[Attribute], walk: impl FnOnce(&mut Self)) {
        let outer = self.impl_context.take();
        self.begin_fn(sig, attrs, false);
        walk(self);
        self.end_fn();
        self.impl_context = outer;
    }
}

impl<'ast> Visit<'ast> for Collector {
    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        let context = ImplContext {
            owner: type_name(&item.self_ty),
            exports: item.attrs.iter().any(is_near_attr),
            is_trait_impl: item.trait_.is_some(),
        };
        let outer = self.impl_context.replace(context);
        visit::visit_item_impl(self, item);
        self.impl_context = outer;
    }

    fn visit_impl_item_fn(&mut self, method: &'ast ImplItemFn) {
        let exported = self.impl_context.as_ref().is_some_and(|context| {
            context.exports && (context.is_trait_impl || matches!(method.vis, Visibility::Public(_)))
        });
        self.begin_fn(&method.sig, &method.attrs, exported);
        visit::visit_impl_item_fn(self, method);
        self.end_fn();
    }

    fn visit_item_fn(&mut self, function: &'ast ItemFn) {
        self.in_free_fn(&function.sig, &function.attrs, |this| visit::visit_item_fn(this, function));
    }

    fn visit_trait_item_fn(&mut self, function: &'ast TraitItemFn) {
        self.in_free_fn(&function.sig, &function.attrs, |this| visit::visit_trait_item_fn(this, function));
    }

    fn visit_local(&mut self, local: &'ast Local) {
        if let (Some(init), Some(name), Some(frame)) = (&local.init, bound_ident(&local.pat), self.frames.last_mut()) {
            if frame.is_caller(&init.expr) {
                frame.caller_locals.insert(name.clone());
            }
            if let Key::Name(source) = frame.key_of(&init.expr) {
                frame.aliases.insert(name, source);
            }
        }
        visit::visit_local(self, local);
    }

    fn visit_expr_path(&mut self, path: &'ast ExprPath) {
        if let (Some(segment), Some(frame)) = (path.path.segments.last(), self.frames.last_mut())
            && ACCOUNTING_FNS.iter().any(|name| segment.ident == name)
        {
            frame.facts.accounts_storage = true;
        }
        visit::visit_expr_path(self, path);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let (Expr::Path(func), Some(frame)) = (&*call.func, self.frames.last_mut()) {
            let segments: Vec<String> = func.path.segments.iter().map(|segment| segment.ident.to_string()).collect();
            if let Some(target) = call_ref(&segments, self.impl_context.as_ref().map(|context| context.owner.as_str()))
            {
                let args = call.args.iter().map(|argument| frame.key_name(argument)).collect();
                frame.facts.calls.push(Call { target, args });
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if let Some(frame) = self.frames.last_mut() {
            let name = call.method.to_string();
            if ACCOUNTING_FNS.iter().any(|accounting| call.method == accounting) {
                frame.facts.accounts_storage = true;
            }
            let args = call.args.iter().map(|argument| frame.key_name(argument)).collect();
            frame.facts.calls.push(Call { target: CallRef::Method(name.clone()), args });

            frame.note_default(call);
            if let (Some(field), Some(key)) = (field_path(&call.receiver), call.args.first()) {
                let field = field.join(".");
                let key = frame.key_of(key);
                match name.as_str() {
                    "insert" | "set" => frame.operate(field, key, Kind::Upsert),
                    "get" | "get_mut" | "contains_key" | "contains" | "entry"
                        if !frame.defaulted.contains(&(std::ptr::from_ref(call) as usize)) =>
                    {
                        frame.operate(field, key, Kind::Presence);
                    }
                    _ => {}
                }
            }
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        if let (BinOp::Eq(_), Some(frame)) = (&binary.op, self.frames.last_mut()) {
            frame.compare(&binary.left, &binary.right);
        }
        visit::visit_expr_binary(self, binary);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        let Some(name) = mac.path.segments.last().map(|segment| segment.ident.to_string()) else { return };
        // `require!`, `assert!`, `assert_eq!`, `format!` ... take comma-separated expressions: parse and walk them.
        let arguments = Punctuated::<Expr, Token![,]>::parse_terminated.parse2(mac.tokens.clone());
        if let Some(frame) = self.frames.last_mut() {
            frame.facts.calls.push(Call { target: CallRef::Macro(format!("{name}!")), args: Vec::new() });
            if let (true, Ok(arguments)) = (matches!(name.as_str(), "assert_eq" | "debug_assert_eq"), &arguments)
                && let [left, right, ..] = arguments.iter().collect::<Vec<_>>()[..]
            {
                frame.compare(left, right);
            }
            if arguments.is_err() && tokens_contain(&mac.tokens, &ACCOUNTING_FNS) {
                frame.facts.accounts_storage = true;
            }
        }
        for argument in arguments.iter().flatten() {
            self.visit_expr(argument);
        }
    }
}

impl Frame {
    /// The plain name an argument is, resolved through the locals bound to parameters.
    fn key_name(&self, argument: &Expr) -> Option<String> {
        match self.key_of(argument) {
            Key::Name(name) => Some(name),
            Key::Foreign | Key::Unknown => None,
        }
    }
}

/// The operations of function `id` and of what it calls, up to `depth` calls down, with keys named in `id`'s scope.
fn effective_ops(fns: &[FnFacts], id: usize, depth: usize) -> Vec<Op> {
    let mut ops = fns[id].ops.clone();
    if depth == 0 {
        return ops;
    }
    for call in &fns[id].calls {
        for (callee, target) in fns.iter().enumerate() {
            if callee == id || !call.target.reaches(&target.name, target.owner.as_deref(), target.has_receiver) {
                continue;
            }
            for op in effective_ops(fns, callee, depth - 1) {
                let key = match &op.key {
                    Key::Name(name) => match target.inputs.iter().position(|input| input == name) {
                        Some(position) => {
                            let position = if matches!(call.target, CallRef::Method(_)) {
                                position.checked_sub(1)
                            } else {
                                Some(position)
                            };
                            match position.and_then(|position| call.args.get(position)) {
                                Some(Some(argument)) => Key::Name(argument.clone()),
                                _ => Key::Unknown,
                            }
                        }
                        None => Key::Foreign,
                    },
                    other => other.clone(),
                };
                ops.push(Op { key, ..op });
            }
        }
    }
    ops
}

/// `id` and every function reachable from it.
fn reachable(fns: &[FnFacts], id: usize) -> Vec<usize> {
    let mut seen = vec![id];
    let mut next = 0;
    while let Some(&current) = seen.get(next) {
        next += 1;
        for call in &fns[current].calls {
            for (callee, f) in fns.iter().enumerate() {
                if call.target.reaches(&f.name, f.owner.as_deref(), f.has_receiver) && !seen.contains(&callee) {
                    seen.push(callee);
                }
            }
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(sources: &[(&str, &str)]) -> Vec<Finding> {
        let krate = Crate::from_sources(sources.iter().copied()).unwrap();
        RULE.check(&krate)
    }

    /// `source` next to the `storage_deposit` that makes it a token with registration.
    fn registered(source: &str) -> String {
        format!("{source}\n#[near] impl Registry {{ #[payable] pub fn storage_deposit(&mut self) {{}} }}")
    }

    fn items(source: &str) -> Vec<String> {
        check(&[("src/lib.rs", &registered(source))]).into_iter().map(|finding| finding.item).collect()
    }

    /// `body` as the body of `ft_transfer` in a `#[near]` impl, next to the usual `balance` helper.
    fn transfer(body: &str) -> String {
        format!(
            "#[near] impl Token {{
                #[payable]
                pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) {{ {body} }}
            }}
            impl Token {{
                fn balance(&self, id: &AccountId) -> u128 {{ self.balances.get(id).copied().unwrap_or(0) }}
            }}"
        )
    }

    const CREDIT: &str = "let held = self.balance(&receiver_id); self.balances.insert(receiver_id, held + amount.0);";

    #[test]
    fn flags_a_transfer_that_credits_a_receiver_from_zero_and_locates_it() {
        let source = "#[near]\nimpl Token {\n    #[payable]\n    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) {\n        assert_one_yocto();\n        let held = self.balances.get(&receiver_id).copied().unwrap_or(0);\n        self.balances.insert(receiver_id, held + amount.0);\n    }\n}";
        let findings = check(&[("src/lib.rs", &registered(source))]);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF024", Severity::Medium));
        assert_eq!(finding.item, "Token::ft_transfer");
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 4, 12));
        assert!(finding.message.contains("`receiver_id` in `self.balances`"), "{}", finding.message);
    }

    #[test]
    fn accepts_near_bindgen_path_qualified_near_and_trait_impls() {
        for attr in ["#[near_bindgen]", "#[near_sdk::near]", "#[near(contract_state)]"] {
            let source = format!(
                "{attr} impl Token {{ pub fn ft_transfer(&mut self, receiver_id: AccountId) {{ let h = self.balances.get(&receiver_id).copied().unwrap_or(0); self.balances.insert(receiver_id, h + 1); }} }}"
            );
            assert_eq!(items(&source), ["Token::ft_transfer"], "{attr}");
        }
        let trait_impl = "#[near] impl FungibleTokenCore for Token { fn ft_transfer(&mut self, receiver_id: AccountId) { let h = self.balances.get(&receiver_id).copied().unwrap_or(0); self.balances.insert(receiver_id, h + 1); } }";
        assert_eq!(items(trait_impl), ["Token::ft_transfer"]);
    }

    #[test]
    fn flags_every_way_of_reading_a_missing_balance_as_a_default() {
        let credits = [
            "let h = self.balances.get(&receiver_id).copied().unwrap_or(0); self.balances.insert(receiver_id, h + 1);",
            "let h = self.balances.get(&receiver_id).unwrap_or(&0); self.balances.insert(receiver_id, *h + 1);",
            "let h = self.balances.get(&receiver_id).cloned().unwrap_or_default(); self.balances.insert(receiver_id, h + 1);",
            "let h = self.balances.get(&receiver_id).map(|v| *v).unwrap_or(0); self.balances.insert(receiver_id, h + 1);",
            "let h = self.balances.get(&receiver_id).map_or(0, |v| *v); self.balances.insert(receiver_id, h + 1);",
            "let h = self.balances.get(&receiver_id).copied().unwrap_or_else(|| 0); self.balances.insert(receiver_id, h + 1);",
            "let h = self.balances.get(&receiver_id).copied().unwrap_or(0); self.balances.set(receiver_id, Some(h + 1));",
            "let h = self.balances.get(&receiver_id).copied().unwrap_or(0); self.balances.insert(receiver_id.clone(), h + 1);",
            "let h = self.balances.get(receiver_id.as_str()).copied().unwrap_or(0); self.balances.insert(receiver_id, h + 1);",
            "let to = receiver_id.clone(); let h = self.balances.get(&to).copied().unwrap_or(0); self.balances.insert(to, h + 1);",
            "let h = self.ledger.balances.get(&receiver_id).copied().unwrap_or(0); self.ledger.balances.insert(receiver_id, h + 1);",
            "*self.balances.entry(receiver_id).or_insert(0) += 1;",
            "*self.balances.entry(receiver_id).or_default() += 1;",
            "*self.balances.entry(receiver_id).or_insert_with(|| 0) += 1;",
            "self.balances.entry(receiver_id).and_modify(|v| *v += 1).or_insert(1);",
        ];
        for credit in credits {
            let source = format!(
                "#[near] impl Token {{ pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) {{ {credit} }} }}"
            );
            assert_eq!(items(&source), ["Token::ft_transfer"], "{credit}");
        }
    }

    #[test]
    fn follows_the_key_through_helpers() {
        let helpers = [
            // The read and the write both in a helper.
            "#[near] impl Token { pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) { self.credit(&receiver_id, amount.0); } }
             impl Token { fn credit(&mut self, id: &AccountId, n: u128) { let h = self.balances.get(id).copied().unwrap_or(0); self.balances.insert(id.clone(), h + n); } }",
            // Two calls deep, with the parameter renamed on the way.
            "#[near] impl Token { pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) { self.route(receiver_id, amount.0); } }
             impl Token { fn route(&mut self, to: AccountId, n: u128) { self.credit(&to, n); } fn credit(&mut self, id: &AccountId, n: u128) { *self.balances.entry(id.clone()).or_insert(0) += n; } }",
            // A free function and an associated function.
            "#[near] impl Token { pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) { credit(&mut self.balances, receiver_id, amount.0); } }
             fn credit(balances: &mut Map, id: AccountId, n: u128) { let h = balances.get(&id).copied().unwrap_or(0); balances.insert(id, h + n); }",
            "#[near] impl Token { pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) { Self::credit(self, &receiver_id, amount.0); } }
             impl Token { fn credit(&mut self, id: &AccountId, n: u128) { let h = self.balances.get(id).copied().unwrap_or(0); self.balances.insert(id.clone(), h + n); } }",
        ];
        // The free-function form keys a map that is not a field of `self` in the callee, so only the method forms count.
        let expected = [true, true, false, true];
        for (source, flagged) in helpers.iter().zip(expected) {
            assert_eq!(!items(source).is_empty(), flagged, "{source}");
        }
        assert_eq!(items(&transfer(CREDIT)), ["Token::ft_transfer"]);
    }

    #[test]
    fn requiring_the_receiver_record_makes_the_method_clean() {
        let checks = [
            "require!(self.balances.contains_key(&receiver_id), \"receiver is not registered\");",
            "require!(self.balances.get(&receiver_id).is_some());",
            "self.balances.get(&receiver_id).expect(\"receiver is not registered\");",
            "self.balances.get(&receiver_id).unwrap();",
            "self.balances.get(&receiver_id).ok_or(\"not registered\").unwrap();",
            "if self.balances.get(&receiver_id).is_none() { env::panic_str(\"not registered\"); }",
            "let _ = self.balances.get(&receiver_id).unwrap_or_else(|| env::panic_str(\"not registered\"));",
            "let _ = self.balances.get(&receiver_id).unwrap_or_else(|| panic!(\"not registered\"));",
            "if !self.balances.contains_key(&receiver_id) { env::panic_str(\"not registered\"); }",
            "self.balances.get_mut(&receiver_id).unwrap();",
            "assert!(self.balances.contains(&receiver_id));",
            "let to = receiver_id.clone(); require!(self.balances.contains_key(&to));",
            "self.assert_registered(&receiver_id);",
            "require!(self.balances.contains_key(&format!(\"{}\", receiver_id)));",
        ];
        for check in checks {
            let source = format!(
                "#[near] impl Token {{
                    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) {{ {check} {CREDIT} }}
                }}
                impl Token {{
                    fn balance(&self, id: &AccountId) -> u128 {{ self.balances.get(id).copied().unwrap_or(0) }}
                    fn assert_registered(&self, id: &AccountId) {{ require!(self.balances.contains_key(id), \"not registered\"); }}
                }}"
            );
            assert!(items(&source).is_empty(), "{check}");
        }
    }

    #[test]
    fn a_read_of_a_different_key_or_collection_does_not_count_as_the_registration_check() {
        let others = [
            "let sender = env::predecessor_account_id(); self.balances.get(&sender).expect(\"no balance\");",
            "self.balances.contains_key(&sender_id);",
            "self.allowed.contains_key(&receiver_id);",
            "require!(self.banned.get(&receiver_id).is_none());",
            "self.assert_unbanned(&receiver_id);",
        ];
        for other in others {
            let source = format!(
                "#[near] impl Token {{
                    pub fn ft_transfer(&mut self, receiver_id: AccountId, sender_id: AccountId, amount: U128) {{ {other} {CREDIT} }}
                }}
                impl Token {{
                    fn balance(&self, id: &AccountId) -> u128 {{ self.balances.get(id).copied().unwrap_or(0) }}
                    fn assert_unbanned(&self, id: &AccountId) {{ require!(self.banned.get(id).is_none()); }}
                }}"
            );
            assert_eq!(items(&source), ["Token::ft_transfer"], "{other}");
        }
    }

    #[test]
    fn a_method_that_pays_for_storage_is_clean() {
        let accounted = [
            "require!(env::attached_deposit() >= STORAGE_COST);",
            "let before = env::storage_usage(); let after = env::storage_usage();",
            "let cost = env::storage_byte_cost();",
            "refund_deposit(0);",
            "require!(near_sdk::env::attached_deposit().as_yoctonear() > 0, \"{}\", 1);",
            "self.take_payment();",
        ];
        for step in accounted {
            let source = format!(
                "#[near] impl Token {{
                    #[payable]
                    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) {{ {step} {CREDIT} }}
                }}
                impl Token {{
                    fn balance(&self, id: &AccountId) -> u128 {{ self.balances.get(id).copied().unwrap_or(0) }}
                    fn take_payment(&self) {{ require!(env::attached_deposit() >= STORAGE_COST); }}
                }}"
            );
            assert!(items(&source).is_empty(), "{step}");
        }
        // Reading the deposit is what clears it, so asking for exactly 1 yoctoNEAR with `assert_one_yocto` does not.
        assert_eq!(items(&transfer(&format!("assert_one_yocto(); {CREDIT}"))), ["Token::ft_transfer"]);
    }

    #[test]
    fn a_transfer_restricted_to_one_account_is_clean() {
        let restrictions = [
            "require!(env::predecessor_account_id() == self.treasury);",
            "assert_eq!(env::predecessor_account_id(), self.treasury);",
            "let caller = env::predecessor_account_id(); require!(caller == self.treasury);",
            "if self.treasury == env::predecessor_account_id() { } else { env::panic_str(\"no\"); }",
            "self.assert_treasury();",
        ];
        for restriction in restrictions {
            let source = format!(
                "#[near] impl Token {{
                    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) {{ {restriction} {CREDIT} }}
                }}
                impl Token {{
                    fn balance(&self, id: &AccountId) -> u128 {{ self.balances.get(id).copied().unwrap_or(0) }}
                    fn assert_treasury(&self) {{ require!(env::predecessor_account_id() == self.treasury); }}
                }}"
            );
            assert!(items(&source).is_empty(), "{restriction}");
        }
        // Excluding one account, or naming a set anyone can join, restricts nobody.
        for open in [
            "require!(env::predecessor_account_id() != self.treasury);",
            "require!(self.members.contains(&env::predecessor_account_id()));",
        ] {
            assert_eq!(items(&transfer(&format!("{open} {CREDIT}"))), ["Token::ft_transfer"], "{open}");
        }
    }

    #[test]
    fn crediting_the_caller_or_a_fixed_key_is_clean() {
        let credits = [
            "let me = env::predecessor_account_id(); let h = self.balance(&me); self.balances.insert(me, h + amount.0);",
            "let h = self.balances.get(&env::predecessor_account_id()).copied().unwrap_or(0); self.balances.insert(env::predecessor_account_id(), h + 1);",
            "let h = self.balances.get(&self.treasury).copied().unwrap_or(0); self.balances.insert(self.treasury.clone(), h + 1);",
            "let h = self.balances.get(&other).copied().unwrap_or(0); self.balances.insert(other, h + 1);",
            "self.balances.insert(receiver_id, amount.0);",
            "let h = self.balances.get(&receiver_id).copied().unwrap_or(0); self.totals.insert(receiver_id, h + 1);",
            "let h = self.totals.get(&receiver_id).copied().unwrap_or(0); self.balances.insert(receiver_id, h + 1);",
            "let h = self.balances.get(&receiver_id).copied().unwrap_or(0); log!(\"{}\", h);",
            "self.balances.remove(&receiver_id);",
            "let h = self.balances.get(&receiver_id).copied().unwrap_or(0); self.balances.insert(other, h + 1);",
        ];
        for credit in credits {
            let source = format!(
                "#[near] impl Token {{ pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) {{ let other = env::current_account_id(); {credit} }} }}
                 impl Token {{ fn balance(&self, id: &AccountId) -> u128 {{ self.balances.get(id).copied().unwrap_or(0) }} }}"
            );
            assert!(items(&source).is_empty(), "{credit}");
        }
    }

    #[test]
    fn only_transfer_methods_that_are_exported_and_change_state_are_checked() {
        let transfer_named = ["ft_transfer", "transfer", "ft_transfer_call", "mt_batch_transfer_call", "transfer_to"];
        for name in transfer_named {
            let source = format!(
                "#[near] impl Token {{ pub fn {name}(&mut self, receiver_id: AccountId) {{ {CREDIT} }} }} impl Token {{ fn balance(&self, id: &AccountId) -> u128 {{ self.balances.get(id).copied().unwrap_or(0) }} }}"
            );
            assert_eq!(items(&source), [format!("Token::{name}")], "{name}");
        }
        let others = [
            "pub fn ft_on_transfer(&mut self, receiver_id: AccountId)",
            "pub fn ft_resolve_transfer(&mut self, receiver_id: AccountId)",
            "pub fn deposit_for(&mut self, receiver_id: AccountId)",
            "pub fn transferred(&mut self, receiver_id: AccountId)",
            "pub fn ft_transfer(&self, receiver_id: AccountId)",
            "#[private] pub fn ft_transfer(&mut self, receiver_id: AccountId)",
            "#[init] pub fn ft_transfer(&mut self, receiver_id: AccountId)",
            "fn ft_transfer(&mut self, receiver_id: AccountId)",
            "pub(crate) fn ft_transfer(&mut self, receiver_id: AccountId)",
            "pub fn ft_transfer(&mut self, receiver_id: String)",
            "pub fn ft_transfer(&mut self, receiver_id: Option<AccountId>)",
        ];
        for signature in others {
            let source = format!(
                "#[near] impl Token {{ {signature} {{ {CREDIT} }} }} impl Token {{ fn balance(&self, id: &AccountId) -> u128 {{ self.balances.get(id).copied().unwrap_or(0) }} }}"
            );
            assert!(items(&source).is_empty(), "{signature}");
        }
        let plain = format!("impl Token {{ pub fn ft_transfer(&mut self, receiver_id: AccountId) {{ {CREDIT} }} }}");
        assert!(items(&plain).is_empty());
    }

    #[test]
    fn a_reference_to_the_receiver_is_still_the_receiver() {
        let source = "#[near] impl Token { pub fn ft_transfer(&mut self, receiver_id: &AccountId, amount: U128) { let h = self.balances.get(receiver_id).copied().unwrap_or(0); self.balances.insert(receiver_id.clone(), h + amount.0); } }";
        assert_eq!(items(source), ["Token::ft_transfer"]);
    }

    #[test]
    fn only_a_token_that_exports_storage_deposit_is_checked() {
        let transfer = "#[near] impl Token { pub fn ft_transfer(&mut self, receiver_id: AccountId) { let h = self.balances.get(&receiver_id).copied().unwrap_or(0); self.balances.insert(receiver_id, h + 1); } }";
        let flagged = |extra: &str| !check(&[("src/lib.rs", &format!("{transfer}\n{extra}"))]).is_empty();
        // Registration the way the NEP has it: an exported method, in an inherent or a trait impl.
        assert!(flagged("#[near] impl Registry { #[payable] pub fn storage_deposit(&mut self) {} }"));
        assert!(flagged("#[near_bindgen] impl StorageManagement for Token { fn storage_deposit(&mut self) {} }"));
        // A ledger that makes accounts lazily, a registration under another name, and one that is not exported.
        assert!(!flagged(""));
        assert!(!flagged("#[near] impl Registry { pub fn register(&mut self) {} }"));
        assert!(!flagged("#[near] impl Registry { fn storage_deposit(&mut self) {} }"));
        assert!(!flagged("impl Registry { pub fn storage_deposit(&mut self) {} }"));
        assert!(!flagged("#[near] impl Registry { pub fn storage_deposit_of(&self) {} }"));
    }

    #[test]
    fn reports_each_transfer_once_across_files() {
        let one = "#[near] impl Token { pub fn ft_transfer(&mut self, receiver_id: AccountId) { let h = self.balances.get(&receiver_id).copied().unwrap_or(0); self.balances.insert(receiver_id, h + 1); } }";
        let other = "#[near] impl Points { pub fn transfer(&mut self, to: AccountId) { *self.points.entry(to).or_default() += 1; } }";
        let registry = "#[near] impl Registry { #[payable] pub fn storage_deposit(&mut self) {} }";
        let findings = check(&[("src/lib.rs", one), ("src/points.rs", other), ("src/registry.rs", registry)]);
        let located: Vec<_> = findings.iter().map(|finding| (finding.file.as_str(), finding.item.as_str())).collect();
        assert_eq!(located, [("src/lib.rs", "Token::ft_transfer"), ("src/points.rs", "Points::transfer")]);
    }
}
