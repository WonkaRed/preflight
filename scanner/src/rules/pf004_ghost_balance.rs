//! PF004: a deposit hook that credits state and then returns a promise whose failure refunds the deposit.
//!
//! A token contract moves tokens to the receiver first, then calls the receiver's `ft_on_transfer` (NEP-141),
//! `nft_on_transfer` (NEP-171) or `mt_on_transfer` (NEP-245), and settles with a resolver callback. That resolver
//! refunds the sender whatever the hook reports as unused, and everything if the hook's promise fails. A hook that
//! writes a credit to its own state and then returns a promise (typically a notification to a third-party contract
//! named in `msg`) has nothing undoing the credit when the promise fails: the hook's own receipt succeeded, so the
//! write is final, while the token contract hands the tokens back. The depositor holds the tokens and a credit.
//! The rule matches that shape only: a hook with one of those names that credits state and returns a promise
//! nothing settles. Docs:
//! https://nomicon.io/Standards/Tokens/FungibleToken/Core and
//! https://docs.near.org/smart-contracts/security/callbacks
//!
//! A hook is reported when all three hold:
//! 1. It is exported by the `#[near]` / `#[near_bindgen]` macro (`pub` in an inherent impl, any method of a trait
//!    impl) and is named `ft_on_transfer`, `nft_on_transfer` or `mt_on_transfer`.
//! 2. A path through its body writes contract state and then returns a cross-contract promise. A write is an
//!    assignment or compound assignment, a `&mut` borrow, or a mutating collection call (`insert`, `remove`,
//!    `push`, `entry`, `get_mut`, ...) on something rooted at `self`; or a call on `self` (or a `self` field) to a
//!    `&mut self` method of the same crate whose body contains one, followed through helpers. Paths are followed
//!    through `if`, `match`, blocks and early `return`, so a credit in a branch that returns a plain value before
//!    the promise is built does not count. A returned promise is a `Type::ext(..)` call chain or `Promise::new(..)`
//!    chain, possibly wrapped in `PromiseOrValue::Promise(..)` or `.into()`, held in a local, or returned by a
//!    same-crate helper.
//! 3. No callback attached to that promise with `.then(..)` can settle it. The callback must be a method of this
//!    crate that reads the promise result (`#[callback_result]`, `env::promise_result*`, `env::is_promise_success`)
//!    and writes state, so it can undo the credit on failure, or one that always returns "nothing unused"
//!    (`U128(0)`, `false`), so the tokens stay and so does the credit. No `.then(..)` at all, or a callback that
//!    does not read the result or does not write state, is reported.
//!
//! Silent by design: a hook that writes no state before its promise (the credit is written in a callback that saw
//! the notification succeed), a hook that credits and returns a plain value, and a notification that is fired but
//! not returned (the hook's own result then decides the refund).
//!
//! Knowingly missed or approximated:
//! - Writes behind trait objects, generics, macros (`require!` arguments are never parsed), other crates, or a
//!   method called on a local variable are invisible, and so are promises built with raw `env::promise_*` calls.
//!   Methods are matched by name only, since the scanner resolves no types.
//! - The callback is checked for reading the result and writing state anywhere in its body, not for writing on the
//!   failure branch. A callback that only writes on success is accepted. A callback that is not defined in this
//!   crate is reported, because nothing in the crate can be seen undoing the credit.
//! - Only a callback attached with `.then(..)` is looked at; when several are chained one that settles is enough.
//!   The argument may be a local bound to the callback (`let callback = if c { Self::ext(..).a() } else { Self::ext(..).b() };
//!   promise.then(callback)`): every alternative it can hold must settle.
//! - The exemption for a callback that always returns zero does not apply when it takes `#[callback_unwrap]`,
//!   `#[callback]` or `#[callback_vec]` (they panic on a failed promise, which fails the hook's promise and refunds).
//!   It looks for the literal `U128(0)` / `false` (also
//!   `0.into()`, `PromiseOrValue::Value(..)`); any other way of returning "nothing unused" is reported.

use std::collections::{BTreeMap, BTreeSet};

use syn::visit::{self, Visit};
use syn::{
    Attribute, BinOp, Block, Expr, ExprCall, ExprClosure, ExprMacro, ExprMethodCall, ExprReturn, ImplItem,
    ImplItemFn, ItemFn, ItemImpl, Lit, Local, Macro, Pat, Signature, Stmt, Type, UnOp, Visibility,
};

use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf004GhostBalance;

pub static RULE: Pf004GhostBalance = Pf004GhostBalance;

/// The receiver hooks of NEP-141, NEP-171 and NEP-245: the token contract refunds when their promise fails.
const HOOKS: [&str; 3] = ["ft_on_transfer", "nft_on_transfer", "mt_on_transfer"];

/// Collection methods that change what a field holds. `get_mut` and `entry` hand out the mutable handle.
const MUTATORS: [&str; 17] = [
    "insert",
    "remove",
    "remove_entry",
    "push",
    "push_back",
    "push_front",
    "pop",
    "pop_back",
    "pop_front",
    "extend",
    "append",
    "clear",
    "truncate",
    "retain",
    "swap_remove",
    "get_mut",
    "entry",
];

/// Methods that keep pointing at the same place: `*self.balances.entry(k).or_default() += x` writes `self`.
const PROJECTIONS: [&str; 8] =
    ["unwrap", "expect", "get_mut", "entry", "or_insert", "or_insert_with", "or_default", "as_mut"];

/// Calls that read how the previous promise ended.
const RESULT_READERS: [&str; 3] = ["promise_result", "promise_result_checked", "is_promise_success"];

/// How far helper calls are followed when looking for the promise a hook returns.
const MAX_DEPTH: usize = 6;

impl Rule for Pf004GhostBalance {
    fn id(&self) -> &'static str {
        "PF004"
    }

    fn title(&self) -> &'static str {
        "Deposit credited before a forwarded call that can refund it"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn help(&self) -> &'static str {
        "write the credit only in a callback that has seen the forwarded call succeed, or undo it there when it fails"
    }

    fn check(&self, krate: &Crate) -> Vec<Finding> {
        let index = Index::build(krate);
        let mut findings = Vec::new();
        for file in &krate.files {
            let mut hooks = Hooks::default();
            hooks.visit_file(&file.ast);
            for (owner, hook) in hooks.found {
                let Some(callbacks) = index.unsettled_promise(&hook.block) else { continue };
                let item = format!("{owner}::{}", hook.sig.ident);
                let message = format!(
                    "`{item}` writes contract state and then returns a cross-contract promise, but {}; if that promise fails \
                     the token contract refunds the transfer to the sender and the credit stays, so the contract owes \
                     tokens it no longer holds",
                    describe(&callbacks)
                );
                findings.push(self.finding(file, hook.sig.ident.span(), item, message));
            }
        }
        findings
    }
}

/// Why the callbacks of a returned promise do not settle it, as the tail of the finding message.
fn describe(callbacks: &[Option<String>]) -> String {
    match callbacks.last() {
        None => "no callback is attached to it".to_owned(),
        Some(None) => "the callback attached to it cannot be identified".to_owned(),
        Some(Some(name)) => {
            format!("the callback `{name}` does not both read the promise result and write state to undo the credit")
        }
    }
}

/// The exported receiver hooks of one file, with the type that implements them.
#[derive(Default)]
struct Hooks<'a> {
    found: Vec<(String, &'a ImplItemFn)>,
}

impl<'ast> Visit<'ast> for Hooks<'ast> {
    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        if item.attrs.iter().any(is_near_attr) {
            let owner = type_name(&item.self_ty);
            let is_trait_impl = item.trait_.is_some();
            for member in &item.items {
                if let ImplItem::Fn(method) = member
                    && HOOKS.iter().any(|hook| method.sig.ident == hook)
                    && (is_trait_impl || matches!(method.vis, Visibility::Public(_)))
                {
                    self.found.push((owner.clone(), method));
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

/// A function or method of the crate, found by name.
struct FnDef<'a> {
    sig: &'a Signature,
    block: &'a Block,
}

impl FnDef<'_> {
    fn takes_mut_self(&self) -> bool {
        self.sig.receiver().is_some_and(|receiver| matches!(&*receiver.ty, Type::Reference(ty) if ty.mutability.is_some()))
    }

    /// Whether a parameter carries one of these callback attributes.
    fn has_arg_attr(&self, names: &[&str]) -> bool {
        self.sig.inputs.iter().any(|arg| {
            matches!(arg, syn::FnArg::Typed(arg)
                if arg.attrs.iter().any(|attr| names.iter().any(|name| attr.path().is_ident(name))))
        })
    }

    fn reads_promise_result(&self) -> bool {
        self.has_arg_attr(&["callback_result"]) || {
            let mut readers = ResultReaders(false);
            readers.visit_block(self.block);
            readers.0
        }
    }

    /// These arguments make the macro panic when the promise failed, which fails the callback and so the hook.
    fn panics_on_failed_promise(&self) -> bool {
        self.has_arg_attr(&["callback", "callback_unwrap", "callback_vec"])
    }
}

/// Every function and method of the crate by name; the scanner resolves no types, so two types that share a method
/// name share an entry.
struct Index<'a> {
    fns: BTreeMap<String, Vec<FnDef<'a>>>,
}

impl<'a> Index<'a> {
    fn build(krate: &'a Crate) -> Self {
        let mut defs = Defs { fns: BTreeMap::new() };
        for file in &krate.files {
            defs.visit_file(&file.ast);
        }
        Self { fns: defs.fns }
    }

    fn defs(&self, name: &str) -> &[FnDef<'a>] {
        self.fns.get(name).map_or(&[], Vec::as_slice)
    }

    /// The callbacks attached to a promise this hook returns after writing state, when none of them settles it.
    fn unsettled_promise(&self, hook: &'a Block) -> Option<Vec<Option<String>>> {
        let locals = locals(hook);
        let mut flow = Flow { index: self, out: Vec::new() };
        flow.block(hook, false, true);
        flow.out.into_iter().filter(|&(_, written)| written).find_map(|(returned, _)| {
            let callbacks = self.promise_of(returned, &locals, 0)?;
            (!callbacks.iter().any(|callback| self.settles(callback))).then_some(callbacks)
        })
    }

    /// Whether the exprs a function returns include a promise, and if so the callbacks attached to it.
    fn returned_promise(&self, def: &FnDef<'a>, depth: usize) -> Option<Vec<Option<String>>> {
        let locals = locals(def.block);
        let mut flow = Flow { index: self, out: Vec::new() };
        flow.block(def.block, false, true);
        flow.out.iter().find_map(|&(returned, _)| self.promise_of(returned, &locals, depth))
    }

    /// The callbacks attached with `.then(..)` if `expr` is a cross-contract promise (a `Type::ext(..)` or
    /// `Promise::new(..)` chain), else `None`. A callback is `None` when its name cannot be read.
    fn promise_of(&self, expr: &'a Expr, locals: &BTreeMap<String, &'a Expr>, depth: usize) -> Option<Vec<Option<String>>> {
        if depth > MAX_DEPTH {
            return None;
        }
        match expr {
            Expr::Paren(inner) => self.promise_of(&inner.expr, locals, depth),
            Expr::Group(inner) => self.promise_of(&inner.expr, locals, depth),
            Expr::Path(path) => {
                let local = locals.get(&path.path.get_ident()?.to_string())?;
                self.promise_of(local, locals, depth + 1)
            }
            Expr::Call(call) => {
                let names = callee_names(call)?;
                let names: Vec<&str> = names.iter().map(String::as_str).collect();
                match names.as_slice() {
                    [.., _, "ext"] | [.., "Promise", "new"] => Some(Vec::new()),
                    [.., "PromiseOrValue", "Promise"] => self.promise_of(call.args.first()?, locals, depth),
                    ["Self" | "self", name] | [name] => self.helper_promise(name, depth),
                    _ => None,
                }
            }
            Expr::MethodCall(call) if call.method == "then" => {
                let mut callbacks = self.promise_of(&call.receiver, locals, depth)?;
                let alternatives = call.args.first().map(|arg| callback_alternatives(arg, locals, depth)).unwrap_or_default();
                // The callback that decides is one that leaves the credit in place, if any alternative does.
                callbacks.push(alternatives.iter().find(|callback| !self.settles(callback)).or(alternatives.first()).cloned().flatten());
                Some(callbacks)
            }
            Expr::MethodCall(call) if is_bare_self(&call.receiver) => self.helper_promise(&call.method.to_string(), depth),
            Expr::MethodCall(call) => self.promise_of(&call.receiver, locals, depth),
            _ => None,
        }
    }

    fn helper_promise(&self, name: &str, depth: usize) -> Option<Vec<Option<String>>> {
        self.defs(name).iter().find_map(|def| self.returned_promise(def, depth + 1))
    }

    /// Whether a callback named like this undoes or accepts the credit on its own.
    fn settles(&self, callback: &Option<String>) -> bool {
        let Some(name) = callback else { return false };
        self.defs(name).iter().any(|def| {
            (def.reads_promise_result() && self.writes_state(def.block)) || self.always_returns_nothing_unused(def)
        })
    }

    fn writes_state(&self, block: &'a Block) -> bool {
        let mut writes = Writes { index: self, expanded: BTreeSet::new(), found: false };
        writes.visit_block(block);
        writes.found
    }

    fn always_returns_nothing_unused(&self, def: &FnDef<'a>) -> bool {
        let mut flow = Flow { index: self, out: Vec::new() };
        flow.block(def.block, false, true);
        !def.panics_on_failed_promise()
            && !flow.out.is_empty()
            && flow.out.iter().all(|&(returned, _)| is_nothing_unused(returned))
    }
}

/// The method a `.then(..)` argument schedules: `Self::ext(..).with_static_gas(g).on_notified(..)` is `on_notified`.
fn callback_name(arg: &Expr) -> Option<String> {
    let Expr::MethodCall(call) = arg else { return None };
    let name = call.method.to_string();
    if name.starts_with("with_") { callback_name(&call.receiver) } else { Some(name) }
}

/// The methods a `.then(..)` argument may schedule: `callback_name`, or for a local the methods of what it was bound
/// to, which is more than one when the initializer is an `if`/`else`.
fn callback_alternatives(arg: &Expr, locals: &BTreeMap<String, &Expr>, depth: usize) -> Vec<Option<String>> {
    fn tail(block: &Block) -> Option<&Expr> {
        match block.stmts.last() {
            Some(Stmt::Expr(expr, None)) => Some(expr),
            _ => None,
        }
    }
    if depth > MAX_DEPTH {
        return vec![None];
    }
    let next = depth + 1;
    match arg {
        Expr::Paren(inner) => callback_alternatives(&inner.expr, locals, depth),
        Expr::Group(inner) => callback_alternatives(&inner.expr, locals, depth),
        Expr::Path(path) => match path.path.get_ident().and_then(|name| locals.get(&name.to_string())) {
            Some(bound) => callback_alternatives(bound, locals, next),
            None => vec![None],
        },
        Expr::If(branch) => {
            let then = tail(&branch.then_branch).map_or_else(|| vec![None], |expr| callback_alternatives(expr, locals, next));
            let otherwise = match branch.else_branch.as_ref().map(|(_, expr)| &**expr) {
                Some(Expr::Block(block)) => tail(&block.block),
                other => other,
            };
            then.into_iter()
                .chain(otherwise.map_or_else(|| vec![None], |expr| callback_alternatives(expr, locals, next)))
                .collect()
        }
        Expr::Block(block) => tail(&block.block).map_or_else(|| vec![None], |expr| callback_alternatives(expr, locals, next)),
        arg => vec![callback_name(arg)],
    }
}

fn is_bare_self(expr: &Expr) -> bool {
    matches!(expr, Expr::Path(path) if path.path.is_ident("self"))
}

/// `U128(0)`, `false`, `0.into()` or `PromiseOrValue::Value(..)` around one of them: the receiver used everything.
fn is_nothing_unused(expr: &Expr) -> bool {
    match expr {
        Expr::Paren(inner) => is_nothing_unused(&inner.expr),
        Expr::Lit(lit) => matches!(&lit.lit, Lit::Bool(value) if !value.value),
        Expr::MethodCall(call) => call.method == "into" && is_zero(&call.receiver),
        Expr::Call(call) => {
            let names = callee_names(call).unwrap_or_default();
            match names.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
                [.., "U128"] => call.args.first().is_some_and(is_zero),
                [.., "PromiseOrValue", "Value"] => call.args.first().is_some_and(is_nothing_unused),
                _ => false,
            }
        }
        _ => false,
    }
}

/// The path segments of the function a call names: `Self::ext` is `["Self", "ext"]`. `None` for a computed callee.
fn callee_names(call: &ExprCall) -> Option<Vec<String>> {
    let Expr::Path(func) = &*call.func else { return None };
    Some(func.path.segments.iter().map(|segment| segment.ident.to_string()).collect())
}

fn is_zero(expr: &Expr) -> bool {
    matches!(expr, Expr::Lit(lit) if matches!(&lit.lit, Lit::Int(int) if int.base10_digits() == "0"))
}

/// `let` bindings of a function body that bind a plain name, so a returned `promise` resolves to its initializer.
fn locals(block: &Block) -> BTreeMap<String, &Expr> {
    struct Locals<'a>(BTreeMap<String, &'a Expr>);
    impl<'ast> Visit<'ast> for Locals<'ast> {
        fn visit_local(&mut self, local: &'ast Local) {
            let mut pat = &local.pat;
            while let Pat::Type(typed) = pat {
                pat = &typed.pat;
            }
            if let (Pat::Ident(ident), Some(init)) = (pat, &local.init) {
                self.0.insert(ident.ident.to_string(), &init.expr);
            }
            visit::visit_local(self, local);
        }
    }
    let mut collected = Locals(BTreeMap::new());
    collected.visit_block(block);
    collected.0
}

/// Collects every `fn` and method of a file into the index.
struct Defs<'a> {
    fns: BTreeMap<String, Vec<FnDef<'a>>>,
}

impl<'ast> Visit<'ast> for Defs<'ast> {
    fn visit_impl_item_fn(&mut self, method: &'ast ImplItemFn) {
        self.fns.entry(method.sig.ident.to_string()).or_default().push(FnDef { sig: &method.sig, block: &method.block });
        visit::visit_impl_item_fn(self, method);
    }

    fn visit_item_fn(&mut self, function: &'ast ItemFn) {
        self.fns
            .entry(function.sig.ident.to_string())
            .or_default()
            .push(FnDef { sig: &function.sig, block: &function.block });
        visit::visit_item_fn(self, function);
    }
}

/// Finds a call that reads the result of the previous promise.
struct ResultReaders(bool);

impl<'ast> Visit<'ast> for ResultReaders {
    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(func) = &*call.func
            && func.path.segments.last().is_some_and(|segment| RESULT_READERS.iter().any(|name| segment.ident == name))
        {
            self.0 = true;
        }
        visit::visit_expr_call(self, call);
    }
}

/// Finds a write to contract state in whatever it visits; follows `&mut self` helper calls into their bodies.
struct Writes<'i, 'a> {
    index: &'i Index<'a>,
    expanded: BTreeSet<String>,
    found: bool,
}

impl<'ast> Visit<'ast> for Writes<'_, 'ast> {
    fn visit_expr(&mut self, expr: &'ast Expr) {
        if self.found {
            return;
        }
        match expr {
            Expr::Assign(assign) if is_rooted_at_self(&assign.left) => self.found = true,
            Expr::Binary(binary) if is_compound_assignment(&binary.op) && is_rooted_at_self(&binary.left) => {
                self.found = true;
            }
            Expr::Reference(reference) if reference.mutability.is_some() && is_rooted_at_self(&reference.expr) => {
                self.found = true;
            }
            Expr::MethodCall(call) if is_rooted_at_self(&call.receiver) => self.visit_call_on_self(call),
            _ => {}
        }
        visit::visit_expr(self, expr);
    }
}

impl<'ast> Writes<'_, 'ast> {
    /// `self.balances.insert(..)` writes; `self.credit(..)` and `self.ledger.credit(..)` write when a `&mut self`
    /// method of that name in this crate does.
    fn visit_call_on_self(&mut self, call: &'ast ExprMethodCall) {
        let name = call.method.to_string();
        if !is_bare_self(&call.receiver) && MUTATORS.contains(&name.as_str()) {
            self.found = true;
        } else if self.expanded.insert(name.clone()) {
            let index = self.index;
            for def in index.defs(&name).iter().filter(|def| def.takes_mut_self()) {
                self.visit_block(def.block);
            }
        }
    }
}

fn is_compound_assignment(op: &BinOp) -> bool {
    matches!(
        op,
        BinOp::AddAssign(_)
            | BinOp::SubAssign(_)
            | BinOp::MulAssign(_)
            | BinOp::DivAssign(_)
            | BinOp::RemAssign(_)
            | BinOp::BitXorAssign(_)
            | BinOp::BitAndAssign(_)
            | BinOp::BitOrAssign(_)
            | BinOp::ShlAssign(_)
            | BinOp::ShrAssign(_)
    )
}

/// Whether `expr` names a place inside `self`: `self`, `self.a.b`, `self.m[k]`, `*self.m.entry(k).or_default()`.
fn is_rooted_at_self(mut expr: &Expr) -> bool {
    loop {
        expr = match expr {
            Expr::Field(field) => &field.base,
            Expr::Index(index) => &index.expr,
            Expr::Unary(unary) if matches!(unary.op, UnOp::Deref(_)) => &unary.expr,
            Expr::MethodCall(call) if PROJECTIONS.iter().any(|name| call.method == name) => &call.receiver,
            Expr::Paren(inner) => &inner.expr,
            Expr::Group(inner) => &inner.expr,
            Expr::Try(inner) => &inner.expr,
            Expr::Reference(inner) => &inner.expr,
            Expr::Path(path) => return path.path.is_ident("self"),
            _ => return false,
        }
    }
}

/// Walks a function body in execution order and records each expression it can return, with whether a write to
/// state has happened on the way there. `if`, `match`, blocks, `let .. else` and `return` are followed; a branch
/// that always returns or panics does not pass its writes on to the code after it.
struct Flow<'i, 'a> {
    index: &'i Index<'a>,
    out: Vec<(&'a Expr, bool)>,
}

impl<'a> Flow<'_, 'a> {
    fn writes(&self, expr: &'a Expr) -> bool {
        let mut writes = Writes { index: self.index, expanded: BTreeSet::new(), found: false };
        writes.visit_expr(expr);
        writes.found
    }

    /// `written` is whether a write already happened; `value` is whether the block's value is returned. The result
    /// is whether a write happened by the end of the block, `None` if the block never completes.
    fn block(&mut self, block: &'a Block, written: bool, value: bool) -> Option<bool> {
        let mut written = written;
        for (i, stmt) in block.stmts.iter().enumerate() {
            let is_last = i + 1 == block.stmts.len();
            written = match stmt {
                Stmt::Local(local) => match &local.init {
                    Some(init) => {
                        let after = self.expr(&init.expr, written, false)?;
                        if let Some((_, otherwise)) = &init.diverge {
                            self.expr(otherwise, after, false);
                        }
                        after
                    }
                    None => written,
                },
                Stmt::Expr(expr, semi) => self.expr(expr, written, value && is_last && semi.is_none())?,
                Stmt::Macro(mac) if diverges(&mac.mac) => return None,
                Stmt::Macro(_) | Stmt::Item(_) => written,
            };
        }
        Some(written)
    }

    fn expr(&mut self, expr: &'a Expr, written: bool, value: bool) -> Option<bool> {
        match expr {
            Expr::Block(block) => self.block(&block.block, written, value),
            Expr::Paren(inner) => self.expr(&inner.expr, written, value),
            Expr::If(branch) => {
                let written = written || self.writes(&branch.cond);
                let then = self.block(&branch.then_branch, written, value);
                let otherwise = match &branch.else_branch {
                    Some((_, otherwise)) => self.expr(otherwise, written, value),
                    None => Some(written),
                };
                join(then, otherwise)
            }
            Expr::Match(switch) => {
                let written = written || self.writes(&switch.expr);
                let mut after = None;
                for arm in &switch.arms {
                    let arm_after = self.expr(&arm.body, written, value);
                    after = join(after, arm_after);
                }
                after
            }
            Expr::Return(ret) => {
                if let Some(returned) = &ret.expr {
                    self.expr(returned, written, true);
                }
                None
            }
            Expr::Macro(ExprMacro { mac, .. }) if diverges(mac) => None,
            Expr::Call(call) if is_panic_call(call) => None,
            _ => {
                let written = written || self.writes(expr);
                let mut nested = NestedReturns(Vec::new());
                nested.visit_expr(expr);
                self.out.extend(nested.0.into_iter().map(|returned| (returned, written)));
                if value {
                    self.out.push((expr, written));
                }
                Some(written)
            }
        }
    }
}

/// Whether a write happened once either branch has completed; a branch that never completes adds nothing.
fn join(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a || b),
        (only, None) | (None, only) => only,
    }
}

fn diverges(mac: &Macro) -> bool {
    mac.path
        .segments
        .last()
        .is_some_and(|segment| ["panic", "unreachable", "todo", "unimplemented"].iter().any(|name| segment.ident == name))
}

/// `env::panic_str(..)`, `near_sdk::env::panic_str(..)`, `panic_str(..)`.
fn is_panic_call(call: &ExprCall) -> bool {
    matches!(&*call.func, Expr::Path(func) if func.path.segments.last().is_some_and(|segment| segment.ident == "panic_str"))
}

/// `return` expressions buried inside a statement (loops, `?`-less closures excluded): each is a returned value.
struct NestedReturns<'a>(Vec<&'a Expr>);

impl<'ast> Visit<'ast> for NestedReturns<'ast> {
    fn visit_expr_return(&mut self, ret: &'ast ExprReturn) {
        if let Some(returned) = &ret.expr {
            self.0.push(returned);
        }
        visit::visit_expr_return(self, ret);
    }

    /// A `return` inside a closure leaves the closure, not the hook.
    fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(source: &str) -> Vec<Finding> {
        RULE.check(&Crate::from_sources([("src/lib.rs", source)]).unwrap())
    }

    fn items(source: &str) -> Vec<String> {
        check(source).into_iter().map(|finding| finding.item).collect()
    }

    /// A vault in the shape of the incident: credit, then notify the receiver named in `msg`, return the promise.
    const VULNERABLE: &str = r#"
        #[near]
        impl FungibleTokenReceiver for Vault {
            fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> PromiseOrValue<U128> {
                require!(env::predecessor_account_id() == self.token, "only the token");
                self.credit(&sender_id, amount.0);
                match msg.parse::<AccountId>() {
                    Ok(receiver) => PromiseOrValue::Promise(
                        ext_receiver::ext(receiver).with_static_gas(GAS).on_deposit(sender_id, amount),
                    ),
                    Err(_) => PromiseOrValue::Value(U128(0)),
                }
            }
        }
        impl Vault {
            fn credit(&mut self, account: &AccountId, amount: u128) {
                let balance = self.balances.get(account).copied().unwrap_or(0);
                self.balances.insert(account.clone(), balance + amount);
            }
        }
    "#;

    /// The smallest fix: the credit moves into a callback that runs only once the notification succeeded.
    const DEFERRED: &str = r#"
        #[near]
        impl FungibleTokenReceiver for Vault {
            fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> PromiseOrValue<U128> {
                match msg.parse::<AccountId>() {
                    Ok(receiver) => PromiseOrValue::Promise(
                        ext_receiver::ext(receiver)
                            .on_deposit(sender_id.clone(), amount)
                            .then(Self::ext(env::current_account_id()).on_notified(sender_id, amount)),
                    ),
                    Err(_) => {
                        self.credit(&sender_id, amount.0);
                        PromiseOrValue::Value(U128(0))
                    }
                }
            }
        }
        #[near]
        impl Vault {
            #[private]
            pub fn on_notified(&mut self, sender_id: AccountId, amount: U128, #[callback_result] notified: Result<(), PromiseError>) -> U128 {
                if notified.is_ok() {
                    self.credit(&sender_id, amount.0);
                    U128(0)
                } else {
                    amount
                }
            }
        }
        impl Vault {
            fn credit(&mut self, account: &AccountId, amount: u128) {
                self.balances.insert(account.clone(), amount);
            }
        }
    "#;

    #[test]
    fn flags_a_credit_followed_by_a_returned_notification_and_locates_it() {
        let findings = check(VULNERABLE);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF004", Severity::Critical));
        assert_eq!((finding.item.as_str(), finding.line, finding.column), ("Vault::ft_on_transfer", 4, 16));
        assert!(finding.message.contains("no callback is attached to it"), "{}", finding.message);
    }

    #[test]
    fn credit_in_a_callback_that_saw_the_notification_succeed_is_clean() {
        assert!(check(DEFERRED).is_empty());
    }

    #[test]
    fn flags_the_other_receiver_hooks_and_near_bindgen() {
        for hook in ["nft_on_transfer", "mt_on_transfer"] {
            let source = VULNERABLE.replace("ft_on_transfer", hook).replace("#[near]", "#[near_bindgen]");
            assert_eq!(items(&source), [format!("Vault::{hook}")], "{hook}");
        }
    }

    #[test]
    fn flags_a_public_hook_in_an_inherent_impl() {
        let source = "#[near] impl Vault { pub fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {
            self.total += a.0;
            ext_receiver::ext(r()).on_deposit(s, a)
        } }";
        assert_eq!(items(source), ["Vault::ft_on_transfer"]);
    }

    #[test]
    fn every_kind_of_write_counts() {
        for write in [
            "self.total = a.0;",
            "self.total += a.0;",
            "self.balances[&s] -= a.0;",
            "*self.balances.entry(s.clone()).or_default() += a.0;",
            "self.balances.insert(s.clone(), a.0);",
            "self.accounts.remove(&s);",
            "self.queue.push(a.0);",
            "if let Some(b) = self.balances.get_mut(&s) { *b += 1; }",
            "credit_all(&mut self.balances, a.0);",
            "self.ledger.credit(a.0);",
        ] {
            let source = format!(
                "#[near] impl FungibleTokenReceiver for Vault {{
                    fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {{
                        {write}
                        ext_receiver::ext(r()).on_deposit(s, a)
                    }}
                }}
                impl Ledger {{ fn credit(&mut self, a: u128) {{ self.total += a; }} }}"
            );
            assert_eq!(items(&source), ["Vault::ft_on_transfer"], "{write}");
        }
    }

    #[test]
    fn reads_and_writes_to_locals_are_not_state_writes() {
        for read in [
            "let held = self.balances.get(&s).copied().unwrap_or(0); log!(\"{}\", held);",
            "let mut copy = self.balances.clone(); copy.insert(s.clone(), 1);",
            "let mut local = 0; local += a.0;",
            "self.ledger.balance_of(&s);",
            "require!(self.balances.contains_key(&s), \"unknown\");",
        ] {
            let source = format!(
                "#[near] impl FungibleTokenReceiver for Vault {{
                    fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {{
                        {read}
                        ext_receiver::ext(r()).on_deposit(s, a)
                    }}
                }}
                impl Ledger {{ fn balance_of(&self, s: &AccountId) -> u128 {{ self.total }} }}"
            );
            assert!(check(&source).is_empty(), "{read}");
        }
    }

    #[test]
    fn follows_a_credit_through_nested_helpers() {
        let source = "#[near] impl FungibleTokenReceiver for Vault {
            fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {
                self.accept(&s, a.0);
                ext_receiver::ext(r()).on_deposit(s, a)
            }
        }
        impl Vault {
            fn accept(&mut self, s: &AccountId, a: u128) { self.book(s, a); }
            fn book(&mut self, s: &AccountId, a: u128) { self.balances.insert(s.clone(), a); }
        }";
        assert_eq!(items(source), ["Vault::ft_on_transfer"]);
    }

    #[test]
    fn a_helper_that_only_reads_is_not_a_write() {
        let source = "#[near] impl FungibleTokenReceiver for Vault {
            fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {
                self.check(&s);
                ext_receiver::ext(r()).on_deposit(s, a)
            }
        }
        impl Vault {
            fn check(&self, s: &AccountId) { require!(self.balances.contains_key(s), \"unknown\"); }
        }";
        assert!(check(source).is_empty());
    }

    #[test]
    fn recursive_helpers_terminate() {
        let source = "#[near] impl FungibleTokenReceiver for Vault {
            fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {
                self.ping();
                self.notify(s, a)
            }
        }
        impl Vault {
            fn ping(&mut self) { self.pong(); }
            fn pong(&mut self) { self.ping(); }
            fn notify(&self, s: AccountId, a: U128) -> Promise { self.notify(s, a) }
        }";
        assert!(check(source).is_empty());
    }

    #[test]
    fn follows_a_promise_through_a_local_a_helper_and_a_wrapper() {
        for returned in [
            "let notice = ext_receiver::ext(r()).on_deposit(s, a); notice",
            "let notice: Promise = ext_receiver::ext(r()).on_deposit(s, a); PromiseOrValue::Promise(notice)",
            "self.notify(s, a)",
            "Self::notify_free(s, a)",
            "notify_free(s, a).into()",
            "return Promise::new(r()).function_call(\"on_deposit\".into(), vec![], NearToken::from_yoctonear(0), GAS);",
            "PromiseOrValue::Promise(ext_receiver::ext(r()).on_deposit(s, a))",
        ] {
            let source = format!(
                "#[near] impl FungibleTokenReceiver for Vault {{
                    fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> PromiseOrValue<U128> {{
                        self.total += a.0;
                        {returned}
                    }}
                }}
                impl Vault {{
                    fn notify(&self, s: AccountId, a: U128) -> Promise {{ ext_receiver::ext(r()).on_deposit(s, a) }}
                    fn notify_free(s: AccountId, a: U128) -> Promise {{ ext_receiver::ext(r()).on_deposit(s, a) }}
                }}"
            );
            assert_eq!(items(&source), ["Vault::ft_on_transfer"], "{returned}");
        }
    }

    #[test]
    fn a_credit_after_the_promise_is_built_but_before_it_is_returned_still_counts() {
        let source = "#[near] impl FungibleTokenReceiver for Vault {
            fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {
                let notice = ext_receiver::ext(r()).on_deposit(s.clone(), a);
                self.balances.insert(s, a.0);
                notice
            }
        }";
        assert_eq!(items(source), ["Vault::ft_on_transfer"]);
    }

    #[test]
    fn a_callback_that_does_not_read_the_result_does_not_settle() {
        for callback in [
            "pub fn on_notified(&mut self, s: AccountId, a: U128) -> U128 { self.balances.insert(s, 0); a }",
            "pub fn on_notified(&mut self, s: AccountId, a: U128, #[callback_unwrap] n: ()) -> U128 { self.balances.remove(&s); U128(0) }",
        ] {
            let source = format!("{VULNERABLE_WITH_CALLBACK} impl Vault {{ {callback} }}");
            let findings = check(&source);
            assert_eq!(findings.len(), 1, "{callback}");
            assert!(findings[0].message.contains("`on_notified` does not both read"), "{}", findings[0].message);
        }
    }

    const VULNERABLE_WITH_CALLBACK: &str = "#[near] impl FungibleTokenReceiver for Vault {
        fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {
            self.total += a.0;
            ext_receiver::ext(r()).on_deposit(s.clone(), a).then(Self::ext(env::current_account_id()).on_notified(s, a))
        }
    }";

    #[test]
    fn a_callback_that_reads_the_result_but_writes_nothing_does_not_settle() {
        let source = format!(
            "{VULNERABLE_WITH_CALLBACK} #[near] impl Vault {{
                pub fn on_notified(&mut self, s: AccountId, a: U128, #[callback_result] n: Result<(), PromiseError>) -> U128 {{
                    if n.is_err() {{ a }} else {{ U128(0) }}
                }}
            }}"
        );
        assert_eq!(items(&source), ["Vault::ft_on_transfer"]);
    }

    #[test]
    fn a_callback_that_reads_the_result_and_writes_state_settles() {
        for read in [
            "#[callback_result] n: Result<(), PromiseError>",
            "n: ()",
        ] {
            let body = if read.starts_with('#') { "" } else { "if !env::is_promise_success() { self.total -= 1; }" };
            let source = format!(
                "{VULNERABLE_WITH_CALLBACK} impl Vault {{
                    pub fn on_notified(&mut self, s: AccountId, a: U128, {read}) -> U128 {{
                        {body} self.total -= a.0; a
                    }}
                }}"
            );
            assert!(check(&source).is_empty(), "{read}");
        }
    }

    #[test]
    fn a_callback_that_undoes_the_credit_through_a_helper_settles() {
        let source = format!(
            "{VULNERABLE_WITH_CALLBACK} impl Vault {{
                pub fn on_notified(&mut self, s: AccountId, a: U128, #[callback_result] n: Result<(), PromiseError>) -> U128 {{
                    if n.is_err() {{ self.uncredit(&s, a.0); return a; }}
                    U128(0)
                }}
                fn uncredit(&mut self, s: &AccountId, a: u128) {{ self.balances.remove(s); }}
            }}"
        );
        assert!(check(&source).is_empty());
    }

    #[test]
    fn a_callback_that_always_reports_nothing_unused_keeps_credit_and_tokens_together() {
        for returned in ["U128(0)", "false", "0.into()", "PromiseOrValue::Value(U128(0))"] {
            let source = format!(
                "{VULNERABLE_WITH_CALLBACK} impl Vault {{
                    pub fn on_notified(&mut self, s: AccountId, a: U128, #[callback_result] n: Result<(), PromiseError>) -> U128 {{
                        if n.is_err() {{ log!(\"receiver failed\"); }}
                        {returned}
                    }}
                }}"
            );
            assert!(check(&source).is_empty(), "{returned}");
        }
    }

    #[test]
    fn a_callback_that_refunds_on_one_branch_is_not_always_nothing_unused() {
        let source = format!(
            "{VULNERABLE_WITH_CALLBACK} impl Vault {{
                pub fn on_notified(&mut self, s: AccountId, a: U128, #[callback_result] n: Result<(), PromiseError>) -> U128 {{
                    if n.is_err() {{ return a; }}
                    U128(0)
                }}
            }}"
        );
        assert_eq!(items(&source), ["Vault::ft_on_transfer"]);
    }

    #[test]
    fn a_callback_missing_from_the_crate_is_reported_by_name() {
        let findings = check(VULNERABLE_WITH_CALLBACK);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`on_notified`"), "{}", findings[0].message);
    }

    #[test]
    fn one_settling_callback_in_a_chain_is_enough() {
        let source = "#[near] impl FungibleTokenReceiver for Vault {
            fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {
                self.total += a.0;
                ext_receiver::ext(r()).on_deposit(s.clone(), a)
                    .then(Self::ext(me()).with_static_gas(GAS).undo(s, a))
                    .then(Self::ext(me()).finish())
            }
        }
        #[near] impl Vault {
            #[private] pub fn undo(&mut self, s: AccountId, a: U128, #[callback_result] n: Result<(), PromiseError>) {
                if n.is_err() { self.total -= a.0; }
            }
            #[private] pub fn finish(&self) {}
        }";
        assert!(check(source).is_empty());
    }

    /// A common shape in deployed code: the callback is picked by currency and held in a local.
    #[test]
    fn a_callback_held_in_a_local_is_followed_and_every_alternative_must_settle() {
        let hook = |callback: &str| {
            format!(
                "#[near] impl FungibleTokenReceiver for Vault {{
                    fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {{
                        self.total += a.0;
                        let transfer = ext_nft::ext(r()).transfer(s.clone());
                        {callback}
                        transfer.then(callback)
                    }}
                }}
                #[near] impl Vault {{
                    #[private] pub fn undo(&mut self, s: AccountId, #[callback_result] n: Result<(), PromiseError>) {{ if n.is_err() {{ self.total = 0; }} }}
                    #[private] pub fn undo_ft(&mut self, s: AccountId, #[callback_result] n: Result<(), PromiseError>) {{ if n.is_err() {{ self.total = 1; }} }}
                    #[private] pub fn log(&self, s: AccountId) {{ env::log_str(\"done\"); }}
                }}"
            )
        };
        for settled in [
            "let callback = Self::ext(me()).with_static_gas(GAS).undo(s);",
            "let callback = if m.is_empty() { Self::ext(me()).undo(s) } else { Self::ext(me()).undo_ft(s) };",
            "let callback = if m.is_empty() { Self::ext(me()).undo(s) } else if a.0 > 1 { Self::ext(me()).undo_ft(s) } else { Self::ext(me()).undo(s) };",
        ] {
            assert!(check(&hook(settled)).is_empty(), "{settled}");
        }
        for unsettled in [
            "let callback = Self::ext(me()).log(s);",
            "let callback = if m.is_empty() { Self::ext(me()).undo(s) } else { Self::ext(me()).log(s) };",
            "let callback = if m.is_empty() { Self::ext(me()).log(s) } else { Self::ext(me()).undo(s) };",
            "let callback = if m.is_empty() { Self::ext(me()).undo(s) };",
            "let callback = other_callback;",
        ] {
            assert_eq!(items(&hook(unsettled)), ["Vault::ft_on_transfer"], "{unsettled}");
        }
    }

    #[test]
    fn a_hook_that_writes_no_state_before_its_promise_is_clean() {
        let source = "#[near] impl FungibleTokenReceiver for Vault {
            fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {
                require!(env::predecessor_account_id() == self.token, \"only the token\");
                ext_receiver::ext(r()).on_deposit(s, a)
            }
        }";
        assert!(check(source).is_empty());
    }

    #[test]
    fn a_synchronous_hook_that_credits_and_returns_a_value_is_clean() {
        let source = "#[near] impl FungibleTokenReceiver for Vault {
            fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> PromiseOrValue<U128> {
                *self.balances.entry(s).or_default() += a.0;
                PromiseOrValue::Value(U128(0))
            }
        }";
        assert!(check(source).is_empty());
    }

    #[test]
    fn a_notification_that_is_fired_but_not_returned_is_clean() {
        let source = "#[near] impl FungibleTokenReceiver for Vault {
            fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> PromiseOrValue<U128> {
                self.total += a.0;
                ext_receiver::ext(r()).on_deposit(s, a);
                PromiseOrValue::Value(U128(0))
            }
        }";
        assert!(check(source).is_empty());
    }

    #[test]
    fn a_credit_in_a_branch_that_returns_before_the_promise_does_not_count() {
        let source = "#[near] impl FungibleTokenReceiver for Vault {
            fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> PromiseOrValue<U128> {
                let Ok(receiver) = m.parse::<AccountId>() else {
                    self.total += a.0;
                    return PromiseOrValue::Value(U128(0));
                };
                if m.is_empty() {
                    self.total += a.0;
                    return PromiseOrValue::Value(U128(0));
                }
                PromiseOrValue::Promise(ext_receiver::ext(receiver).on_deposit(s, a))
            }
        }";
        assert!(check(source).is_empty());
    }

    #[test]
    fn a_credit_in_one_match_arm_does_not_reach_the_promise_in_another() {
        let source = "#[near] impl FungibleTokenReceiver for Vault {
            fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> PromiseOrValue<U128> {
                match m.parse::<AccountId>() {
                    Ok(receiver) => PromiseOrValue::Promise(ext_receiver::ext(receiver).on_deposit(s, a)),
                    Err(_) => { self.total += a.0; PromiseOrValue::Value(U128(0)) }
                }
            }
        }";
        assert!(check(source).is_empty());
    }

    #[test]
    fn a_credit_before_the_branch_reaches_the_promise_in_it() {
        let source = "#[near] impl FungibleTokenReceiver for Vault {
            fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> PromiseOrValue<U128> {
                self.total += a.0;
                match m.parse::<AccountId>() {
                    Ok(receiver) => PromiseOrValue::Promise(ext_receiver::ext(receiver).on_deposit(s, a)),
                    Err(_) => PromiseOrValue::Value(U128(0)),
                }
            }
        }";
        assert_eq!(items(source), ["Vault::ft_on_transfer"]);
    }

    #[test]
    fn a_credit_that_falls_through_an_if_reaches_the_promise_after_it() {
        let source = "#[near] impl FungibleTokenReceiver for Vault {
            fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {
                if m.is_empty() { self.total += a.0; }
                ext_receiver::ext(r()).on_deposit(s, a)
            }
        }";
        assert_eq!(items(source), ["Vault::ft_on_transfer"]);
    }

    #[test]
    fn a_branch_that_panics_does_not_pass_its_credit_on() {
        let source = "#[near] impl FungibleTokenReceiver for Vault {
            fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {
                if m.is_empty() { self.total += a.0; env::panic_str(\"no msg\"); }
                if m.len() > 99 { self.total += a.0; panic!(\"long\"); }
                ext_receiver::ext(r()).on_deposit(s, a)
            }
        }";
        assert!(check(source).is_empty());
    }

    #[test]
    fn only_exported_hooks_of_near_impls_are_considered() {
        let body = "{ self.total += a.0; ext_receiver::ext(r()).on_deposit(s, a) }";
        for source in [
            format!("impl Vault {{ pub fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {body} }}"),
            format!("#[near] impl Vault {{ fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {body} }}"),
            format!("#[near] impl Vault {{ pub fn on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {body} }}"),
            format!("#[derive(Debug)] impl Vault {{ pub fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {body} }}"),
        ] {
            assert!(check(&source).is_empty(), "{source}");
        }
    }

    #[test]
    fn a_helper_in_another_file_of_the_crate_is_followed() {
        let hook = "#[near] impl FungibleTokenReceiver for Vault {
            fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {
                self.credit(&s, a.0);
                ext_receiver::ext(r()).on_deposit(s, a)
            }
        }";
        let helper = "impl Vault { fn credit(&mut self, s: &AccountId, a: u128) { self.balances.insert(s.clone(), a); } }";
        let crate_ = Crate::from_sources([("src/lib.rs", hook), ("src/ledger.rs", helper)]).unwrap();
        let findings = RULE.check(&crate_);
        assert_eq!(findings.iter().map(|f| (f.file.as_str(), f.item.as_str())).collect::<Vec<_>>(), [("src/lib.rs", "Vault::ft_on_transfer")]);
    }

    #[test]
    fn reports_each_hook_once() {
        let source = "#[near] impl Vault {
            pub fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> Promise {
                self.total += a.0;
                if m.is_empty() { return ext_receiver::ext(r()).on_deposit(s, a); }
                ext_receiver::ext(r()).on_other(s, a)
            }
        }";
        assert_eq!(items(source), ["Vault::ft_on_transfer"]);
    }
}
