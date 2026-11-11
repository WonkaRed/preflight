//! The one recognizer of "who may call this method", shared by the rules that ask (PF007, PF008, PF013), and the
//! small syntax helpers it is built from.
//!
//! [`Guards::of`] answers for an exported method with a [`Strength`], from the method and from every same-crate
//! function, method or `macro_rules!` it reaches (followed by name through bare calls, `Self::f` / `Type::f` /
//! `module::f` paths, `self.f()` and `self.field.f()` method calls and macro calls). A call on any other receiver
//! (`Promise::new(..).transfer(..)`, `ext(..).f()`, `value.f()`) is not followed: it names no function of this
//! contract, and a promise runs in a later receipt, after the caller's state is committed. Only what a method
//! does on every path counts: a check inside one branch of an `if`, a `match` arm, a loop or a closure does not.
//! From weakest to strongest:
//!
//! - [`Strength::Mentioned`]: the body names `predecessor_account_id` or `signer_account_id` on every path, even only
//!   to log it. Rules that err towards silence (PF007, PF013) accept this.
//! - [`Strength::Restricted`]: the body restricts the caller, by one of
//!   1. `#[private]` on the method itself, or a near-plugins attribute that checks the caller:
//!      `#[access_control_any(..)]`, `#[only(..)]`. The macro puts the check into the body of the function it is
//!      written on, so it holds for every method that calls that function. `#[pause]` and `#[if_paused]` are not
//!      here: they gate on the contract being paused, whoever calls;
//!   2. a comparison of the caller with `env::current_account_id()` or with a value of the contract: `self.<field>`,
//!      or a local initialised from one (`let staking = self.staking_id.clone().expect(..)`), as an `==` argument of
//!      `require!`, `assert!` or `assert_eq!`, as the condition of an `if` whose `else` panics or returns, or as a
//!      `!=` condition of an `if` whose branch panics or returns. An `==` that only lands in a `let` or a `bool` is
//!      no check.
//!
//! No function is trusted by its name: `assert_owner()`, `require_role(..)` and `is_member(&caller)` count only
//! through the body of a function the crate defines under that name, found like any other call. A check that lives
//! in another crate (`near_sdk::assert_self`, a sibling crate's `assert_owner`) has no source here and is not seen:
//! the name could be a no-op (`use util::noop as assert_owner`), and the name is all there is to tell.
//! `assert!(amount > 0)`, `assert_one_yocto()` and `contains` on a set (which may be a set anyone can join) check
//! something other than the caller. `#[private]` counts only on the method it is written on: near-sdk checks it in the
//! generated wrapper of an exported method, not in the body, so a helper marked `#[private]` does not guard the
//! exported method that calls it.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{Span, TokenStream, TokenTree};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Attribute, BinOp, Block, Expr, ExprCall, ExprClosure, ExprForLoop, ExprIf, ExprLit, ExprMatch, ExprMethodCall,
    ExprPath, ExprWhile, ImplItemFn, Item, ItemFn, ItemImpl, ItemMacro, ItemStruct, Lit, Local, Macro, Member, Pat,
    Signature, Stmt, Token, TraitItemFn, Type, UnOp,
};

use crate::source::Crate;

/// A field below `self`, outermost first: `self.config.owner` is `["config", "owner"]`.
pub(crate) type FieldPath = Vec<String>;

pub(crate) const CALLER_FNS: [&str; 2] = ["predecessor_account_id", "signer_account_id"];

/// near-plugins attributes that check the caller's role or ownership. `pause` and `if_paused` are left out: they
/// check the contract's pause state, which says nothing about who calls.
const GUARD_ATTRS: [&str; 2] = ["access_control_any", "only"];

/// Methods that hand back the value they were called on, so `self.owner.as_ref().unwrap()` is `self.owner`.
const IDENTITY_METHODS: [&str; 10] =
    ["clone", "to_owned", "to_string", "as_ref", "as_str", "as_deref", "borrow", "unwrap", "expect", "get"];

const COMPARISON_MACROS: [&str; 4] = ["assert_eq", "assert_ne", "debug_assert_eq", "debug_assert_ne"];

/// Macros that panic unless their first argument holds.
const CONDITION_MACROS: [&str; 3] = ["require", "assert", "debug_assert"];

/// How firmly a method restricts its caller; the strongest evidence found wins.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Strength {
    #[default]
    None,
    Mentioned,
    Restricted,
}

impl Strength {
    pub(crate) fn looks_at_caller(self) -> bool {
        self >= Self::Mentioned
    }

    pub(crate) fn restricts_caller(self) -> bool {
        self >= Self::Restricted
    }
}

/// A near-plugins guard attribute: the macro writes the check into the function body.
fn plugin_strength(attrs: &[Attribute]) -> Strength {
    if attrs.iter().any(|attr| last_segment_is_one_of(attr, &GUARD_ATTRS)) {
        Strength::Restricted
    } else {
        Strength::None
    }
}

/// The attributes of a method, for the method itself: `#[private]` lets only the contract in, a near-plugins guard
/// restricts the caller.
fn attr_strength(attrs: &[Attribute]) -> Strength {
    if attrs.iter().any(|attr| attr.path().is_ident("private")) { Strength::Restricted } else { plugin_strength(attrs) }
}

/// How a call names its target, to resolve it to same-crate definitions by name.
#[derive(Clone)]
pub(crate) enum CallRef {
    /// `helper(..)`.
    Free(String),
    /// `Type::helper(..)`, `Self::helper(..)` or `module::helper(..)`.
    Assoc(String, String),
    /// `value.helper(..)`.
    Method(String),
    /// `helper!(..)`.
    Macro(String),
}

impl CallRef {
    fn name(&self) -> &str {
        match self {
            Self::Free(name) | Self::Assoc(_, name) | Self::Method(name) | Self::Macro(name) => name,
        }
    }

    /// Whether this call can reach the function `name` of impl type `owner` (`None` for a free function or
    /// macro). Calls that leave the crate, such as `Promise::new`, match nothing because no `owner` is `Promise`.
    pub(crate) fn reaches(&self, name: &str, owner: Option<&str>, has_receiver: bool) -> bool {
        match self {
            Self::Free(called) => owner.is_none() && called == name,
            Self::Assoc(qualifier, called) => called == name && owner.is_none_or(|owner| owner == qualifier),
            Self::Method(called) => has_receiver && called == name,
            Self::Macro(called) => called == name,
        }
    }
}

pub(crate) fn call_ref(segments: &[String], owner: Option<&str>) -> Option<CallRef> {
    match segments {
        [name] => Some(CallRef::Free(name.clone())),
        [.., qualifier, name] if qualifier == "Self" => Some(CallRef::Assoc(owner?.to_owned(), name.clone())),
        [.., qualifier, name] => Some(CallRef::Assoc(qualifier.clone(), name.clone())),
        [] => None,
    }
}

/// One call in a body: how it names its target, the field of `self` it goes through (`self.limits.validate()`), and
/// whether every run of the function reaches it (a call in one branch of an `if` does not dominate).
struct Site {
    call: CallRef,
    field: Option<String>,
    dominating: bool,
}

/// The crate's functions and macros with their call graph, and what each of them says about the caller.
pub(crate) struct Guards {
    fns: Vec<FnInfo>,
    /// For each function, the same-crate functions it calls on every path: what its guard strength comes from.
    guard_edges: Vec<Vec<usize>>,
    /// `(file, line, column)` of a function's name, to its index.
    sites: BTreeMap<(usize, usize, usize), usize>,
}

struct FnInfo {
    name: String,
    owner: Option<String>,
    has_receiver: bool,
    /// What its attributes establish for the method itself (`#[private]` included).
    attr: Strength,
    /// What its body establishes, for the method itself and for every method that reaches it; a near-plugins guard
    /// attribute is part of the body.
    body: Strength,
    calls: Vec<Site>,
}

impl Guards {
    pub(crate) fn new(krate: &Crate) -> Self {
        let mut collector = Collector::default();
        for (index, file) in krate.files.iter().enumerate() {
            collector.file = index;
            collector.visit_file(&file.ast);
        }
        let Collector { fns, sites, field_types, .. } = collector;
        let mut by_name: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (id, function) in fns.iter().enumerate() {
            by_name.entry(function.name.as_str()).or_default().push(id);
        }
        let targets = |function: &FnInfo| -> Vec<usize> {
            let mut targets = BTreeSet::new();
            for site in function.calls.iter().filter(|site| site.dominating) {
                for &id in by_name.get(site.call.name()).into_iter().flatten() {
                    let callee = &fns[id];
                    let reached = match (&site.field, &site.call) {
                        (Some(field), _) => {
                            callee.has_receiver
                                && callee.owner.as_ref().is_some_and(|owner| {
                                    field_types.get(field).is_some_and(|types| types.contains(owner))
                                })
                        }
                        (None, CallRef::Method(_)) => {
                            callee.has_receiver
                                && (function.owner.is_none()
                                    || callee.owner.is_none()
                                    || function.owner == callee.owner)
                        }
                        (None, call) => call.reaches(&callee.name, callee.owner.as_deref(), callee.has_receiver),
                    };
                    if reached {
                        targets.insert(id);
                    }
                }
            }
            targets.into_iter().collect()
        };
        let guard_edges = fns.iter().map(targets).collect();
        Self { fns, guard_edges, sites }
    }

    fn id_of(&self, file: usize, name: Span) -> Option<usize> {
        let start = name.start();
        self.sites.get(&(file, start.line, start.column)).copied()
    }

    /// What the method whose name is at `name` in file number `file` of the crate says about its caller.
    /// [`Strength::None`] when no such method was collected.
    pub(crate) fn of(&self, file: usize, name: Span) -> Strength {
        self.id_of(file, name).map_or(Strength::None, |id| self.of_id(id))
    }

    fn of_id(&self, id: usize) -> Strength {
        let mut strength = self.fns[id].attr;
        for reached in reachable(id, &self.guard_edges) {
            strength = strength.max(self.fns[reached].body);
        }
        strength
    }
}

/// `id` and every function reachable from it through `edges`.
fn reachable(id: usize, edges: &[Vec<usize>]) -> Vec<usize> {
    let mut seen = vec![id];
    let mut next = 0;
    while let Some(&current) = seen.get(next) {
        next += 1;
        for &callee in &edges[current] {
            if !seen.contains(&callee) {
                seen.push(callee);
            }
        }
    }
    seen
}

#[derive(Default)]
struct Collector {
    file: usize,
    fns: Vec<FnInfo>,
    sites: BTreeMap<(usize, usize, usize), usize>,
    /// The self type of the impl block being walked.
    owner: Option<String>,
    /// For each field name of a struct, the type names it has anywhere in the crate: `self.limits.f()` reaches a
    /// method of one of them.
    field_types: BTreeMap<String, BTreeSet<String>>,
}

impl Collector {
    fn push(&mut self, sig: &Signature, attrs: &[Attribute], block: &Block, owner: Option<String>) {
        let mut body = Body { owner: owner.clone(), ..Body::default() };
        body.visit_block(block);
        let start = sig.ident.span().start();
        self.sites.insert((self.file, start.line, start.column), self.fns.len());
        self.fns.push(FnInfo {
            name: sig.ident.to_string(),
            owner,
            has_receiver: sig.receiver().is_some(),
            attr: attr_strength(attrs),
            body: body.strength.max(plugin_strength(attrs)),
            calls: body.calls,
        });
    }
}

impl<'ast> Visit<'ast> for Collector {
    fn visit_item_struct(&mut self, item: &'ast ItemStruct) {
        for field in &item.fields {
            if let Some(name) = &field.ident {
                self.field_types.entry(name.to_string()).or_default().insert(type_name(&field.ty));
            }
        }
        visit::visit_item_struct(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        let outer = self.owner.replace(type_name(&item.self_ty));
        visit::visit_item_impl(self, item);
        self.owner = outer;
    }

    fn visit_impl_item_fn(&mut self, method: &'ast ImplItemFn) {
        self.push(&method.sig, &method.attrs, &method.block, self.owner.clone());
        visit::visit_impl_item_fn(self, method);
    }

    /// A free function is never in an impl, even when nested inside one.
    fn visit_item_fn(&mut self, function: &'ast ItemFn) {
        self.push(&function.sig, &function.attrs, &function.block, None);
        let outer = self.owner.take();
        visit::visit_item_fn(self, function);
        self.owner = outer;
    }

    fn visit_trait_item_fn(&mut self, function: &'ast TraitItemFn) {
        if let Some(block) = &function.default {
            self.push(&function.sig, &function.attrs, block, None);
        }
        let outer = self.owner.take();
        visit::visit_trait_item_fn(self, function);
        self.owner = outer;
    }

    fn visit_item_macro(&mut self, item: &'ast ItemMacro) {
        let (Some(path), Some(name)) = (item.mac.path.get_ident(), &item.ident) else {
            return visit::visit_item_macro(self, item);
        };
        if path != "macro_rules" {
            return visit::visit_item_macro(self, item);
        }
        let start = name.span().start();
        self.sites.insert((self.file, start.line, start.column), self.fns.len());
        let (body, calls) = macro_body(&item.mac.tokens);
        self.fns.push(FnInfo {
            name: format!("{name}!"),
            owner: None,
            has_receiver: false,
            attr: Strength::None,
            body,
            calls: calls.into_iter().map(|call| Site { call, field: None, dominating: true }).collect(),
        });
    }
}

/// What a `macro_rules!` body says about the caller, and the macros it calls. Its tokens are not expressions, so this
/// reads names: `predecessor_account_id`, and `current_account_id` beside it.
fn macro_body(tokens: &TokenStream) -> (Strength, Vec<CallRef>) {
    let mut calls = Vec::new();
    let mut idents = Vec::new();
    collect_macro_names(tokens, &mut calls, &mut idents);
    let mut strength = Strength::None;
    if idents.iter().any(|name| name == "current_account_id")
        && idents.iter().any(|name| name == "predecessor_account_id")
    {
        strength = Strength::Restricted;
    }
    if idents.iter().any(|name| CALLER_FNS.contains(&name.as_str())) {
        strength = strength.max(Strength::Mentioned);
    }
    (strength, calls)
}

fn collect_macro_names(tokens: &TokenStream, calls: &mut Vec<CallRef>, idents: &mut Vec<String>) {
    let mut previous: Option<String> = None;
    for tree in tokens.clone() {
        match tree {
            TokenTree::Ident(ident) => {
                let name = ident.to_string();
                idents.push(name.clone());
                previous = Some(name);
            }
            TokenTree::Punct(punct) if punct.as_char() == '!' => {
                if let Some(name) = previous.take() {
                    calls.push(CallRef::Macro(format!("{name}!")));
                }
            }
            TokenTree::Group(group) => {
                previous = None;
                collect_macro_names(&group.stream(), calls, idents);
            }
            TokenTree::Punct(_) | TokenTree::Literal(_) => previous = None,
        }
    }
}

/// One function body: what it establishes by itself, and what it calls.
#[derive(Default)]
struct Body {
    owner: Option<String>,
    strength: Strength,
    calls: Vec<Site>,
    /// How many branches, arms, loops and closures the walk is inside: nothing they establish holds on every path.
    conditional: usize,
    /// Locals bound to the caller, to `env::current_account_id()`, and to a value read from `self`.
    caller_locals: BTreeSet<String>,
    current_locals: BTreeSet<String>,
    field_locals: BTreeSet<String>,
}

impl Body {
    fn establish(&mut self, strength: Strength) {
        if self.conditional == 0 {
            self.strength = self.strength.max(strength);
        }
    }

    fn conditionally(&mut self, walk: impl FnOnce(&mut Self)) {
        self.conditional += 1;
        walk(self);
        self.conditional -= 1;
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

    fn is_current_account(&self, expr: &Expr) -> bool {
        match peel(expr) {
            Expr::Call(call) => is_call_to(call, &["current_account_id"]),
            Expr::Path(path) => {
                path.path.get_ident().is_some_and(|name| self.current_locals.contains(&name.to_string()))
            }
            _ => false,
        }
    }

    /// A value the contract holds: `self.owner`, or a local initialised from one.
    fn is_contract_value(&self, expr: &Expr) -> bool {
        field_path(expr).is_some()
            || matches!(peel(expr), Expr::Path(path)
                if path.path.get_ident().is_some_and(|name| self.field_locals.contains(&name.to_string())))
    }

    /// `left == right` (or `!=` guarding a divergent branch): the caller against the contract itself or a value
    /// of the contract.
    fn compare(&mut self, left: &Expr, right: &Expr) {
        for (caller, other) in [(left, right), (right, left)] {
            if !self.is_caller(caller) {
                continue;
            }
            if self.is_current_account(other) || self.is_contract_value(other) {
                self.establish(Strength::Restricted);
            }
        }
    }
}

impl<'ast> Visit<'ast> for Body {
    /// Items nested in a body are collected as functions of their own.
    fn visit_item(&mut self, _: &'ast Item) {}

    fn visit_local(&mut self, local: &'ast Local) {
        if let (Some(init), Some(name)) = (&local.init, bound_ident(&local.pat)) {
            if self.is_caller(&init.expr) {
                self.caller_locals.insert(name.clone());
            }
            if self.is_current_account(&init.expr) {
                self.current_locals.insert(name.clone());
            }
            if field_path(&init.expr).is_some() {
                self.field_locals.insert(name);
            }
        }
        visit::visit_local(self, local);
    }

    fn visit_expr_if(&mut self, branch: &'ast ExprIf) {
        if diverges(&branch.then_branch) {
            for (left, right) in inequalities(&branch.cond) {
                self.compare(left, right);
            }
        }
        if let Some((_, otherwise)) = &branch.else_branch
            && matches!(&**otherwise, Expr::Block(block) if diverges(&block.block))
        {
            for (left, right) in equalities(&branch.cond) {
                self.compare(left, right);
            }
        }
        self.visit_expr(&branch.cond);
        self.conditionally(|body| body.visit_block(&branch.then_branch));
        if let Some((_, otherwise)) = &branch.else_branch {
            self.conditionally(|body| body.visit_expr(otherwise));
        }
    }

    fn visit_expr_match(&mut self, matched: &'ast ExprMatch) {
        self.visit_expr(&matched.expr);
        self.conditionally(|body| matched.arms.iter().for_each(|arm| body.visit_arm(arm)));
    }

    fn visit_expr_for_loop(&mut self, looped: &'ast ExprForLoop) {
        self.visit_expr(&looped.expr);
        self.conditionally(|body| body.visit_block(&looped.body));
    }

    fn visit_expr_while(&mut self, looped: &'ast ExprWhile) {
        self.conditionally(|body| visit::visit_expr_while(body, looped));
    }

    fn visit_expr_closure(&mut self, closure: &'ast ExprClosure) {
        self.conditionally(|body| visit::visit_expr_closure(body, closure));
    }

    fn visit_expr_path(&mut self, path: &'ast ExprPath) {
        if path.path.segments.last().is_some_and(|segment| CALLER_FNS.iter().any(|name| segment.ident == name)) {
            self.establish(Strength::Mentioned);
        }
        visit::visit_expr_path(self, path);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(func) = &*call.func {
            let segments: Vec<String> = func.path.segments.iter().map(|segment| segment.ident.to_string()).collect();
            if let Some(call) = call_ref(&segments, self.owner.as_deref()) {
                self.site(call, None);
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let name = call.method.to_string();
        if CALLER_FNS.contains(&name.as_str()) {
            self.establish(Strength::Mentioned);
        }
        // Only a call on `self` or on a field of `self` can be a method of this contract.
        if matches!(peel(&call.receiver), Expr::Path(receiver) if receiver.path.is_ident("self")) {
            self.site(CallRef::Method(name), None);
        } else if let Some(field) = field_path(&call.receiver).and_then(|path| path.last().cloned()) {
            self.site(CallRef::Method(name), Some(field));
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        let Some(name) = mac.path.segments.last().map(|segment| segment.ident.to_string()) else { return };
        let key = format!("{name}!");
        self.site(CallRef::Macro(key), None);
        // `require!`, `assert!`, `assert_eq!`, `format!` ... take comma-separated expressions: parse and walk them.
        match Punctuated::<Expr, Token![,]>::parse_terminated.parse2(mac.tokens.clone()) {
            Ok(arguments) => {
                if COMPARISON_MACROS.contains(&name.as_str())
                    && name.ends_with("_eq")
                    && let [left, right, ..] = arguments.iter().collect::<Vec<_>>()[..]
                {
                    self.compare(left, right);
                }
                if CONDITION_MACROS.contains(&name.as_str())
                    && let Some(condition) = arguments.first()
                {
                    for (left, right) in equalities(condition) {
                        self.compare(left, right);
                    }
                }
                for argument in &arguments {
                    self.visit_expr(argument);
                }
            }
            Err(_) if tokens_contain(&mac.tokens, &CALLER_FNS) => self.establish(Strength::Mentioned),
            Err(_) => {}
        }
    }
}

impl Body {
    fn site(&mut self, call: CallRef, field: Option<String>) {
        self.calls.push(Site { call, field, dominating: self.conditional == 0 });
    }
}

/// The operands of every `==` that must hold for execution to go on: `a == b`, `a == b && c`, `a == b || c == d`.
fn equalities(cond: &Expr) -> Vec<(&Expr, &Expr)> {
    match cond {
        Expr::Binary(binary) if matches!(binary.op, BinOp::Eq(_)) => vec![(&*binary.left, &*binary.right)],
        Expr::Binary(binary) if matches!(binary.op, BinOp::And(_) | BinOp::Or(_)) => {
            let mut all = equalities(&binary.left);
            all.extend(equalities(&binary.right));
            all
        }
        Expr::Paren(inner) => equalities(&inner.expr),
        Expr::Group(inner) => equalities(&inner.expr),
        _ => Vec::new(),
    }
}

/// The operands of every `!=` that, when it is false, lets execution go on: `a != b` and `a != b || c`.
fn inequalities(cond: &Expr) -> Vec<(&Expr, &Expr)> {
    match cond {
        Expr::Binary(binary) if matches!(binary.op, BinOp::Ne(_)) => vec![(&*binary.left, &*binary.right)],
        Expr::Binary(binary) if matches!(binary.op, BinOp::Or(_)) => {
            let mut all = inequalities(&binary.left);
            all.extend(inequalities(&binary.right));
            all
        }
        Expr::Paren(inner) => inequalities(&inner.expr),
        Expr::Group(inner) => inequalities(&inner.expr),
        Expr::Unary(inner) if matches!(inner.op, UnOp::Not(_)) => match peel_parens(&inner.expr) {
            Expr::Binary(binary) if matches!(binary.op, BinOp::Eq(_)) => vec![(&*binary.left, &*binary.right)],
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

fn peel_parens(mut expr: &Expr) -> &Expr {
    while let Expr::Paren(inner) = expr {
        expr = &inner.expr;
    }
    expr
}

/// Whether a block ends the call when it runs: a `return`, a panic macro or `env::panic_str`, at its top level.
pub(crate) fn diverges(block: &Block) -> bool {
    block.stmts.iter().any(|stmt| matches!(stmt, Stmt::Expr(Expr::Return(_), _)) || is_panic(stmt))
}

fn is_panic(stmt: &Stmt) -> bool {
    const PANIC_MACROS: [&str; 4] = ["panic", "unreachable", "todo", "unimplemented"];
    let is_panic_macro =
        |mac: &Macro| mac.path.segments.last().is_some_and(|name| PANIC_MACROS.iter().any(|panic| name.ident == panic));
    match stmt {
        Stmt::Expr(Expr::Macro(mac), _) => is_panic_macro(&mac.mac),
        Stmt::Macro(mac) => is_panic_macro(&mac.mac),
        Stmt::Expr(Expr::Call(call), _) => is_call_to(call, &["panic_str", "panic", "abort"]),
        _ => false,
    }
}

/// Whether every call of a body ends in a panic: it has no `return` or `?`, and its last top-level statement is
/// `env::panic_str("not supported")`, `unreachable!()` or the like. A failed call leaves no state change and no
/// promise behind, so whatever runs before the panic (`self.assert_live();`) has no effect.
pub(crate) fn always_panics(block: &Block) -> bool {
    #[derive(Default)]
    struct Leaves(bool);
    impl<'ast> Visit<'ast> for Leaves {
        fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) {
            self.0 = true;
        }
        fn visit_expr_try(&mut self, _: &'ast syn::ExprTry) {
            self.0 = true;
        }
        /// A macro that is not known to leave the function alone may expand to a `return`.
        fn visit_macro(&mut self, mac: &'ast Macro) {
            const PLAIN: [&str; 17] = [
                "panic",
                "unreachable",
                "todo",
                "unimplemented",
                "assert",
                "assert_eq",
                "assert_ne",
                "debug_assert",
                "debug_assert_eq",
                "debug_assert_ne",
                "require",
                "log",
                "format",
                "vec",
                "matches",
                "write",
                "writeln",
            ];
            self.0 |= !mac.path.segments.last().is_some_and(|name| PLAIN.iter().any(|plain| name.ident == plain));
        }
    }
    let mut leaves = Leaves::default();
    leaves.visit_block(block);
    !leaves.0 && block.stmts.last().is_some_and(is_panic)
}

/// `#[near]`, `#[near(..)]` or `#[near_bindgen]` style matching: whether the last path segment is one of `names`.
pub(crate) fn last_segment_is_one_of(attr: &Attribute, names: &[&str]) -> bool {
    attr.path().segments.last().is_some_and(|segment| names.iter().any(|name| segment.ident == name))
}

pub(crate) fn type_name(ty: &Type) -> String {
    match ty {
        Type::Path(path) => path.path.segments.last().map_or_else(String::new, |segment| segment.ident.to_string()),
        _ => "<unnamed type>".to_owned(),
    }
}

pub(crate) fn bound_ident(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(ident) => Some(ident.ident.to_string()),
        Pat::Type(typed) => bound_ident(&typed.pat),
        _ => None,
    }
}

/// Whether any identifier in `tokens`, at any depth, is one of `names`.
pub(crate) fn tokens_contain(tokens: &TokenStream, names: &[&str]) -> bool {
    tokens.clone().into_iter().any(|token| match token {
        TokenTree::Ident(ident) => names.iter().any(|name| ident == name),
        TokenTree::Group(group) => tokens_contain(&group.stream(), names),
        _ => false,
    })
}

/// A call whose function path ends in one of `names`, as in `env::predecessor_account_id()`.
pub(crate) fn is_call_to(call: &ExprCall, names: &[&str]) -> bool {
    matches!(&*call.func, Expr::Path(func)
        if func.path.segments.last().is_some_and(|segment| names.iter().any(|name| segment.ident == name)))
}

/// `expr` without the wrappers that do not change what value it is: references, dereferences, parentheses,
/// `Some(..)`, and calls such as `.clone()` or `.unwrap()`.
pub(crate) fn peel(mut expr: &Expr) -> &Expr {
    loop {
        expr = match expr {
            Expr::Paren(inner) => &inner.expr,
            Expr::Group(inner) => &inner.expr,
            Expr::Reference(inner) => &inner.expr,
            Expr::Unary(inner) if matches!(inner.op, UnOp::Deref(_)) => &inner.expr,
            Expr::MethodCall(call)
                if IDENTITY_METHODS.iter().any(|name| call.method == name)
                    && (call.args.is_empty() || call.method == "expect") =>
            {
                &call.receiver
            }
            Expr::Call(call) if call.args.len() == 1 && is_call_to(call, &["Some"]) => &call.args[0],
            _ => return expr,
        }
    }
}

/// The field of `self` that `expr` names, if it is `self.a.b`, possibly indexed, borrowed or dereferenced.
pub(crate) fn field_path(expr: &Expr) -> Option<FieldPath> {
    match peel(expr) {
        Expr::Field(field) => {
            let member = match &field.member {
                Member::Named(name) => name.to_string(),
                Member::Unnamed(index) => index.index.to_string(),
            };
            let mut path = match peel(&field.base) {
                Expr::Path(base) if base.path.is_ident("self") => Vec::new(),
                base => field_path(base)?,
            };
            path.push(member);
            Some(path)
        }
        Expr::Index(index) => field_path(&index.expr),
        _ => None,
    }
}

/// Every variable a pattern binds.
pub(crate) fn pattern_idents(pat: &Pat) -> Vec<String> {
    #[derive(Default)]
    struct Idents(Vec<String>);
    impl<'ast> Visit<'ast> for Idents {
        fn visit_pat_ident(&mut self, ident: &'ast syn::PatIdent) {
            self.0.push(ident.ident.to_string());
            visit::visit_pat_ident(self, ident);
        }
    }
    let mut idents = Idents::default();
    idents.visit_pat(pat);
    idents.0
}

/// Whether the node `walk` visits mentions one of `names`.
pub(crate) fn mentions(names: &BTreeSet<String>, walk: impl FnOnce(&mut Mentions<'_>)) -> bool {
    let mut search = Mentions { names, found: false };
    walk(&mut search);
    search.found
}

/// Looks for the identifiers in `names` in an expression, including inside macro arguments.
pub(crate) struct Mentions<'a> {
    names: &'a BTreeSet<String>,
    found: bool,
}

impl<'ast> Visit<'ast> for Mentions<'_> {
    fn visit_expr_path(&mut self, path: &'ast ExprPath) {
        self.found |= path.path.get_ident().is_some_and(|ident| self.names.contains(&ident.to_string()));
    }

    fn visit_expr_lit(&mut self, literal: &'ast ExprLit) {
        // `format!("{text}")` captures `text` from the format string.
        if let Lit::Str(format) = &literal.lit {
            self.found |= captured_names(&format.value()).iter().any(|name| self.names.contains(*name));
        }
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        match Punctuated::<Expr, Token![,]>::parse_terminated.parse2(mac.tokens.clone()) {
            Ok(arguments) => arguments.iter().for_each(|argument| self.visit_expr(argument)),
            Err(_) => self.found |= self.names.iter().any(|name| tokens_contain(&mac.tokens, &[name.as_str()])),
        }
    }
}

/// The names a format string captures inline: `["text", "n"]` for `"{text}: {n:>4} {{literal}}"`.
pub(crate) fn captured_names(format: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let mut rest = format;
    while let Some(open) = rest.find('{') {
        rest = &rest[open + 1..];
        if let Some(escaped) = rest.strip_prefix('{') {
            rest = escaped;
            continue;
        }
        let end = rest.find(|c: char| !(c.is_alphanumeric() || c == '_')).unwrap_or(rest.len());
        names.push(&rest[..end]);
        rest = &rest[end..];
    }
    names
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_format_string_captures_inline_arguments_but_not_escaped_braces() {
        assert_eq!(captured_names("{text}: {n:>4} {{literal}} {} {0}"), ["text", "n", "", "0"]);
    }

    /// The strength of the function named `name` in `source`.
    fn strength(source: &str, name: &str) -> Strength {
        let krate = Crate::from_sources([("src/lib.rs", source)]).unwrap();
        let guards = Guards::new(&krate);
        let id = guards.fns.iter().position(|function| function.name == name).expect("function in the source");
        guards.of_id(id)
    }

    fn of_body(body: &str) -> Strength {
        strength(&format!("#[near] impl C {{ pub fn m(&mut self, amount: u128) {{ {body} }} }}"), "m")
    }

    #[test]
    fn private_and_near_plugins_attributes_restrict() {
        let on = |attr: &str| strength(&format!("#[near] impl C {{ {attr} pub fn m(&mut self) {{}} }}"), "m");
        assert_eq!(on("#[private]"), Strength::Restricted);
        for attr in ["#[access_control_any(roles(Role::Dao))]", "#[only(owner)]", "#[near_plugins::only(self)]"] {
            assert_eq!(on(attr), Strength::Restricted, "{attr}");
        }
    }

    /// near-plugins `Pausable`: `#[pause]` makes the method panic while the contract is paused, for every caller.
    #[test]
    fn a_pause_attribute_does_not_restrict_the_caller() {
        let on = |attr: &str| strength(&format!("#[near] impl C {{ {attr} pub fn m(&mut self) {{}} }}"), "m");
        for attr in ["#[pause]", "#[pause(except(roles(Role::Dao)))]", "#[if_paused]", "#[near_plugins::pause]"] {
            assert_eq!(on(attr), Strength::None, "{attr}");
        }
    }

    #[test]
    fn the_caller_compared_with_the_current_account_restricts() {
        for body in [
            "assert_eq!(env::predecessor_account_id(), env::current_account_id());",
            "assert_eq!(env::current_account_id(), env::predecessor_account_id(), \"no\");",
            "require!(env::predecessor_account_id() == env::current_account_id());",
            "let me = env::current_account_id(); require!(me == env::predecessor_account_id());",
            "let caller = env::predecessor_account_id(); require!(caller == env::current_account_id());",
            "if env::predecessor_account_id() != env::current_account_id() { env::panic_str(\"no\"); }",
        ] {
            assert_eq!(of_body(body), Strength::Restricted, "{body}");
        }
    }

    #[test]
    fn the_caller_compared_with_a_value_of_the_contract_restricts() {
        for body in [
            "require!(env::predecessor_account_id() == self.owner_id);",
            "assert_eq!(self.owner_id, env::predecessor_account_id());",
            "let staking = self.staking_id.clone().expect(\"ERR\"); assert_eq!(env::predecessor_account_id(), staking);",
            "let caller = env::predecessor_account_id(); let owner = self.config.owner.clone(); require!(caller == owner);",
            "if env::predecessor_account_id() != self.owner_id { env::panic_str(\"no\"); }",
            "if env::signer_account_id() != self.owner_id || amount == 0 { return; }",
            "if !(env::predecessor_account_id() == self.owner_id) { panic!(\"no\"); }",
        ] {
            assert_eq!(of_body(body), Strength::Restricted, "{body}");
        }
    }

    #[test]
    fn a_not_equal_that_does_not_end_the_call_is_not_a_guard() {
        for body in [
            "if env::predecessor_account_id() != self.owner_id { self.strikes += 1; }",
            "if env::predecessor_account_id() != self.owner_id && amount > 0 { panic!(\"no\"); }",
            "assert_ne!(env::predecessor_account_id(), self.banned);",
            "require!(env::predecessor_account_id() != self.banned);",
        ] {
            assert_eq!(of_body(body), Strength::Mentioned, "{body}");
        }
    }

    /// A name proves nothing: a call is a guard only through the body of the function the crate defines under it.
    /// Re-audit: `use util::noop as assert_owner`, a re-export and a sibling crate's no-op all look like this.
    #[test]
    fn no_function_is_trusted_by_its_name() {
        for body in [
            "assert_self();",
            "near_sdk::assert_self();",
            "common::assert_owner(self);",
            "<Self as Rbac>::require_role(&Role::Administrator);",
            "self.assert_owner();",
            "Self::assert_admin(self);",
            "only_owner!(self);",
            "self.check_authorized();",
            "require!(self.is_member(&other));",
        ] {
            assert_eq!(of_body(body), Strength::None, "{body}");
        }
        for body in [
            "require!(self.is_member(&env::predecessor_account_id()));",
            "let caller = env::predecessor_account_id(); require!(self.has_role(&caller));",
        ] {
            assert_eq!(of_body(body), Strength::Mentioned, "{body}");
        }
        let aliased = "use util::noop as assert_owner; #[near] impl C { pub fn m(&mut self) { assert_owner(); } }";
        assert_eq!(strength(aliased, "m"), Strength::None);
    }

    /// The true positives of the recognizer: checks that are not about the caller must not count.
    #[test]
    fn checks_that_are_not_about_the_caller_do_not_count() {
        for body in [
            "assert!(amount > 0);",
            "assert_eq!(amount, 5);",
            "require!(amount > 0, \"zero\");",
            "assert_one_yocto();",
            "self.assert_not_paused();",
            "Self::require_unpaused();",
            "self.assert_enough_balance(amount);",
            "self.assert_not_self();",
            "self.assert_not_owner();",
            "self.check_deposit(amount);",
            "require!(self.members.contains(&other));",
            "self.get_owner();",
        ] {
            assert_eq!(of_body(body), Strength::None, "{body}");
        }
    }

    #[test]
    fn naming_the_caller_without_restricting_it_is_only_mentioned() {
        assert_eq!(of_body("env::log_str(&format!(\"{}\", env::predecessor_account_id()));"), Strength::Mentioned);
        assert_eq!(of_body("guard!(caller => env::predecessor_account_id());"), Strength::Mentioned);
    }

    #[test]
    fn a_helper_or_a_crate_local_macro_it_calls_counts() {
        let helper = "
            #[near] impl C { pub fn m(&mut self) { self.gate(); } }
            impl C { fn gate(&self) { Self::inner(); } fn inner() { require!(env::predecessor_account_id() == env::current_account_id()); } }";
        assert_eq!(strength(helper, "m"), Strength::Restricted);
        let local_macro = "
            macro_rules! only_dao { () => { require!(env::predecessor_account_id() == env::current_account_id()) } }
            macro_rules! outer { () => { only_dao!() } }
            #[near] impl C { pub fn m(&mut self) { outer!(); } }";
        assert_eq!(strength(local_macro, "m"), Strength::Restricted);
        let unrelated = "
            #[near] impl C { pub fn m(&mut self) { self.other(); } }
            impl D { fn gate(&self) { require!(env::predecessor_account_id() == env::current_account_id()); } }
            impl C { fn other(&self) {} }";
        assert_eq!(strength(unrelated, "m"), Strength::None);
    }

    #[test]
    fn private_guards_only_the_method_it_is_written_on_but_a_plugin_check_runs_in_its_callers_too() {
        let source = |attr: &str| {
            format!("#[near] impl C {{ pub fn m(&mut self) {{ self.helper(); }} {attr} fn helper(&self) {{}} }}")
        };
        assert_eq!(strength(&source("#[private]"), "m"), Strength::None);
        assert_eq!(strength(&source("#[private]"), "helper"), Strength::Restricted);
        assert_eq!(strength(&source("#[only(owner)]"), "m"), Strength::Restricted);
        assert_eq!(strength(&source("#[access_control_any(roles(Role::Dao))]"), "m"), Strength::Restricted);
        assert_eq!(strength(&source("#[pause]"), "m"), Strength::None);
    }

    /// A name the crate defines is decided by the definition: a no-op `assert_owner`, or a local macro that does
    /// nothing, guards nothing; the same name defined with a real check still guards.
    #[test]
    fn an_authority_name_the_crate_defines_is_decided_by_its_body() {
        let with = |function: &str, local_macro: &str| {
            strength(
                &format!(
                    "{local_macro} #[near] impl C {{ pub fn m(&mut self) {{ self.assert_owner(); only_owner!(self); }} {function} }}"
                ),
                "m",
            )
        };
        let noop_macro = "macro_rules! only_owner { ($s:expr) => { let _ = &$s; } }";
        let real_macro = "macro_rules! only_owner { ($s:expr) => { $s.assert_owner() } }";
        let real_fn = "fn assert_owner(&self) { require!(env::predecessor_account_id() == self.owner); }";
        for noop_fn in [
            "fn assert_owner(&self) { env::log_str(\"TODO\"); }",
            "fn assert_owner(&self) { require!(!self.owner.as_str().is_empty()); }",
        ] {
            assert_eq!(with(noop_fn, noop_macro), Strength::None, "{noop_fn}");
        }
        assert_eq!(with(real_fn, real_macro), Strength::Restricted);
        // the macro is not trusted by its name either: a definition of the function alone decides
        assert_eq!(with("fn assert_owner(&self) {}", ""), Strength::None);
    }

    /// Only `self.f()` and `self.field.f()` can be methods of the contract; a promise runs in a later receipt.
    #[test]
    fn a_method_call_is_followed_only_on_self_or_on_a_field_of_that_type() {
        let source = |call: &str| {
            format!(
                "struct C {{ limits: Limits }}
                 #[near] impl C {{ pub fn m(&mut self, to: AccountId) {{ self.owner = to.clone(); {call} }}
                    pub fn transfer(&mut self) {{ require!(env::predecessor_account_id() == self.owner); }}
                    pub fn after(&mut self) {{ require!(env::predecessor_account_id() == env::current_account_id()); }} }}
                 impl Limits {{ fn validate(&self) {{ require!(env::predecessor_account_id() == self.owner); }} }}
                 impl Config {{ fn validate(&self) {{ require!(env::predecessor_account_id() == env::current_account_id()); }} }}"
            )
        };
        for call in [
            "Promise::new(to).transfer(NearToken::from_near(1));",
            "Self::ext(env::current_account_id()).after();",
            "other.after();",
            "self.config.validate();",
        ] {
            assert_eq!(strength(&source(call), "m"), Strength::None, "{call}");
        }
        assert_eq!(strength(&source("self.after();"), "m"), Strength::Restricted);
        assert_eq!(strength(&source("self.limits.validate();"), "m"), Strength::Restricted);
        assert_eq!(strength(&source("Self::after(self);"), "m"), Strength::Restricted);
    }

    /// An `==` is a check only as the condition of `require!`, `assert!`, `assert_eq!`, or of an `if` that panics or
    /// returns on one side; a guard on one path of the method guards nothing.
    #[test]
    fn an_equality_or_a_guard_that_does_not_decide_the_path_is_no_check() {
        for body in [
            "let from_owner = env::predecessor_account_id() == self.owner;",
            "if env::predecessor_account_id() == self.owner { self.n += 1; }",
            "if amount > 1000 { require!(env::predecessor_account_id() == env::current_account_id()); }",
            "match amount { 0 => require!(env::predecessor_account_id() == env::current_account_id()), _ => {} }",
            "for _ in 0..amount { require!(env::predecessor_account_id() == env::current_account_id()); }",
            "let check = || { require!(env::predecessor_account_id() == env::current_account_id()); }; check();",
        ] {
            assert!(of_body(body) <= Strength::Mentioned, "{body}");
        }
        for body in [
            "require!(env::predecessor_account_id() == self.owner);",
            "assert!(env::predecessor_account_id() == self.owner && amount > 0);",
            "if env::predecessor_account_id() == self.owner { self.n += 1; } else { env::panic_str(\"no\"); }",
            "if env::predecessor_account_id() != self.owner { return; }",
        ] {
            assert_eq!(of_body(body), Strength::Restricted, "{body}");
        }
    }

    #[test]
    fn a_function_nested_in_a_body_does_not_guard_its_parent() {
        let source = "#[near] impl C { pub fn m(&mut self) { fn never_called() { require!(env::predecessor_account_id() == env::current_account_id()); } } }";
        assert_eq!(strength(source, "m"), Strength::None);
    }
}
