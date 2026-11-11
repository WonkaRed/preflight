//! PF008: a method stores caller-supplied data without making the caller pay for the storage.
//!
//! Every byte a NEAR contract stores locks part of the contract's own balance (10^19 yoctoNEAR per byte). A
//! method that lets anyone add entries to the contract's state for the price of gas lets anyone lock up the
//! contract's funds, until a payout it owes fails. Docs: https://docs.near.org/smart-contracts/security/storage
//! and the "million small deposits" page next to it.
//!
//! The rule looks at the methods the `#[near]` / `#[near_bindgen]` macro exports (`pub` methods of an inherent
//! impl, every method of a trait impl) and flags a `&mut self` method that adds to a collection held by the
//! contract with data taken from its arguments, and never accounts for the storage. "Adds" is `insert`, `push`,
//! `push_back`, `push_front`, `extend` or `entry(..).or_insert*` / `or_default` on `self.<field>` (also on an
//! element fetched from it, as in `self.by_user.get_mut(&k).unwrap().push(x)`), or `env::storage_write`.
//! "From its arguments" means the call mentions a parameter, or a local computed from one, or a variable bound by
//! a `for`, `if let`, `while let` or `match` over one.
//!
//! A method accounts for the storage when it, or a same-crate function it calls, mentions `attached_deposit`,
//! `storage_usage`, `storage_byte_cost`, `refund_deposit` or `refund_deposit_to_account` anywhere (followed by
//! name through bare calls, `Self::f` / `Type::f` / `module::f` paths and method calls). Never flagged: a
//! `#[payable]` method (it takes a deposit, so the author has priced it; a payable method that ignores the
//! deposit is missed), `#[private]` and `#[init]` methods, view methods, and removals.
//!
//! Not the defect, so never flagged:
//! - A store keyed by the caller itself (`env::predecessor_account_id()` or a local holding it) whose
//!   parameters are all of bounded size: a balance update such as `self.credits.insert(player, held - amount)`
//!   with `amount: U128`. It is one small entry per account, not data the caller chooses. Bounded types are the
//!   integers, `bool`, `char`, `U128`, `U64`, `I128`, `I64`, `AccountId`, `NearToken`, `Gas`, and `Option`,
//!   references and tuples of those. A `String`, `Vec`, bytes or any other type feeding the store makes it a
//!   finding again, and so does a key taken from a parameter, which can name any number of new entries.
//! - A method that restricts its caller (`guards::Guards`: `#[private]`, a near-plugins attribute, the caller
//!   compared with a field of `self` or with the current account on every path), itself or through a same-crate
//!   helper. A guard called by name (`assert_owner()`, `Self::require_role`) counts only through a body the crate
//!   defines. Only a privileged account can grow the storage. Naming the caller,
//!   `!=` without a panic and `contains` do not count: they exclude one account, or name a set anyone may join.
//! - An update of an existing record: the key was fetched earlier in the same function with `self.<field>.get(k)`
//!   or `get_mut(k)` followed by `.unwrap()`, `.expect(..)`, `.expect_or_reject(..)`, `.unwrap_or_else(|| panic)`,
//!   `.ok_or(..)?` or a `let .. else`, so the entry exists, and `self.<field>.insert(k, ..)` replaces it. The fetch
//!   may be made by a same-crate method (unique by name) that does exactly that with one of its parameters
//!   (`fn assert_proposal(&self, id: u32) -> Proposal { self.proposals.get(&id).expect(..) }`), and `k` may be a
//!   plain variable, a local bound from one, or either with `.clone()`, `.as_str()`, `.into()` and the like. The
//!   fetch must be made on every path to the store: one made inside an `if` or `else` branch, a `match` arm, a
//!   loop body, a closure or the right side of `&&` / `||` proves the entry only for what that branch itself
//!   stores. The two keys are taken to be the same value when they come from the same variable. The entry also
//!   exists inside the branch of `if let Some(..) = self.<field>.get(k)` (alone or before `&&`) and a `Some(..)` arm
//!   of a `match` on it, and after a `match` whose `None` arm panics or returns, or a method that is just
//!   `self.<field>.get(<parameter>)` (defined once) called in place of the `get`; an `else` or `None` arm that stores
//!   is still a new entry. The exemption is for the entry, not for what is put in it: when the value stored back is
//!   of unbounded type (the bounded types above are the test) and comes from a parameter, directly, through a
//!   local, or written into the fetched record (`p.note = note`, `p.note += &note`, `p.lines.push(line)`,
//!   `.extend`, `.insert`, `.push_str`), it is still a finding. A bounded value, such as a counter or a flag,
//!   stays silent, and so does a record read back from the state by a parameter that is only its key.
//!
//! NEP-145 judgment: if the crate exports `storage_deposit`, callers register and pay there, so an `insert` or
//! `entry(..)` keyed by the caller itself is treated as covered by that registration even when its data is of
//! free size. A key taken from a parameter is not: it can name an unregistered account.
//!
//! Knowingly missed: a store made inside a helper function rather than the exported method; a collection
//! reached through a local (`let list = &mut self.items; list.push(x)`); a bare field assignment of a growing
//! value (`self.name = name`), which replaces rather than adds; one entry per account created by many
//! throwaway accounts, which the caller-keyed exemption allows; and a deposit that is checked but too small,
//! which needs arithmetic the scanner cannot judge; unbounded data written into a fetched record through any
//! other method (`p.set_note(note)`), which the scanner cannot tell from a harmless call.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::Span;
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Attribute, BinOp, Block, Expr, ExprAssign, ExprBinary, ExprCall, ExprClosure, ExprForLoop, ExprIf, ExprLet,
    ExprMatch, ExprMethodCall, ExprPath, ExprTry, ExprWhile, FnArg, GenericArgument, ImplItemFn, ItemFn, ItemImpl, Local, Macro, Pat, PathArguments, Signature, Stmt, Token,
    TraitItemFn, Type, Visibility,
};

use super::pf007_unguarded_admin::{
    CALLER_FNS, CallRef, bound_ident, call_ref, is_call_to, is_compound_assignment, is_near_attr, peel,
    tokens_contain, type_name,
};
use crate::finding::{Finding, Severity};
use crate::guards::{Guards, Mentions, diverges, mentions, pattern_idents};
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf008StorageDeposit;

pub static RULE: Pf008StorageDeposit = Pf008StorageDeposit;

impl Rule for Pf008StorageDeposit {
    fn id(&self) -> &'static str {
        "PF008"
    }

    fn title(&self) -> &'static str {
        "Storage stored without a deposit"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn help(&self) -> &'static str {
        "make the method #[payable], measure env::storage_usage() before and after, and require the attached deposit to cover the growth"
    }

    fn check(&self, krate: &Crate) -> Vec<Finding> {
        // A second pass, once the methods that fetch a record by one of their parameters are known.
        let mut fns = collect(krate, &Fetchers::default());
        let fetchers = Fetchers::of(&fns);
        if !fetchers.is_empty() {
            fns = collect(krate, &fetchers);
        }
        let guards = Guards::new(krate);
        let registers_storage = fns.iter().any(|f| f.name == "storage_deposit" && f.export.is_some());

        let mut findings = Vec::new();
        for (id, function) in fns.iter().enumerate() {
            let Some(export) = &function.export else { continue };
            if !export.mut_self || export.private || export.payable || export.init {
                continue;
            }
            let unpaid = function.stores.iter().find(|store| !(registers_storage && store.keyed_by_caller));
            let Some(store) = unpaid else { continue };
            if guards.of(function.file, export.span).restricts_caller()
                || reachable(&fns, id).into_iter().any(|reached| fns[reached].accounts_storage)
            {
                continue;
            }
            let item = format!("{}::{}", function.owner.as_deref().unwrap_or_default(), function.name);
            let message = format!(
                "`{item}` stores caller-supplied data with `{}` but never charges for it: it is not #[payable] and \
                 neither it nor a function it calls reads `env::attached_deposit()` or `env::storage_usage()`, so \
                 any account can lock the contract's balance by filling its storage",
                store.operation
            );
            findings.push(self.finding(&krate.files[function.file], export.span, item, message));
        }
        findings
    }
}

/// Names whose mention means the method looks at what it stores or what was paid for it.
const ACCOUNTING_FNS: [&str; 5] =
    ["attached_deposit", "storage_usage", "storage_byte_cost", "refund_deposit", "refund_deposit_to_account"];

/// Methods that add to a collection.
const ADDERS: [&str; 5] = ["insert", "push", "push_back", "push_front", "extend"];

/// `entry(..)` followers that insert the entry when it is missing.
const ENTRY_ADDERS: [&str; 3] = ["or_insert", "or_insert_with", "or_default"];

struct Export {
    span: Span,
    private: bool,
    payable: bool,
    init: bool,
    mut_self: bool,
}

/// An addition to a collection with data from the method's arguments.
struct Store {
    /// What was called, for the message: `self.entries.push`.
    operation: String,
    /// The key is the caller (`env::predecessor_account_id()` or a local holding it).
    keyed_by_caller: bool,
}

#[derive(Default)]
struct FnFacts {
    file: usize,
    name: String,
    owner: Option<String>,
    has_receiver: bool,
    export: Option<Export>,
    accounts_storage: bool,
    calls: Vec<CallRef>,
    stores: Vec<Store>,
    /// `(field, parameter index)` of every fetch of the field by one of the function's own parameters.
    fetches: Vec<(String, usize)>,
    /// `(field, parameter index)` when the whole body is `self.<field>.get(<parameter>)`: it hands back the entry
    /// or `None`, so a caller that panics on `None` has proved the entry exists.
    lookup: Option<(String, usize)>,
}

/// The same-crate methods that fetch a record by one of their parameters, keyed by name. A name defined twice in the
/// crate is left out: a call by name cannot tell which one runs.
#[derive(Default)]
struct Fetchers {
    /// Methods that insist on the record (`fetches`).
    insisting: BTreeMap<String, Vec<(String, usize)>>,
    /// Methods that only look it up (`lookup`).
    looking: BTreeMap<String, Vec<(String, usize)>>,
}

impl Fetchers {
    fn of(fns: &[FnFacts]) -> Self {
        let mut by_name: BTreeMap<&str, Vec<&FnFacts>> = BTreeMap::new();
        for function in fns.iter().filter(|function| function.has_receiver) {
            by_name.entry(&function.name).or_default().push(function);
        }
        let mut fetchers = Self::default();
        for (name, defined) in by_name {
            if let [only] = defined.as_slice() {
                if !only.fetches.is_empty() {
                    fetchers.insisting.insert(name.to_owned(), only.fetches.clone());
                }
                if let Some(lookup) = &only.lookup {
                    fetchers.looking.insert(name.to_owned(), vec![lookup.clone()]);
                }
            }
        }
        fetchers
    }

    fn is_empty(&self) -> bool {
        self.insisting.is_empty() && self.looking.is_empty()
    }
}

#[derive(Default)]
struct Frame {
    facts: FnFacts,
    /// Parameters and every local computed from one.
    derived: BTreeSet<String>,
    /// The part of `derived` that comes from a parameter of unbounded type.
    free_derived: BTreeSet<String>,
    /// The locals that hold unbounded data of the caller: `free_derived`, except that a record fetched from the
    /// contract's state by such a parameter as the key is the contract's data, not the caller's.
    free_content: BTreeSet<String>,
    caller_locals: BTreeSet<String>,
    /// `(field, key variable)` of every `self.<field>.get(key)` whose absence the function does not survive.
    existing: BTreeSet<(String, String)>,
    /// Every typed parameter in order, `""` for a pattern that binds no single name.
    params: Vec<String>,
    /// `let name = <variable>` (through `.clone()` and the like): the variable it stands for.
    aliases: BTreeMap<String, String>,
}

impl Frame {
    /// Whether the node `walk` visits mentions a parameter or a local computed from one.
    fn is_derived(&self, walk: impl FnOnce(&mut Mentions<'_>)) -> bool {
        mentions(&self.derived, walk)
    }

    /// Whether the node `walk` visits mentions a parameter of unbounded type, or a local computed from one.
    fn is_free_derived(&self, walk: impl FnOnce(&mut Mentions<'_>)) -> bool {
        mentions(&self.free_derived, walk)
    }

    fn is_caller(&self, expr: &Expr) -> bool {
        match peel(expr) {
            Expr::Call(call) => is_call_to(call, &CALLER_FNS),
            Expr::MethodCall(call) => call.args.is_empty() && CALLER_FNS.iter().any(|name| call.method == name),
            Expr::Path(path) => path.path.get_ident().is_some_and(|name| self.caller_locals.contains(&name.to_string())),
            _ => false,
        }
    }

    fn replaces_existing(&self, field: &str, key: Option<&Expr>) -> bool {
        key.and_then(|key| self.key(key)).is_some_and(|key| self.existing.contains(&(field.to_owned(), key)))
    }

    /// The variable a key expression comes from, with a local bound from another variable resolved to it.
    fn key(&self, expr: &Expr) -> Option<String> {
        let variable = key_variable(expr)?;
        Some(self.aliases.get(&variable).cloned().unwrap_or(variable))
    }

    /// Notes the fetch `expr` as `self.<field>.get(key)`, or as a call of a method that only looks the entry up, when
    /// it is one.
    fn note_fetch(&mut self, fetchers: &Fetchers, expr: &Expr) {
        if let Some((field, key)) = fetch(expr) {
            self.note_existing(field, key);
        } else if let Expr::MethodCall(call) = expr
            && is_self(&call.receiver)
            && let Some(lookups) = fetchers.looking.get(&call.method.to_string())
        {
            for (field, index) in lookups {
                if let Some(key) = call.args.iter().nth(*index) {
                    self.note_existing(field.clone(), key);
                }
            }
        }
    }

    /// Notes that `field` has an entry under the key expression `key`.
    fn note_existing(&mut self, field: String, key: &Expr) {
        if let Some(key) = self.key(key) {
            self.existing.insert((field, key));
        }
    }

    /// Whether the value `call` inserts (every argument after the key) is of unbounded size and comes from a
    /// parameter: replacing an existing record with it still grows storage.
    fn stores_free_data(&self, call: &ExprMethodCall) -> bool {
        mentions(&self.free_content, |search| call.args.iter().skip(1).for_each(|value| search.visit_expr(value)))
    }

    /// Whether `source` holds unbounded data of the caller: it mentions a parameter or local of that kind anywhere
    /// but in the key of a fetch from the contract's state.
    fn carries_free_data(&self, source: &Expr, fetchers: &Fetchers) -> bool {
        match source {
            Expr::MethodCall(call) => {
                let fetch = field_of_self(&call.receiver).is_some()
                    || (is_self(&call.receiver)
                        && [&fetchers.insisting, &fetchers.looking].iter().any(|known| known.contains_key(&call.method.to_string())));
                !fetch
                    && (mentions(&self.free_content, |search| call.args.iter().for_each(|arg| search.visit_expr(arg)))
                        || self.carries_free_data(&call.receiver, fetchers))
            }
            Expr::Try(attempt) => self.carries_free_data(&attempt.expr, fetchers),
            Expr::Paren(inner) => self.carries_free_data(&inner.expr, fetchers),
            Expr::Reference(inner) => self.carries_free_data(&inner.expr, fetchers),
            _ => mentions(&self.free_content, |search| search.visit_expr(source)),
        }
    }

    /// Notes that the local `target` is built from (`target.field = value`, `target.items.push(value)`) holds what
    /// `value` holds, so that storing it back stores that data.
    fn note_write_into(&mut self, target: &Expr, value: impl FnOnce(&mut Mentions<'_>)) {
        if let Some(local) = root_local(target)
            && mentions(&self.free_content, value)
        {
            self.derived.insert(local.clone());
            self.free_content.insert(local);
        }
    }

    /// Notes `self.<field>...<adder>(..)` when the call mentions something derived from the arguments.
    fn note_store(&mut self, call: &ExprMethodCall) {
        let name = call.method.to_string();
        let adds = ADDERS.contains(&name.as_str()) || ENTRY_ADDERS.contains(&name.as_str());
        let Some(field) = adds.then(|| field_of_self(&call.receiver)).flatten() else { return };
        if !self.is_derived(|search| search.visit_expr_method_call(call)) {
            return;
        }
        let key = match name.as_str() {
            "insert" if self.replaces_existing(&field, call.args.first()) && !self.stores_free_data(call) => return,
            "insert" => call.args.first(),
            _ if ENTRY_ADDERS.contains(&name.as_str()) => entry_key(&call.receiver),
            _ => None,
        };
        let keyed_by_caller = key.is_some_and(|key| self.is_caller(key));
        if keyed_by_caller && !self.is_free_derived(|search| search.visit_expr_method_call(call)) {
            return;
        }
        self.facts.stores.push(Store { operation: format!("self.{field}.{name}"), keyed_by_caller });
    }
}

struct ImplContext {
    owner: String,
    exports: bool,
    is_trait_impl: bool,
}

struct Collector<'a> {
    fetchers: &'a Fetchers,
    file: usize,
    fns: Vec<FnFacts>,
    frames: Vec<Frame>,
    impl_context: Option<ImplContext>,
}

impl<'a> Collector<'a> {
    fn new(fetchers: &'a Fetchers) -> Self {
        Self { fetchers, file: 0, fns: Vec::new(), frames: Vec::new(), impl_context: None }
    }

    fn begin_fn(&mut self, sig: &Signature, attrs: &[Attribute], exported: bool) {
        let has_attr = |name: &str| attrs.iter().any(|attr| attr.path().is_ident(name));
        let typed: Vec<_> = sig
            .inputs
            .iter()
            .filter_map(|arg| match arg {
                FnArg::Typed(arg) => Some(arg),
                FnArg::Receiver(_) => None,
            })
            .collect();
        let params: Vec<(String, bool)> =
            typed.iter().filter_map(|arg| Some((bound_ident(&arg.pat)?, is_bounded(&arg.ty)))).collect();
        let positions = typed.iter().map(|arg| bound_ident(&arg.pat).unwrap_or_default()).collect();
        let derived = params.iter().map(|(name, _)| name.clone()).collect();
        let free_derived: BTreeSet<String> =
            params.into_iter().filter(|(_, bounded)| !bounded).map(|(name, _)| name).collect();
        let export = exported.then(|| Export {
            span: sig.ident.span(),
            private: has_attr("private"),
            payable: has_attr("payable"),
            init: has_attr("init"),
            mut_self: sig.receiver().is_some_and(|receiver| receiver.reference.is_some() && receiver.mutability.is_some()),
        });
        self.frames.push(Frame {
            facts: FnFacts {
                file: self.file,
                name: sig.ident.to_string(),
                owner: self.impl_context.as_ref().map(|context| context.owner.clone()),
                has_receiver: sig.receiver().is_some(),
                export,
                ..FnFacts::default()
            },
            derived,
            free_content: free_derived.clone(),
            free_derived,
            params: positions,
            ..Frame::default()
        });
    }

    fn end_fn(&mut self) {
        if let Some(mut frame) = self.frames.pop() {
            frame.facts.fetches = frame
                .existing
                .iter()
                .filter_map(|(field, key)| Some((field.clone(), frame.params.iter().position(|param| param == key)?)))
                .collect();
            self.fns.push(frame.facts);
        }
    }

    /// Runs `walk` over code that only some paths reach: a fetch made inside proves its entry for that code alone.
    fn conditionally(&mut self, walk: impl FnOnce(&mut Self)) {
        let outer = self.frames.last().map(|frame| frame.existing.clone());
        walk(self);
        if let (Some(outer), Some(frame)) = (outer, self.frames.last_mut()) {
            frame.existing = outer;
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

    /// Notes the entry fetched by `expr` as existing, for the code that runs once it was found.
    fn note_found_in(&mut self, expr: &Expr) {
        if let Some(frame) = self.frames.last_mut() {
            frame.note_fetch(self.fetchers, expr);
        }
    }

    /// Notes the entries a condition fetches with `if let Some(..) = self.<field>.get(k)`, alone or on the left of
    /// `&&`: where the condition held, they exist.
    fn note_found(&mut self, condition: &Expr) {
        match condition {
            Expr::Let(found) if is_some(&found.pat) => self.note_found_in(&found.expr),
            Expr::Binary(both) if matches!(both.op, BinOp::And(_)) => {
                self.note_found(&both.left);
                self.note_found(&both.right);
            }
            _ => {}
        }
    }

    /// Marks the variables `pat` binds as derived from the arguments when `source` mentions one. A `let` that
    /// shadows a name (`let proposal = self.proposals.get(&id).unwrap()` over a parameter `proposal`) makes it a
    /// new variable: it holds the caller's data only when `source` does.
    fn bind(&mut self, pat: &Pat, source: &Expr, shadows: bool) {
        let Some(frame) = self.frames.last_mut() else { return };
        let carries_free_data = frame.carries_free_data(source, self.fetchers);
        if shadows {
            for name in pattern_idents(pat) {
                frame.free_content.remove(&name);
            }
        }
        if frame.is_derived(|search| search.visit_expr(source)) {
            let bound = pattern_idents(pat);
            if frame.is_free_derived(|search| search.visit_expr(source)) {
                frame.free_derived.extend(bound.iter().cloned());
            }
            if carries_free_data {
                frame.free_content.extend(bound.iter().cloned());
            }
            frame.derived.extend(bound);
        }
    }
}

impl<'ast> Visit<'ast> for Collector<'_> {
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
        if let Some(frame) = self.frames.last_mut() {
            frame.facts.lookup = lookup_of(&method.block, &frame.params);
        }
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
        if let Some(init) = &local.init {
            self.bind(&local.pat, &init.expr, true);
            if let Some(frame) = self.frames.last_mut() {
                if let Some(name) = bound_ident(&local.pat) {
                    // A new binding of the name: what was known of the old one no longer applies.
                    let stands_for = frame.key(&init.expr).filter(|key| *key != name);
                    frame.existing.retain(|(_, key)| *key != name);
                    frame.aliases.remove(&name);
                    frame.aliases.extend(stands_for.map(|key| (name.clone(), key)));
                }
                if let (Some(name), true) = (bound_ident(&local.pat), frame.is_caller(&init.expr)) {
                    frame.caller_locals.insert(name);
                }
                if init.diverge.is_some() {
                    frame.note_fetch(self.fetchers, &init.expr);
                }
            }
        }
        visit::visit_local(self, local);
    }

    /// A name shadowed inside a block is the caller's data again once the block ends.
    fn visit_block(&mut self, block: &'ast Block) {
        let outer = self.frames.last().map(|frame| frame.free_content.clone());
        visit::visit_block(self, block);
        if let (Some(outer), Some(frame)) = (outer, self.frames.last_mut()) {
            frame.free_content.extend(outer);
        }
    }

    fn visit_expr_for_loop(&mut self, looped: &'ast ExprForLoop) {
        self.bind(&looped.pat, &looped.expr, false);
        self.visit_expr(&looped.expr);
        self.conditionally(|this| this.visit_block(&looped.body));
    }

    fn visit_expr_while(&mut self, looped: &'ast ExprWhile) {
        self.visit_expr(&looped.cond);
        self.conditionally(|this| this.visit_block(&looped.body));
    }

    fn visit_expr_if(&mut self, branch: &'ast ExprIf) {
        self.visit_expr(&branch.cond);
        self.conditionally(|this| {
            this.note_found(&branch.cond);
            this.visit_block(&branch.then_branch);
        });
        if let Some((_, otherwise)) = &branch.else_branch {
            self.conditionally(|this| this.visit_expr(otherwise));
        }
    }

    fn visit_expr_closure(&mut self, closure: &'ast ExprClosure) {
        self.conditionally(|this| visit::visit_expr_closure(this, closure));
    }

    fn visit_expr_assign(&mut self, assign: &'ast ExprAssign) {
        if let Some(frame) = self.frames.last_mut() {
            frame.note_write_into(&assign.left, |search| search.visit_expr(&assign.right));
        }
        visit::visit_expr_assign(self, assign);
    }

    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        if is_compound_assignment(&binary.op)
            && let Some(frame) = self.frames.last_mut()
        {
            frame.note_write_into(&binary.left, |search| search.visit_expr(&binary.right));
        }
        self.visit_expr(&binary.left);
        if matches!(binary.op, BinOp::And(_) | BinOp::Or(_)) {
            self.conditionally(|this| this.visit_expr(&binary.right));
        } else {
            self.visit_expr(&binary.right);
        }
    }

    fn visit_expr_let(&mut self, condition: &'ast ExprLet) {
        self.bind(&condition.pat, &condition.expr, false);
        visit::visit_expr_let(self, condition);
    }

    fn visit_expr_match(&mut self, matched: &'ast ExprMatch) {
        for arm in &matched.arms {
            self.bind(&arm.pat, &matched.expr, false);
        }
        self.visit_expr(&matched.expr);
        if matched.arms.iter().any(|arm| is_none(&arm.pat) && ends_the_call(&arm.body)) {
            self.note_found_in(&matched.expr);
        }
        for arm in &matched.arms {
            self.conditionally(|this| {
                if is_some(&arm.pat) {
                    this.note_found_in(&matched.expr);
                }
                visit::visit_arm(this, arm);
            });
        }
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
        if let Expr::Path(func) = &*call.func {
            let segments: Vec<String> = func.path.segments.iter().map(|segment| segment.ident.to_string()).collect();
            let reference = call_ref(&segments, self.impl_context.as_ref().map(|context| context.owner.as_str()));
            if let Some(frame) = self.frames.last_mut() {
                frame.facts.calls.extend(reference);
                if segments.last().is_some_and(|name| name == "storage_write")
                    && frame.is_derived(|search| search.visit_expr_call(call)) {
                    frame.facts.stores.push(Store { operation: "env::storage_write".to_owned(), keyed_by_caller: false });
                }
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if let Some(frame) = self.frames.last_mut() {
            if ACCOUNTING_FNS.iter().any(|name| call.method == name) {
                frame.facts.accounts_storage = true;
            }
            frame.facts.calls.push(CallRef::Method(call.method.to_string()));
            if proves_existence(call) {
                frame.note_fetch(self.fetchers, &call.receiver);
            }
            if let (Some(fetches), true) = (self.fetchers.insisting.get(&call.method.to_string()), is_self(&call.receiver)) {
                for (field, index) in fetches {
                    if let Some(key) = call.args.iter().nth(*index) {
                        frame.note_existing(field.clone(), key);
                    }
                }
            }
            frame.note_store(call);
            if ADDERS.contains(&call.method.to_string().as_str()) || call.method == "push_str" {
                frame.note_write_into(&call.receiver, |search| call.args.iter().for_each(|value| search.visit_expr(value)));
            }
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_try(&mut self, attempt: &'ast ExprTry) {
        if let (Expr::MethodCall(call), Some(frame)) = (&*attempt.expr, self.frames.last_mut())
            && matches!(call.method.to_string().as_str(), "ok_or" | "ok_or_else")
        {
            frame.note_fetch(self.fetchers, &call.receiver);
        }
        visit::visit_expr_try(self, attempt);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        let Some(name) = mac.path.segments.last().map(|segment| segment.ident.to_string()) else { return };
        // `require!`, `assert!`, `format!` ... take comma-separated expressions: parse and walk them.
        let arguments = Punctuated::<Expr, Token![,]>::parse_terminated.parse2(mac.tokens.clone());
        if let Some(frame) = self.frames.last_mut() {
            frame.facts.calls.push(CallRef::Macro(format!("{name}!")));
            if arguments.is_err() && tokens_contain(&mac.tokens, &ACCOUNTING_FNS) {
                frame.facts.accounts_storage = true;
            }
        }
        for argument in arguments.iter().flatten() {
            self.visit_expr(argument);
        }
    }
}

fn collect(krate: &Crate, fetchers: &Fetchers) -> Vec<FnFacts> {
    let mut collector = Collector::new(fetchers);
    for (index, file) in krate.files.iter().enumerate() {
        collector.file = index;
        collector.visit_file(&file.ast);
    }
    collector.fns
}

/// `id` and every function reachable from it.
fn reachable(fns: &[FnFacts], id: usize) -> Vec<usize> {
    let mut seen = vec![id];
    let mut next = 0;
    while let Some(&current) = seen.get(next) {
        next += 1;
        for call in &fns[current].calls {
            for (callee, f) in fns.iter().enumerate() {
                if call.reaches(&f.name, f.owner.as_deref(), f.has_receiver) && !seen.contains(&callee) {
                    seen.push(callee);
                }
            }
        }
    }
    seen
}

/// The field of `self` at the root of `expr`: `items` for `self.items`, `self.items[3]` and
/// `self.items.get_mut(&k).unwrap()`.
fn field_of_self(expr: &Expr) -> Option<String> {
    match peel(expr) {
        Expr::Field(field) => match peel(&field.base) {
            Expr::Path(base) if base.path.is_ident("self") => Some(match &field.member {
                syn::Member::Named(name) => name.to_string(),
                syn::Member::Unnamed(index) => index.index.to_string(),
            }),
            base => field_of_self(base),
        },
        Expr::Index(index) => field_of_self(&index.expr),
        Expr::MethodCall(call) => field_of_self(&call.receiver),
        _ => None,
    }
}

/// `self.<field>.get(<key>)` or `get_mut(<key>)`: the field and the key expression.
fn fetch(expr: &Expr) -> Option<(String, &Expr)> {
    let Expr::MethodCall(call) = expr else { return None };
    if call.method != "get" && call.method != "get_mut" {
        return None;
    }
    Some((field_of_self(&call.receiver)?, call.args.first()?))
}

/// Whether the call turns a missing value into a panic: `unwrap()`, `expect(..)`, `expect_or_reject(..)` (the
/// near-sdk-contract-tools spelling) and `unwrap_or_else(|| panic)`. `unwrap_or(..)` and `unwrap_or_default()` supply
/// a value instead, so the entry may not exist.
fn proves_existence(call: &ExprMethodCall) -> bool {
    let name = call.method.to_string();
    match name.as_str() {
        "unwrap" | "expect" => true,
        _ if name.starts_with("expect_") => true,
        "unwrap_or_else" => matches!(call.args.first(), Some(Expr::Closure(closure)) if is_panicking(&closure.body)),
        _ => false,
    }
}

/// `Some(..)`.
fn is_some(pat: &Pat) -> bool {
    matches!(pat, Pat::TupleStruct(some) if some.path.is_ident("Some"))
}

/// `None`.
fn is_none(pat: &Pat) -> bool {
    matches!(pat, Pat::Ident(none) if none.ident == "None" && none.subpat.is_none())
        || matches!(pat, Pat::Path(none) if none.path.is_ident("None"))
}

/// Whether the arm body ends the call when it runs: a `return`, a panic, or a block that does either.
fn ends_the_call(expr: &Expr) -> bool {
    match expr {
        Expr::Return(_) => true,
        Expr::Block(block) => {
            diverges(&block.block)
                || matches!(block.block.stmts.last(), Some(Stmt::Expr(last, _)) if ends_the_call(last))
        }
        _ => is_panicking(expr),
    }
}

/// `(field, parameter index)` when `block` is just `self.<field>.get(<parameter>)`.
fn lookup_of(block: &syn::Block, params: &[String]) -> Option<(String, usize)> {
    let [Stmt::Expr(tail, None)] = block.stmts.as_slice() else { return None };
    let (field, key) = fetch(tail)?;
    let key = key_variable(key)?;
    Some((field, params.iter().position(|param| *param == key)?))
}

/// `panic!(..)`, `near_panic!(..)`, `env::panic_str(..)`.
fn is_panicking(expr: &Expr) -> bool {
    match expr {
        Expr::Macro(mac) => mac.mac.path.segments.last().is_some_and(|name| name.ident.to_string().contains("panic")),
        Expr::Call(call) => is_call_to(call, &["panic", "panic_str", "abort"]),
        Expr::Block(block) if block.block.stmts.len() == 1 => match &block.block.stmts[0] {
            syn::Stmt::Expr(expr, _) => is_panicking(expr),
            _ => false,
        },
        _ => false,
    }
}

fn is_self(expr: &Expr) -> bool {
    matches!(peel(expr), Expr::Path(path) if path.path.is_ident("self"))
}

/// The variable a key is made from: `id`, `&id`, `id.clone()`, `id.as_str().into()`.
fn key_variable(expr: &Expr) -> Option<String> {
    const SAME_VALUE: [&str; 5] = ["clone", "as_str", "into", "to_owned", "to_string"];
    match expr {
        Expr::Reference(reference) => key_variable(&reference.expr),
        Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
        Expr::MethodCall(call) if call.args.is_empty() && SAME_VALUE.iter().any(|name| call.method == name) => {
            key_variable(&call.receiver)
        }
        _ => None,
    }
}

/// The local variable at the root of `local.field[i]`, `*local` and the like; never `self`.
fn root_local(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Field(field) => root_local(&field.base),
        Expr::Index(index) => root_local(&index.expr),
        Expr::Paren(inner) => root_local(&inner.expr),
        Expr::Reference(inner) => root_local(&inner.expr),
        Expr::Unary(inner) => root_local(&inner.expr),
        Expr::Path(path) => path.path.get_ident().map(ToString::to_string).filter(|name| name != "self"),
        _ => None,
    }
}

/// The key of the `entry(..)` call in a chain like `self.m.entry(key).or_default()`, given the part before
/// `.or_default()`.
fn entry_key(receiver: &Expr) -> Option<&Expr> {
    match receiver {
        Expr::MethodCall(call) if call.method == "entry" => call.args.first(),
        Expr::MethodCall(call) => entry_key(&call.receiver),
        _ => None,
    }
}

/// Whether values of `ty` have a small fixed size, so that a caller cannot grow storage by choosing one.
fn is_bounded(ty: &Type) -> bool {
    const SCALARS: [&str; 21] = [
        "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "bool", "char", "U128",
        "U64", "I128", "I64", "AccountId", "NearToken", "Gas",
    ];
    match ty {
        Type::Reference(reference) => is_bounded(&reference.elem),
        Type::Paren(paren) => is_bounded(&paren.elem),
        Type::Tuple(tuple) => tuple.elems.iter().all(is_bounded),
        Type::Path(path) => path.path.segments.last().is_some_and(|segment| match &segment.arguments {
            PathArguments::None => SCALARS.iter().any(|name| segment.ident == name),
            PathArguments::AngleBracketed(generics) if segment.ident == "Option" => generics
                .args
                .iter()
                .all(|argument| matches!(argument, GenericArgument::Type(inner) if is_bounded(inner))),
            _ => false,
        }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(sources: &[(&str, &str)]) -> Vec<Finding> {
        let krate = Crate::from_sources(sources.iter().copied()).unwrap();
        RULE.check(&krate)
    }

    fn items(source: &str) -> Vec<String> {
        check(&[("src/lib.rs", source)]).into_iter().map(|finding| finding.item).collect()
    }

    /// One method in a `#[near]` impl.
    fn method(signature_and_body: &str) -> String {
        format!("#[near] impl Book {{ {signature_and_body} }}")
    }

    #[test]
    fn flags_a_guest_book_that_pushes_the_callers_text_and_locates_it() {
        let source = "#[near]\nimpl Book {\n    pub fn sign(&mut self, text: String) {\n        self.entries.push(text);\n    }\n}";
        let findings = check(&[("src/lib.rs", source)]);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF008", Severity::Medium));
        assert_eq!(finding.item, "Book::sign");
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 3, 12));
        assert!(finding.message.contains("`self.entries.push`"), "{}", finding.message);
    }

    #[test]
    fn accepts_near_bindgen_and_path_qualified_near() {
        for attr in ["#[near_bindgen]", "#[near_sdk::near]", "#[near(contract_state)]"] {
            let source = format!("{attr} impl Book {{ pub fn sign(&mut self, text: String) {{ self.entries.push(text); }} }}");
            assert_eq!(items(&source), ["Book::sign"], "{attr}");
        }
    }

    #[test]
    fn flags_every_way_of_adding_to_a_collection() {
        let stores = [
            "self.entries.push(text);",
            "self.entries.push_back(text);",
            "self.entries.push_front(text);",
            "self.entries.extend(vec![text]);",
            "self.map.insert(id, text);",
            "self.map.insert(self.next_id, text);",
            "self.map.entry(id).or_insert(0);",
            "self.map.entry(id).or_insert_with(Vec::new);",
            "self.map.entry(id).or_default();",
            "self.map.entry(2).or_default().push(text);",
            "self.by_user.get_mut(&id).unwrap().push(1u8);",
            "self.groups[0].insert(text);",
            "self.state.entries.push(text);",
            "env::storage_write(b\"key\", text.as_bytes());",
            "let copy = text.clone(); self.entries.push(copy);",
            "let n = format!(\"{text}!\"); self.entries.push(n);",
            "self.entries.push(Row { id, text });",
            "for line in lines { self.entries.push(line); }",
            "if let Some(t) = maybe { self.entries.push(t); }",
            "match maybe { Some(t) => self.entries.push(t), None => {} }",
            "self.entries.push(format!(\"{}\", text));",
        ];
        for store in stores {
            let source = method(&format!(
                "pub fn sign(&mut self, id: u64, text: String, lines: Vec<String>, maybe: Option<String>) {{ {store} }}"
            ));
            assert_eq!(items(&source), ["Book::sign"], "{store}");
        }
    }

    #[test]
    fn data_that_is_not_from_the_arguments_is_clean() {
        let stores = [
            "self.entries.push(0);",
            "self.entries.push(self.entries.len());",
            "self.log.insert(env::block_height(), 1);",
            "let mut local = Vec::new(); local.push(text);",
            "self.entries.clear();",
        ];
        for store in stores {
            let source = method(&format!("pub fn sign(&mut self, text: String) {{ {store} }}"));
            assert!(items(&source).is_empty(), "{store}");
        }
    }

    #[test]
    fn removals_overwrites_and_reads_are_clean() {
        let bodies = [
            "pub fn forget(&mut self, id: u64) { self.map.remove(&id); }",
            "pub fn rename(&mut self, name: String) { self.name = name; }",
            "pub fn get(&self, id: u64) -> Option<String> { self.map.get(&id).cloned() }",
            "pub fn count(&mut self, id: u64) { self.counter += id; }",
        ];
        for body in bodies {
            assert!(items(&method(body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn payable_private_and_init_methods_are_clean() {
        for attr in ["#[payable]", "#[private]", "#[init]"] {
            let source = method(&format!("{attr} pub fn sign(&mut self, text: String) {{ self.entries.push(text); }}"));
            assert!(items(&source).is_empty(), "{attr}");
        }
    }

    #[test]
    fn a_method_that_accounts_for_the_storage_is_clean() {
        let accounted = [
            "let before = env::storage_usage(); self.entries.push(text); let used = env::storage_usage() - before;",
            "self.entries.push(text); require!(env::attached_deposit() >= env::storage_byte_cost());",
            "self.entries.push(text); near_sdk::env::storage_usage();",
            "self.entries.push(text); refund_deposit(used);",
            "self.entries.push(text); require!(env::attached_deposit().as_yoctonear() > 0, \"pay\");",
            "self.entries.push(text); self.charge();",
            "self.entries.push(text); Self::charge(self);",
            "self.entries.push(text); self.settle();",
        ];
        for body in accounted {
            let source = format!(
                "#[near] impl Book {{ pub fn sign(&mut self, text: String) {{ {body} }} }}
                 impl Book {{
                     fn charge(&self) {{ let _ = env::attached_deposit(); }}
                     fn settle(&self) {{ self.charge(); }}
                 }}"
            );
            assert!(items(&source).is_empty(), "{body}");
        }
    }

    #[test]
    fn a_call_that_leaves_the_crate_is_not_a_charge() {
        let source = "#[near] impl Book { pub fn sign(&mut self, text: String) { Promise::new(text); self.entries.push(text); } }
                      impl Book { fn new() -> Self { let _ = env::storage_usage(); Self {} } }";
        assert_eq!(items(source), ["Book::sign"]);
    }

    #[test]
    fn a_store_keyed_by_the_caller_is_covered_only_when_the_crate_implements_storage_deposit() {
        let vote = "#[near] impl Poll { pub fn vote(&mut self, choice: String) { self.votes.insert(env::predecessor_account_id(), choice); } }";
        assert_eq!(items(vote), ["Poll::vote"]);
        let registry = "#[near] impl Poll { #[payable] pub fn storage_deposit(&mut self) {} }";
        let source = format!("{vote} {registry}");
        assert!(items(&source).is_empty());
        let by_local = "#[near] impl Poll {
            pub fn vote(&mut self, choice: String) { let who = env::predecessor_account_id(); self.votes.insert(who.clone(), choice); }
            pub fn tally(&mut self, choice: String) { self.votes.entry(env::predecessor_account_id()).or_insert(choice); }
        }";
        assert!(items(&format!("{by_local} {registry}")).is_empty());
    }

    #[test]
    fn a_balance_update_keyed_by_the_caller_is_not_a_store() {
        let bodies = [
            "let player = env::predecessor_account_id(); let held = self.credits.get(&player).unwrap_or(0); self.credits.insert(player, held - amount.0);",
            "self.credits.insert(env::predecessor_account_id(), amount.0);",
            "self.credits.entry(env::signer_account_id()).or_insert(amount.0);",
        ];
        for body in bodies {
            let source = method(&format!("pub fn cash_out(&mut self, amount: U128, note: Option<u64>) {{ {body} }}"));
            assert!(items(&source).is_empty(), "{body}");
        }
    }

    #[test]
    fn a_caller_keyed_store_of_unbounded_data_is_still_a_store() {
        let bodies = [
            "self.notes.insert(env::predecessor_account_id(), text);",
            "let note = format!(\"{text}!\"); self.notes.insert(env::predecessor_account_id(), note);",
            "for byte in text.bytes() { self.notes.insert(env::predecessor_account_id(), byte); }",
        ];
        for body in bodies {
            let source = method(&format!("pub fn note(&mut self, text: String) {{ {body} }}"));
            assert_eq!(items(&source), ["Book::note"], "{body}");
        }
        for ty in ["Vec<u8>", "&str", "(u8, String)", "Option<String>", "Custom"] {
            let source = method(&format!("pub fn note(&mut self, data: {ty}) {{ self.notes.insert(env::predecessor_account_id(), data); }}"));
            assert_eq!(items(&source), ["Book::note"], "{ty}");
        }
    }

    #[test]
    fn a_key_from_a_parameter_is_a_store_even_when_the_value_is_bounded() {
        let source = method("pub fn credit(&mut self, receiver: AccountId, amount: U128) { self.credits.insert(receiver, amount.0); }");
        assert_eq!(items(&source), ["Book::credit"]);
    }

    #[test]
    fn bounded_types_are_small_fixed_size_values() {
        for ty in ["u8", "i128", "bool", "char", "U128", "AccountId", "near_sdk::json_types::U64", "NearToken", "Gas", "&u64", "Option<U128>", "(u8, bool)"] {
            let source = method(&format!("pub fn set(&mut self, value: {ty}) {{ self.credits.insert(env::predecessor_account_id(), value); }}"));
            assert!(items(&source).is_empty(), "{ty}");
        }
    }

    #[test]
    fn a_method_restricted_to_one_account_by_equality_is_not_flagged() {
        let bodies = [
            "require!(env::predecessor_account_id() == self.shop, \"shop only\"); self.entries.push(text);",
            "require!(self.shop == env::predecessor_account_id()); self.entries.push(text);",
            "assert_eq!(env::predecessor_account_id(), self.config.shop); self.entries.push(text);",
            "debug_assert_eq!(self.shop, env::signer_account_id(), \"shop only\"); self.entries.push(text);",
            "let caller = env::predecessor_account_id(); if caller == self.shop { self.entries.push(text); } else { panic!(\"shop only\"); }",
            "let caller = env::predecessor_account_id(); if caller != self.shop { return; } self.entries.push(text);",
            "self.only_shop(); self.entries.push(text);",
        ];
        for body in bodies {
            let source = format!(
                "#[near] impl Book {{ pub fn sign(&mut self, text: String) {{ {body} }} }}
                 impl Book {{ fn only_shop(&self) {{ require!(env::predecessor_account_id() == self.shop); }} }}"
            );
            assert!(items(&source).is_empty(), "{body}");
        }
    }

    #[test]
    fn only_an_equality_with_a_field_of_self_restricts_the_caller() {
        let bodies = [
            "require!(env::predecessor_account_id() != self.banned); self.entries.push(text);",
            "require!(self.members.contains(&env::predecessor_account_id())); self.entries.push(text);",
            "require!(env::predecessor_account_id() == text); self.entries.push(text);",
            "require!(self.shop == self.owner); self.entries.push(text);",
            "let _ = env::predecessor_account_id(); self.entries.push(text);",
            // an equality that decides nothing: a `bool`, or an `if` that goes on either way
            "let from_shop = env::predecessor_account_id() == self.shop; self.entries.push(text);",
            "if env::predecessor_account_id() == self.shop { self.entries.push(text); } self.entries.push(text);",
            "if text.len() > 8 { require!(env::predecessor_account_id() == self.shop); } self.entries.push(text);",
        ];
        for body in bodies {
            let source = method(&format!("pub fn sign(&mut self, text: String) {{ {body} }}"));
            assert_eq!(items(&source), ["Book::sign"], "{body}");
        }
    }

    /// A common shape in deployed code: the guard is an attribute or a current-account check; a role check
    /// by name (`<Self as Rbac>::require_role`) is not seen, see the next test.
    #[test]
    fn an_attribute_or_a_current_account_check_restricts_the_caller() {
        let bodies = [
            "#[access_control_any(roles(Role::Dao))] pub fn sign(&mut self, text: String) { self.entries.push(text); }",
            "pub fn sign(&mut self, text: String) { assert_eq!(env::current_account_id(), env::predecessor_account_id()); self.entries.push(text); }",
            "pub fn sign(&mut self, text: String) { let staking = self.staking_id.clone().expect(\"ERR\"); assert_eq!(env::predecessor_account_id(), staking); self.entries.push(text); }",
        ];
        for body in bodies {
            let source = if body.starts_with("pub fn") || body.starts_with('#') {
                method(body)
            } else {
                method(&format!("pub fn sign(&mut self, text: String) {{ {body} }}"))
            };
            assert!(items(&source).is_empty(), "{body}");
        }
    }

    /// True positives: checks that are not about the caller do not make the store free of charge.
    #[test]
    fn checks_that_are_not_about_the_caller_do_not_restrict_it() {
        for check in [
            "assert!(text.len() < 100);",
            "assert_one_yocto();",
            "self.assert_not_paused();",
            "require!(!text.is_empty());",
            "<Self as Rbac>::require_role(&Role::Manager);",
            "self.assert_owner();",
            "common::assert_owner(self);",
        ] {
            let source = method(&format!("pub fn sign(&mut self, text: String) {{ {check} self.entries.push(text); }}"));
            assert_eq!(items(&source), ["Book::sign"], "{check}");
        }
    }

    /// A common shape in deployed code: the proposal is fetched with a call that panics when it is missing, then stored back.
    #[test]
    fn storing_back_a_record_fetched_with_a_panic_on_absence_is_an_update() {
        let updates = [
            "let mut p = self.proposals.get(&id).unwrap(); p.votes += 1; self.proposals.insert(&id, &p);",
            "let mut p = self.proposals.get(&id).expect(\"missing\"); self.proposals.insert(&id, &p);",
            "let mut p = self.proposals.get(&id).ok_or(Error::Missing)?; self.proposals.insert(&id, &p);",
            "let mut p = self.proposals.get_mut(&id).ok_or_else(|| Error::Missing)?; self.proposals.insert(id, p.clone());",
            "let Some(mut p) = self.proposals.get(&id) else { panic!(\"missing\") }; self.proposals.insert(&id, &p);",
        ];
        for update in updates {
            let source = method(&format!("pub fn vote(&mut self, id: u64, note: String) {{ {update} }}"));
            assert!(items(&source).is_empty(), "{update}");
        }
    }

    #[test]
    fn a_fetch_that_does_not_insist_on_the_record_is_not_an_update() {
        let stores = [
            "let p = self.proposals.get(&id); self.proposals.insert(&id, &n);",
            "let p = self.proposals.get(&id).unwrap(); self.other.insert(&id, &n);",
            "let p = self.proposals.get(&other).unwrap(); self.proposals.insert(&id, &n);",
            "let p = self.others.get(&id).unwrap(); self.proposals.insert(&id, &n);",
            "self.proposals.insert(&id, &n);",
        ];
        for store in stores {
            let source = method(&format!("pub fn vote(&mut self, id: u64, other: u64, n: u64, note: String) {{ {store} }}"));
            assert_eq!(items(&source), ["Book::vote"], "{store}");
        }
    }

    /// A common shape in deployed code: panics spelled the ways crates spell them.
    #[test]
    fn the_spellings_of_a_panic_on_absence_count_and_a_default_does_not() {
        for fetch in [
            "self.proposals.get(&id).expect_or_reject(Missing { id })",
            "self.proposals.get(&id).unwrap_or_else(|| near_panic!(\"missing {}\", id))",
            "self.proposals.get(&id).unwrap_or_else(|| env::panic_str(\"missing\"))",
        ] {
            let source = method(&format!("pub fn vote(&mut self, id: u64, n: u64, note: String) {{ let p = {fetch}; self.proposals.insert(&id, &p); }}"));
            assert!(items(&source).is_empty(), "{fetch}");
        }
        for fetch in [
            "self.proposals.get(&id).unwrap_or_default()",
            "self.proposals.get(&id).unwrap_or(0)",
            "self.proposals.get(&id).unwrap_or_else(|| Proposal::new())",
            "self.proposals.get(&id).unwrap_or_else(|| { log(\"missing\"); Proposal::new() })",
        ] {
            let source = method(&format!("pub fn vote(&mut self, id: u64, n: u64, note: String) {{ let p = {fetch}; self.proposals.insert(&id, &p); }}"));
            assert_eq!(items(&source), ["Book::vote"], "{fetch}");
        }
    }

    /// The key may be a local bound from the parameter (`let key: TokenKey = token_key.as_str().into()`).
    #[test]
    fn a_key_derived_from_the_same_variable_is_the_same_key() {
        let update = "pub fn flip(&mut self, id: String) { let mut p = self.proposals.get(&id.as_str().into()).unwrap(); self.proposals.insert(&id.clone(), &p); }";
        assert!(items(&method(update)).is_empty());
        let aliased = "pub fn flip(&mut self, id: String) { let key = id.as_str().into(); let p = self.proposals.get(&key).unwrap(); self.proposals.insert(&id, &p); }";
        assert!(items(&method(aliased)).is_empty());
        let rebound = "pub fn flip(&mut self, id: String, other: String) { let p = self.proposals.get(&id).unwrap(); let id = other; self.proposals.insert(&id, &p); }";
        assert_eq!(items(&method(rebound)), ["Book::flip"]);
        let other = "pub fn flip(&mut self, id: String, other: String) { let key = other.clone(); let p = self.proposals.get(&id).unwrap(); self.proposals.insert(&key, &p); }";
        assert_eq!(items(&method(other)), ["Book::flip"]);
    }

    /// A common shape in deployed code: the fetch is made by a helper.
    #[test]
    fn a_helper_that_fetches_the_record_by_the_key_makes_the_store_an_update() {
        let helpers = "impl Book {
            fn assert_proposal(&self, id: u64) -> Proposal { self.proposals.get(&id).expect(\"missing\") }
            fn assert_pair(&self, a: u64, b: u64) -> Proposal { self.proposals.get(&b).unwrap() }
            fn find_or_new(&self, id: u64) -> Proposal { self.proposals.get(&id).unwrap_or_default() }
        }";
        let book = |body: &str| format!("#[near] impl Book {{ pub fn vote(&mut self, id: u64, other: u64, n: u64, note: String) {{ {body} }} }} {helpers}");
        for update in [
            "let mut p = self.assert_proposal(id); p.votes += 1; self.proposals.insert(&id, &p);",
            "let p = self.assert_proposal(id.clone()); self.proposals.insert(id, p);",
            "let p = self.assert_pair(other, id); self.proposals.insert(&id, &p);",
        ] {
            assert!(items(&book(update)).is_empty(), "{update}");
        }
        // A different key, a different field, a helper that supplies a default, an unknown helper, and the wrong argument.
        for store in [
            "let p = self.assert_proposal(other); self.proposals.insert(&id, &p);",
            "let p = self.assert_proposal(id); self.others.insert(&id, &p);",
            "let p = self.find_or_new(id); self.proposals.insert(&id, &p);",
            "let p = self.load(id); self.proposals.insert(&id, &p);",
            "let p = self.assert_pair(id, other); self.proposals.insert(&id, &p);",
        ] {
            assert_eq!(items(&book(store)), ["Book::vote"], "{store}");
        }
    }

    /// A record found by `if let Some(..)` or a `Some` arm, or refused when missing by a `None` arm that panics or
    /// returns, also through a method that only looks it up, is stored back as an update.
    #[test]
    fn storing_back_a_record_found_or_refused_when_missing_is_an_update() {
        let book = |body: &str| {
            format!(
                "#[near] impl Book {{ pub fn vote(&mut self, id: u64, other: u64, n: u64, note: String) {{ {body} }} }}
                 impl Book {{ fn find(&self, id: &u64) -> Option<Proposal> {{ self.proposals.get(id) }} }}"
            )
        };
        for update in [
            "if let Some(mut p) = self.proposals.get(&id) { p.n += 1; self.proposals.insert(&id, &p); }",
            "if let Some(p) = self.proposals.get_mut(&id) { self.proposals.insert(&id, &n); }",
            "if !note.is_empty() && let Some(p) = self.proposals.get(&id) { self.proposals.insert(&id, &p); }",
            "match self.proposals.get(&id) { Some(p) => { self.proposals.insert(&id, &p); } None => {} }",
            "let p = match self.proposals.get(&id) { None => env::panic_str(\"missing\"), Some(p) => p }; self.proposals.insert(&id, &p);",
            "let p = match self.find(&id) { None => { env::log_str(\"no\"); return; } Some(p) => p }; self.proposals.insert(&id, &p);",
            "let Some(p) = self.find(&id) else { return }; self.proposals.insert(&id, &p);",
            "self.find(&id).unwrap(); self.proposals.insert(&id, &n);",
        ] {
            assert!(items(&book(update)).is_empty(), "{update}");
        }
        for store in [
            "if let Some(p) = self.proposals.get(&id) { } else { self.proposals.insert(&id, &n); }",
            "if let Some(p) = self.proposals.get(&other) { self.proposals.insert(&id, &n); }",
            "if let None = self.proposals.get(&id) { self.proposals.insert(&id, &n); }",
            "if let Some(p) = self.proposals.get(&id) { } self.proposals.insert(&id, &n);",
            "match self.proposals.get(&id) { Some(p) => {} None => { self.proposals.insert(&id, &n); } }",
            "match self.proposals.get(&id) { None => { self.proposals.insert(&id, &n); } Some(p) => {} }",
            "let p = match self.proposals.get(&id) { None => Proposal::default(), Some(p) => p }; self.proposals.insert(&id, &p);",
            "let p = match self.find(&id) { None => Proposal::default(), Some(p) => p }; self.proposals.insert(&id, &p);",
            "let p = match self.find(&other) { None => return, Some(p) => p }; self.proposals.insert(&id, &n);",
            "let Some(p) = self.find(&other) else { return }; self.proposals.insert(&id, &n);",
            "self.find(&id); self.proposals.insert(&id, &n);",
        ] {
            assert_eq!(items(&book(store)), ["Book::vote"], "{store}");
        }
    }

    /// A lookup method counts only when it is the whole body, defined once, over the field it names.
    #[test]
    fn a_method_that_is_not_just_a_lookup_proves_nothing() {
        let vote = "#[near] impl Book { pub fn vote(&mut self, id: u64, n: u64, note: String) { let Some(p) = self.find(&id) else { return }; self.proposals.insert(&id, &n); } }";
        for find in [
            "impl Book { fn find(&self, id: &u64) -> Option<Proposal> { self.proposals.get(id).or(Some(Proposal::new())) } }",
            "impl Book { fn find(&self, id: &u64) -> Option<Proposal> { self.others.get(id) } }",
            "impl Book { fn find(&self, id: &u64) -> Option<Proposal> { self.proposals.get(id) } }
             impl Shelf { fn find(&self, id: &u64) -> Option<Proposal> { None } }",
        ] {
            assert_eq!(items(&format!("{vote} {find}")), ["Book::vote"], "{find}");
        }
    }

    /// u02, u06: a fetch made on one branch does not make a store after the branch an update.
    #[test]
    fn a_fetch_on_only_one_path_does_not_make_the_store_an_update() {
        let helper = "impl Book { fn assert_proposal(&self, id: u64) -> Proposal { self.proposals.get(&id).expect(\"missing\") } }";
        let book = |body: &str| format!("#[near] impl Book {{ pub fn vote(&mut self, id: u64, n: u64, note: String) {{ {body} }} }} {helper}");
        for store in [
            "if self.proposals.contains_key(&id) { let old = self.proposals.get(&id).unwrap(); self.log.push(old); } self.proposals.insert(&id, &n);",
            "if note.is_empty() { self.assert_proposal(id); } self.proposals.insert(&id, &n);",
            "match note.len() { 0 => { self.assert_proposal(id); } _ => {} } self.proposals.insert(&id, &n);",
            "for _ in 0..note.len() { self.assert_proposal(id); } self.proposals.insert(&id, &n);",
            "let _ = note.is_empty() && self.proposals.get(&id).is_some_and(|p| p.open); self.proposals.insert(&id, &n);",
            "let check = || self.assert_proposal(id); self.proposals.insert(&id, &n);",
        ] {
            assert_eq!(items(&book(store)), ["Book::vote"], "{store}");
        }
        // On every path, or fetched and stored inside the same branch, it is an update.
        for update in [
            "self.assert_proposal(id); if note.is_empty() { return; } self.proposals.insert(&id, &n);",
            "if !note.is_empty() { let p = self.proposals.get(&id).unwrap(); self.proposals.insert(&id, &n); }",
            "let a = self.proposals.get(&id).unwrap(); match note.len() { 0 => {} _ => { self.proposals.insert(&id, &n); } }",
        ] {
            assert!(items(&book(update)).is_empty(), "{update}");
        }
    }

    /// Replacing an existing record still grows storage when the new value is data the caller sizes: the exemption
    /// is for the entry, not for what is put in it.
    #[test]
    fn overwriting_an_existing_record_with_unbounded_caller_data_is_still_a_finding() {
        let book = |body: &str| {
            format!(
                "#[near] impl Book {{ pub fn vote(&mut self, id: u64, note: String, lines: Vec<String>) {{ {body} }} }}
                 impl Book {{
                     fn find(&self, id: &u64) -> Option<Proposal> {{ self.proposals.get(id) }}
                     fn assert_proposal(&self, id: u64) -> Proposal {{ self.proposals.get(&id).expect(\"missing\") }}
                 }}"
            )
        };
        for store in [
            "self.assert_proposal(id); self.proposals.insert(&id, &note);",
            "self.proposals.get(&id).unwrap(); self.proposals.insert(&id, &note);",
            "if let Some(p) = self.proposals.get_mut(&id) { self.proposals.insert(&id, &note); }",
            "match self.proposals.get(&id) { Some(p) => { self.proposals.insert(&id, &note); } None => {} }",
            "let Some(p) = self.find(&id) else { return }; self.proposals.insert(&id, &lines);",
            "self.find(&id).unwrap(); self.proposals.insert(&id, &note);",
            "let mut p = self.proposals.get(&id).unwrap(); p.note = note; self.proposals.insert(&id, &p);",
            "let mut p = self.proposals.get(&id).unwrap(); p.note += &note; self.proposals.insert(&id, &p);",
            "let mut p = self.proposals.get(&id).unwrap(); p.lines.extend(lines); self.proposals.insert(&id, &p);",
            "let mut p = self.proposals.get(&id).unwrap(); p.text.push_str(&note); self.proposals.insert(&id, &p);",
            "let text = format!(\"{note}!\"); self.assert_proposal(id); self.proposals.insert(&id, &text);",
        ] {
            assert_eq!(items(&book(store)), ["Book::vote"], "{store}");
        }
    }

    /// `let proposal = self.proposals.get(&id).unwrap()` over a parameter of the same name is the stored record, not
    /// the caller's data; a shadow that keeps the caller's data, or one that ends with its block, is not.
    #[test]
    fn a_name_shadowed_by_a_fetched_record_is_not_the_callers_data() {
        let book = |body: &str| format!("#[near] impl Book {{ pub fn vote(&mut self, id: u64, proposal: String) {{ {body} }} }}");
        for update in [
            "let proposal = self.proposals.get(&id).unwrap(); self.proposals.insert(&id, &proposal);",
            "let mut proposal: Proposal = self.proposals.get(&id).expect(\"missing\").into(); self.proposals.insert(&id, &proposal);",
        ] {
            assert!(items(&book(update)).is_empty(), "{update}");
        }
        for store in [
            "self.proposals.get(&id).unwrap(); let proposal = proposal.trim(); self.proposals.insert(&id, &proposal);",
            "self.proposals.get(&id).unwrap(); { let proposal = 0; } self.proposals.insert(&id, &proposal);",
            "self.proposals.get(&id).unwrap(); if id > 1 { let proposal = 0; } self.proposals.insert(&id, &proposal);",
        ] {
            assert_eq!(items(&book(store)), ["Book::vote"], "{store}");
        }
    }

    #[test]
    fn overwriting_an_existing_record_with_bounded_data_is_clean() {
        let book = |body: &str| {
            format!(
                "#[near] impl Book {{ pub fn vote(&mut self, id: u64, n: u64, flag: bool, note: String) {{ {body} }} }}
                 impl Book {{ fn assert_proposal(&self, id: u64) -> Proposal {{ self.proposals.get(&id).expect(\"missing\") }} }}"
            )
        };
        for update in [
            "self.assert_proposal(id); self.proposals.insert(&id, &n);",
            "self.proposals.get(&id).unwrap(); self.proposals.insert(&id, &(n, flag));",
            "let mut p = self.proposals.get(&id).unwrap(); p.votes += n; p.open = flag; self.proposals.insert(&id, &p);",
        ] {
            assert!(items(&book(update)).is_empty(), "{update}");
        }
    }

    #[test]
    fn a_helper_name_defined_twice_in_the_crate_proves_nothing() {
        let source = "#[near] impl Book { pub fn vote(&mut self, id: u64) { let p = self.assert_proposal(id); self.proposals.insert(&id, &p); } }
            impl Book { fn assert_proposal(&self, id: u64) -> Proposal { self.proposals.get(&id).unwrap() } }
            impl Shelf { fn assert_proposal(&self, id: u64) -> Proposal { Proposal::new() } }";
        assert_eq!(items(source), ["Book::vote"]);
    }

    #[test]
    fn registration_does_not_cover_a_key_from_a_parameter_or_a_push() {
        let registry = "#[near] impl Poll { #[payable] pub fn storage_deposit(&mut self) {} }";
        let by_parameter = "#[near] impl Poll { pub fn vote_for(&mut self, who: AccountId, choice: u8) { self.votes.insert(who, choice); } }";
        assert_eq!(items(&format!("{by_parameter} {registry}")), ["Poll::vote_for"]);
        let push = "#[near] impl Poll { pub fn log(&mut self, note: String) { self.notes.push(note); } }";
        assert_eq!(items(&format!("{push} {registry}")), ["Poll::log"]);
    }

    #[test]
    fn storage_deposit_must_be_exported_to_count() {
        let hidden = "impl Poll { fn storage_deposit(&mut self) {} }";
        let vote = "#[near] impl Poll { pub fn vote(&mut self, choice: String) { self.votes.insert(env::predecessor_account_id(), choice); } }";
        assert_eq!(items(&format!("{vote} {hidden}")), ["Poll::vote"]);
    }

    #[test]
    fn methods_the_near_macro_does_not_export_are_ignored() {
        let source = "
            impl NotNear { pub fn sign(&mut self, text: String) { self.entries.push(text); } }
            #[near] impl Book {
                fn hidden(&mut self, text: String) { self.entries.push(text); }
                pub(crate) fn crate_only(&mut self, text: String) { self.entries.push(text); }
            }";
        assert!(items(source).is_empty());
    }

    #[test]
    fn every_method_of_a_near_trait_impl_is_exported() {
        let source = "#[near] impl Guestbook for Book { fn sign(&mut self, text: String) { self.entries.push(text); } }";
        assert_eq!(items(source), ["Book::sign"]);
    }

    #[test]
    fn follows_a_charge_in_another_file() {
        let lib = "#[near] impl Book { pub fn sign(&mut self, text: String) { self.entries.push(text); self.charge(); } }";
        let helpers = "impl Book { fn charge(&self) { let _ = env::attached_deposit(); } }";
        assert!(check(&[("src/lib.rs", lib), ("src/helpers.rs", helpers)]).is_empty());
        assert_eq!(check(&[("src/lib.rs", lib)]).len(), 1);
    }

    #[test]
    fn a_macro_the_rule_cannot_parse_still_counts_when_it_names_the_deposit() {
        let source = method("pub fn sign(&mut self, text: String) { self.entries.push(text); charge!(paid => env::attached_deposit()); }");
        assert!(items(&source).is_empty());
    }
}
