//! PF017: `ft_on_transfer` credits a deposit and then reports the whole amount as unused.
//!
//! NEP-141 (https://nomicon.io/Standards/Tokens/FungibleToken/Core): the token contract calls the receiver's
//! `ft_on_transfer` after moving the tokens, and the receiver returns how many tokens it did NOT use, `0` when it
//! kept everything. The token's resolver refunds that unused amount to the sender. A receiver that credits the
//! sender and returns `amount` (a common misreading: "return what I accepted") therefore keeps the credit while
//! the sender gets every token back: a balance nothing backs, redeemable against other depositors' tokens.
//! Docs: https://docs.near.org/smart-contracts/security/cross-contract-calls/ft-transfer-call
//!
//! A hook is reported when all three hold:
//! 1. It is a method named `ft_on_transfer` that the `#[near]` / `#[near_bindgen]` macro exports (`pub` in an
//!    inherent impl, any method of a trait impl).
//! 2. A path through its body writes contract state with a value or key that involves the `amount` parameter: an
//!    assignment or compound assignment to a place rooted at `self` (`*self.balances.entry(id).or_insert(0) +=
//!    amount.0`), a call of `insert`, `set`, `push`, `push_back`, `push_front`, `extend`, `append` or `replace` on
//!    such a place, or a call of a `self` method of the same crate whose body writes state (`self.credit(&id,
//!    amount.0)`, followed through helpers). A local derived from `amount` (`let shares = amount.0 * RATE;`)
//!    counts as `amount`. Paths are followed through `if`, `match`, loops, blocks and early `return`.
//! 3. On that same path, after the write, the hook returns the `amount` parameter itself: `amount`, `amount.into()`,
//!    `U128(amount.0)`, `PromiseOrValue::Value(amount)` and combinations of these, as the tail expression or in a
//!    `return`.
//!
//! Silent by design: the reject branch that returns `amount` before anything is written (the correct way to refuse
//! an unexpected token), a hook that returns `U128(0)`, a partial refund (`U128(amount.0 - used)`), and a hook
//! whose writes do not involve `amount`.
//!
//! Knowingly missed or approximated: `mt_on_transfer` (returns a list of unused amounts) and `nft_on_transfer`
//! (returns whether to send the token back); a hook that returns a promise; an `amount` renamed or rebound to
//! something other than itself (`let amount = amount.0 - fee;` silences the hook); returns and writes inside
//! closures or macro arguments; a write in a function the hook reaches through a local variable, a trait object or
//! another crate. Methods are matched by name only, since the scanner resolves no types. Knowingly noisy: a hook
//! that records rejected tokens (`self.rejected += amount.0; return amount`) is reported although it credits no
//! one.

use std::collections::{BTreeMap, BTreeSet};

use syn::visit::{self, Visit};
use syn::{
    Attribute, BinOp, Block, Expr, ExprAssign, ExprBinary, ExprMethodCall, FnArg, ImplItem, ImplItemFn,
    ItemFn, ItemImpl, Local, Member, Pat, Stmt, Type, UnOp, Visibility,
};

use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf017FtReceiverReturn;

pub static RULE: Pf017FtReceiverReturn = Pf017FtReceiverReturn;

const HOOK: &str = "ft_on_transfer";

/// Collection methods that store a value.
const STORES: [&str; 8] = ["insert", "set", "push", "push_back", "push_front", "extend", "append", "replace"];

/// Methods that hand out a mutable handle to something inside `self`, so `let b = self.m.entry(k).or_default();
/// *b += x;` writes `self`.
const HANDLES: [&str; 6] = ["get_mut", "entry", "as_mut", "iter_mut", "values_mut", "or_insert"];

/// How far helper calls are followed when looking for a write.
const MAX_DEPTH: usize = 4;

impl Rule for Pf017FtReceiverReturn {
    fn id(&self) -> &'static str {
        "PF017"
    }

    fn title(&self) -> &'static str {
        "ft_on_transfer credits a deposit and returns it as unused"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn help(&self) -> &'static str {
        "return U128(0) once the deposit is credited: the value is the amount NOT used, and the token refunds it to the sender"
    }

    fn check(&self, krate: &Crate) -> Vec<Finding> {
        let index = Index::build(krate);
        let mut findings = Vec::new();
        for file in &krate.files {
            let mut hooks = Hooks::default();
            hooks.visit_file(&file.ast);
            for (owner, hook) in hooks.found {
                if !credits_and_returns_the_amount(hook, &index) {
                    continue;
                }
                let item = format!("{owner}::{HOOK}");
                let message = format!(
                    "`{item}` credits the deposit and then returns `amount` as the unused part, so the token contract refunds \
                     the whole transfer to the sender while the credit stays"
                );
                findings.push(self.finding(file, hook.sig.ident.span(), item, message));
            }
        }
        findings
    }
}

/// The exported `ft_on_transfer` methods of one file, with the type that implements them.
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
                    && method.sig.ident == HOOK
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

/// The bodies of every function and method of the crate by name; two that share a name share an entry.
#[derive(Default)]
pub(super) struct Index<'a> {
    fns: BTreeMap<String, Vec<&'a Block>>,
}

impl<'ast> Visit<'ast> for Index<'ast> {
    fn visit_impl_item_fn(&mut self, method: &'ast ImplItemFn) {
        self.fns.entry(method.sig.ident.to_string()).or_default().push(&method.block);
        visit::visit_impl_item_fn(self, method);
    }

    fn visit_item_fn(&mut self, function: &'ast ItemFn) {
        self.fns.entry(function.sig.ident.to_string()).or_default().push(&function.block);
        visit::visit_item_fn(self, function);
    }
}

impl<'a> Index<'a> {
    pub(super) fn build(krate: &'a Crate) -> Self {
        let mut index = Self::default();
        for file in &krate.files {
            index.visit_file(&file.ast);
        }
        index
    }

    pub(super) fn bodies(&self, name: &str) -> &[&'a Block] {
        self.fns.get(name).map_or(&[], Vec::as_slice)
    }

    /// Whether `body` writes contract state, directly or through a method of the crate it calls on `self`.
    pub(super) fn writes_state(&self, body: &Block) -> bool {
        self.writes_at(body, 0)
    }

    fn writes_at(&self, body: &Block, depth: usize) -> bool {
        let mut writes = Writes { index: self, names: None, aliases: aliases(body), depth, found: false };
        writes.visit_block(body);
        writes.found
    }

    /// Whether a method of that name writes contract state (any write: its parameters are not the hook's).
    fn helper_writes(&self, name: &str, depth: usize) -> bool {
        depth < MAX_DEPTH && self.bodies(name).iter().any(|body| self.writes_at(body, depth + 1))
    }
}

fn credits_and_returns_the_amount(hook: &ImplItemFn, index: &Index) -> bool {
    let mut args = hook.sig.inputs.iter().filter_map(|arg| match arg {
        FnArg::Typed(arg) => Some(&*arg.pat),
        FnArg::Receiver(_) => None,
    });
    let Some(Pat::Ident(amount)) = args.nth(1) else { return false };
    let amount = amount.ident.to_string();
    let Some(names) = names_of_the_amount(&hook.block, &amount) else { return false };
    let writes = Writes { index, names: Some(&names), aliases: aliases(&hook.block), depth: 0, found: false };
    let mut flow = Flow { writes, amount: &amount, returned: false };
    flow.block(&hook.block, true, States::START);
    flow.returned
}

/// `amount` and every local derived from it, in source order; `None` when `amount` is rebound to something that
/// is not the same value, since later uses of the name no longer mean the deposit.
fn names_of_the_amount(body: &Block, amount: &str) -> Option<BTreeSet<String>> {
    struct Derived<'a> {
        amount: &'a str,
        names: BTreeSet<String>,
        rebound: bool,
    }
    impl<'ast> Visit<'ast> for Derived<'_> {
        fn visit_local(&mut self, local: &'ast Local) {
            if let Some(init) = &local.init
                && let Some(name) = bound_name(&local.pat)
            {
                self.rebound |= name == self.amount && !is_amount(&init.expr, self.amount);
                if mentions(&init.expr, &self.names) {
                    self.names.insert(name);
                }
            }
            visit::visit_local(self, local);
        }
    }
    let mut derived = Derived { amount, names: BTreeSet::from([amount.to_owned()]), rebound: false };
    derived.visit_block(body);
    (!derived.rebound).then_some(derived.names)
}

pub(super) fn bound_name(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(ident) => Some(ident.ident.to_string()),
        Pat::Type(typed) => bound_name(&typed.pat),
        _ => None,
    }
}

/// Whether the expression is the deposit amount itself: `amount`, `amount.0`, `amount.into()`, `U128(amount.0)`,
/// `PromiseOrValue::Value(..)` around one of those.
fn is_amount(expr: &Expr, amount: &str) -> bool {
    match expr {
        Expr::Path(path) => path.path.is_ident(amount),
        Expr::Paren(inner) => is_amount(&inner.expr, amount),
        Expr::Group(inner) => is_amount(&inner.expr, amount),
        Expr::Field(field) => matches!(&field.member, Member::Unnamed(index) if index.index == 0) && is_amount(&field.base, amount),
        Expr::MethodCall(call) => {
            matches!(call.method.to_string().as_str(), "into" | "clone") && is_amount(&call.receiver, amount)
        }
        Expr::Call(call) => {
            let Expr::Path(func) = &*call.func else { return false };
            let names: Vec<String> = func.path.segments.iter().map(|segment| segment.ident.to_string()).collect();
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            matches!(names.as_slice(), [.., "U128"] | [.., "PromiseOrValue", "Value"])
                && call.args.first().is_some_and(|arg| is_amount(arg, amount))
        }
        _ => false,
    }
}

/// Whether any identifier of the expression is one of `names`.
fn mentions(expr: &Expr, names: &BTreeSet<String>) -> bool {
    struct Mentions<'a>(&'a BTreeSet<String>, bool);
    impl<'ast> Visit<'ast> for Mentions<'_> {
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            self.1 |= path.path.get_ident().is_some_and(|ident| self.0.contains(&ident.to_string()));
        }
    }
    let mut found = Mentions(names, false);
    found.visit_expr(expr);
    found.1
}

/// Names bound to a mutable handle into `self`: `let balance = self.balances.entry(id).or_insert(0);`.
pub(super) fn aliases(body: &Block) -> BTreeSet<String> {
    struct Aliases(BTreeSet<String>);
    impl<'ast> Visit<'ast> for Aliases {
        fn visit_local(&mut self, local: &'ast Local) {
            if let (Some(name), Some(init)) = (bound_name(&local.pat), &local.init)
                && rooted_at_self(&init.expr, &self.0)
                && hands_out_a_mutable_handle(&init.expr)
            {
                self.0.insert(name);
            }
            visit::visit_local(self, local);
        }
    }
    let mut found = Aliases(BTreeSet::new());
    found.visit_block(body);
    found.0
}

fn hands_out_a_mutable_handle(expr: &Expr) -> bool {
    match expr {
        Expr::Reference(reference) => reference.mutability.is_some(),
        Expr::MethodCall(call) => {
            HANDLES.iter().any(|name| call.method == name) || hands_out_a_mutable_handle(&call.receiver)
        }
        Expr::Paren(inner) => hands_out_a_mutable_handle(&inner.expr),
        _ => false,
    }
}

/// Whether the expression is a place inside `self` (or inside something `aliases` points into).
pub(super) fn rooted_at_self(expr: &Expr, aliases: &BTreeSet<String>) -> bool {
    match expr {
        Expr::Path(path) => path.path.get_ident().is_some_and(|ident| ident == "self" || aliases.contains(&ident.to_string())),
        Expr::Field(field) => rooted_at_self(&field.base, aliases),
        Expr::Index(index) => rooted_at_self(&index.expr, aliases),
        Expr::MethodCall(call) => rooted_at_self(&call.receiver, aliases),
        Expr::Unary(unary) => matches!(unary.op, UnOp::Deref(_)) && rooted_at_self(&unary.expr, aliases),
        Expr::Reference(reference) => rooted_at_self(&reference.expr, aliases),
        Expr::Paren(inner) => rooted_at_self(&inner.expr, aliases),
        _ => false,
    }
}

fn is_bare_self(expr: &Expr) -> bool {
    matches!(expr, Expr::Path(path) if path.path.is_ident("self"))
}

/// Finds a write to contract state in whatever it visits.
struct Writes<'i, 'a> {
    index: &'i Index<'a>,
    /// Only a write whose value, key or arguments mention one of these names counts; `None`: any write.
    names: Option<&'i BTreeSet<String>>,
    aliases: BTreeSet<String>,
    depth: usize,
    found: bool,
}

impl Writes<'_, '_> {
    fn involves(&self, expr: &Expr) -> bool {
        self.names.is_none_or(|names| mentions(expr, names))
    }
}

impl<'ast> Visit<'ast> for Writes<'_, '_> {
    fn visit_expr_assign(&mut self, assign: &'ast ExprAssign) {
        self.found |= rooted_at_self(&assign.left, &self.aliases) && self.involves(&assign.right);
        visit::visit_expr_assign(self, assign);
    }

    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        let compound = matches!(
            binary.op,
            BinOp::AddAssign(_) | BinOp::SubAssign(_) | BinOp::MulAssign(_) | BinOp::DivAssign(_) | BinOp::RemAssign(_)
        );
        self.found |= compound && rooted_at_self(&binary.left, &self.aliases) && self.involves(&binary.right);
        visit::visit_expr_binary(self, binary);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let involved = self.names.is_none() || call.args.iter().any(|arg| self.involves(arg));
        if involved {
            self.found |= (STORES.iter().any(|name| call.method == name) && rooted_at_self(&call.receiver, &self.aliases))
                || (is_bare_self(&call.receiver) && self.index.helper_writes(&call.method.to_string(), self.depth));
        }
        visit::visit_expr_method_call(self, call);
    }
}

/// Which of the two things can be true of the paths that reach a point: no write yet, a write made.
#[derive(Clone, Copy)]
struct States {
    clean: bool,
    credited: bool,
}

impl States {
    const START: Self = Self { clean: true, credited: false };
    const NONE: Self = Self { clean: false, credited: false };

    fn union(self, other: Self) -> Self {
        Self { clean: self.clean || other.clean, credited: self.credited || other.credited }
    }

    fn is_none(self) -> bool {
        !self.clean && !self.credited
    }

    fn after_write(self) -> Self {
        Self { clean: false, credited: self.clean || self.credited }
    }
}

/// Walks the hook's body in execution order, tracking whether a credit has been written, and notes when a value
/// that is the amount is returned after one.
struct Flow<'i, 'a, 'n> {
    writes: Writes<'i, 'a>,
    amount: &'n str,
    returned: bool,
}

impl Flow<'_, '_, '_> {
    /// `tail`: the block's last expression is the value the function returns.
    fn block(&mut self, block: &Block, tail: bool, mut states: States) -> States {
        for (position, stmt) in block.stmts.iter().enumerate() {
            if states.is_none() {
                break;
            }
            let last = tail && position + 1 == block.stmts.len();
            states = match stmt {
                Stmt::Expr(expr, None) => self.expr(expr, last, states),
                Stmt::Expr(expr, Some(_)) => self.expr(expr, false, states),
                Stmt::Local(local) => local.init.as_ref().map_or(states, |init| self.expr(&init.expr, false, states)),
                Stmt::Item(_) | Stmt::Macro(_) => states,
            };
        }
        states
    }

    fn expr(&mut self, expr: &Expr, tail: bool, states: States) -> States {
        match expr {
            Expr::Return(ret) => {
                if let Some(value) = &ret.expr {
                    self.value(value, states);
                }
                States::NONE
            }
            Expr::Block(block) => self.block(&block.block, tail, states),
            Expr::Paren(inner) => self.expr(&inner.expr, tail, states),
            Expr::If(branch) => {
                let states = self.simple(&branch.cond, states);
                let then = self.block(&branch.then_branch, tail, states);
                let otherwise = match &branch.else_branch {
                    Some((_, otherwise)) => self.expr(otherwise, tail, states),
                    None => states,
                };
                then.union(otherwise)
            }
            Expr::Match(branches) => {
                let states = self.simple(&branches.expr, states);
                let mut after = States::NONE;
                for arm in &branches.arms {
                    after = after.union(self.expr(&arm.body, tail, states));
                }
                after
            }
            Expr::ForLoop(looped) => {
                let states = self.simple(&looped.expr, states);
                states.union(self.block(&looped.body, false, states))
            }
            Expr::While(looped) => {
                let states = self.simple(&looped.cond, states);
                states.union(self.block(&looped.body, false, states))
            }
            Expr::Loop(looped) => {
                let body = self.block(&looped.body, false, states);
                states.union(body)
            }
            _ => {
                let states = self.simple(expr, states);
                if tail {
                    self.value(expr, states);
                    return States::NONE;
                }
                states
            }
        }
    }

    /// An expression with no control flow of its own: it writes or it does not.
    fn simple(&mut self, expr: &Expr, states: States) -> States {
        self.writes.found = false;
        self.writes.visit_expr(expr);
        if self.writes.found { states.after_write() } else { states }
    }

    /// The hook returns `value` on the paths in `states`.
    fn value(&mut self, value: &Expr, states: States) {
        self.returned |= states.credited && is_amount(value, self.amount);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(source: &str) -> Vec<Finding> {
        RULE.check(&Crate::from_sources([("src/lib.rs", source)]).unwrap())
    }

    fn hook(body: &str) -> String {
        format!(
            "#[near] impl Vault {{ pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> PromiseOrValue<U128> {{ {body} }} }}"
        )
    }

    fn flagged(body: &str) -> bool {
        !check(&hook(body)).is_empty()
    }

    #[test]
    fn flags_a_credit_followed_by_returning_the_amount_and_locates_it() {
        let findings = check(&hook(
            "require!(env::predecessor_account_id() == self.token); *self.balances.entry(sender_id).or_insert(0) += amount.0; PromiseOrValue::Value(amount)",
        ));
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity, finding.item.as_str()), ("PF017", Severity::Critical, "Vault::ft_on_transfer"));
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 1, 29));
        assert!(finding.message.contains("`Vault::ft_on_transfer`") && finding.message.contains("returns `amount`"));
    }

    #[test]
    fn flags_every_way_of_returning_the_amount() {
        for returned in [
            "amount.into()",
            "PromiseOrValue::Value(U128(amount.0))",
            "PromiseOrValue::Value(amount.0.into())",
            "near_sdk::PromiseOrValue::Value(amount)",
            "(amount).into()",
            "return amount.into();",
            "return PromiseOrValue::Value(amount.clone());",
        ] {
            let body = format!("self.total += amount.0; {returned}");
            assert!(flagged(&body), "{returned}");
        }
    }

    #[test]
    fn flags_each_kind_of_credit() {
        for credit in [
            "self.total += amount.0;",
            "self.total = self.total + amount.0;",
            "self.balances.insert(sender_id.clone(), amount.0);",
            "self.deposits.push((sender_id.clone(), amount));",
            "self.credit(&sender_id, amount.0);",
            "let balance = self.balances.entry(sender_id).or_default(); *balance += amount.0;",
            "let shares = amount.0 * 2; self.shares += shares;",
            "let amount = amount.0; self.total += amount;",
            "self.accounts[0].balance += amount.0;",
        ] {
            let body = format!(
                "{credit} amount.into()"
            );
            let source = format!("{} impl Vault {{ fn credit(&mut self, id: &AccountId, n: u128) {{ self.balances.insert(id.clone(), n); }} }}", hook(&body));
            assert!(!check(&source).is_empty(), "{credit}");
        }
    }

    #[test]
    fn flags_a_credit_made_by_a_helper_two_calls_down() {
        let source = format!(
            "{} impl Vault {{ fn credit(&mut self, id: &AccountId, n: u128) {{ self.book(id, n); }} fn book(&mut self, id: &AccountId, n: u128) {{ self.balances.insert(id.clone(), n); }} }}",
            hook("self.credit(&sender_id, amount.0); amount.into()")
        );
        assert_eq!(check(&source).len(), 1);
    }

    #[test]
    fn follows_the_paths_of_branches_and_early_returns() {
        assert!(flagged("if msg.is_empty() { self.total += amount.0; return amount.into(); } U128(0).into()"));
        assert!(flagged("self.total += amount.0; if msg.is_empty() { return U128(0).into(); } amount.into()"));
        assert!(flagged("if msg.is_empty() { self.total += amount.0; } amount.into()"));
        assert!(flagged("match msg.as_str() { \"\" => { self.total += amount.0; amount.into() } _ => U128(0).into() }"));
        assert!(flagged("for _ in 0..1 { self.total += amount.0; } amount.into()"));
    }

    #[test]
    fn a_reject_branch_that_returns_the_amount_before_any_write_is_correct() {
        let guarded = "if env::predecessor_account_id() != self.token { return PromiseOrValue::Value(amount); } self.total += amount.0; PromiseOrValue::Value(U128(0))";
        assert!(!flagged(guarded));
        let branched = "if env::predecessor_account_id() == self.token { self.total += amount.0; PromiseOrValue::Value(U128(0)) } else { PromiseOrValue::Value(amount) }";
        assert!(!flagged(branched));
        let matched = "match msg.as_str() { \"stake\" => { self.total += amount.0; U128(0).into() } _ => amount.into() }";
        assert!(!flagged(matched));
    }

    #[test]
    fn a_hook_that_reports_the_unused_part_correctly_is_silent() {
        assert!(!flagged("self.total += amount.0; PromiseOrValue::Value(U128(0))"));
        assert!(!flagged("self.total += amount.0; U128(0).into()"));
        assert!(!flagged("let used = amount.0 / 2; self.total += used; PromiseOrValue::Value(U128(amount.0 - used))"));
    }

    #[test]
    fn a_write_that_does_not_involve_the_amount_is_not_a_credit() {
        assert!(!flagged("self.calls += 1; amount.into()"));
        assert!(!flagged("self.last_sender = sender_id; amount.into()"));
        assert!(!flagged("log(amount); amount.into()"));
    }

    #[test]
    fn a_helper_that_writes_nothing_is_not_a_credit() {
        let source = format!(
            "{} impl Vault {{ fn record(&self, id: &AccountId, n: u128) {{ env::log_str(\"deposit\"); }} }}",
            hook("self.record(&sender_id, amount.0); amount.into()")
        );
        assert!(check(&source).is_empty());
    }

    #[test]
    fn an_amount_rebound_to_something_else_is_not_tracked() {
        assert!(!flagged("let amount = amount.0 - 1; self.total += amount; PromiseOrValue::Value(U128(amount))"));
    }

    #[test]
    fn a_hook_that_returns_something_other_than_the_amount_is_silent() {
        assert!(!flagged("self.total += amount.0; PromiseOrValue::Value(U128(msg.len() as u128))"));
        assert!(!flagged("self.total += amount.0; PromiseOrValue::Value(U128(amount.0 - amount.0))"));
        assert!(!flagged("self.total += amount.0; ext_log::ext(self.log.clone()).record(amount).into()"));
    }

    #[test]
    fn accepts_the_near_bindgen_attribute_and_trait_impls() {
        let source = "#[near_bindgen] impl FungibleTokenReceiver for Vault { fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> PromiseOrValue<U128> { self.total += amount.0; amount.into() } }";
        assert_eq!(check(source).len(), 1);
        let qualified = "#[near_sdk::near] impl Vault { pub fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> U128 { self.total += a.0; a } }";
        assert_eq!(check(qualified).len(), 1);
    }

    #[test]
    fn methods_the_near_macro_does_not_export_are_ignored() {
        let body = "{ self.total += amount.0; amount.into() }";
        let sig = "(&mut self, sender_id: AccountId, amount: U128, msg: String) -> PromiseOrValue<U128>";
        assert!(check(&format!("impl Vault {{ pub fn ft_on_transfer{sig} {body} }}")).is_empty());
        assert!(check(&format!("#[near] impl Vault {{ fn ft_on_transfer{sig} {body} }}")).is_empty());
        assert!(check(&format!("#[near] impl Vault {{ pub fn on_transfer{sig} {body} }}")).is_empty());
        assert!(check(&format!("#[near] impl Vault {{ pub fn mt_on_transfer{sig} {body} }}")).is_empty());
    }

    #[test]
    fn reports_each_hook_of_each_type_and_follows_helpers_across_files() {
        let vault = "#[near] impl Vault { pub fn ft_on_transfer(&mut self, s: AccountId, amount: U128, m: String) -> U128 { self.credit(&s, amount.0); amount } }";
        let pool = "#[near] impl Pool { pub fn ft_on_transfer(&mut self, s: AccountId, amount: U128, m: String) -> U128 { U128(0) } }";
        let helpers = "impl Vault { fn credit(&mut self, id: &AccountId, n: u128) { self.balances.insert(id.clone(), n); } }";
        let krate = Crate::from_sources([("src/lib.rs", vault), ("src/pool.rs", pool), ("src/helpers.rs", helpers)]).unwrap();
        let findings = RULE.check(&krate);
        assert_eq!(findings.iter().map(|f| f.item.as_str()).collect::<Vec<_>>(), ["Vault::ft_on_transfer"]);
    }
}
