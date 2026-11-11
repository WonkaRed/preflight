//! PF005: a payout that is only booked in its callback.
//!
//! A NEAR cross-contract call is asynchronous: the receipt that moves the tokens and the callback that follows it
//! run in later blocks, and any other call can run in between. A method that reads a balance, sends it out and
//! leaves the balance untouched until the callback can therefore be called again while the old balance is still on
//! the books, and it pays twice. The balance must be debited before the promise leaves and restored in the callback
//! only if the call failed. Docs: https://docs.near.org/smart-contracts/security/reentrancy
//!
//! A finding needs all of these, in one `#[near]` type:
//! 1. An exported method (`pub` in a `#[near]` or `#[near_bindgen]` impl, or any method of a trait impl) whose own
//!    body has a `.then(..)` call that attaches a callback of the same type, scheduled with `Self::ext(..)` or
//!    `Type::ext(env::current_account_id())`.
//! 2. The promise before that `.then(..)` sends value: a `.transfer(..)` call, a call whose name contains
//!    `transfer` (`ft_transfer`, `nft_transfer_call`), or `.with_attached_deposit(..)`.
//! 3. The method reads a state field `self.F`, writes no part of `self.F` anywhere in its body, and the callback
//!    writes `self.F`. Writes anywhere in the body count, not only those before the promise is built, because the
//!    promise leaves only after the method returns and its state is committed.
//!
//! State access is followed through the type's own methods: `self.helper(..)` contributes what `helper`'s body
//! reads and writes. A write is an assignment or compound assignment to `self.F`, a `&mut` borrow of it, or a call
//! on it. The two sides err towards silence in opposite directions. In the method, any call on `self.F` that is not
//! a known read (`get`, `contains_key`, `len`, ..) counts as a write, so `self.ledger.debit(..)` is trusted. In the
//! callback only known mutators (`insert`, `remove`, `push`, `get_mut`, ..) count, so an unknown call is not
//! assumed to write.
//!
//! Knowingly missed: a promise built in a helper or stored in a variable before `.then(..)`; a payout described
//! only by a name (`Promise::function_call("ft_transfer", ..)`); a callback in a type other than the method's;
//! state kept through `env::storage_*` or statics; a debit that sits in only one branch (it counts as a write);
//! and a callback that merely re-reads state. Re-entrancy that needs no callback (a failed transfer refunded by
//! the runtime) is out of scope.

use std::collections::BTreeSet;

use syn::visit::{self, Visit};
use syn::{
    Attribute, BinOp, Expr, ExprAssign, ExprBinary, ExprCall, ExprField, ExprMethodCall, ExprReference, ImplItem,
    ImplItemFn, ItemImpl, Member, Type, UnOp, Visibility,
};

use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::{Crate, SourceFile};

pub struct Pf005Reentrancy;

pub static RULE: Pf005Reentrancy = Pf005Reentrancy;

impl Rule for Pf005Reentrancy {
    fn id(&self) -> &'static str {
        "PF005"
    }

    fn title(&self) -> &'static str {
        "Payout booked only after its callback"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn help(&self) -> &'static str {
        "debit the balance before the promise is created and restore it in the callback only if the call failed"
    }

    fn check(&self, krate: &Crate) -> Vec<Finding> {
        let methods: Vec<Method> = krate
            .files
            .iter()
            .flat_map(|file| {
                let mut collector = Collector { file, methods: Vec::new() };
                collector.visit_file(&file.ast);
                collector.methods
            })
            .collect();

        let mut findings = Vec::new();
        for method in methods.iter().filter(|method| method.exported) {
            let mut thens = ValueThens::default();
            thens.visit_block(&method.item.block);
            if thens.callbacks.is_empty() {
                continue;
            }
            let own = method.access(&methods);
            let unprotected = thens.callbacks.iter().find_map(|name| {
                let written: BTreeSet<String> = methods
                    .iter()
                    .filter(|callback| callback.owner == method.owner && callback.item.sig.ident == name)
                    .flat_map(|callback| callback.access(&methods).writes)
                    .collect();
                let fields: Vec<String> = written
                    .into_iter()
                    .filter(|field| own.reads.contains(field) && !own.may_write.contains(field))
                    .map(|field| format!("`self.{field}`"))
                    .collect();
                (!fields.is_empty()).then_some((name, fields.join(", ")))
            });
            let Some((callback, fields)) = unprotected else { continue };
            let owner = &method.owner;
            let name = &method.item.sig.ident;
            findings.push(self.finding(
                method.file,
                name.span(),
                format!("{owner}::{name}"),
                format!(
                    "`{owner}::{name}` sends value in a promise and reads {fields} without updating it, and its \
                     callback `{owner}::{callback}` is the only place that does, so the method can run again \
                     while the old state is still on the books"
                ),
            ));
        }
        findings
    }
}

/// A method of an `impl` block, exported or not.
struct Method<'a> {
    file: &'a SourceFile,
    owner: String,
    exported: bool,
    item: &'a ImplItemFn,
}

impl Method<'_> {
    fn access(&self, methods: &[Method]) -> Access {
        access_of(methods, &self.owner, self.item, &mut vec![self.item.sig.ident.to_string()])
    }
}

struct Collector<'a> {
    file: &'a SourceFile,
    methods: Vec<Method<'a>>,
}

impl<'a> Visit<'a> for Collector<'a> {
    fn visit_item_impl(&mut self, item: &'a ItemImpl) {
        let owner = type_name(&item.self_ty);
        let near = item.attrs.iter().any(is_near_attr);
        for member in &item.items {
            if let ImplItem::Fn(method) = member {
                let exported = near && (item.trait_.is_some() || matches!(method.vis, Visibility::Public(_)));
                self.methods.push(Method { file: self.file, owner: owner.clone(), exported, item: method });
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

/// The names of the callbacks a method body attaches with `.then(Self::ext(..).callback(..))` after a promise that
/// sends value.
#[derive(Default)]
struct ValueThens {
    callbacks: Vec<String>,
}

impl<'ast> Visit<'ast> for ValueThens {
    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if call.method == "then"
            && sends_value(&call.receiver)
            && call.args.len() == 1
            && let Some(name) = call.args.first().and_then(self_callback_name)
            && !self.callbacks.contains(&name)
        {
            self.callbacks.push(name);
        }
        visit::visit_expr_method_call(self, call);
    }
}

/// Whether a promise chain, read from its last call backwards, sends tokens.
fn sends_value(mut chain: &Expr) -> bool {
    while let Expr::MethodCall(call) = chain {
        let name = call.method.to_string();
        if name == "with_attached_deposit" || name.contains("transfer") {
            return true;
        }
        chain = &call.receiver;
    }
    false
}

/// For `Self::ext(env::current_account_id()).with_static_gas(g).on_done(x)`, `on_done`: the method a promise
/// schedules on the contract itself. `None` for a chain that starts anywhere else.
fn self_callback_name(arg: &Expr) -> Option<String> {
    let Expr::MethodCall(outer) = arg else { return None };
    let mut receiver = &*outer.receiver;
    loop {
        match receiver {
            Expr::MethodCall(inner) => receiver = &inner.receiver,
            Expr::Call(root) => return is_self_ext(root).then(|| outer.method.to_string()),
            _ => return None,
        }
    }
}

fn is_self_ext(call: &ExprCall) -> bool {
    let Expr::Path(func) = &*call.func else { return false };
    let mut segments = func.path.segments.iter().rev();
    let (Some(last), Some(owner)) = (segments.next(), segments.next()) else { return false };
    last.ident == "ext" && (owner.ident == "Self" || first_arg_is_current_account(call))
}

fn first_arg_is_current_account(call: &ExprCall) -> bool {
    matches!(
        call.args.first(),
        Some(Expr::Call(arg)) if matches!(
            &*arg.func,
            Expr::Path(path) if path.path.segments.last().is_some_and(|s| s.ident == "current_account_id")
        )
    )
}

/// The state a method body touches, by the name of the `self` field.
#[derive(Default)]
struct Access {
    /// Every `self.F` mentioned.
    reads: BTreeSet<String>,
    /// `F` written by an assignment, a `&mut` borrow, or a known mutating call.
    writes: BTreeSet<String>,
    /// `writes`, plus `F` touched by any call that is not a known read.
    may_write: BTreeSet<String>,
}

impl Access {
    fn absorb(&mut self, other: Access) {
        self.reads.extend(other.reads);
        self.writes.extend(other.writes);
        self.may_write.extend(other.may_write);
    }

    fn write(&mut self, field: String) {
        self.may_write.insert(field.clone());
        self.writes.insert(field);
    }
}

/// Calls on a state field that only read it.
const READS: &[&str] = &[
    "get",
    "contains_key",
    "contains",
    "len",
    "is_empty",
    "iter",
    "keys",
    "values",
    "first",
    "last",
    "clone",
    "as_ref",
    "as_str",
    "to_vec",
    "to_string",
    "copied",
    "cloned",
    "unwrap_or",
    "unwrap_or_default",
    "is_some",
    "is_none",
    "is_zero",
    "as_yoctonear",
    "checked_add",
    "checked_sub",
    "saturating_sub",
];

/// Calls on a state field that change it, in `near_sdk::store`, `near_sdk::collections` and `std`.
const MUTATIONS: &[&str] = &[
    "insert",
    "remove",
    "remove_entry",
    "set",
    "push",
    "push_back",
    "push_front",
    "pop",
    "pop_back",
    "pop_front",
    "clear",
    "extend",
    "append",
    "retain",
    "drain",
    "take",
    "replace",
    "swap",
    "swap_remove",
    "truncate",
    "get_mut",
    "iter_mut",
    "values_mut",
    "entry",
    "as_mut",
    "flush",
];

/// What `item`, a method of `owner`, reads and writes, following `self.helper(..)` calls into the same type.
/// `active` holds the methods being walked, so recursive helpers terminate.
fn access_of(methods: &[Method], owner: &str, item: &ImplItemFn, active: &mut Vec<String>) -> Access {
    let mut visitor = AccessVisitor { methods, owner, active, access: Access::default() };
    visitor.visit_block(&item.block);
    visitor.access
}

struct AccessVisitor<'v, 'a> {
    methods: &'v [Method<'a>],
    owner: &'v str,
    active: &'v mut Vec<String>,
    access: Access,
}

impl<'ast> Visit<'ast> for AccessVisitor<'_, '_> {
    fn visit_expr_field(&mut self, field: &'ast ExprField) {
        if is_self(&field.base) {
            self.access.reads.insert(member_name(&field.member));
        }
        visit::visit_expr_field(self, field);
    }

    fn visit_expr_assign(&mut self, assign: &'ast ExprAssign) {
        if let Some(field) = state_field(&assign.left) {
            self.access.write(field);
        }
        visit::visit_expr_assign(self, assign);
    }

    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        if is_compound_assignment(&binary.op)
            && let Some(field) = state_field(&binary.left)
        {
            self.access.write(field);
        }
        visit::visit_expr_binary(self, binary);
    }

    fn visit_expr_reference(&mut self, reference: &'ast ExprReference) {
        if reference.mutability.is_some()
            && let Some(field) = state_field(&reference.expr)
        {
            self.access.write(field);
        }
        visit::visit_expr_reference(self, reference);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let name = call.method.to_string();
        if let Some(field) = state_field(&call.receiver) {
            if MUTATIONS.contains(&name.as_str()) {
                self.access.write(field);
            } else if !READS.contains(&name.as_str()) {
                self.access.may_write.insert(field);
            }
        } else if is_self(&call.receiver) {
            self.follow_helper(&name);
        }
        visit::visit_expr_method_call(self, call);
    }
}

impl AccessVisitor<'_, '_> {
    /// Adds what the same type's method `name` reads and writes, unless it is already being walked.
    fn follow_helper(&mut self, name: &str) {
        if self.active.iter().any(|active| active == name) {
            return;
        }
        let methods = self.methods;
        self.active.push(name.to_owned());
        for helper in methods.iter().filter(|m| m.owner == self.owner && m.item.sig.ident == name) {
            let access = access_of(methods, self.owner, helper.item, self.active);
            self.access.absorb(access);
        }
        self.active.pop();
    }
}

fn is_self(expr: &Expr) -> bool {
    matches!(expr, Expr::Path(path) if path.path.is_ident("self"))
}

fn member_name(member: &Member) -> String {
    match member {
        Member::Named(ident) => ident.to_string(),
        Member::Unnamed(index) => index.index.to_string(),
    }
}

/// The `self` field a place expression such as `self.balances`, `self.stats.total`, `self.items[i]` or
/// `*self.count` lives in. Calls end the search: `self.balances.get(..)` is a value, not the place.
fn state_field(place: &Expr) -> Option<String> {
    match place {
        Expr::Field(field) if is_self(&field.base) => Some(member_name(&field.member)),
        Expr::Field(field) => state_field(&field.base),
        Expr::Index(index) => state_field(&index.expr),
        Expr::Paren(paren) => state_field(&paren.expr),
        Expr::Reference(reference) => state_field(&reference.expr),
        Expr::Unary(unary) if matches!(unary.op, UnOp::Deref(_)) => state_field(&unary.expr),
        _ => None,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn check(sources: &[(&str, &str)]) -> Vec<Finding> {
        let krate = Crate::from_sources(sources.iter().copied()).unwrap();
        RULE.check(&krate)
    }

    fn items(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|finding| finding.item.as_str()).collect()
    }

    fn flagged(source: &str) -> Vec<String> {
        items(&check(&[("src/lib.rs", source)])).into_iter().map(str::to_owned).collect()
    }

    /// The vulnerable shape: read the balance, pay it, clear it in the callback.
    fn pool(withdraw_body: &str, callback_body: &str) -> String {
        format!(
            "#[near] impl Pool {{
                pub fn withdraw(&mut self, to: AccountId) -> Promise {{ {withdraw_body} }}
                #[private]
                pub fn on_withdraw(&mut self, account: AccountId) {{ {callback_body} }}
                pub fn balance_of(&self, account: AccountId) -> u128 {{ self.balances.get(&account).copied().unwrap_or(0) }}
            }}"
        )
    }

    const PAY: &str = "let amount = self.balance_of(env::predecessor_account_id());
        Promise::new(to).transfer(amount).then(Self::ext(env::current_account_id()).on_withdraw(env::predecessor_account_id()))";
    const CLEAR: &str = "self.balances.remove(&account);";

    #[test]
    fn flags_a_payout_that_is_only_booked_in_its_callback_and_locates_it() {
        let findings = check(&[("src/lib.rs", &pool(PAY, CLEAR))]);
        assert_eq!(items(&findings), ["Pool::withdraw"]);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF005", Severity::High));
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 2, 24));
        assert!(finding.message.contains("`self.balances`") && finding.message.contains("Pool::on_withdraw"));
    }

    #[test]
    fn flags_each_way_a_callback_can_write_state() {
        for callback in [
            "self.balances.insert(account, 0);",
            "self.balances = Default::default();",
            "self.balances.total -= 1;",
            "*self.balances.get_mut(&account).unwrap() -= 1;",
            "let balance = self.balances.get_mut(&account).unwrap(); *balance = 0;",
            "let handle = &mut self.balances; handle.clear();",
            "self.settle(account);",
        ] {
            let source = format!("{} impl Pool {{ fn settle(&mut self, a: AccountId) {{ self.balances.remove(&a); }} }}", pool(PAY, callback));
            assert_eq!(flagged(&source), ["Pool::withdraw"], "{callback}");
        }
    }

    #[test]
    fn flags_a_token_payout_with_an_attached_deposit() {
        let pay = "let amount = self.balances.get(&to).copied().unwrap_or(0);
            ext_ft::ext(self.token.clone()).with_attached_deposit(ONE_YOCTO).ft_transfer(to, amount)
                .then(Self::ext(env::current_account_id()).with_static_gas(GAS).on_withdraw(me()))";
        assert_eq!(flagged(&pool(pay, CLEAR)), ["Pool::withdraw"]);
    }

    #[test]
    fn flags_nft_and_call_variants_and_a_type_qualified_callback_schedule() {
        let pay = "let id = self.listings.get(&to).copied().unwrap_or(0);
            nft::ext(self.nft.clone()).nft_transfer_call(to, id)
                .then(Pool::ext(env::current_account_id()).on_withdraw(me()))";
        let source = pool(pay, "self.listings.remove(&account);");
        assert_eq!(flagged(&source), ["Pool::withdraw"]);
    }

    #[test]
    fn reads_and_writes_are_followed_through_helpers_of_the_same_type() {
        let pay = "let amount = self.balance_of(me()); Promise::new(to).transfer(amount).then(Self::ext(env::current_account_id()).on_withdraw(me()))";
        assert_eq!(flagged(&pool(pay, CLEAR)), ["Pool::withdraw"]);
    }

    #[test]
    fn accepts_near_bindgen_and_trait_impls_and_a_callback_in_another_file() {
        let method = "pub fn withdraw(&mut self, to: AccountId) -> Promise {
            let amount = self.balances.get(&to).copied().unwrap_or(0);
            Promise::new(to).transfer(amount).then(Self::ext(env::current_account_id()).on_withdraw(me()))
        }";
        let callback = "impl Pool { pub fn on_withdraw(&mut self, account: AccountId) { self.balances.remove(&account); } }";
        for attr_impl in ["#[near_bindgen] impl Pool", "#[near_sdk::near] impl Pool", "#[near] impl Payouts for Pool"] {
            let method = if attr_impl.contains(" for ") { method.replace("pub fn", "fn") } else { method.to_owned() };
            let source = format!("{attr_impl} {{ {method} }}");
            let findings = check(&[("src/lib.rs", &source), ("src/callbacks.rs", callback)]);
            assert_eq!(items(&findings), ["Pool::withdraw"], "{attr_impl}");
            assert_eq!(findings[0].file, "src/lib.rs");
        }
    }

    #[test]
    fn silent_when_the_method_debits_before_it_pays() {
        for debit in [
            "self.balances.remove(&env::predecessor_account_id());",
            "self.balances.insert(env::predecessor_account_id(), 0);",
            "self.balances = Default::default();",
            "self.balances.total -= 1;",
            "let balance = self.balances.get_mut(&env::predecessor_account_id()).unwrap(); *balance = 0;",
            "debit(&mut self.balances);",
            "self.balances.debit(&env::predecessor_account_id());",
            "self.settle(env::predecessor_account_id());",
        ] {
            let pay = format!("{debit} {PAY}");
            let source = format!("{} impl Pool {{ fn settle(&mut self, a: AccountId) {{ self.balances.remove(&a); }} }}", pool(&pay, CLEAR));
            assert!(flagged(&source).is_empty(), "{debit}");
        }
    }

    #[test]
    fn silent_when_the_debit_comes_after_the_promise_is_built_but_before_the_method_returns() {
        let pay = "let amount = self.balance_of(me());
            let payout = Promise::new(to).transfer(amount).then(Self::ext(env::current_account_id()).on_withdraw(me()));
            self.balances.remove(&env::predecessor_account_id());
            payout";
        assert!(flagged(&pool(pay, CLEAR)).is_empty());
    }

    #[test]
    fn silent_when_the_debit_is_inside_the_promise_expression() {
        let pay = "Promise::new(to).transfer(self.balances.remove(&me()).unwrap())
            .then(Self::ext(env::current_account_id()).on_withdraw(me()))";
        assert!(flagged(&pool(pay, CLEAR)).is_empty());
    }

    #[test]
    fn silent_when_the_callback_only_restores_after_a_failure() {
        let pay = format!("self.balances.remove(&me()); {PAY}");
        let restore = "if failed() { self.balances.insert(account, 1); }";
        assert!(flagged(&pool(&pay, restore)).is_empty());
    }

    #[test]
    fn silent_for_a_proxy_that_keeps_no_state() {
        let source = "#[near] impl Proxy {
            pub fn forward(&self, to: AccountId, amount: NearToken) -> Promise {
                Promise::new(to).transfer(amount).then(Self::ext(env::current_account_id()).on_forward())
            }
            #[private] pub fn on_forward(&self) { env::log_str(\"sent\"); }
        }";
        assert!(flagged(source).is_empty());
    }

    #[test]
    fn silent_when_the_callback_only_reads_state() {
        assert!(flagged(&pool(PAY, "let _ = self.balances.get(&account);")).is_empty());
    }

    #[test]
    fn silent_when_the_callback_writes_state_the_method_does_not_read() {
        assert!(flagged(&pool(PAY, "self.history.push(account);")).is_empty());
    }

    #[test]
    fn silent_for_a_call_that_sends_no_value() {
        let fetch = "let cached = self.prices.get(&to).copied();
            oracle::ext(self.oracle.clone()).get_price(to).then(Self::ext(env::current_account_id()).on_withdraw(me()))";
        assert!(flagged(&pool(fetch, "self.prices.insert(account, 1);")).is_empty());
    }

    #[test]
    fn silent_for_a_callback_scheduled_on_another_contract_or_not_found() {
        let other = "let amount = self.balance_of(me());
            Promise::new(to).transfer(amount).then(other::ext(token()).on_withdraw(me()))";
        assert!(flagged(&pool(other, CLEAR)).is_empty());
        let missing = "let amount = self.balance_of(me());
            Promise::new(to).transfer(amount).then(Self::ext(env::current_account_id()).elsewhere(me()))";
        assert!(flagged(&pool(missing, CLEAR)).is_empty());
    }

    #[test]
    fn silent_for_methods_the_near_macro_does_not_export() {
        let source = pool(PAY, CLEAR).replace("#[near] impl Pool", "impl Pool").replace("pub fn withdraw", "fn withdraw");
        assert!(flagged(&source).is_empty());
        let hidden = pool(PAY, CLEAR).replace("pub fn withdraw", "fn withdraw");
        assert!(flagged(&hidden).is_empty());
    }

    #[test]
    fn recursive_helpers_terminate() {
        let source = format!("{} impl Pool {{ fn a(&self) {{ self.b() }} fn b(&self) {{ self.a() }} }}", pool(PAY, CLEAR));
        assert_eq!(flagged(&source.replace("let amount =", "self.a(); let amount =")), ["Pool::withdraw"]);
    }
}
