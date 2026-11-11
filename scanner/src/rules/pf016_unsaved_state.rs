//! PF016: a copy of stored state is changed and never written back.
//!
//! Reading a value out of a collection with `get` gives the method a copy (`.cloned()`, `.copied()`,
//! `.unwrap_or(0)`, or the owned value of a `near_sdk::collections` map). Changing the copy changes nothing in
//! storage: the debit, credit or counter update dies with the local variable when the method returns, while the
//! rest of the method (a payout, a granted item) goes ahead. Rustle calls this `unsaved-changes`:
//! https://github.com/blocksecteam/rustle/blob/master/docs/detectors/unsaved-changes.md
//!
//! Matched, in any method with a `&mut self` receiver (public or not, in any impl): `let mut v = <place>.get(..)`
//! where `<place>` is a field of `self` (`self.accounts`), optionally followed by `.unwrap()`, `.expect(..)`,
//! `.cloned()`, `.clone()`, `.copied()`, `.to_owned()`, `.unwrap_or(..)`, `.unwrap_or_default()`,
//! `.unwrap_or_else(..)`, `.ok_or(..)`, `.ok_or_else(..)`, `?` or a `*`; and in the statements after it `v` is
//! changed (`v = ..`, `v += ..`, `v.field -= ..`, `v.items[i] = ..`, `&mut v` or `&mut v.field`, or a mutating
//! method such as `v.items.push(..)`, `.insert(..)`, `.remove(..)`, `.clear()`), and after the last change `v` is
//! neither read again nor handed anywhere. The change is then a dead store: nothing can persist it.
//!
//! `v` is read or handed on when it appears in any other way than as the target of a change: an argument of a
//! call (`self.accounts.insert(id, v)`, `save(&v)`), a struct field, a `let` initialiser, a return value or tail
//! expression, a comparison or arithmetic operand, `v.field` in any expression, or in the arguments of a macro.
//! The logging macros `log!`, `format!`, `panic!`, `println!`, `print!`, `eprintln!` and `eprint!` do not count,
//! and `assert!`/`require!` (and their variants) read `v` without handing it on. `v` handed on as a whole value
//! anywhere (`f(v)`, `&v`, `&mut v`, `v.clone()`, `let w = v`, a return, an unknown macro) may be saved by
//! someone else and ends the check for good.
//!
//! Knowingly missed: a copy obtained through a helper (`self.internal_get_account(&id)`) or through anything but
//! a `get` on a field of `self`; a copy that is changed and then read again for a payout or a check (the read is
//! taken as the reason for the change); a change reached through a method of `v` that the scanner cannot tell is
//! mutating (`v.accrue()`).

use proc_macro2::{Span, TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, FnArg, ImplItem, ItemImpl, Local, Macro, Pat, Stmt, Type, UnOp};

use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf016UnsavedState;

pub static RULE: Pf016UnsavedState = Pf016UnsavedState;

impl Rule for Pf016UnsavedState {
    fn id(&self) -> &'static str {
        "PF016"
    }

    fn title(&self) -> &'static str {
        "State read into a local copy, changed, and never saved"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn help(&self) -> &'static str {
        "write the changed value back with insert(..), or take a mutable reference with get_mut(..) and change it in place"
    }

    fn check(&self, krate: &Crate) -> Vec<Finding> {
        let mut findings = Vec::new();
        for file in &krate.files {
            let mut scan = FileScan::default();
            scan.visit_file(&file.ast);
            for lost in scan.lost {
                findings.push(self.finding(
                    file,
                    lost.span,
                    lost.item.clone(),
                    format!(
                        "`{}` copies `{}` out of `{}` with `.get(..)` and changes it, but never writes it back or uses it again, so the change is lost when the method returns",
                        lost.item, lost.variable, lost.source
                    ),
                ));
            }
        }
        findings
    }
}

struct Lost {
    item: String,
    span: Span,
    variable: String,
    source: String,
}

#[derive(Default)]
struct FileScan {
    lost: Vec<Lost>,
}

impl<'ast> Visit<'ast> for FileScan {
    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        let owner = type_name(&item.self_ty);
        for member in &item.items {
            if let ImplItem::Fn(method) = member
                && method.sig.inputs.iter().any(is_mut_self)
            {
                let mut reads = StateReads { item: format!("{owner}::{}", method.sig.ident), lost: Vec::new() };
                reads.visit_block(&method.block);
                self.lost.extend(reads.lost);
            }
        }
        visit::visit_item_impl(self, item);
    }
}

fn is_mut_self(arg: &FnArg) -> bool {
    matches!(arg, FnArg::Receiver(receiver) if receiver.reference.is_some() && receiver.mutability.is_some())
}

fn type_name(ty: &Type) -> String {
    match ty {
        Type::Path(path) => path.path.segments.last().map_or_else(String::new, |segment| segment.ident.to_string()),
        _ => "<unnamed type>".to_owned(),
    }
}

/// Finds the `let mut v = self.<field>.get(..)..` statements of one method, in any block, and judges each.
struct StateReads {
    item: String,
    lost: Vec<Lost>,
}

impl<'ast> Visit<'ast> for StateReads {
    fn visit_block(&mut self, block: &'ast syn::Block) {
        for (index, stmt) in block.stmts.iter().enumerate() {
            let Stmt::Local(local) = stmt else { continue };
            let Some((ident, source)) = state_copy(local) else { continue };
            let name = ident.to_string();
            let mut flow = Flow { name: &name, changed: false, handed_on: false, read_since_change: false };
            for later in &block.stmts[index + 1..] {
                flow.visit_stmt(later);
            }
            if flow.changed && !flow.handed_on && !flow.read_since_change {
                self.lost.push(Lost { item: self.item.clone(), span: ident.span(), variable: name.clone(), source });
            }
        }
        visit::visit_block(self, block);
    }
}

/// Methods that return a copy of the value they were called on, or of its content.
const COPIES: [&str; 11] = [
    "unwrap",
    "expect",
    "cloned",
    "clone",
    "copied",
    "to_owned",
    "unwrap_or",
    "unwrap_or_default",
    "unwrap_or_else",
    "ok_or",
    "ok_or_else",
];

/// `let mut v = self.<field>.get(..)` with only copying steps after the `get`: the bound name and the place.
fn state_copy(local: &Local) -> Option<(&syn::Ident, String)> {
    let mut pat = &local.pat;
    if let Pat::Type(typed) = pat {
        pat = &typed.pat;
    }
    let Pat::Ident(binding) = pat else { return None };
    if binding.mutability.is_none() || binding.by_ref.is_some() || binding.subpat.is_some() {
        return None;
    }
    let mut expr = &*local.init.as_ref()?.expr;
    loop {
        match expr {
            Expr::MethodCall(call) if call.method == "get" => return Some((&binding.ident, field_path(&call.receiver)?)),
            Expr::MethodCall(call) if COPIES.contains(&call.method.to_string().as_str()) => expr = &call.receiver,
            Expr::Try(inner) => expr = &inner.expr,
            Expr::Paren(inner) => expr = &inner.expr,
            Expr::Unary(inner) if matches!(inner.op, UnOp::Deref(_)) => expr = &inner.expr,
            _ => return None,
        }
    }
}

/// `self.accounts` for the expression `self.accounts`; `None` unless it is a chain of fields starting at `self`.
fn field_path(expr: &Expr) -> Option<String> {
    let Expr::Field(field) = expr else { return None };
    let syn::Member::Named(name) = &field.member else { return None };
    match &*field.base {
        Expr::Path(path) if path.path.is_ident("self") => Some(format!("self.{name}")),
        base => Some(format!("{}.{name}", field_path(base)?)),
    }
}

/// Methods that change the collection or option they are called on.
const MUTATORS: [&str; 18] = [
    "push",
    "push_back",
    "push_front",
    "push_str",
    "pop",
    "pop_back",
    "pop_front",
    "insert",
    "remove",
    "swap_remove",
    "clear",
    "extend",
    "retain",
    "truncate",
    "append",
    "drain",
    "take",
    "replace",
];

/// Methods that hand the whole value on as a new value.
const VALUE_COPIES: [&str; 5] = ["clone", "to_owned", "into", "to_vec", "borrow"];

/// Macros that only print or format their arguments: a mention in them is not a use of the value.
const LOG_MACROS: [&str; 7] = ["log", "format", "panic", "println", "print", "eprintln", "eprint"];

/// Macros that check their arguments: a mention in them reads the value but does not hand it on.
const CHECK_MACROS: [&str; 7] =
    ["require", "assert", "assert_eq", "assert_ne", "debug_assert", "debug_assert_eq", "debug_assert_ne"];

/// What happens to the local `name` in the statements after its `let`, in source order.
struct Flow<'a> {
    name: &'a str,
    /// Somewhere assigned to, borrowed mutably or mutated by a method.
    changed: bool,
    /// Passed on as a whole value: `f(v)`, `&v`, `v.clone()`, `let w = v`, returned.
    handed_on: bool,
    /// Read since the last change.
    read_since_change: bool,
}

/// The name a place expression (`v`, `v.f`, `v[i]`, `*v`) starts from.
fn place_root(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
        Expr::Field(inner) => place_root(&inner.base),
        Expr::Index(inner) => place_root(&inner.expr),
        Expr::Unary(inner) if matches!(inner.op, UnOp::Deref(_)) => place_root(&inner.expr),
        Expr::Paren(inner) => place_root(&inner.expr),
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

impl Flow<'_> {
    fn is_place(&self, expr: &Expr) -> bool {
        place_root(expr).is_some_and(|root| root == self.name)
    }

    fn change(&mut self) {
        self.changed = true;
        self.read_since_change = false;
    }

    /// Visits what a place expression contains besides the name itself: the index expressions.
    fn visit_place(&mut self, expr: &Expr) {
        match expr {
            Expr::Field(inner) => self.visit_place(&inner.base),
            Expr::Index(inner) => {
                self.visit_place(&inner.expr);
                self.visit_expr(&inner.index);
            }
            Expr::Unary(inner) => self.visit_place(&inner.expr),
            Expr::Paren(inner) => self.visit_place(&inner.expr),
            _ => {}
        }
    }

    /// An operand of arithmetic or a comparison: reading the name or a field of it, not handing it on.
    fn operand(&mut self, expr: &Expr) {
        if self.is_place(expr) {
            self.visit_place(expr);
            self.read_since_change = true;
        } else {
            self.visit_expr(expr);
        }
    }
}

impl<'ast> Visit<'ast> for Flow<'_> {
    fn visit_expr(&mut self, expr: &'ast Expr) {
        match expr {
            Expr::Path(_) | Expr::Field(_) | Expr::Index(_) | Expr::Unary(_) if self.is_place(expr) => {
                self.visit_place(expr);
                self.read_since_change = true;
                self.handed_on |= matches!(expr, Expr::Path(_));
            }
            Expr::Binary(binary) if is_compound_assignment(&binary.op) && self.is_place(&binary.left) => {
                self.visit_expr(&binary.right);
                self.visit_place(&binary.left);
                self.change();
            }
            Expr::Binary(binary) => {
                self.operand(&binary.left);
                self.operand(&binary.right);
            }
            Expr::Assign(assign) if self.is_place(&assign.left) => {
                self.visit_expr(&assign.right);
                self.visit_place(&assign.left);
                self.change();
            }
            Expr::MethodCall(call) if self.is_place(&call.receiver) => {
                for arg in &call.args {
                    self.visit_expr(arg);
                }
                self.visit_place(&call.receiver);
                let method = call.method.to_string();
                if MUTATORS.contains(&method.as_str()) {
                    self.change();
                } else {
                    self.read_since_change = true;
                    self.handed_on |= matches!(*call.receiver, Expr::Path(_)) && VALUE_COPIES.contains(&method.as_str());
                }
            }
            Expr::Reference(reference) if self.is_place(&reference.expr) => {
                self.visit_place(&reference.expr);
                self.handed_on |= matches!(*reference.expr, Expr::Path(_));
                if reference.mutability.is_some() {
                    self.change();
                } else {
                    self.read_since_change = true;
                }
            }
            _ => visit::visit_expr(self, expr),
        }
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        if !mentions(&mac.tokens, self.name) {
            return;
        }
        let named = |names: &[&str]| mac.path.segments.last().is_some_and(|segment| names.iter().any(|name| segment.ident == name));
        if named(&LOG_MACROS) {
            return;
        }
        self.read_since_change = true;
        self.handed_on |= !named(&CHECK_MACROS);
    }
}

/// Whether `name` is an identifier anywhere in `tokens`.
fn mentions(tokens: &TokenStream, name: &str) -> bool {
    tokens.clone().into_iter().any(|tree| match tree {
        TokenTree::Ident(ident) => ident == name,
        TokenTree::Group(group) => mentions(&group.stream(), name),
        TokenTree::Punct(_) | TokenTree::Literal(_) => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(source: &str) -> Vec<Finding> {
        let krate = Crate::from_sources([("src/lib.rs", source)]).unwrap();
        RULE.check(&krate)
    }

    fn items(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|finding| finding.item.as_str()).collect()
    }

    /// A bank whose `withdraw` subtracts from a copy of the account and pays out, and forgets to save it.
    const BANK: &str = r#"
        #[near]
        impl Bank {
            pub fn withdraw(&mut self, amount: U128) -> Promise {
                let caller = env::predecessor_account_id();
                let mut account = self.accounts.get(&caller).cloned().unwrap();
                require!(account.balance >= amount.0, "not enough");
                account.balance -= amount.0;
                Promise::new(caller).transfer(NearToken::from_yoctonear(amount.0))
            }
        }
    "#;

    #[test]
    fn flags_a_copy_changed_and_never_saved_and_locates_it() {
        let findings = check(BANK);
        assert_eq!(items(&findings), ["Bank::withdraw"]);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF016", Severity::High));
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 6, 25));
        assert!(finding.message.contains("`account`") && finding.message.contains("`self.accounts`"));
    }

    #[test]
    fn saving_the_copy_in_any_way_is_silent() {
        for save in [
            "self.accounts.insert(caller.clone(), account);",
            "self.accounts.insert(caller.clone(), account.clone());",
            "self.accounts.set(&caller, &account);",
            "self.save(&caller, &account);",
            "save(&mut account);",
            "self.current = account;",
            "let kept = account;",
            "return account;",
            "log_and_keep(Some(account));",
        ] {
            let source = BANK.replace("Promise::new", &format!("{save} Promise::new"));
            assert!(check(&source).is_empty(), "{save}");
        }
    }

    #[test]
    fn a_copy_that_is_the_result_of_the_method_is_silent() {
        let source = "impl C { pub fn bump(&mut self, id: u64) -> Item {
            let mut item = self.items.get(&id).cloned().unwrap();
            item.count += 1;
            item
        } }";
        assert!(check(source).is_empty());
    }

    #[test]
    fn flags_every_way_of_reading_the_copy() {
        for read in [
            "self.accounts.get(&k).cloned().unwrap()",
            "self.accounts.get(&k).unwrap().clone()",
            "self.accounts.get(&k).expect(\"missing\").to_owned()",
            "self.accounts.get(&k).unwrap_or_default().clone()",
            "self.accounts.get(&k).cloned().unwrap_or_else(Account::new)",
            "self.accounts.get(&k).cloned().ok_or(Error::Missing)?",
            "*self.accounts.get(&k).unwrap()",
            "self.accounts.get(&k).unwrap()",
            "self.state.accounts.get(&k).cloned().unwrap()",
        ] {
            let source = format!("impl C {{ pub fn go(&mut self, k: u64) {{ let mut a = {read}; a.balance -= 1; }} }}");
            assert_eq!(items(&check(&source)), ["C::go"], "{read}");
        }
    }

    #[test]
    fn flags_every_way_of_changing_the_copy() {
        for change in [
            "a.balance -= 1;",
            "a.balance = 0;",
            "a.items[0] = 1;",
            "a.items.push(1);",
            "a.items.clear();",
            "a.pending.take();",
            "let r = &mut a.balance;",
            "a = Account::default();",
            "a -= 1;",
        ] {
            let source = format!("impl C {{ pub fn go(&mut self, k: u64) {{ let mut a = self.items.get(&k).cloned().unwrap(); {change} }} }}");
            assert_eq!(items(&check(&source)), ["C::go"], "{change}");
        }
    }

    #[test]
    fn flags_a_scalar_balance_that_is_lowered_and_dropped() {
        let source = "impl C { pub fn spend(&mut self, id: u64, amount: u128) {
            let mut balance = self.balances.get(&id).copied().unwrap_or(0);
            require!(balance >= amount);
            balance -= amount;
            env::log_str(&format!(\"{balance} left\"));
        } }";
        let findings = check(source);
        assert_eq!(items(&findings), ["C::spend"]);
        assert!(findings[0].message.contains("`balance`"));
    }

    #[test]
    fn a_copy_that_is_read_after_the_change_is_silent() {
        for read in [
            "require!(price <= attached);",
            "if price > attached { return; }",
            "Promise::new(to).transfer(price);",
            "let total = price * 2;",
            "match price { _ => {} }",
        ] {
            let source = format!(
                "impl C {{ pub fn quote(&mut self, k: u64, fee: u128, attached: u128, to: AccountId) {{
                    let mut price = self.prices.get(&k).copied().unwrap_or(0);
                    price += fee;
                    {read}
                }} }}"
            );
            assert!(check(&source).is_empty(), "{read}");
        }
    }

    #[test]
    fn a_read_before_the_last_change_does_not_save_it() {
        let source = "impl C { pub fn go(&mut self, k: u64) {
            let mut a = self.items.get(&k).cloned().unwrap();
            a.count += 1;
            log!(\"count {}\", a.count);
            a.count += 1;
            println!(\"{}\", a.count);
        } }";
        assert_eq!(items(&check(source)), ["C::go"]);
    }

    #[test]
    fn macros_other_than_logging_count_as_a_use() {
        for mac in ["assert!(a.balance > 0);", "require!(a.balance > 0);", "store!(a);", "let _ = vec![a.clone()];"] {
            let source = format!("impl C {{ pub fn go(&mut self, k: u64) {{ let mut a = self.items.get(&k).cloned().unwrap(); a.balance -= 1; {mac} }} }}");
            assert!(check(&source).is_empty(), "{mac}");
        }
    }

    #[test]
    fn a_get_mut_or_a_copy_never_changed_is_silent() {
        let source = "impl C { pub fn go(&mut self, k: u64) -> u128 {
            let account = self.accounts.get_mut(&k).unwrap();
            account.balance -= 1;
            let mut by_ref = self.accounts.get_mut(&k).unwrap();
            by_ref.balance -= 1;
            let snapshot = self.accounts.get(&k).cloned().unwrap();
            let mut other = self.accounts.get(&k).cloned().unwrap();
            snapshot.balance + other.balance
        } }";
        assert!(check(source).is_empty());
    }

    #[test]
    fn only_a_get_on_a_field_of_self_is_a_state_read() {
        for read in [
            "local.get(&k).cloned().unwrap()",
            "self.get(&k).cloned().unwrap()",
            "self.accounts.find(&k).cloned().unwrap()",
            "self.accounts.get(&k).map(|a| a.balance).unwrap()",
            "self.internal_get_account(&k)",
            "Account::default()",
        ] {
            let source = format!("impl C {{ pub fn go(&mut self, k: u64) {{ let mut a = {read}; a.balance -= 1; }} }}");
            assert!(check(&source).is_empty(), "{read}");
        }
    }

    #[test]
    fn only_mut_self_methods_are_checked() {
        for receiver in ["&self", "self", "mut self"] {
            let source = format!("impl C {{ pub fn view({receiver}, k: u64) {{ let mut a = self.items.get(&k).cloned().unwrap(); a.n += 1; }} }}");
            assert!(check(&source).is_empty(), "{receiver}");
        }
        let view = "impl C { pub fn preview(&self, k: u64) -> u128 { let mut a = self.items.get(&k).cloned().unwrap(); a.n += 1; 0 } }";
        assert!(check(view).is_empty());
        let private = "impl C { fn helper(&mut self, k: u64) { let mut a = self.items.get(&k).cloned().unwrap(); a.n += 1; } }";
        assert_eq!(items(&check(private)), ["C::helper"]);
        let in_trait = "impl Bank for C { fn helper(&mut self, k: u64) { let mut a = self.items.get(&k).cloned().unwrap(); a.n += 1; } }";
        assert_eq!(items(&check(in_trait)), ["C::helper"]);
    }

    #[test]
    fn works_in_a_nested_block_and_reports_each_copy() {
        let source = "impl C { pub fn go(&mut self, k: u64) {
            if k > 0 {
                let mut a = self.items.get(&k).cloned().unwrap();
                a.n += 1;
            }
            for i in 0..k {
                let mut b = self.others.get(&i).copied().unwrap_or(0);
                b += 1;
            }
        } }";
        let findings = check(source);
        assert_eq!(findings.len(), 2);
        assert_eq!((findings[0].line, findings[1].line), (3, 7));
    }

    #[test]
    fn a_copy_is_judged_in_its_own_block_only() {
        let source = "impl C { pub fn go(&mut self, k: u64) {
            { let mut a = self.items.get(&k).cloned().unwrap(); a.n += 1; }
            let a = 5;
            self.total = a;
        } }";
        assert_eq!(check(source).len(), 1);
    }
}
