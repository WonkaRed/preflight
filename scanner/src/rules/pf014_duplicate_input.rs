//! PF014: a caller-supplied list is paid entry by entry, but the charge is applied once.
//!
//! When a method loops over a list the caller passes in and pays or credits each entry, while the cost (shares
//! burned, a balance lowered) is applied once outside the loop, then listing the same entry several times is paid
//! several times for one charge. A public 2022 incident on NEAR lost about 1.1M NEAR this way: `redeem` paid out every
//! token id in the caller's list and nothing checked that the ids were distinct. Docs:
//! https://docs.near.org/smart-contracts/security/duplicate-inputs
//!
//! A method is checked when the `#[near]` macro exports it (`pub` method of an inherent impl, or any method of a
//! trait impl) and it is reported when all of these hold:
//! - it takes a parameter `list: Vec<..>`;
//! - it has `for entry in list` (also `&list`, `list.iter()`, `list.into_iter()`, `.clone()`, `.cloned()`,
//!   `.copied()`, `.enumerate()`) whose body pays or credits using the entry: a send of value that mentions it
//!   (`Promise::new(entry).transfer(..)`, `ext(entry).ft_transfer(..)` and the other NEP transfer calls), or a
//!   cumulative write that mentions it (`+=`, or `.insert(..)` / `.set(..)` with an addition in its arguments;
//!   a plain `insert` overwrites, so a repeat does no harm), and the body does not consume per-entry state
//!   (`.remove(..)`, `.take(..)`, `.pop(..)` or `.swap_remove(..)` of something that mentions the entry, which
//!   makes a repeat pay nothing);
//! - outside that loop the method debits an amount (`place -= x`, `place = .. - x`, `.insert(..)` / `.set(..)`
//!   with a subtraction) that does not mention `list` itself, and `x` is used inside the loop and not changed
//!   there. A cost that scales with the list (`self.balance -= amount * list.len()`) is therefore not reported, and
//!   neither is a running total that the loop builds up and the method then subtracts;
//! - nothing in the method looks like a duplicate check: `dedup`, `dedup_by`, `dedup_by_key`, `windows`,
//!   `contains`, `contains_key`, or any of `HashSet`, `BTreeSet`, `IndexSet`, `UnorderedSet`, `LookupSet`,
//!   `TreeSet`, written anywhere in the method, macro arguments included, whatever `contains` is called on (an
//!   allowlist check such as `self.supported.contains(..)` also counts, which errs towards silence).
//!
//! Knowingly missed: iteration written as `list.iter().for_each(..)` or a `map` chain; a list wrapped in another
//! type (`Option<Vec<..>>`, a struct field, a slice); a charge made in a helper the method calls; a duplicate
//! check made in a helper; a loop whose entry reaches the payment only through a variable bound from it.

use std::collections::BTreeSet;
use std::iter;

use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprAssign, ExprBinary, ExprForLoop, ExprMethodCall, FnArg, ImplItem, ImplItemFn, ItemImpl, Pat, PatIdent, Type, Visibility};

use super::pf015_no_rollback::{Names, idents, root_name, send_of, subtracted};
use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf014DuplicateInput;

pub static RULE: Pf014DuplicateInput = Pf014DuplicateInput;

impl Rule for Pf014DuplicateInput {
    fn id(&self) -> &'static str {
        "PF014"
    }

    fn title(&self) -> &'static str {
        "Caller-supplied list paid per entry but charged once"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn help(&self) -> &'static str {
        "reject a list with a repeated entry before paying (collect it into a BTreeSet and compare lengths, or dedup it)"
    }

    fn check(&self, krate: &Crate) -> Vec<Finding> {
        let mut findings = Vec::new();
        for file in &krate.files {
            let mut scan = FileScan::default();
            scan.visit_file(&file.ast);
            for (item, method, hit) in scan.hits {
                findings.push(self.finding(
                    file,
                    method.sig.ident.span(),
                    item.clone(),
                    format!(
                        "`{item}` pays out for every entry of the caller-supplied list `{}` using `{}`, which it debits once outside the loop, but never checks the list for repeats, so an entry listed several times is paid several times for one charge",
                        hit.list, hit.charged
                    ),
                ));
            }
        }
        findings
    }
}

struct Hit {
    list: String,
    /// A variable of the amount debited outside the loop that the loop also uses.
    charged: String,
}

#[derive(Default)]
struct FileScan<'ast> {
    hits: Vec<(String, &'ast ImplItemFn, Hit)>,
}

impl<'ast> Visit<'ast> for FileScan<'ast> {
    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        let near = item.attrs.iter().any(is_near_attr);
        let owner = type_name(&item.self_ty);
        for member in &item.items {
            if let ImplItem::Fn(method) = member
                && near
                && (item.trait_.is_some() || matches!(method.vis, Visibility::Public(_)))
                && let Some(hit) = judge(method)
            {
                self.hits.push((format!("{owner}::{}", method.sig.ident), method, hit));
            }
        }
        visit::visit_item_impl(self, item);
    }
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

fn judge(method: &ImplItemFn) -> Option<Hit> {
    let lists: BTreeSet<String> = method
        .sig
        .inputs
        .iter()
        .filter_map(|arg| match arg {
            FnArg::Typed(arg) => match (&*arg.pat, &*arg.ty) {
                (Pat::Ident(PatIdent { ident, .. }), Type::Path(ty)) if ty.path.segments.last()?.ident == "Vec" => {
                    Some(ident.to_string())
                }
                _ => None,
            },
            FnArg::Receiver(_) => None,
        })
        .collect();
    if lists.is_empty() {
        return None;
    }
    let mut loops = PayingLoops { lists: &lists, found: Vec::new() };
    loops.visit_block(&method.block);
    if loops.found.is_empty() {
        return None;
    }
    let mut duplicate_check = DuplicateCheck(false);
    duplicate_check.visit_block(&method.block);
    if duplicate_check.0 {
        return None;
    }
    let mut outside = Outside { loops: &loops.found, debits: Vec::new() };
    outside.visit_block(&method.block);
    loops.found.iter().find_map(|paying| {
        outside.debits.iter().find_map(|debit| {
            let charged = debit.intersection(&paying.reused).next()?;
            (!debit.contains(&paying.list)).then(|| Hit { list: paying.list.clone(), charged: charged.clone() })
        })
    })
}

/// A `for` loop over a caller-supplied list whose body pays or credits entries.
struct PayingLoop<'ast> {
    node: &'ast ExprForLoop,
    list: String,
    /// What the body mentions and does not change: the variables a payment can be computed from.
    reused: BTreeSet<String>,
}

struct PayingLoops<'a, 'ast> {
    lists: &'a BTreeSet<String>,
    found: Vec<PayingLoop<'ast>>,
}

impl<'ast> Visit<'ast> for PayingLoops<'_, 'ast> {
    fn visit_expr_for_loop(&mut self, node: &'ast ExprForLoop) {
        if let Some(list) = iterated_list(&node.expr, self.lists) {
            let mut entries = EntryNames::default();
            entries.visit_pat(&node.pat);
            let mut body = Body { entries: entries.0, pays: false, consumes: false, changed: BTreeSet::new() };
            body.visit_block(&node.body);
            if body.pays && !body.consumes {
                let mut mentioned = Names::default();
                mentioned.visit_block(&node.body);
                let reused = mentioned.0.difference(&body.changed).cloned().collect();
                self.found.push(PayingLoop { node, list: list.clone(), reused });
            }
        }
        visit::visit_expr_for_loop(self, node);
    }
}

/// Adaptors that still iterate the entries of the list itself.
const ADAPTORS: [&str; 6] = ["iter", "into_iter", "clone", "cloned", "copied", "enumerate"];

/// The list a `for` loop walks: `list`, `&list`, `list.iter()`, `list.clone().into_iter()`..
fn iterated_list<'a>(expr: &Expr, lists: &'a BTreeSet<String>) -> Option<&'a String> {
    match expr {
        Expr::Path(path) => lists.get(&path.path.get_ident()?.to_string()),
        Expr::Reference(inner) => iterated_list(&inner.expr, lists),
        Expr::Paren(inner) => iterated_list(&inner.expr, lists),
        Expr::MethodCall(call) if ADAPTORS.contains(&call.method.to_string().as_str()) => iterated_list(&call.receiver, lists),
        _ => None,
    }
}

/// The names a loop pattern binds.
#[derive(Default)]
struct EntryNames(BTreeSet<String>);

impl<'ast> Visit<'ast> for EntryNames {
    fn visit_pat_ident(&mut self, ident: &'ast PatIdent) {
        self.0.insert(ident.ident.to_string());
    }
}

/// What a loop body does with the entries and with the variables it writes to.
struct Body {
    entries: BTreeSet<String>,
    pays: bool,
    consumes: bool,
    /// Roots of the places the body assigns to or adds to.
    changed: BTreeSet<String>,
}

impl Body {
    fn mentions_an_entry(&self, names: &BTreeSet<String>) -> bool {
        !names.is_disjoint(&self.entries)
    }
}

/// Methods that take an entry's state out, so that a repeated entry finds nothing.
const CONSUMING: [&str; 4] = ["remove", "take", "pop", "swap_remove"];

impl<'ast> Visit<'ast> for Body {
    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        visit::visit_expr_binary(self, binary);
        if matches!(binary.op, BinOp::AddAssign(_) | BinOp::SubAssign(_)) {
            self.changed.extend(root_name(&binary.left));
            let names = idents([&*binary.left, &*binary.right]);
            self.pays |= matches!(binary.op, BinOp::AddAssign(_)) && self.mentions_an_entry(&names);
        }
    }

    fn visit_expr_assign(&mut self, assign: &'ast ExprAssign) {
        visit::visit_expr_assign(self, assign);
        self.changed.extend(root_name(&assign.left));
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        visit::visit_expr_method_call(self, call);
        let names = call_idents(call);
        if !self.mentions_an_entry(&names) {
            return;
        }
        let method = call.method.to_string();
        self.consumes |= CONSUMING.contains(&method.as_str());
        self.pays |= send_of(call).is_some()
            || (matches!(method.as_str(), "insert" | "set") && call.args.iter().any(adds));
    }
}

/// Everything a method call mentions but its method name.
fn call_idents(call: &ExprMethodCall) -> BTreeSet<String> {
    idents(iter::once(&*call.receiver).chain(&call.args))
}

/// Whether `expr` contains an addition: `a + b`, `a.checked_add(b)`, `a.saturating_add(b)`.
fn adds(expr: &Expr) -> bool {
    #[derive(Default)]
    struct Additions(bool);

    impl<'ast> Visit<'ast> for Additions {
        fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
            self.0 |= matches!(binary.op, BinOp::Add(_));
            visit::visit_expr_binary(self, binary);
        }

        fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
            self.0 |= matches!(call.method.to_string().as_str(), "checked_add" | "saturating_add" | "wrapping_add");
            visit::visit_expr_method_call(self, call);
        }
    }

    let mut found = Additions::default();
    found.visit_expr(expr);
    found.0
}

/// The amounts the method debits outside the paying loops, as the variables each amount is made of.
struct Outside<'a, 'ast> {
    loops: &'a [PayingLoop<'ast>],
    debits: Vec<BTreeSet<String>>,
}

impl<'ast> Visit<'ast> for Outside<'_, 'ast> {
    fn visit_expr_for_loop(&mut self, node: &'ast ExprForLoop) {
        if self.loops.iter().any(|paying| std::ptr::eq(paying.node, node)) {
            self.visit_expr(&node.expr);
        } else {
            visit::visit_expr_for_loop(self, node);
        }
    }

    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        visit::visit_expr_binary(self, binary);
        if matches!(binary.op, BinOp::SubAssign(_)) && !matches!(*binary.left, Expr::Path(_)) {
            self.debits.push(idents([&*binary.right]));
        }
    }

    fn visit_expr_assign(&mut self, assign: &'ast ExprAssign) {
        visit::visit_expr_assign(self, assign);
        if !matches!(*assign.left, Expr::Path(_))
            && let Some(amount) = subtracted(&assign.right)
        {
            self.debits.push(amount);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        visit::visit_expr_method_call(self, call);
        if matches!(call.method.to_string().as_str(), "insert" | "set")
            && root_name(&call.receiver).is_some_and(|root| root == "self")
        {
            self.debits.extend(call.args.iter().filter_map(subtracted));
        }
    }
}

/// Names and methods that make a list unique or check an entry against what was seen.
const UNIQUENESS: [&str; 12] = [
    "HashSet",
    "BTreeSet",
    "IndexSet",
    "UnorderedSet",
    "LookupSet",
    "TreeSet",
    "dedup",
    "dedup_by",
    "dedup_by_key",
    "windows",
    "contains",
    "contains_key",
];

/// Set when the visited code mentions any of [`UNIQUENESS`], in an expression or in macro arguments.
struct DuplicateCheck(bool);

impl<'ast> Visit<'ast> for DuplicateCheck {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        self.0 |= UNIQUENESS.contains(&ident.to_string().as_str());
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let mut names = Names::default();
        names.visit_macro(mac);
        self.0 |= names.0.iter().any(|name| UNIQUENESS.contains(&name.as_str()));
    }
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

    /// The incident's shape: every listed token is paid a share of its reserve, the shares are burned once.
    const TREASURY: &str = r#"
        #[near]
        impl Treasury {
            pub fn redeem(&mut self, shares: U128, tokens: Vec<AccountId>) {
                assert_one_yocto();
                let caller = env::predecessor_account_id();
                for token in tokens {
                    let reserve = self.reserves.get(&token).copied().unwrap_or(0);
                    let payout = reserve * shares.0 / self.total_shares;
                    ext_ft::ext(token).ft_transfer(caller.clone(), U128(payout));
                }
                self.total_shares -= shares.0;
            }
        }
    "#;

    #[test]
    fn flags_a_list_paid_per_entry_and_charged_once_and_locates_it() {
        let findings = check(TREASURY);
        assert_eq!(items(&findings), ["Treasury::redeem"]);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF014", Severity::Critical));
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 4, 20));
        assert!(finding.message.contains("list `tokens`") && finding.message.contains("using `shares`"));
    }

    #[test]
    fn flags_the_charge_before_the_loop_and_every_way_of_walking_the_list() {
        for walk in ["tokens", "&tokens", "tokens.iter()", "tokens.into_iter()", "tokens.clone()", "tokens.iter().cloned().enumerate()"] {
            let loop_header = if walk.contains("enumerate") { "for (_, token) in" } else { "for token in" };
            let source = TREASURY.replace("for token in tokens", &format!("{loop_header} {walk}"));
            assert_eq!(items(&check(&source)), ["Treasury::redeem"], "{walk}");
        }
        let before = TREASURY.replace("self.total_shares -= shares.0;", "").replace(
            "let caller",
            "self.total_shares -= shares.0; let caller",
        );
        assert_eq!(items(&check(&before)), ["Treasury::redeem"]);
    }

    #[test]
    fn flags_every_way_of_charging_and_paying() {
        for charge in [
            "self.total_shares -= shares.0;",
            "self.total_shares = self.total_shares - shares.0;",
            "self.total_shares = self.total_shares.checked_sub(shares.0).unwrap();",
            "self.holders.insert(me(), held - shares.0);",
            "*self.holders.get_mut(&me()).unwrap() -= shares.0;",
        ] {
            let source = TREASURY.replace("self.total_shares -= shares.0;", charge);
            assert_eq!(items(&check(&source)), ["Treasury::redeem"], "{charge}");
        }
        for pay in [
            "Promise::new(token).transfer(NearToken::from_yoctonear(payout));",
            "*self.owed.entry(token).or_insert(0) += payout;",
            "self.owed.insert(token.clone(), self.owed.get(&token).copied().unwrap_or(0) + payout);",
            "self.owed.set(token, old.checked_add(payout).unwrap());",
        ] {
            let source = TREASURY.replace("ext_ft::ext(token).ft_transfer(caller.clone(), U128(payout));", pay);
            assert_eq!(items(&check(&source)), ["Treasury::redeem"], "{pay}");
        }
    }

    #[test]
    fn flags_a_list_of_tuples_and_a_loop_variable_pattern() {
        let source = "#[near] impl V { pub fn claim(&mut self, units: u128, grants: Vec<(AccountId, u128)>) {
            for (to, bonus) in grants.iter() { Promise::new(to.clone()).transfer(units * bonus); }
            self.pool -= units;
        } }";
        assert_eq!(items(&check(source)), ["V::claim"]);
    }

    #[test]
    fn a_duplicate_check_anywhere_in_the_method_is_silent() {
        for guard in [
            "let unique: HashSet<_> = tokens.iter().cloned().collect(); require!(unique.len() == tokens.len());",
            "let unique: BTreeSet<AccountId> = tokens.iter().cloned().collect();",
            "let mut seen = Vec::new(); for t in &tokens { require!(!seen.contains(t)); seen.push(t.clone()); }",
            "let mut sorted = tokens.clone(); sorted.sort(); sorted.dedup(); require!(sorted.len() == tokens.len());",
            "require!(tokens.windows(2).all(|w| w[0] != w[1]));",
            "require!(!set.contains_key(&tokens[0]));",
            "let mut seen = near_sdk::store::LookupSet::new(b's');",
            "assert!(seen.contains(&caller));",
        ] {
            let source = TREASURY.replace("let caller", &format!("{guard} let caller"));
            assert!(check(&source).is_empty(), "{guard}");
        }
    }

    #[test]
    fn a_contains_check_of_any_kind_counts_even_an_allowlist() {
        let source = TREASURY.replace("let caller", "require!(self.supported.contains(&tokens[0])); let caller");
        assert!(check(&source).is_empty());
    }

    #[test]
    fn a_charge_that_scales_with_the_list_is_silent() {
        for charge in [
            "self.total_shares -= shares.0 * tokens.len() as u128;",
            "self.total_shares -= tokens.iter().map(|_| shares.0).sum::<u128>();",
            "self.total_shares = self.total_shares - tokens.len() as u128 * shares.0;",
        ] {
            let source = TREASURY.replace("self.total_shares -= shares.0;", charge);
            assert!(check(&source).is_empty(), "{charge}");
        }
    }

    #[test]
    fn a_running_total_built_in_the_loop_and_subtracted_after_it_is_silent() {
        let source = "#[near] impl V { pub fn claim(&mut self, ids: Vec<u64>, to: AccountId) {
            let mut total = 0;
            for id in ids {
                let amount = self.owed.get(&id).copied().unwrap_or(0);
                total += amount;
                Promise::new(to.clone()).transfer(amount);
            }
            self.liabilities -= total;
        } }";
        assert!(check(source).is_empty());
    }

    #[test]
    fn a_loop_that_consumes_the_entrys_state_is_silent() {
        for consume in [
            "let amount = self.owed.remove(&id).unwrap_or(0);",
            "let amount = self.pending.take(id);",
            "let amount = queue.swap_remove(id);",
        ] {
            let source = format!(
                "#[near] impl V {{ pub fn claim(&mut self, ids: Vec<u64>, to: AccountId, units: u128) {{
                    for id in ids {{ {consume} Promise::new(to.clone()).transfer(amount * units); }}
                    self.liabilities -= units;
                }} }}"
            );
            assert!(check(&source).is_empty(), "{consume}");
        }
    }

    #[test]
    fn an_overwriting_insert_is_not_a_credit() {
        let source = "#[near] impl V { pub fn airdrop(&mut self, amount: u128, accounts: Vec<AccountId>) {
            for account in accounts { self.balances.insert(account, amount); }
            self.reserve -= amount;
        } }";
        assert!(check(source).is_empty());
    }

    #[test]
    fn needs_a_charge_outside_the_loop_that_the_loop_uses() {
        let none = TREASURY.replace("self.total_shares -= shares.0;", "");
        assert!(check(&none).is_empty());
        let unrelated = TREASURY.replace("self.total_shares -= shares.0;", "self.redemptions -= 1;");
        assert!(check(&unrelated).is_empty());
        let local = TREASURY.replace("self.total_shares -= shares.0;", "let mut left = 5; left -= shares.0;");
        assert!(check(&local).is_empty());
        let inside = TREASURY.replace("self.total_shares -= shares.0;", "").replace(
            "ext_ft::ext(token)",
            "self.total_shares -= shares.0; ext_ft::ext(token)",
        );
        assert!(check(&inside).is_empty());
    }

    #[test]
    fn the_loop_must_pay_using_the_entry_and_walk_a_vec_parameter() {
        let no_entry = TREASURY.replace("ext_ft::ext(token).ft_transfer(caller.clone(), U128(payout));", "Promise::new(caller.clone()).transfer(payout);");
        assert!(check(&no_entry).is_empty());
        let not_a_param = TREASURY.replace("for token in tokens", "for token in self.listed.clone()");
        assert!(check(&not_a_param).is_empty());
        let not_a_vec = TREASURY.replace("tokens: Vec<AccountId>", "tokens: HashSet<AccountId>");
        assert!(check(&not_a_vec).is_empty());
        let reads_only = TREASURY.replace("ext_ft::ext(token).ft_transfer(caller.clone(), U128(payout));", "require!(payout > 0, \"{}\", token);");
        assert!(check(&reads_only).is_empty());
    }

    #[test]
    fn methods_the_near_macro_does_not_export_are_silent() {
        let private = TREASURY.replace("pub fn", "fn");
        assert!(check(&private).is_empty());
        let not_near = TREASURY.replace("#[near]", "");
        assert!(check(&not_near).is_empty());
        for attr in ["#[near_bindgen]", "#[near_sdk::near]", "#[near(contract_state)]"] {
            assert_eq!(items(&check(&TREASURY.replace("#[near]", attr))), ["Treasury::redeem"], "{attr}");
        }
        let in_trait = TREASURY.replace("impl Treasury", "impl Redeem for Treasury").replace("pub fn", "fn");
        assert_eq!(items(&check(&in_trait)), ["Treasury::redeem"]);
    }
}
