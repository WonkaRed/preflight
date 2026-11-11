//! PF021: a state-changing method that loops over a whole collection that users can keep growing.
//!
//! A NEAR call has a finite gas budget (`max_total_prepaid_gas`: 300 Tgas up to protocol version 83, 1000 Tgas
//! after), and every element a loop touches costs gas: storage reads, and for a payout the gas reserved for each
//! promise it creates. A method that walks a whole collection works while the
//! collection is small and fails for good once enough entries exist, and if that method is the one that pays
//! out, the funds are stuck. Entries added by anyone make the size the attacker's choice. Docs:
//! https://docs.near.org/smart-contracts/security/storage and the collections page on iteration limits.
//!
//! The rule looks at the methods the `#[near]` / `#[near_bindgen]` macro exports (`pub` methods of an inherent
//! impl, every method of a trait impl; `#[private]` and `#[init]` methods are skipped) and reports a `for` loop
//! in a `&mut self` method over a whole field of `self`: `self.f`, `&self.f` or `self.f.iter()` (also `iter_mut`,
//! `values`, `values_mut`, `keys`, `into_iter`, `drain`), followed by any of `enumerate`, `rev`, `cloned`,
//! `copied`, `filter`, `map`, `filter_map`, `skip`, `step_by`, `peekable`, `zip`, `chain`, `inspect`, `flat_map`.
//! It reports only when another exported method of the same type (or the same method) grows that field with
//! `insert`, `push`, `push_back`, `push_front`, `extend`, `append` or `entry` on `self.f`, and that method is
//! neither capped nor restricted:
//!
//! - capped: it compares `self.f.len()` with something using `<`, `<=`, `>` or `>=`, as in
//!   `require!(self.f.len() < MAX)`;
//! - restricted: it compares the caller (`env::predecessor_account_id()`, `signer_account_id()`, or a local
//!   holding it) with a field of `self` using `==`, or it calls a method of `self` named `assert_*`, `only_*`
//!   or `require_*`. Only that account can grow the collection, so its size is not the attacker's choice.
//!
//! A loop is bounded when its iterator has `take` or `take_while`: the page-at-a-time fix is not reported.
//!
//! Knowingly missed: a loop inside a helper that the exported method calls; a loop that is not a `for` (a
//! `while` over an iterator, `.iter().for_each(..)`, a terminal such as `.sum()` or `.collect()`); a collection
//! reached through a local (`let items = &self.items; for i in items`); growth through a helper; a collection
//! grown by a cap kept elsewhere (a cap in a different method, or a size limit on the entries' content).
//! Knowingly over-reported: a loop over a collection that is small by an invariant the scanner cannot see.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::Span;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Attribute, BinOp, Expr, ExprBinary, ExprForLoop, ExprMethodCall, ImplItem, ImplItemFn, ItemImpl, Local, Macro, Pat,
    Token, Visibility,
};

use super::pf007_unguarded_admin::{CALLER_FNS, field_path, is_near_attr, type_name};
use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf021UnboundedLoop;

pub static RULE: Pf021UnboundedLoop = Pf021UnboundedLoop;

impl Rule for Pf021UnboundedLoop {
    fn id(&self) -> &'static str {
        "PF021"
    }

    fn title(&self) -> &'static str {
        "Loop over a collection that users can grow without bound"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn help(&self) -> &'static str {
        "process the collection one page at a time (`.skip(from).take(limit)` with the page as arguments), or cap how many entries it can hold"
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
        // `(type, field)` -> the first exported method that adds to it for anyone to call and without a cap.
        let mut growers: BTreeMap<(&str, &str), &str> = BTreeMap::new();
        for method in scans.iter().flat_map(|scan| &scan.methods).filter(|method| method.callable_by_anyone()) {
            for field in method.grown.iter().filter(|field| !method.capped.contains(*field)) {
                growers.entry((method.owner.as_str(), field.as_str())).or_insert(method.name.as_str());
            }
        }

        let mut findings = Vec::new();
        for (file, scan) in krate.files.iter().zip(&scans) {
            for method in scan.methods.iter().filter(|method| method.mutating && !method.skipped) {
                for walk in &method.walks {
                    let Some(grower) = growers.get(&(method.owner.as_str(), walk.field.as_str())) else { continue };
                    let (owner, name, field) = (&method.owner, &method.name, &walk.field);
                    findings.push(self.finding(
                        file,
                        walk.span,
                        format!("{owner}::{name}"),
                        format!(
                            "`{owner}::{name}` loops over all of `self.{field}`, and `{grower}` lets any caller add to it \
                             with no cap, so enough entries push the loop past the gas limit and `{name}` can never succeed again"
                        ),
                    ));
                }
            }
        }
        findings
    }
}

/// An exported method and what its body does to the collections of `self`.
struct Method {
    owner: String,
    name: String,
    /// `&mut self`.
    mutating: bool,
    /// `#[private]` or `#[init]`: not something a user calls.
    skipped: bool,
    walks: Vec<Walk>,
    /// Fields of `self` that the body adds to.
    grown: BTreeSet<String>,
    /// Fields the body compares the length of with a bound.
    capped: BTreeSet<String>,
    restricted: bool,
}

impl Method {
    fn callable_by_anyone(&self) -> bool {
        !self.skipped && !self.restricted
    }
}

/// A `for` loop over every element of a field of `self`.
struct Walk {
    span: Span,
    field: String,
}

#[derive(Default)]
struct FileScan {
    methods: Vec<Method>,
}

impl<'ast> Visit<'ast> for FileScan {
    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        if item.attrs.iter().any(is_near_attr) {
            let owner = type_name(&item.self_ty);
            let is_trait_impl = item.trait_.is_some();
            for member in &item.items {
                if let ImplItem::Fn(method) = member
                    && (is_trait_impl || matches!(method.vis, Visibility::Public(_)))
                {
                    self.methods.push(analyse(&owner, method));
                }
            }
        }
        visit::visit_item_impl(self, item);
    }
}

fn has_helper_attr(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident(name))
}

fn analyse(owner: &str, method: &ImplItemFn) -> Method {
    let mut body = Body::default();
    body.visit_block(&method.block);
    Method {
        owner: owner.to_owned(),
        name: method.sig.ident.to_string(),
        mutating: method.sig.receiver().is_some_and(|receiver| receiver.reference.is_some() && receiver.mutability.is_some()),
        skipped: has_helper_attr(&method.attrs, "private") || has_helper_attr(&method.attrs, "init"),
        walks: body.walks,
        grown: body.grown,
        capped: body.capped,
        restricted: body.restricted,
    }
}

const WALKERS: [&str; 8] = ["iter", "iter_mut", "values", "values_mut", "keys", "into_iter", "drain", "into_values"];
const ADAPTERS: [&str; 14] = [
    "enumerate", "rev", "cloned", "copied", "filter", "map", "filter_map", "skip", "step_by", "peekable", "zip",
    "chain", "inspect", "flat_map",
];
const BOUNDING: [&str; 2] = ["take", "take_while"];
const GROWERS: [&str; 7] = ["insert", "push", "push_back", "push_front", "extend", "append", "entry"];
const ACCESS_HELPER_PREFIXES: [&str; 3] = ["assert_", "only_", "require_"];

fn is_one_of(name: &syn::Ident, names: &[&str]) -> bool {
    names.iter().any(|candidate| name == candidate)
}

/// The field of `self` a `for` loop walks end to end, if the iterable is one: `self.f`, `&self.f`, or
/// `self.f.iter()` with adapters that do not bound it.
fn walked_field(iterable: &Expr) -> Option<String> {
    let mut expr = iterable;
    loop {
        match expr {
            Expr::MethodCall(call) if is_one_of(&call.method, &BOUNDING) => return None,
            Expr::MethodCall(call) if is_one_of(&call.method, &ADAPTERS) => {
                expr = &call.receiver;
            }
            Expr::MethodCall(call) if is_one_of(&call.method, &WALKERS) => return field_path(&call.receiver).map(|path| path.join(".")),
            _ => return field_path(expr).map(|path| path.join(".")),
        }
    }
}

#[derive(Default)]
struct Body {
    walks: Vec<Walk>,
    grown: BTreeSet<String>,
    capped: BTreeSet<String>,
    restricted: bool,
    /// Locals bound from the caller (`let caller = env::predecessor_account_id();`).
    callers: BTreeSet<String>,
}

/// Whether an expression names the caller: `env::predecessor_account_id()`, `signer_account_id()`, or a local
/// that was bound from one.
struct MentionsCaller<'a> {
    callers: &'a BTreeSet<String>,
    found: bool,
}

impl<'ast> Visit<'ast> for MentionsCaller<'_> {
    fn visit_ident(&mut self, ident: &'ast proc_macro2::Ident) {
        self.found |= is_one_of(ident, &CALLER_FNS) || self.callers.contains(&ident.to_string());
    }
}

impl Body {
    fn mentions_caller(&self, expr: &Expr) -> bool {
        let mut mentions = MentionsCaller { callers: &self.callers, found: false };
        mentions.visit_expr(expr);
        mentions.found
    }

    /// `caller == self.owner` in either order.
    fn note_equality(&mut self, left: &Expr, right: &Expr) {
        for (caller, other) in [(left, right), (right, left)] {
            self.restricted |= self.mentions_caller(caller) && field_path(other).is_some();
        }
    }

    /// `self.f.len() < MAX` and the other three bounds, in either order.
    fn note_length_bound(&mut self, left: &Expr, right: &Expr) {
        for side in [left, right] {
            if let Expr::MethodCall(call) = side
                && call.method == "len"
                && let Some(path) = field_path(&call.receiver)
            {
                self.capped.insert(path.join("."));
            }
        }
    }
}

impl<'ast> Visit<'ast> for Body {
    fn visit_expr_for_loop(&mut self, looped: &'ast ExprForLoop) {
        if let Some(field) = walked_field(&looped.expr) {
            self.walks.push(Walk { span: looped.for_token.span, field });
        }
        visit::visit_expr_for_loop(self, looped);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if is_one_of(&call.method, &GROWERS)
            && let Some(path) = field_path(&call.receiver)
        {
            self.grown.insert(path.join("."));
        }
        if matches!(&*call.receiver, Expr::Path(path) if path.path.is_ident("self"))
            && ACCESS_HELPER_PREFIXES.iter().any(|prefix| call.method.to_string().starts_with(prefix))
        {
            self.restricted = true;
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        match binary.op {
            BinOp::Eq(_) => self.note_equality(&binary.left, &binary.right),
            BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_) => self.note_length_bound(&binary.left, &binary.right),
            _ => {}
        }
        visit::visit_expr_binary(self, binary);
    }

    fn visit_local(&mut self, local: &'ast Local) {
        if let (Pat::Ident(name), Some(init)) = (&local.pat, &local.init)
            && self.mentions_caller(&init.expr)
        {
            self.callers.insert(name.ident.to_string());
        }
        visit::visit_local(self, local);
    }

    /// `require!(a == b, ..)` and `assert_eq!(a, b)`: read the arguments as expressions when they parse as such.
    fn visit_macro(&mut self, mac: &'ast Macro) {
        let Ok(args) = mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated) else { return };
        if mac.path.is_ident("assert_eq") && args.len() >= 2 {
            self.note_equality(&args[0], &args[1]);
        }
        args.iter().for_each(|arg| self.visit_expr(arg));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(sources: &[(&str, &str)]) -> Vec<Finding> {
        RULE.check(&Crate::from_sources(sources.iter().copied()).unwrap())
    }

    fn items(source: &str) -> Vec<String> {
        check(&[("src/lib.rs", source)]).into_iter().map(|finding| finding.item).collect()
    }

    /// A pool whose `join` lets anyone add to `self.members` and whose `pay_all` is `loop_method`'s body.
    fn pool(extra_methods: &str) -> String {
        format!(
            "#[near] impl Pool {{
                #[payable] pub fn join(&mut self) {{ self.members.insert(env::predecessor_account_id(), 1); }}
                {extra_methods}
            }}"
        )
    }

    #[test]
    fn flags_a_payout_loop_over_a_collection_anyone_can_join() {
        let source = pool("pub fn pay_all(&mut self) { for (id, stake) in self.members.iter() { pay(id, stake); } }");
        let findings = check(&[("src/lib.rs", &source)]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].item, "Pool::pay_all");
        assert!(findings[0].message.contains("loops over all of `self.members`, and `join` lets any caller add to it"), "{}", findings[0].message);
    }

    #[test]
    fn flags_every_way_of_walking_the_whole_collection() {
        for iterable in [
            "&self.members",
            "&mut self.members",
            "self.members.clone()",
            "self.members.iter_mut()",
            "self.members.values()",
            "self.members.keys()",
            "self.members.drain()",
            "self.members.iter().enumerate()",
            "self.members.iter().rev().cloned()",
            "self.members.iter().skip(2)",
            "self.members.iter().filter(|m| m.1 > 0).map(|m| m.0)",
        ] {
            let source = pool(&format!("pub fn pay_all(&mut self) {{ for m in {iterable} {{ pay(m); }} }}"));
            assert_eq!(items(&source), ["Pool::pay_all"], "{iterable}");
        }
    }

    #[test]
    fn flags_every_way_of_growing_the_collection() {
        for grow in [
            "self.members.push(x);",
            "self.members.push_back(x);",
            "self.members.extend(xs);",
            "self.members.entry(x).or_insert(0);",
            "self.members.insert(x, 1);",
        ] {
            let source = format!(
                "#[near] impl Pool {{ pub fn join(&mut self, x: u64) {{ {grow} }}
                    pub fn pay_all(&mut self) {{ for m in self.members.iter() {{ pay(m); }} }} }}"
            );
            assert_eq!(items(&source), ["Pool::pay_all"], "{grow}");
        }
    }

    #[test]
    fn accepts_near_bindgen_a_trait_impl_a_nested_field_and_another_file() {
        let growth = "#[near_bindgen] impl Receiver for Pool { fn ft_on_transfer(&mut self, x: u64) { self.state.members.push(x); } }";
        let walk = "#[near_sdk::near] impl Pool { pub fn pay_all(&mut self) { for m in self.state.members.iter() { pay(m); } } }";
        let findings = check(&[("src/lib.rs", walk), ("src/receiver.rs", growth)]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].item, "Pool::pay_all");
        assert!(findings[0].message.contains("`self.state.members`"), "{}", findings[0].message);
    }

    #[test]
    fn a_method_that_grows_and_loops_is_reported() {
        let source = "#[near] impl Pool { pub fn join(&mut self, x: u64) { self.members.push(x); for m in self.members.iter() { notify(m); } } }";
        assert_eq!(items(source), ["Pool::join"]);
    }

    #[test]
    fn a_page_at_a_time_loop_is_bounded() {
        for iterable in [
            "self.members.iter().take(10)",
            "self.members.iter().skip(from).take(limit)",
            "self.members.iter().take_while(|m| m.0 < end)",
            "self.members.iter().enumerate().take(5)",
        ] {
            let source = pool(&format!("pub fn pay_all(&mut self, from: usize, limit: usize) {{ for m in {iterable} {{ pay(m); }} }}"));
            assert!(items(&source).is_empty(), "{iterable}");
        }
    }

    #[test]
    fn only_loops_in_exported_state_changing_methods_count() {
        for method in [
            "pub fn all(&self) { for m in self.members.iter() { show(m); } }",
            "#[private] pub fn pay_all(&mut self) { for m in self.members.iter() { pay(m); } }",
            "fn pay_all(&mut self) { for m in self.members.iter() { pay(m); } }",
            "pub(crate) fn pay_all(&mut self) { for m in self.members.iter() { pay(m); } }",
            "pub fn pay_all(self) { for m in self.members.iter() { pay(m); } }",
        ] {
            assert!(items(&pool(method)).is_empty(), "{method}");
        }
        let plain = "impl Pool { pub fn join(&mut self) { self.members.push(1); } pub fn pay_all(&mut self) { for m in self.members.iter() {} } }";
        assert!(items(plain).is_empty(), "an impl without #[near] exports nothing");
    }

    #[test]
    fn a_collection_nobody_can_grow_is_not_reported() {
        let loops = "#[near] impl Pool { pub fn pay_all(&mut self) { for m in self.members.iter() { pay(m); } } }";
        assert!(items(loops).is_empty());
        for growth in [
            "#[private] pub fn add(&mut self, x: u64) { self.members.push(x); }",
            "#[init] pub fn new() -> Self { let mut s = Self::default(); s.members.push(1); s }",
            "pub fn rename(&mut self, x: u64) { self.names.push(x); }",
            "pub fn forget(&mut self, x: u64) { self.members.remove(&x); self.members.set(0, x); }",
        ] {
            let source = format!("#[near] impl Pool {{ {growth} pub fn pay_all(&mut self) {{ for m in self.members.iter() {{ pay(m); }} }} }}");
            assert!(items(&source).is_empty(), "{growth}");
        }
    }

    #[test]
    fn growth_only_the_owner_can_do_is_not_attacker_sized() {
        for restriction in [
            "require!(env::predecessor_account_id() == self.owner_id);",
            "assert!(self.owner_id == env::signer_account_id());",
            "assert_eq!(self.owner_id, env::predecessor_account_id());",
            "let caller = env::predecessor_account_id(); if caller == self.owner_id {} else { env::panic_str(\"no\") }",
            "self.assert_owner();",
            "self.only_admin();",
            "self.require_role(1);",
        ] {
            let source = format!(
                "#[near] impl Pool {{ pub fn add(&mut self, x: u64) {{ {restriction} self.members.push(x); }}
                    pub fn pay_all(&mut self) {{ for m in self.members.iter() {{ pay(m); }} }} }}"
            );
            assert!(items(&source).is_empty(), "{restriction}");
        }
    }

    #[test]
    fn a_check_that_does_not_restrict_the_caller_to_one_account_does_not_count() {
        for check in [
            "require!(env::predecessor_account_id() != self.banned);",
            "require!(self.allowed.contains(&env::predecessor_account_id()));",
            "require!(x == self.limit);",
            "let id = env::predecessor_account_id();",
        ] {
            let source = format!(
                "#[near] impl Pool {{ pub fn add(&mut self, x: u64) {{ {check} self.members.push(x); }}
                    pub fn pay_all(&mut self) {{ for m in self.members.iter() {{ pay(m); }} }} }}"
            );
            assert_eq!(items(&source), ["Pool::pay_all"], "{check}");
        }
    }

    #[test]
    fn a_cap_on_the_length_stops_the_growth_from_counting() {
        for cap in [
            "require!(self.members.len() < MAX_MEMBERS, \"full\");",
            "assert!(MAX_MEMBERS > self.members.len());",
            "if self.members.len() >= 100 { env::panic_str(\"full\"); }",
        ] {
            let source = format!(
                "#[near] impl Pool {{ pub fn add(&mut self, x: u64) {{ {cap} self.members.push(x); }}
                    pub fn pay_all(&mut self) {{ for m in self.members.iter() {{ pay(m); }} }} }}"
            );
            assert!(items(&source).is_empty(), "{cap}");
        }
    }

    #[test]
    fn a_cap_on_another_collection_does_not_count() {
        let source = "#[near] impl Pool { pub fn add(&mut self, x: u64) { require!(self.other.len() < 5); self.members.push(x); }
            pub fn pay_all(&mut self) { for m in self.members.iter() { pay(m); } } }";
        assert_eq!(items(source), ["Pool::pay_all"]);
    }

    #[test]
    fn loops_that_do_not_walk_a_whole_field_of_self_are_not_reported() {
        for walk in [
            "for m in members.iter() {}",
            "for m in self.members.range(a..b) {}",
            "for i in 0..10 {}",
            "for m in self.members.get(&k).unwrap().iter() {}",
            "for m in self.members.iter().map(|m| m).collect::<Vec<_>>().iter().take(3) {}",
        ] {
            let source = pool(&format!("pub fn pay_all(&mut self, members: Vec<u64>) {{ {walk} }}"));
            assert!(items(&source).is_empty(), "{walk}");
        }
    }

    #[test]
    fn growth_in_another_type_does_not_count() {
        let source = "#[near] impl Other { pub fn join(&mut self) { self.members.push(1); } }
            #[near] impl Pool { pub fn pay_all(&mut self) { for m in self.members.iter() { pay(m); } } }";
        assert!(items(source).is_empty());
    }

    #[test]
    fn reports_each_loop() {
        let source = pool("pub fn a(&mut self) { for m in self.members.iter() {} for m in self.members.keys() {} }");
        assert_eq!(items(&source), ["Pool::a", "Pool::a"]);
    }
}
