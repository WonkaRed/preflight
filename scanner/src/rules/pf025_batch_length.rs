//! PF025: a batch method that walks two caller-supplied lists together without checking they have the same length.
//!
//! A batch method takes parallel lists (`token_ids` and `amounts`, `recipients` and `shares`) and pairs them up.
//! `a.iter().zip(b.iter())` stops at the shorter list, so a caller who passes lists of different lengths makes the
//! method act on fewer pairs than the lists suggest, while anything computed from a whole list (a sum, a payout)
//! still counts the extra entries. NEP-245 requires the batch methods to panic when the lengths differ
//! (https://github.com/near/NEPs/blob/master/neps/nep-0245.md: `mt_batch_transfer`, `mt_batch_transfer_call`).
//!
//! The rule looks at the methods the `#[near]` / `#[near_bindgen]` macro exports (`pub` methods of an inherent
//! impl, every method of a trait impl) that take `&mut self` and are not `#[private]`, and finds two parameters of
//! type `Vec<..>` or a slice (also behind `&`) that the method pairs up in either of two ways:
//! - `a.zip(b)` where the receiver chain starts at one parameter and the argument is the other (`a.iter()
//!   .zip(b.iter())`, `a.into_iter().zip(&b)`, `a.iter().enumerate().zip(b)`, also `std::iter::zip(a, b)`); the
//!   adapters walked through are `iter`, `into_iter`, `iter_mut`, `cloned`, `copied`, `rev`, `enumerate`, `map` and
//!   `zip`, and the argument may carry `&` or `.clone()`;
//! - `for i in 0..a.len()` (also `0..n` after `let n = a.len();`) whose body indexes another parameter with the
//!   same variable, `b[i]`.
//!
//! The pair is reported unless the method compares the lengths of the two lists with `==` or `!=` (also in
//! `assert_eq!`, `assert_ne!`, `require!` and `if`), directly or through a local bound to `a.len()`, or through
//! a chain of such comparisons (`a.len() == b.len()` and `b.len() == c.len()` cover the pair `a`, `c`). A
//! same-crate function the method reaches, found by name, that compares the lengths of any two things is trusted
//! as the check for every pair.
//!
//! Knowingly missed: lists that are not `Vec` or slices (`Option<Vec<..>>`, a struct that holds them); a length
//! check that is not an equality (`a.len() >= b.len()` lets the longer one through); lists walked with
//! `zip_eq`-like adapters, `windows` or a `while` loop; a list indexed with `get(i)`; two lists compared against
//! the same constant instead of each other (`a.len() == 3 && b.len() == 3` is reported); a method that pairs a
//! list with a field of `self`, which has no caller-chosen length to mismatch. Knowingly noisy: a batch method
//! that really does want to stop at the shorter list, and one whose lengths are checked by a function the rule
//! cannot resolve by name.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::Span;
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    BinOp, Expr, ExprBinary, ExprCall, ExprForLoop, ExprIndex, ExprMethodCall, ExprRange, FnArg, ImplItemFn, ItemFn,
    ItemImpl, Local, Macro, Signature, Token, TraitItemFn, Type, Visibility,
};

use super::pf007_unguarded_admin::{CallRef, bound_ident, call_ref, is_call_to, is_near_attr, peel, type_name};
use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf025BatchLength;

pub static RULE: Pf025BatchLength = Pf025BatchLength;

impl Rule for Pf025BatchLength {
    fn id(&self) -> &'static str {
        "PF025"
    }

    fn title(&self) -> &'static str {
        "Batch method does not check its lists have the same length"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn help(&self) -> &'static str {
        "require the two lists to have the same length at the top of the method, as NEP-245 does for its batch methods"
    }

    fn check(&self, krate: &Crate) -> Vec<Finding> {
        let mut collector = Collector::default();
        for (index, file) in krate.files.iter().enumerate() {
            collector.file = index;
            collector.visit_file(&file.ast);
        }
        let fns = collector.fns;

        let mut findings = Vec::new();
        for (id, function) in fns.iter().enumerate() {
            let Some(export) = &function.export else { continue };
            if !export.mut_self || export.private {
                continue;
            }
            if reachable(&fns, id).into_iter().any(|reached| reached != id && fns[reached].compares_lengths) {
                continue;
            }
            let Some(pair) = function.pairs.iter().find(|pair| !function.lengths_equal(&pair.first, &pair.second))
            else {
                continue;
            };
            let item = format!("{}::{}", function.owner.as_deref().unwrap_or_default(), function.name);
            let (first, second) = (&pair.first, &pair.second);
            let message = format!(
                "`{item}` walks `{first}` and `{second}` together with `{}` but never checks that `{first}.len() == \
                 {second}.len()`, so a caller can pass lists of different lengths and the longer one is silently cut off",
                pair.how
            );
            findings.push(self.finding(&krate.files[function.file], export.span, item, message));
        }
        findings
    }
}

/// Adapters that keep one item per element, so a chain made of them starts at the list it walks.
const ELEMENT_WISE: [&str; 9] = ["iter", "into_iter", "iter_mut", "cloned", "copied", "rev", "enumerate", "map", "zip"];

struct Export {
    span: Span,
    private: bool,
    mut_self: bool,
}

/// Two parameters walked together.
struct Pair {
    first: String,
    second: String,
    /// What pairs them, for the message: `.zip(..)` or `a[i]` and `b[i]`.
    how: &'static str,
}

#[derive(Default)]
struct FnFacts {
    file: usize,
    name: String,
    owner: Option<String>,
    has_receiver: bool,
    export: Option<Export>,
    calls: Vec<CallRef>,
    pairs: Vec<Pair>,
    /// Names whose lengths a comparison in this function sets equal.
    equal_lengths: Vec<(String, String)>,
    /// Compares the lengths of two things with `==` or `!=`, whichever they are.
    compares_lengths: bool,
}

impl FnFacts {
    /// Whether a chain of length comparisons ties `first` to `second`.
    fn lengths_equal(&self, first: &str, second: &str) -> bool {
        let mut reached = BTreeSet::from([first]);
        let mut grew = true;
        while grew {
            grew = false;
            for (left, right) in &self.equal_lengths {
                for (known, other) in [(left, right), (right, left)] {
                    if reached.contains(known.as_str()) {
                        grew |= reached.insert(other.as_str());
                    }
                }
            }
        }
        reached.contains(second)
    }
}

#[derive(Default)]
struct Frame {
    facts: FnFacts,
    /// Parameters of type `Vec<..>` or a slice.
    lists: BTreeSet<String>,
    /// Locals bound to `<name>.len()`, mapped to that name.
    length_locals: BTreeMap<String, String>,
}

impl Frame {
    /// The list parameter `expr` walks: `a`, `&a`, `a.clone()`, or a chain of element-wise adapters on one.
    fn list_of(&self, expr: &Expr) -> Option<String> {
        let mut expr = peel(expr);
        while let Expr::MethodCall(call) = expr {
            if !ELEMENT_WISE.iter().any(|adapter| call.method == adapter) {
                return None;
            }
            expr = peel(&call.receiver);
        }
        let Expr::Path(path) = expr else { return None };
        path.path.get_ident().map(ToString::to_string).filter(|name| self.lists.contains(name))
    }

    /// The name whose length `expr` is: `a.len()`, or a local bound to it.
    fn length_of(&self, expr: &Expr) -> Option<String> {
        match peel(expr) {
            Expr::MethodCall(call) if call.method == "len" && call.args.is_empty() => match peel(&call.receiver) {
                Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
                _ => None,
            },
            Expr::Path(path) => {
                path.path.get_ident().and_then(|name| self.length_locals.get(&name.to_string())).cloned()
            }
            _ => None,
        }
    }

    fn compare_lengths(&mut self, left: &Expr, right: &Expr) {
        if let (Some(left), Some(right)) = (self.length_of(left), self.length_of(right)) {
            self.facts.compares_lengths = true;
            self.facts.equal_lengths.push((left, right));
        }
    }

    fn pair(&mut self, first: Option<String>, second: Option<String>, how: &'static str) {
        if let (Some(first), Some(second)) = (first, second)
            && first != second
        {
            self.facts.pairs.push(Pair { first, second, how });
        }
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
    fn begin_fn(&mut self, sig: &Signature, attrs: &[syn::Attribute], exported: bool) {
        let lists = sig
            .inputs
            .iter()
            .filter_map(|arg| match arg {
                FnArg::Typed(arg) if is_list(&arg.ty) => bound_ident(&arg.pat),
                _ => None,
            })
            .collect();
        let export = exported.then(|| Export {
            span: sig.ident.span(),
            private: attrs.iter().any(|attr| attr.path().is_ident("private")),
            mut_self: sig
                .receiver()
                .is_some_and(|receiver| receiver.reference.is_some() && receiver.mutability.is_some()),
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
            lists,
            ..Frame::default()
        });
    }

    fn end_fn(&mut self) {
        if let Some(frame) = self.frames.pop() {
            self.fns.push(frame.facts);
        }
    }

    /// Runs `walk` over a free or trait function, which is never in an impl even when nested inside one.
    fn in_free_fn(&mut self, sig: &Signature, attrs: &[syn::Attribute], walk: impl FnOnce(&mut Self)) {
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
        if let (Some(init), Some(name), Some(frame)) = (&local.init, bound_ident(&local.pat), self.frames.last_mut())
            && let Some(list) = frame.length_of(&init.expr)
        {
            frame.length_locals.insert(name, list);
        }
        visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let (Expr::Path(func), Some(frame)) = (&*call.func, self.frames.last_mut()) {
            let segments: Vec<String> = func.path.segments.iter().map(|segment| segment.ident.to_string()).collect();
            frame
                .facts
                .calls
                .extend(call_ref(&segments, self.impl_context.as_ref().map(|context| context.owner.as_str())));
            if is_call_to(call, &["zip"]) && call.args.len() == 2 {
                frame.pair(frame.list_of(&call.args[0]), frame.list_of(&call.args[1]), "zip");
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if let Some(frame) = self.frames.last_mut() {
            frame.facts.calls.push(CallRef::Method(call.method.to_string()));
            if call.method == "zip"
                && let [argument] = call.args.iter().collect::<Vec<_>>()[..]
            {
                frame.pair(frame.list_of(&call.receiver), frame.list_of(argument), ".zip(..)");
            }
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        if let (BinOp::Eq(_) | BinOp::Ne(_), Some(frame)) = (&binary.op, self.frames.last_mut()) {
            frame.compare_lengths(&binary.left, &binary.right);
        }
        visit::visit_expr_binary(self, binary);
    }

    fn visit_expr_for_loop(&mut self, looped: &'ast ExprForLoop) {
        if let (Some(index), Some(frame)) = (bound_ident(&looped.pat), self.frames.last_mut())
            && let Expr::Range(ExprRange { end: Some(end), .. }) = peel(&looped.expr)
            && let Some(bound) = frame.length_of(end)
            && frame.lists.contains(&bound)
        {
            let mut indexed = Indexed { index: &index, lists: &frame.lists, found: BTreeSet::new() };
            indexed.visit_block(&looped.body);
            let found = indexed.found;
            for other in found {
                frame.pair(Some(bound.clone()), Some(other), "an index loop");
            }
        }
        visit::visit_expr_for_loop(self, looped);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        let Some(name) = mac.path.segments.last().map(|segment| segment.ident.to_string()) else { return };
        // `require!`, `assert!`, `assert_eq!` ... take comma-separated expressions: parse and walk them.
        let Ok(arguments) = Punctuated::<Expr, Token![,]>::parse_terminated.parse2(mac.tokens.clone()) else { return };
        if let (Some(frame), "assert_eq" | "assert_ne" | "debug_assert_eq" | "debug_assert_ne", [left, right, ..]) =
            (self.frames.last_mut(), name.as_str(), &arguments.iter().collect::<Vec<_>>()[..])
        {
            frame.compare_lengths(left, right);
        }
        for argument in &arguments {
            self.visit_expr(argument);
        }
    }
}

/// The list parameters indexed with the loop variable in a loop body: `b[i]`.
struct Indexed<'a> {
    index: &'a str,
    lists: &'a BTreeSet<String>,
    found: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for Indexed<'_> {
    fn visit_expr_index(&mut self, indexed: &'ast ExprIndex) {
        if let (Expr::Path(list), Expr::Path(index)) = (peel(&indexed.expr), peel(&indexed.index))
            && index.path.is_ident(self.index)
            && let Some(name) = list.path.get_ident().map(ToString::to_string)
            && self.lists.contains(&name)
        {
            self.found.insert(name);
        }
        visit::visit_expr_index(self, indexed);
    }
}

/// Whether `ty` is a `Vec<..>` or a slice, possibly behind a reference.
fn is_list(ty: &Type) -> bool {
    match ty {
        Type::Reference(reference) => is_list(&reference.elem),
        Type::Paren(paren) => is_list(&paren.elem),
        Type::Slice(_) => true,
        Type::Path(path) => path.path.segments.last().is_some_and(|segment| segment.ident == "Vec"),
        _ => false,
    }
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

    /// A batch method with the given body, in a `#[near]` impl.
    fn batch(body: &str) -> String {
        format!("#[near] impl Shop {{ pub fn redeem(&mut self, ids: Vec<u64>, amounts: Vec<U128>) {{ {body} }} }}")
    }

    #[test]
    fn flags_a_zip_of_two_parameters_and_locates_it() {
        let source = "#[near]\nimpl Shop {\n    pub fn redeem(&mut self, ids: Vec<u64>, amounts: Vec<U128>) {\n        \
                      for (id, amount) in ids.iter().zip(amounts.iter()) { self.pay(id, amount); }\n    }\n}";
        let findings = check(&[("src/lib.rs", source)]);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF025", Severity::Medium));
        assert_eq!(finding.item, "Shop::redeem");
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 3, 12));
        assert!(
            finding.message.contains("`ids` and `amounts`") && finding.message.contains("`.zip(..)`"),
            "{}",
            finding.message
        );
    }

    #[test]
    fn accepts_near_bindgen_path_qualified_near_and_trait_impls() {
        let body = "for (id, a) in ids.iter().zip(amounts.iter()) { self.pay(id, a); }";
        let inherent = |attr: &str| {
            format!("{attr} impl Shop {{ pub fn redeem(&mut self, ids: Vec<u64>, amounts: Vec<U128>) {{ {body} }} }}")
        };
        for attr in ["#[near_bindgen]", "#[near_sdk::near]", "#[near(contract_state)]"] {
            assert_eq!(items(&inherent(attr)), ["Shop::redeem"], "{attr}");
        }
        let trait_impl = format!(
            "#[near] impl Batch for Shop {{ fn redeem(&mut self, ids: Vec<u64>, amounts: Vec<U128>) {{ {body} }} }}"
        );
        assert_eq!(items(&trait_impl), ["Shop::redeem"]);
    }

    #[test]
    fn flags_every_way_of_walking_two_lists_together() {
        let walks = [
            "for (id, a) in ids.iter().zip(amounts.iter()) { self.pay(id, a); }",
            "for (id, a) in ids.iter().zip(&amounts) { self.pay(id, a); }",
            "for (id, a) in ids.into_iter().zip(amounts) { self.pay(id, a); }",
            "for (id, a) in ids.iter().zip(amounts.clone()) { self.pay(id, a); }",
            "for ((n, id), a) in ids.iter().enumerate().zip(amounts.iter()) { self.pay(id, a); }",
            "for (id, a) in ids.iter().rev().zip(amounts.iter().rev()) { self.pay(id, a); }",
            "let pairs: Vec<_> = ids.iter().zip(amounts.iter()).map(|(i, a)| (*i, a.0)).collect();",
            "let total: u128 = ids.iter().zip(amounts.iter()).map(|(_, a)| a.0).sum();",
            "for (id, a) in std::iter::zip(ids, amounts) { self.pay(id, a); }",
            "for i in 0..ids.len() { self.pay(ids[i], amounts[i]); }",
            "for i in 0..ids.len() { self.pay(ids[i], &amounts[i]); }",
            "let n = ids.len(); for i in 0..n { self.pay(ids[i], amounts[i]); }",
            "for i in 0..amounts.len() { self.pay(ids[i], amounts[i]); }",
            "for i in 0..ids.len() { self.pay(0, amounts[i]); }",
        ];
        for walk in walks {
            assert_eq!(items(&batch(walk)), ["Shop::redeem"], "{walk}");
        }
    }

    #[test]
    fn flags_slice_parameters_and_references_to_lists() {
        for types in ["&[u64], amounts: &[U128]", "&Vec<u64>, amounts: &Vec<U128>", "Vec<u64>, amounts: &[U128]"] {
            let source = format!(
                "#[near] impl Shop {{ pub fn redeem(&mut self, ids: {types}) {{ for (id, a) in ids.iter().zip(amounts.iter()) {{}} }} }}"
            );
            assert_eq!(items(&source), ["Shop::redeem"], "{types}");
        }
    }

    #[test]
    fn a_third_list_is_checked_against_the_first_through_the_second() {
        let signature = "pub fn redeem(&mut self, ids: Vec<u64>, amounts: Vec<U128>, memos: Vec<String>)";
        let walk = "for ((id, a), m) in ids.iter().zip(amounts.iter()).zip(memos.iter()) {}";
        let source = |check: &str| format!("#[near] impl Shop {{ {signature} {{ {check} {walk} }} }}");
        assert_eq!(items(&source("require!(ids.len() == amounts.len());")), ["Shop::redeem"]);
        assert!(items(&source("require!(ids.len() == amounts.len() && amounts.len() == memos.len());")).is_empty());
    }

    #[test]
    fn a_length_comparison_in_any_form_makes_the_method_clean() {
        let checks = [
            "require!(ids.len() == amounts.len());",
            "require!(amounts.len() == ids.len(), \"lists differ\");",
            "assert_eq!(ids.len(), amounts.len());",
            "assert_ne!(ids.len(), amounts.len() + 1); assert_eq!(amounts.len(), ids.len());",
            "debug_assert_eq!(ids.len(), amounts.len());",
            "assert!(ids.len() == amounts.len());",
            "if ids.len() != amounts.len() { env::panic_str(\"lists differ\"); }",
            "if amounts.len() != ids.len() { panic!(\"lists differ\"); }",
            "let n = ids.len(); require!(amounts.len() == n);",
            "let n = amounts.len(); require!(n == ids.len());",
            "let a = ids.len(); let b = amounts.len(); require!(a == b);",
            "require!((ids.len()) == (&amounts).len());",
        ];
        for check in checks {
            let source =
                batch(&format!("{check} for (id, a) in ids.iter().zip(amounts.iter()) {{ self.pay(id, a); }}"));
            assert!(items(&source).is_empty(), "{check}");
        }
    }

    #[test]
    fn a_check_that_is_not_an_equality_of_the_two_lengths_does_not_count() {
        let checks = [
            "require!(ids.len() >= amounts.len());",
            "require!(ids.len() <= 10 && amounts.len() <= 10);",
            "require!(ids.len() == 3 && amounts.len() == 3);",
            "require!(ids.len() != 0);",
            "require!(ids.len() == ids.len());",
        ];
        for check in checks {
            let source =
                batch(&format!("{check} for (id, a) in ids.iter().zip(amounts.iter()) {{ self.pay(id, a); }}"));
            assert_eq!(items(&source), ["Shop::redeem"], "{check}");
        }
    }

    #[test]
    fn a_same_crate_helper_that_compares_two_lengths_is_trusted() {
        let source = "#[near] impl Shop {
            pub fn redeem(&mut self, ids: Vec<u64>, amounts: Vec<U128>) {
                self.validate(&ids, &amounts);
                for (id, a) in ids.iter().zip(amounts.iter()) { self.pay(id, a); }
            }
        }
        impl Shop { fn validate(&self, ids: &[u64], amounts: &[U128]) { require!(ids.len() == amounts.len()); } }";
        assert!(items(source).is_empty());
        let free = "#[near] impl Shop {
            pub fn redeem(&mut self, ids: Vec<u64>, amounts: Vec<U128>) {
                same_length(&ids, &amounts);
                for (id, a) in ids.iter().zip(amounts.iter()) { self.pay(id, a); }
            }
        }
        fn same_length(a: &[u64], b: &[U128]) { if a.len() != b.len() { env::panic_str(\"lists differ\"); } }";
        assert!(items(free).is_empty());
    }

    #[test]
    fn a_helper_that_never_compares_lengths_does_not_hide_the_bug() {
        let source = "#[near] impl Shop {
            pub fn redeem(&mut self, ids: Vec<u64>, amounts: Vec<U128>) {
                self.validate(&ids);
                for (id, a) in ids.iter().zip(amounts.iter()) { self.pay(id, a); }
            }
        }
        impl Shop { fn validate(&self, ids: &[u64]) { require!(ids.len() < 100); } }";
        assert_eq!(items(source), ["Shop::redeem"]);
    }

    #[test]
    fn pairing_a_list_with_something_that_is_not_a_second_list_is_clean() {
        let bodies = [
            "for (id, a) in ids.iter().zip(self.prices.iter()) {}",
            "let local = vec![1u8]; for (id, a) in ids.iter().zip(local.iter()) {}",
            "for (id, a) in ids.iter().zip(ids.iter()) {}",
            "for (n, id) in ids.iter().enumerate() { self.pay(id, &amounts[0]); }",
            "for i in 0..ids.len() { self.pay(ids[i], 0); }",
            "for i in 0..ids.len() { self.pay(ids[i], amounts[0]); }",
            "for i in 0..self.items.len() { self.pay(ids[i], amounts[i]); }",
            "for i in 0..3 { self.pay(ids[i], amounts[i]); }",
            "for j in 0..ids.len() { let i = 0; self.pay(ids[j], amounts[i]); }",
            "for (id, a) in ids.iter().take(2).zip(amounts.iter()) {}",
            "for (id, a) in ids.iter().zip(amounts.iter().skip(1)) {}",
            "for id in ids.iter() {} for a in amounts.iter() {}",
        ];
        for body in bodies {
            assert!(items(&batch(body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn only_lists_count_not_other_parameter_types() {
        let source = "#[near] impl Shop {
            pub fn redeem(&mut self, ids: Vec<u64>, amounts: Option<Vec<U128>>, pair: (u8, u8), map: HashMap<u8, u8>) {
                for (id, a) in ids.iter().zip(amounts.iter()) {}
                for (id, a) in ids.iter().zip(map.iter()) {}
            }
        }";
        assert!(items(source).is_empty());
    }

    #[test]
    fn view_private_internal_and_unexported_methods_are_clean() {
        let zip = "for (id, a) in ids.iter().zip(amounts.iter()) {}";
        let view =
            format!("#[near] impl Shop {{ pub fn quote(&self, ids: Vec<u64>, amounts: Vec<U128>) {{ {zip} }} }}");
        let private = format!(
            "#[near] impl Shop {{ #[private] pub fn on_done(&mut self, ids: Vec<u64>, amounts: Vec<U128>) {{ {zip} }} }}"
        );
        let internal =
            format!("#[near] impl Shop {{ fn redeem(&mut self, ids: Vec<u64>, amounts: Vec<U128>) {{ {zip} }} }}");
        let crate_only = format!(
            "#[near] impl Shop {{ pub(crate) fn redeem(&mut self, ids: Vec<u64>, amounts: Vec<U128>) {{ {zip} }} }}"
        );
        let plain_impl =
            format!("impl Shop {{ pub fn redeem(&mut self, ids: Vec<u64>, amounts: Vec<U128>) {{ {zip} }} }}");
        let free = format!("pub fn redeem(ids: Vec<u64>, amounts: Vec<U128>) {{ {zip} }}");
        for (name, source) in [
            ("view", view),
            ("private", private),
            ("internal", internal),
            ("crate_only", crate_only),
            ("plain_impl", plain_impl),
            ("free", free),
        ] {
            assert!(items(&source).is_empty(), "{name}");
        }
    }

    #[test]
    fn checks_the_exported_method_even_when_the_zip_is_in_a_closure() {
        let source =
            batch("let total: u128 = ids.iter().zip(amounts.iter()).map(|(_, a)| a.0).sum(); self.total = total;");
        assert_eq!(items(&source), ["Shop::redeem"]);
    }

    #[test]
    fn reports_one_finding_per_method_across_files() {
        let one = "#[near] impl Shop { pub fn redeem(&mut self, ids: Vec<u64>, amounts: Vec<U128>) {
            for (id, a) in ids.iter().zip(amounts.iter()) {} for i in 0..ids.len() { amounts[i]; } } }";
        let other = "#[near] impl Vault { pub fn drain(&mut self, owners: Vec<AccountId>, shares: Vec<u16>) {
            for (o, s) in owners.iter().zip(shares.iter()) {} } }";
        let findings = check(&[("src/lib.rs", one), ("src/vault.rs", other)]);
        let located: Vec<_> = findings.iter().map(|finding| (finding.file.as_str(), finding.item.as_str())).collect();
        assert_eq!(located, [("src/lib.rs", "Shop::redeem"), ("src/vault.rs", "Vault::drain")]);
    }
}
