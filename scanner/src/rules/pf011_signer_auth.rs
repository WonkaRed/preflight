//! PF011: an authorization check made with `env::signer_account_id()`.
//!
//! `signer_account_id()` is the account that signed the transaction; `predecessor_account_id()` is the account
//! that called this method. They differ as soon as a contract sits in between: if the owner signs a call to a
//! malicious contract, that contract calls the vault, and a vault that compares the signer to its owner sees the
//! owner. NEAR's name for the Ethereum `tx.origin` mistake.
//! Docs: https://docs.near.org/smart-contracts/security/checklist and
//! https://sigmaprime.io/blog/near-accounts-and-access-control/
//!
//! A function is reported when it uses the signer in an access check, once, at the first such check:
//! - as an operand of `==` or `!=`, or of `.eq(..)` / `.ne(..)`, or an argument of `assert_eq!` / `assert_ne!`
//!   (the signer may be wrapped in `&`, `.clone()` or `.as_str()`);
//! - as the argument of `.contains(..)` or `.contains_key(..)`, an allowlist or owner-set membership test;
//! - in any of those through a local bound to the signer in the same function (`let who = env::signer_account_id();`
//!   then `who == self.owner`).
//!
//! Silent when the same function also mentions `predecessor_account_id`, which covers both the safe idiom
//! `signer == predecessor` (a direct-call check) and code that really wants the transaction's origin. Test code
//! (`#[cfg(test)]` items and `#[test]` functions) is skipped. The checks inside `require!`, `assert!`,
//! `assert_eq!` and their `debug_` forms are found by parsing the macro's arguments.
//!
//! Knowingly missed: the signer used as a storage key for balances (`self.balances.get(&signer)`) or passed to a
//! helper that compares it; a comparison written through a method other than the ones above; a check in one
//! function whose predecessor check lives in another (reported, since the rule looks at one function at a time).

use std::collections::BTreeSet;

use proc_macro2::{Span, TokenStream, TokenTree};
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    BinOp, Block, Expr, ExprBinary, ExprCall, ExprMethodCall, ImplItem, ItemFn, ItemImpl,
    ItemTrait, Local, Pat, Token, TraitItem, Type,
};

use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf011SignerAuth;

pub static RULE: Pf011SignerAuth = Pf011SignerAuth;

impl Rule for Pf011SignerAuth {
    fn id(&self) -> &'static str {
        "PF011"
    }

    fn title(&self) -> &'static str {
        "Authorization uses signer_account_id instead of predecessor_account_id"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn help(&self) -> &'static str {
        "compare env::predecessor_account_id() instead, so only a direct call from the authorised account passes"
    }

    fn check(&self, krate: &Crate) -> Vec<Finding> {
        let mut findings = Vec::new();
        for file in &krate.files {
            let mut scan = FileScan::default();
            scan.visit_file(&file.ast);
            for func in scan.functions {
                if let Some(span) = func.first_signer_check() {
                    findings.push(self.finding(
                        file,
                        span,
                        func.name.clone(),
                        format!(
                            "`{}` decides who may call it from `env::signer_account_id()`, the account that signed the transaction, \
                             so a contract that the authorised account is tricked into calling passes the check",
                            func.name
                        ),
                    ));
                }
            }
        }
        findings
    }
}

/// A function body that makes an access check with the signer, and whether it also looks at the predecessor.
struct Func {
    name: String,
    /// Where the signer is used in an access check.
    signer_checks: Vec<Span>,
    mentions_predecessor: bool,
}

impl Func {
    /// The earliest signer check, or `None` when the function is clean or looks at the predecessor too.
    fn first_signer_check(&self) -> Option<Span> {
        if self.mentions_predecessor {
            return None;
        }
        self.signer_checks.iter().copied().min_by_key(|span| (span.start().line, span.start().column))
    }
}

#[derive(Default)]
struct FileScan {
    functions: Vec<Func>,
}

fn type_name(ty: &Type) -> String {
    match ty {
        Type::Path(path) => path.path.segments.last().map_or_else(String::new, |segment| segment.ident.to_string()),
        _ => "<unnamed type>".to_owned(),
    }
}

fn func_of(name: String, block: &Block) -> Func {
    let mut body = BodyScan::default();
    body.visit_block(block);
    body.finish();
    Func { name, signer_checks: body.signer_checks, mentions_predecessor: body.mentions_predecessor }
}

impl<'ast> Visit<'ast> for FileScan {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.functions.push(func_of(item.sig.ident.to_string(), &item.block));
        visit::visit_item_fn(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        let owner = type_name(&item.self_ty);
        for member in &item.items {
            if let ImplItem::Fn(method) = member {
                self.functions.push(func_of(format!("{owner}::{}", method.sig.ident), &method.block));
            }
        }
    }

    fn visit_item_trait(&mut self, item: &'ast ItemTrait) {
        for member in &item.items {
            if let TraitItem::Fn(method) = member
                && let Some(block) = &method.default
            {
                self.functions.push(func_of(format!("{}::{}", item.ident, method.sig.ident), block));
            }
        }
    }
}

#[derive(Default)]
struct BodyScan {
    signer_checks: Vec<Span>,
    mentions_predecessor: bool,
    /// Locals bound straight to the signer, with the span of that call.
    signer_locals: Vec<(String, Span)>,
    /// Names of locals used as an operand of a comparison.
    compared_locals: BTreeSet<String>,
}

const GUARD_MACROS: [&str; 3] = ["require", "assert", "debug_assert"];
const COMPARING_MACROS: [&str; 4] = ["assert_eq", "assert_ne", "debug_assert_eq", "debug_assert_ne"];

/// Strips what does not change which account an expression is: parentheses, `&`, `*`, `.clone()` and friends.
fn peel(mut expr: &Expr) -> &Expr {
    loop {
        expr = match expr {
            Expr::Paren(inner) => &inner.expr,
            Expr::Group(inner) => &inner.expr,
            Expr::Reference(inner) => &inner.expr,
            Expr::Unary(inner) if matches!(inner.op, syn::UnOp::Deref(_)) => &inner.expr,
            Expr::MethodCall(call)
                if call.args.is_empty()
                    && ["clone", "to_owned", "to_string", "as_str", "as_ref"].contains(&call.method.to_string().as_str()) =>
            {
                &call.receiver
            }
            _ => return expr,
        };
    }
}

/// The span of the call when `expr` is `env::signer_account_id()` (any path form).
fn signer_call(expr: &Expr) -> Option<Span> {
    let Expr::Call(call) = peel(expr) else { return None };
    let Expr::Path(func) = &*call.func else { return None };
    let last = func.path.segments.last()?;
    (last.ident == "signer_account_id" && call.args.is_empty()).then(|| last.ident.span())
}

fn local_name(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(ident) => Some(ident.ident.to_string()),
        Pat::Type(typed) => local_name(&typed.pat),
        _ => None,
    }
}

impl BodyScan {
    /// An expression compared with something else: the signer itself, or a local that may hold it.
    fn compared(&mut self, expr: &Expr) {
        if let Some(span) = signer_call(expr) {
            self.signer_checks.push(span);
        } else if let Expr::Path(path) = peel(expr)
            && let Some(ident) = path.path.get_ident()
        {
            self.compared_locals.insert(ident.to_string());
        }
    }

    /// Adds the checks made through locals once the whole body has been seen.
    fn finish(&mut self) {
        for (name, span) in &self.signer_locals {
            if self.compared_locals.contains(name) {
                self.signer_checks.push(*span);
            }
        }
    }

    fn mentions_predecessor_in(&mut self, tokens: TokenStream) {
        for tree in tokens {
            match tree {
                TokenTree::Ident(ident) => self.mentions_predecessor |= ident == "predecessor_account_id",
                TokenTree::Group(group) => self.mentions_predecessor_in(group.stream()),
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_local(&mut self, local: &'ast Local) {
        if let Some(init) = &local.init
            && let Some(name) = local_name(&local.pat)
            && let Some(span) = signer_call(&init.expr)
        {
            self.signer_locals.push((name, span));
        }
        visit::visit_local(self, local);
    }

    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        if matches!(binary.op, BinOp::Eq(_) | BinOp::Ne(_)) {
            self.compared(&binary.left);
            self.compared(&binary.right);
        }
        visit::visit_expr_binary(self, binary);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        match (call.method.to_string().as_str(), call.args.first()) {
            ("eq" | "ne", Some(other)) => {
                self.compared(&call.receiver);
                self.compared(other);
            }
            ("contains" | "contains_key", Some(member)) => self.compared(member),
            _ => {}
        }
        self.mentions_predecessor |= call.method == "predecessor_account_id";
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(func) = &*call.func {
            self.mentions_predecessor |= func.path.segments.last().is_some_and(|last| last.ident == "predecessor_account_id");
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.mentions_predecessor_in(mac.tokens.clone());
        let name = mac.path.segments.last().map(|segment| segment.ident.to_string()).unwrap_or_default();
        let comparing = COMPARING_MACROS.contains(&name.as_str());
        if (comparing || GUARD_MACROS.contains(&name.as_str()))
            && let Ok(args) = mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
        {
            if comparing {
                for operand in args.iter().take(2) {
                    self.compared(operand);
                }
            }
            for arg in &args {
                self.visit_expr(arg);
            }
        }
        visit::visit_macro(self, mac);
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

    const TREASURY: &str = r#"
        #[near]
        impl Treasury {
            pub fn withdraw(&mut self, to: AccountId, amount: U128) -> Promise {
                require!(env::signer_account_id() == self.owner, "only the owner");
                Promise::new(to).transfer(NearToken::from_yoctonear(amount.0))
            }
        }
    "#;

    /// A treasury method whose body is `body`.
    fn method(body: &str) -> String {
        format!("#[near] impl Treasury {{ pub fn withdraw(&mut self) {{ {body} }} }}")
    }

    #[test]
    fn flags_a_signer_comparison_and_locates_the_call() {
        let findings = check(TREASURY);
        assert_eq!(items(&findings), ["Treasury::withdraw"]);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF011", Severity::High));
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 5, 31));
        assert!(finding.message.contains("`Treasury::withdraw`"), "{}", finding.message);
    }

    #[test]
    fn flags_every_way_of_comparing_the_signer() {
        for body in [
            "require!(env::signer_account_id() == self.owner);",
            "require!(self.owner == env::signer_account_id(), \"only {}\", self.owner);",
            "assert!(near_sdk::env::signer_account_id() == self.owner);",
            "assert_eq!(env::signer_account_id(), self.owner);",
            "assert_ne!(self.owner, env::signer_account_id());",
            "debug_assert_eq!(env::signer_account_id(), self.owner);",
            "if env::signer_account_id() != self.owner { env::panic_str(\"no\"); }",
            "if signer_account_id() != self.owner { env::panic_str(\"no\"); }",
            "require!(env::signer_account_id().clone() == self.owner);",
            "require!(&env::signer_account_id() == &self.owner);",
            "require!(env::signer_account_id().as_str() == \"alice.near\");",
            "require!(env::signer_account_id().eq(&self.owner));",
            "require!(self.admins.contains(&env::signer_account_id()));",
            "require!(self.admins.contains_key(&env::signer_account_id()));",
            "let who = env::signer_account_id(); require!(who == self.owner);",
            "let who: AccountId = env::signer_account_id(); if self.owner != who { env::panic_str(\"no\"); }",
            "let who = env::signer_account_id(); require!(self.admins.contains(&who));",
            "let who = env::signer_account_id(); assert_eq!(who, self.owner);",
        ] {
            assert_eq!(items(&check(&method(body))), ["Treasury::withdraw"], "{body}");
        }
    }

    #[test]
    fn flags_helpers_free_functions_and_trait_default_methods() {
        let source = "
            impl Treasury { fn assert_owner(&self) { require!(env::signer_account_id() == self.owner); } }
            fn only_owner(owner: &AccountId) { assert_eq!(&env::signer_account_id(), owner); }
            trait Owned { fn guard(&self, owner: AccountId) { if env::signer_account_id() != owner { panic!(); } } }";
        assert_eq!(items(&check(source)), ["Treasury::assert_owner", "only_owner", "Owned::guard"]);
    }

    #[test]
    fn accepts_both_near_spellings() {
        for attr in ["#[near_bindgen]", "#[near_sdk::near]", "#[near(contract_state)]", ""] {
            let source = TREASURY.replace("#[near]", attr);
            assert_eq!(items(&check(&source)), ["Treasury::withdraw"], "{attr}");
        }
    }

    #[test]
    fn reports_a_function_once_at_its_first_check() {
        let source = method(
            "require!(env::signer_account_id() == self.owner); let who = env::signer_account_id(); require!(who == self.owner);",
        );
        let findings = check(&source);
        assert_eq!(items(&findings), ["Treasury::withdraw"]);
        assert_eq!(findings[0].column, 68);
    }

    #[test]
    fn a_function_that_also_looks_at_the_predecessor_is_clean() {
        for body in [
            "require!(env::signer_account_id() == env::predecessor_account_id());",
            "require!(env::signer_account_id() == self.owner && env::predecessor_account_id() == self.owner);",
            "let caller = env::predecessor_account_id(); require!(env::signer_account_id() == self.owner);",
            "require!(env::signer_account_id() == self.owner); env::log_str(&format!(\"{}\", env::predecessor_account_id()));",
            "require!(env::signer_account_id() == self.owner, \"{}\", near_sdk::env::predecessor_account_id());",
        ] {
            assert!(check(&method(body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn using_the_signer_as_a_value_is_not_an_access_check() {
        for body in [
            "self.owner = env::signer_account_id();",
            "let who = env::signer_account_id(); self.visits.insert(who, 1);",
            "env::log_str(&format!(\"signed by {}\", env::signer_account_id()));",
            "self.visits.insert(env::signer_account_id(), 1);",
            "let who = env::signer_account_id(); let other = self.owner.clone(); require!(other == self.owner);",
            "let who = env::signer_account_id(); require!(self.owner == self.admin);",
            "self.record(env::signer_account_id());",
            "let _ = env::signer_account_id();",
        ] {
            assert!(check(&method(body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn the_predecessor_alone_is_clean() {
        assert!(check(&TREASURY.replace("signer_account_id", "predecessor_account_id")).is_empty());
    }

    #[test]
    fn test_code_is_skipped() {
        let source = format!("#[cfg(test)] mod tests {{ {TREASURY} }}");
        assert!(check(&source).is_empty());
        let source = "#[test] fn signs() { assert_eq!(env::signer_account_id(), alice()); }
            #[cfg(test)] impl Treasury { fn helper(&self) { require!(env::signer_account_id() == self.owner); } }
            impl Treasury { #[cfg(test)] fn helper(&self) { require!(env::signer_account_id() == self.owner); } }";
        assert!(check(source).is_empty());
        let source = "#[cfg(not(test))] fn real() { assert_eq!(env::signer_account_id(), owner()); }";
        assert_eq!(items(&check(source)), ["real"]);
    }
}
