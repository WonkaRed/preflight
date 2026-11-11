//! PF022: balance arithmetic that relies on overflow checks the release build does not have.
//!
//! Rust wraps integer overflow silently in release builds unless `overflow-checks = true` is set in the
//! `[profile.release]` of the workspace root (cargo ignores profiles in member manifests). Contracts are built
//! with the release profile, so `balance - amount` with no earlier comparison turns an overdraw into a balance
//! near `u128::MAX`. Docs: https://docs.near.org/smart-contracts/security/checklist (enable overflow checks).
//!
//! A finding needs both halves. The profile half: the crate's manifests (the scanner reads them, see
//! [`Manifest`](crate::source::Manifest)) do not turn on `overflow-checks` for the release profile, looking at
//! `[profile.release.package.<crate name>]` first and `[profile.release]` second; absent means off. The source half:
//! a subtraction (`a - b` or `a -= b`) in any function that is not test code, where an operand has an identifier
//! named like money (`balance`, `amount`, `deposit`, `share`, `supply`, `stake`, `reward`, `fund`, `fee`, `price`,
//! `payout`, `debt`, `collateral`, `allowance`) and no earlier comparison (`<`, `<=`, `>`, `>=`, also inside
//! `require!`/`assert!`) in the same function has the same two operands.
//!
//! The contract's own balance minus its storage cost, `env::account_balance() - env::storage_usage() * price` (also
//! through a local the product was bound to), is not reported when the left side is exactly `env::account_balance()`
//! (`.as_yoctonear()` allowed): the runtime refuses any state in which an account's `amount + locked` is below its
//! storage cost, and `env::account_balance()` is the `amount`. So the subtraction cannot go below zero for an account
//! with no locked stake. A staking contract can hold `locked` stake that covers its storage, leaving `amount` below
//! the cost: there the exemption hides a real wrap, a gap this rule does not close. Anything derived from the
//! balance (`account_balance() / 2`, `.saturating_sub(self.locked)`) is not the balance and is reported.
//!
//! A macro the crate defines once (or a `#[macro_export]` one of a path dependency in the same scan) whose pattern is a
//! plain list of `$name:fragment` parameters is expanded where it is called, so `assert_storage_deposit!(cost)` over
//! `if env::attached_deposit() < $required { panic }` is the comparison of the deposit with `cost` at that line. A
//! subtraction written inside a macro body is not reported at the call.
//!
//! Knowingly missed: addition and multiplication (a guard for them cannot be recognised without types, and an
//! attacker-sized sum is rarer than an overdraw); a subtraction whose operands are not named like money; a
//! comparison guard that lives in another function; a custom profile (`--profile`) or `RUSTFLAGS`/`CARGO_PROFILE_*`
//! overrides outside the manifests; a crate scanned as loose files (no `Cargo.toml`), which gets no finding; a
//! subtraction inside a crate macro body, which is never reported (the rule reads the macro only to expand its
//! comparisons at the call, see above).
//! Knowingly over-reported when overflow checks are off: a money-named subtraction that an invariant (not a
//! comparison in the same function) keeps non-negative.

use std::collections::BTreeMap;

use proc_macro2::{Delimiter, Group, LineColumn, Span, TokenStream, TokenTree};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Attribute, BinOp, Expr, ExprBinary, ImplItemFn, ItemFn, ItemImpl, ItemMacro, ItemMod, Local, Macro, Pat, Token};
use toml_edit::Item as Toml;

use super::pf007_unguarded_admin::type_name;
use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::{Crate, Manifest};

pub struct Pf022OverflowChecksOff;

pub static RULE: Pf022OverflowChecksOff = Pf022OverflowChecksOff;

impl Rule for Pf022OverflowChecksOff {
    fn id(&self) -> &'static str {
        "PF022"
    }

    fn title(&self) -> &'static str {
        "Unchecked balance subtraction with overflow checks off"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn help(&self) -> &'static str {
        "set `overflow-checks = true` in the workspace root's `[profile.release]` (and drop any per-package override), or use `checked_sub`"
    }

    fn check(&self, krate: &Crate) -> Vec<Finding> {
        let Some(manifest) = &krate.manifest else { return Vec::new() };
        if release_overflow_checks(manifest) {
            return Vec::new();
        }
        let macros = macro_arms(krate);
        let mut findings = Vec::new();
        for file in &krate.files {
            let mut functions = Functions { macros: &macros, found: Vec::new(), owner: None };
            functions.visit_file(&file.ast);
            for function in functions.found {
                for sub in function.unguarded_money_subtractions() {
                    findings.push(self.finding(
                        file,
                        sub.span,
                        function.name.clone(),
                        format!(
                            "`{}` subtracts `{}` from `{}` with no earlier comparison of the two, and the release profile \
                             does not enable `overflow-checks`, so an amount larger than the balance wraps around instead of failing",
                            function.name, sub.rhs.label(), sub.lhs.label()
                        ),
                    ));
                }
            }
        }
        findings
    }
}

/// Whether cargo builds this crate's release profile with `overflow-checks` on. Profiles come from the workspace
/// root only; a package override beats the profile, and the release default is off.
fn release_overflow_checks(manifest: &Manifest) -> bool {
    let release = lookup(manifest.workspace_root.as_item(), &["profile", "release"]);
    let package_name = lookup(manifest.package.as_item(), &["package", "name"]).and_then(Toml::as_str);
    package_name
        .and_then(|name| lookup(release?, &["package", name, "overflow-checks"]))
        .or_else(|| lookup(release?, &["overflow-checks"]))
        .and_then(Toml::as_bool)
        .unwrap_or(false)
}

fn lookup<'a>(item: &'a Toml, path: &[&str]) -> Option<&'a Toml> {
    path.iter().try_fold(item, |item, key| item.get(key))
}

/// The functions of a file that are not test code, with their subtractions and comparisons.
struct Functions<'m> {
    macros: &'m Macros,
    found: Vec<Function>,
    owner: Option<String>,
}

struct Function {
    name: String,
    subtractions: Vec<Subtraction>,
    comparisons: Vec<Comparison>,
}

struct Subtraction {
    span: Span,
    lhs: Operand,
    rhs: Operand,
    /// `account_balance() - <storage cost>`: see the module docs.
    storage_cost_of_balance: bool,
}

struct Comparison {
    at: LineColumn,
    sides: [Operand; 2],
}

/// The identifiers an operand is made of, in source order: `self.balances.get(&id)` is `self balances get id`.
/// Two operands with the same identifiers are taken to be the same value.
#[derive(PartialEq, Eq, Default)]
struct Operand(Vec<String>);

const MONEY_WORDS: [&str; 14] = [
    "balance", "amount", "deposit", "share", "supply", "stake", "reward", "fund", "fee", "price", "payout", "debt",
    "collateral", "allowance",
];

impl Operand {
    fn of(expr: &Expr) -> Self {
        let mut operand = Self::default();
        operand.visit_expr(expr);
        operand
    }

    fn mentions(&self, name: &str) -> bool {
        self.0.iter().any(|ident| ident == name)
    }

    fn money_name(&self) -> Option<&str> {
        self.0
            .iter()
            .find(|ident| {
                let lower = ident.to_lowercase();
                MONEY_WORDS.iter().any(|word| lower.contains(word))
            })
            .map(String::as_str)
    }

    /// The name that says "money" if there is one, else the last identifier.
    fn label(&self) -> &str {
        self.money_name().or_else(|| self.0.last().map(String::as_str)).unwrap_or("..")
    }
}

impl<'ast> Visit<'ast> for Operand {
    fn visit_ident(&mut self, ident: &'ast proc_macro2::Ident) {
        self.0.push(ident.to_string());
    }
}

impl Function {
    fn unguarded_money_subtractions(&self) -> impl Iterator<Item = &Subtraction> {
        self.subtractions.iter().filter(|sub| {
            (sub.lhs.money_name().is_some() || sub.rhs.money_name().is_some())
                && !sub.storage_cost_of_balance
                && !self.comparisons.iter().any(|cmp| {
                    cmp.at < sub.span.start()
                        && ((cmp.sides[0] == sub.lhs && cmp.sides[1] == sub.rhs)
                            || (cmp.sides[0] == sub.rhs && cmp.sides[1] == sub.lhs))
                })
        })
    }
}

fn is_test_code(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || attr.path().is_ident("cfg") && attr.parse_args::<syn::Ident>().is_ok_and(|arg| arg == "test")
    })
}

impl Functions<'_> {
    fn record(&mut self, name: String, block: &syn::Block) {
        let mut body = Body::new(self.macros);
        body.visit_block(block);
        self.found.push(Function { name, subtractions: body.subtractions, comparisons: body.comparisons });
    }
}

impl<'ast> Visit<'ast> for Functions<'_> {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        if !is_test_code(&item.attrs) {
            self.record(item.sig.ident.to_string(), &item.block);
        }
    }

    fn visit_impl_item_fn(&mut self, method: &'ast ImplItemFn) {
        if !is_test_code(&method.attrs) {
            let name = match &self.owner {
                Some(owner) => format!("{owner}::{}", method.sig.ident),
                None => method.sig.ident.to_string(),
            };
            self.record(name, &method.block);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        if !is_test_code(&item.attrs) {
            self.owner = Some(type_name(&item.self_ty));
            visit::visit_item_impl(self, item);
            self.owner = None;
        }
    }

    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        if !is_test_code(&item.attrs) {
            visit::visit_item_mod(self, item);
        }
    }
}

/// The subtractions and comparisons inside one function body, macro arguments included.
struct Body<'m> {
    macros: &'m Macros,
    /// Where the macro call being expanded stands: the comparisons its expansion makes are made there, not at the
    /// definition, which may be in another file.
    call_site: Option<LineColumn>,
    subtractions: Vec<Subtraction>,
    comparisons: Vec<Comparison>,
    /// What each `let name = <expr>;` so far bound.
    locals: Vec<(String, Operand)>,
}

/// The arms of every `macro_rules!` the crate defines once, or imports from a path dependency: its parameters
/// (`$name:expr, ..`) and what it expands to. A macro defined twice, or with a pattern that is not a plain list of
/// parameters, is left out.
type Macros = BTreeMap<String, Vec<(Vec<String>, TokenStream)>>;

fn macro_arms(krate: &Crate) -> Macros {
    #[derive(Default)]
    struct Definitions(Vec<ItemMacro>);
    impl<'ast> Visit<'ast> for Definitions {
        fn visit_item_macro(&mut self, item: &'ast ItemMacro) {
            if item.mac.path.is_ident("macro_rules") && item.ident.is_some() {
                self.0.push(item.clone());
            }
            visit::visit_item_macro(self, item);
        }
    }
    let mut definitions = Definitions::default();
    krate.files.iter().for_each(|file| definitions.visit_file(&file.ast));
    // An imported macro is dropped when the crate defines the name too, as `link_macros` already did.
    definitions.0.extend(krate.imported_macros.iter().cloned());
    let mut times: BTreeMap<String, usize> = BTreeMap::new();
    for item in &definitions.0 {
        *times.entry(item.ident.as_ref().map(ToString::to_string).unwrap_or_default()).or_default() += 1;
    }
    definitions
        .0
        .iter()
        .filter_map(|item| {
            let name = item.ident.as_ref()?.to_string();
            (times[&name] == 1).then(|| (name, arms(item.mac.tokens.clone())))
        })
        .collect()
}

/// `(params) => { body };` repeated, as far as every pattern is `$name:fragment, ..` and every body is a group.
fn arms(tokens: TokenStream) -> Vec<(Vec<String>, TokenStream)> {
    let mut arms = Vec::new();
    let mut tokens = tokens.into_iter().peekable();
    while let Some(pattern) = tokens.next() {
        let (TokenTree::Group(pattern), Some(TokenTree::Punct(eq)), Some(TokenTree::Punct(gt)), Some(TokenTree::Group(body))) =
            (pattern, tokens.next(), tokens.next(), tokens.next())
        else {
            return Vec::new();
        };
        if eq.as_char() != '=' || gt.as_char() != '>' {
            return Vec::new();
        }
        if let Some(params) = parameters(pattern.stream()) {
            arms.push((params, body.stream()));
        }
        if matches!(tokens.peek(), Some(TokenTree::Punct(semicolon)) if semicolon.as_char() == ';') {
            tokens.next();
        }
    }
    arms
}

/// `$a:expr, $b:expr` is `[a, b]`; anything else (a repetition, a literal token) is `None`.
fn parameters(pattern: TokenStream) -> Option<Vec<String>> {
    let mut tokens = pattern.into_iter();
    let mut names = Vec::new();
    while let Some(dollar) = tokens.next() {
        let (TokenTree::Punct(dollar), Some(TokenTree::Ident(name)), Some(TokenTree::Punct(colon)), Some(TokenTree::Ident(_))) =
            (dollar, tokens.next(), tokens.next(), tokens.next())
        else {
            return None;
        };
        if dollar.as_char() != '$' || colon.as_char() != ':' {
            return None;
        }
        names.push(name.to_string());
        match tokens.next() {
            None => {}
            Some(TokenTree::Punct(comma)) if comma.as_char() == ',' => {}
            Some(_) => return None,
        }
    }
    Some(names)
}

/// The call's arguments split at top-level commas (a trailing comma adds none).
fn arguments(tokens: TokenStream) -> Vec<TokenStream> {
    let mut all = vec![TokenStream::new()];
    for token in tokens {
        match &token {
            TokenTree::Punct(comma) if comma.as_char() == ',' => all.push(TokenStream::new()),
            _ => all.last_mut().expect("never empty").extend([token]),
        }
    }
    if all.last().is_some_and(TokenStream::is_empty) {
        all.pop();
    }
    all
}

/// `body` with each `$param` replaced by its argument.
fn substitute(body: TokenStream, params: &[String], args: &[TokenStream]) -> TokenStream {
    let mut out = TokenStream::new();
    let mut tokens = body.into_iter().peekable();
    while let Some(token) = tokens.next() {
        match token {
            TokenTree::Punct(dollar) if dollar.as_char() == '$' => {
                let Some(TokenTree::Ident(name)) = tokens.peek().cloned() else {
                    out.extend([TokenTree::Punct(dollar)]);
                    continue;
                };
                match params.iter().position(|param| *name.to_string() == **param) {
                    Some(index) => {
                        tokens.next();
                        out.extend([TokenTree::Group(Group::new(Delimiter::None, args[index].clone()))]);
                    }
                    // `$crate::path` is `crate::path` for what is read here.
                    None if name == "crate" => {}
                    None => out.extend([TokenTree::Punct(dollar)]),
                }
            }
            TokenTree::Group(group) => {
                let mut inner = Group::new(group.delimiter(), substitute(group.stream(), params, args));
                inner.set_span(group.span());
                out.extend([TokenTree::Group(inner)]);
            }
            other => out.extend([other]),
        }
    }
    out
}

impl<'m> Body<'m> {
    fn new(macros: &'m Macros) -> Self {
        Self { macros, call_site: None, subtractions: Vec::new(), comparisons: Vec::new(), locals: Vec::new() }
    }

    /// The comparisons `mac` makes when it expands, when its definition is known: a call such as
    /// `assert_deposit!(cost)` whose body is `if env::attached_deposit() < $r { panic }` compares those two.
    fn expand(&mut self, mac: &Macro) {
        let Some(arms) = mac.path.segments.last().and_then(|name| self.macros.get(&name.ident.to_string())) else { return };
        let args = arguments(mac.tokens.clone());
        let Some((params, body)) = arms.iter().find(|(params, _)| params.len() == args.len()) else { return };
        let expanded = substitute(body.clone(), params, &args);
        let Ok(statements) = syn::Block::parse_within.parse2(expanded) else { return };
        let outer = self.call_site.replace(mac.span().start());
        for statement in &statements {
            self.visit_stmt(statement);
        }
        self.call_site = outer;
    }

    /// The identifiers of `operand`, or of the expression its single local identifier was bound to.
    fn resolve<'a>(&'a self, operand: &'a Operand) -> &'a Operand {
        match operand.0.as_slice() {
            [name] => self.locals.iter().rev().find(|(bound, _)| bound == name).map_or(operand, |(_, value)| value),
            _ => operand,
        }
    }
}

/// Exactly `env::account_balance()`, `near_sdk::env::account_balance()` or either with `.as_yoctonear()`.
fn is_account_balance(expr: &Expr) -> bool {
    match expr {
        Expr::Paren(inner) => is_account_balance(&inner.expr),
        Expr::MethodCall(call) => call.method == "as_yoctonear" && call.args.is_empty() && is_account_balance(&call.receiver),
        Expr::Call(call) if call.args.is_empty() => matches!(&*call.func, Expr::Path(func)
            if func.qself.is_none()
                && func.path.segments.last().is_some_and(|last| last.ident == "account_balance")
                && func.path.segments.iter().rev().skip(1).all(|segment| segment.ident == "env" || segment.ident == "near_sdk")),
        _ => false,
    }
}

impl<'ast> Visit<'ast> for Body<'_> {
    fn visit_expr_binary(&mut self, expr: &'ast ExprBinary) {
        match expr.op {
            BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_) => self.comparisons.push(Comparison {
                at: self.call_site.unwrap_or_else(|| expr.span().start()),
                sides: [Operand::of(&expr.left), Operand::of(&expr.right)],
            }),
            // `x - 1` and `x -= 1` take a literal off a counter, not an attacker-sized amount.
            BinOp::Sub(_) | BinOp::SubAssign(_) if self.call_site.is_none() && !matches!(&*expr.right, Expr::Lit(_)) => {
                let (lhs, rhs) = (Operand::of(&expr.left), Operand::of(&expr.right));
                let storage_cost_of_balance =
                    is_account_balance(&expr.left) && self.resolve(&rhs).mentions("storage_usage");
                self.subtractions.push(Subtraction { span: expr.span(), lhs, rhs, storage_cost_of_balance });
            }
            _ => {}
        }
        visit::visit_expr_binary(self, expr);
    }

    fn visit_local(&mut self, local: &'ast Local) {
        visit::visit_local(self, local);
        let pat = match &local.pat {
            Pat::Type(typed) => &*typed.pat,
            pat => pat,
        };
        if let (Pat::Ident(pat), Some(init)) = (pat, &local.init) {
            self.locals.push((pat.ident.to_string(), Operand::of(&init.expr)));
        }
    }

    /// `require!(balance >= amount, "..")` and friends: read the arguments as expressions when they parse as such.
    fn visit_macro(&mut self, mac: &'ast Macro) {
        if self.call_site.is_none() {
            self.expand(mac);
        }
        if let Ok(args) = mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated) {
            args.iter().for_each(|arg| self.visit_expr(arg));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELEASE_DEFAULT: &str = "[package]\nname = \"vault\"\n";

    fn check_with(manifest: &str, root: &str, source: &str) -> Vec<Finding> {
        let krate = Crate::from_sources([("src/lib.rs", source)])
            .unwrap()
            .with_manifest(Manifest::parse(manifest, root).unwrap());
        RULE.check(&krate)
    }

    fn check(source: &str) -> Vec<Finding> {
        check_with(RELEASE_DEFAULT, RELEASE_DEFAULT, source)
    }

    fn items(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|finding| finding.item.as_str()).collect()
    }

    const WITHDRAW: &str = "#[near] impl Vault {
        pub fn withdraw(&mut self, amount: U128) {
            let id = env::predecessor_account_id();
            let balance = self.balances.get(&id).copied().unwrap_or(0);
            self.balances.insert(id, balance - amount.0);
        }
    }";

    #[test]
    fn flags_an_unguarded_balance_subtraction_when_overflow_checks_are_not_set() {
        let findings = check(WITHDRAW);
        assert_eq!(items(&findings), ["Vault::withdraw"]);
        assert!(findings[0].message.contains("subtracts `amount` from `balance`"), "{}", findings[0].message);
    }

    #[test]
    fn flags_compound_assignment_free_functions_and_plain_impls() {
        for source in [
            "impl Vault { pub fn take(&mut self, amount: u128) { self.total_supply -= amount; } }",
            "#[near_bindgen] impl Vault { pub fn take(&mut self, n: u128) { *self.balances.get_mut(&a).unwrap() -= n; } }",
            "fn debit(balance: u128, fee: u128) -> u128 { balance - fee }",
        ] {
            assert_eq!(check(source).len(), 1, "{source}");
        }
    }

    #[test]
    fn a_crate_with_no_manifest_gets_no_finding() {
        let krate = Crate::from_sources([("src/lib.rs", WITHDRAW)]).unwrap();
        assert!(RULE.check(&krate).is_empty());
    }

    #[test]
    fn overflow_checks_in_the_release_profile_silence_the_rule() {
        let root = "[workspace]\n[profile.release]\noverflow-checks = true\n";
        assert!(check_with(RELEASE_DEFAULT, root, WITHDRAW).is_empty());
        let own = "[package]\nname = \"vault\"\n[profile.release]\noverflow-checks = true\n";
        assert!(check_with(own, own, WITHDRAW).is_empty());
    }

    #[test]
    fn an_explicit_false_and_a_missing_profile_both_mean_off() {
        let root = "[workspace]\n[profile.release]\noverflow-checks = false\n";
        assert_eq!(check_with(RELEASE_DEFAULT, root, WITHDRAW).len(), 1);
        assert_eq!(check_with(RELEASE_DEFAULT, "[workspace]\n[profile.dev]\noverflow-checks = true\n", WITHDRAW).len(), 1);
    }

    #[test]
    fn a_package_override_in_the_workspace_root_beats_the_profile() {
        let off = "[workspace]\n[profile.release]\noverflow-checks = true\n[profile.release.package.vault]\noverflow-checks = false\n";
        assert_eq!(check_with(RELEASE_DEFAULT, off, WITHDRAW).len(), 1);
        let on = "[workspace]\n[profile.release]\noverflow-checks = false\n[profile.release.package.vault]\noverflow-checks = true\n";
        assert!(check_with(RELEASE_DEFAULT, on, WITHDRAW).is_empty());
        let other = "[workspace]\n[profile.release.package.other]\noverflow-checks = true\n";
        assert_eq!(check_with(RELEASE_DEFAULT, other, WITHDRAW).len(), 1);
    }

    #[test]
    fn a_profile_in_a_member_manifest_is_ignored_because_cargo_ignores_it() {
        let member = "[package]\nname = \"vault\"\n[profile.release]\noverflow-checks = true\n";
        assert_eq!(check_with(member, "[workspace]\nmembers = [\"vault\"]\n", WITHDRAW).len(), 1);
    }

    #[test]
    fn the_wildcard_override_does_not_reach_workspace_members() {
        let root = "[workspace]\n[profile.release.package.\"*\"]\noverflow-checks = true\n";
        assert_eq!(check_with(RELEASE_DEFAULT, root, WITHDRAW).len(), 1);
    }

    #[test]
    fn a_comparison_of_the_same_operands_before_the_subtraction_is_a_guard() {
        for guard in [
            "require!(balance >= amount.0, \"insufficient\");",
            "require!(amount.0 <= balance);",
            "assert!(balance > amount.0);",
            "if balance < amount.0 { env::panic_str(\"insufficient\"); }",
        ] {
            let source = format!(
                "#[near] impl Vault {{ pub fn withdraw(&mut self, amount: U128) {{
                    let balance = self.balance_of();
                    {guard}
                    self.balances.insert(id, balance - amount.0);
                }} }}"
            );
            assert!(check(&source).is_empty(), "{guard}");
        }
    }

    #[test]
    fn a_guard_after_the_subtraction_or_on_other_operands_is_not_a_guard() {
        for body in [
            "let b = balance - amount; require!(balance >= amount);",
            "require!(balance >= fee); let b = balance - amount;",
            "require!(amount > 0); let b = balance - amount;",
        ] {
            let source = format!("impl Vault {{ fn f(&mut self, balance: u128, amount: u128, fee: u128) {{ {body} }} }}");
            assert_eq!(check(&source).len(), 1, "{body}");
        }
    }

    #[test]
    fn checked_and_saturating_arithmetic_is_not_flagged() {
        let source = "impl Vault { fn f(&mut self, balance: u128, amount: u128) {
            let a = balance.checked_sub(amount).expect(\"insufficient\");
            let b = balance.saturating_sub(amount);
        } }";
        assert!(check(source).is_empty());
    }

    #[test]
    fn subtractions_that_are_not_money_or_that_take_a_literal_are_not_flagged() {
        for body in ["let n = end - start;", "let i = index - offset;", "self.balance -= 1;", "let b = balance - 10;"] {
            let source = format!("impl Vault {{ fn f(&mut self, end: u64, start: u64, index: usize, offset: usize) {{ {body} }} }}");
            assert!(check(&source).is_empty(), "{body}");
        }
    }

    #[test]
    fn addition_and_multiplication_are_not_flagged() {
        let source = "impl Vault { fn f(&mut self, balance: u128, amount: u128) { let a = balance + amount; let b = balance * amount; } }";
        assert!(check(source).is_empty());
    }

    #[test]
    fn test_code_is_ignored() {
        let source = "#[cfg(test)] mod tests { fn f(balance: u128, amount: u128) -> u128 { balance - amount } }
            #[test] fn g() { let _ = balance - amount; }";
        assert!(check(source).is_empty());
    }

    #[test]
    fn reports_each_subtraction_in_its_function() {
        let source = "impl Vault { fn f(&mut self, a: u128, b: u128) { self.a_balance -= a; self.fee_total -= b; }
            fn g(&mut self, a: u128) { self.supply -= a; } }";
        let findings = check(source);
        assert_eq!(items(&findings), ["Vault::f", "Vault::f", "Vault::g"]);
    }

    /// A common shape in deployed code: the runtime keeps an account's
    /// balance above its storage cost.
    #[test]
    fn the_balance_minus_the_storage_cost_cannot_wrap() {
        for source in [
            "fn free() -> u128 { env::account_balance() - env::storage_usage() as u128 * env::storage_byte_cost() }",
            "fn free(&self) -> u128 { env::account_balance() - env::storage_usage() as u128 * self.price_per_byte }",
            "fn free() -> u128 { let used_storage_stake = env::storage_usage() as u128 * env::storage_byte_cost();
                env::account_balance() - used_storage_stake }",
            "fn free() -> u128 { let used: u128 = env::storage_usage() as u128 * env::storage_byte_cost();
                env::account_balance() - used }",
            "fn free() -> u128 { near_sdk::env::account_balance().as_yoctonear() - env::storage_usage() as u128 * env::storage_byte_cost() }",
        ] {
            assert!(check(source).is_empty(), "{source}");
        }
    }

    /// The exemption is for the balance of the contract itself and for storage; the same names elsewhere still count.
    #[test]
    fn other_subtractions_beside_storage_are_still_flagged() {
        for source in [
            "fn free(&self, amount: u128) -> u128 { env::account_balance() - amount }",
            // locked stake and halving are not the balance
            "fn free(&self) -> u128 { env::account_balance().as_yoctonear().saturating_sub(self.locked) - env::storage_usage() as u128 * env::storage_byte_cost() }",
            "fn free(&self) -> u128 { env::account_balance() / 2 - env::storage_usage() as u128 * env::storage_byte_cost() }",
            "fn free(&self) -> u128 { self.env.account_balance() - env::storage_usage() as u128 * env::storage_byte_cost() }",
            "fn free(&self) -> u128 { self.balance - env::storage_usage() as u128 * env::storage_byte_cost() }",
            "fn free(&self, used: u128) -> u128 { let used_storage_stake = used; env::account_balance() - used_storage_stake }",
            "fn free(&self, amount: u128) -> u128 { let storage_cost = env::storage_usage() as u128; let storage_cost = amount;
                env::account_balance() - storage_cost }",
        ] {
            assert_eq!(check(source).len(), 1, "{source}");
        }
    }

    const DEPOSIT_MACRO: &str = "macro_rules! assert_deposit { ($required:expr) => { if env::attached_deposit() < $required { $crate::fail!(\"deposit\") } } }";

    fn approve(guard: &str) -> String {
        format!(
            "{DEPOSIT_MACRO}
            #[near] impl Store {{ pub fn approve(&mut self, storage_stake: u128) -> u128 {{ {guard} env::attached_deposit() - storage_stake }} }}"
        )
    }

    /// A common shape in deployed code: `assert_storage_deposit!(storage_stake)` stands before the subtraction.
    #[test]
    fn a_macro_that_compares_the_operands_is_a_guard_where_it_is_called() {
        assert!(check(&approve("assert_deposit!(storage_stake);")).is_empty());
        for guard in [
            "assert_deposit!(other);",
            "assert_deposit!(storage_stake, 1);",
            "assert_nothing!(storage_stake);",
            "",
        ] {
            assert_eq!(items(&check(&approve(guard))), ["Store::approve"], "{guard}");
        }
        // Called after the subtraction, or defined twice, it proves nothing.
        let after = approve("").replace("env::attached_deposit() - storage_stake", "let left = env::attached_deposit() - storage_stake; assert_deposit!(storage_stake); left");
        assert_eq!(items(&check(&after)), ["Store::approve"]);
        let twice = approve("assert_deposit!(storage_stake);") + "macro_rules! assert_deposit { ($r:expr) => {} }";
        assert_eq!(items(&check(&twice)), ["Store::approve"]);
    }

    #[test]
    fn a_subtraction_inside_a_macro_body_is_not_reported_at_the_call() {
        let source = "macro_rules! take { ($amount:expr) => { balance - $amount } }
            #[near] impl Store { pub fn run(&mut self, amount: u128) { take!(amount); } }";
        assert!(check(source).is_empty());
    }

    #[test]
    fn a_macro_exported_by_a_path_dependency_is_expanded_too() {
        let common = format!("#[macro_export] {DEPOSIT_MACRO}");
        let app = "#[near] impl Store { pub fn approve(&mut self, storage_stake: u128) -> u128 { assert_deposit!(storage_stake); env::attached_deposit() - storage_stake } }";
        let manifest = |name: &str, dependencies: &str| {
            Manifest::parse(&format!("[package]\nname = \"{name}\"\n[dependencies]\n{dependencies}"), "[workspace]").unwrap()
        };
        let run = |dependencies: &str| {
            let mut crates = [
                Crate::from_sources([("app/src/lib.rs", app)]).unwrap().with_manifest(manifest("app", dependencies)),
                Crate::from_sources([("common/src/lib.rs", common.as_str())]).unwrap().with_manifest(manifest("common", "")),
            ];
            crate::source::link_macros(&mut crates);
            RULE.check(&crates[0]).len()
        };
        assert_eq!(run("common = { path = \"../common\" }"), 0);
        assert_eq!(run(""), 1);
    }
}
