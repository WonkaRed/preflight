//! PF010: a transfer that reads both balances before writing either and never rules out sender == receiver.
//!
//! A hand-written token's transfer often reads the sender's balance and the receiver's balance, then writes both
//! back (`sender - amount`, `receiver + amount`). When sender and receiver are the same account, both reads see
//! the same old balance and the second write overwrites the first: the account ends with `balance + amount`, so
//! every transfer to yourself mints `amount` out of nothing (written in the other order, it burns it). This is the
//! Stader NEAR liquid token incident of 2022-08-16 (https://github.com/blocksecteam/rustle/blob/master/docs/detectors/self-transfer.md);
//! near-contract-standards guards it with `require!(sender_id != receiver_id, ..)`.
//!
//! A function is checked when its name has the word `transfer` in it (split at `_`: `transfer`, `ft_transfer`,
//! `internal_transfer`, `mt_batch_transfer`, `ft_transfer_call`; not the callbacks `ft_on_transfer` and
//! `ft_resolve_transfer`), whatever its visibility. It is reported when all of this holds:
//! - its body reads one collection on `self` with `get(K)` for two different keys, and writes that collection with
//!   `insert(K, ..)` or `set(K, ..)` for both of those keys, and no write to the collection comes before both
//!   reads (reading, writing, then reading and writing the other account is safe: the second read sees the first
//!   write);
//! - the function does not compare its two keys with each other, or one of them with the caller
//!   (`env::predecessor_account_id()`, `env::signer_account_id()`), using `==`, `!=`, `assert_eq!` or `assert_ne!`
//!   (a key may be written `&k`, `*k`, `k.clone()`, `a.b`, or `env::predecessor_account_id()`); a key compared with
//!   anything else (`receiver_id != self.treasury`) is some other check;
//! - no same-crate function that calls it compares an account it passes down as one of the two keys. This lets
//!   `ft_transfer` carry the check and call an `internal_transfer(sender_id, receiver_id, amount)` helper: the
//!   keys are parameters of the helper, a caller's argument at such a position is the account the caller names,
//!   and a comparison of two such accounts, or of one with the caller's identity, is the guard. The search
//!   climbs through callers of callers by the same rule: an intermediate `route(a, b)` passes `a` and `b`
//!   on, so its callers' comparisons of what they hand `route` count. A key that is not a parameter (a local
//!   bound from `env::predecessor_account_id()`) cannot be passed by a caller, so only the function's own
//!   comparisons can guard it.
//!
//! Plain values are paths, field chains (`self.owner`), and `env::predecessor_account_id()` or
//! `env::signer_account_id()`, with `&`, `*` and `.clone()` ignored. Callers and callees are found by name (free
//! function, inherent or trait method, any file of the crate), and macro arguments that parse as expressions
//! (`require!`, `assert!`, `assert_ne!`, ...) are read like ordinary code; a call inside a macro whose arguments
//! are not expressions is not seen.
//!
//! Knowingly missed: balances read or written through a helper (`self.balance_of(&k)`, `self.set_balance(..)`),
//! through indexing (`self.balances[&k]`) or through a tuple or computed key (`(token_id, owner)`); a transfer
//! split so that the read and the write sit in different functions; a self-transfer guard that is not an
//! equality, or one written with a different expression than the key (`require!(sender_id.as_str() !=
//! receiver_id.as_str())`, `require!(a == b)` after `let a = sender_id.clone()`), which the rule then reports. A
//! caller found by name may be a same-named function that never calls the helper (the name match is lenient).

use std::collections::BTreeSet;

use proc_macro2::Span;
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    BinOp, Block, Expr, ExprBinary, ExprCall, ExprMethodCall, FnArg, ImplItem, ItemFn, ItemImpl, Pat, Signature, Token,
    TraitItemFn, Type,
};

use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::{Crate, SourceFile};

pub struct Pf010SelfTransferMint;

pub static RULE: Pf010SelfTransferMint = Pf010SelfTransferMint;

impl Rule for Pf010SelfTransferMint {
    fn id(&self) -> &'static str {
        "PF010"
    }

    fn title(&self) -> &'static str {
        "Transfer to oneself changes the balance"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn help(&self) -> &'static str {
        "reject the transfer when sender and receiver are the same account: require!(sender_id != receiver_id)"
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
        let all: Vec<(&SourceFile, &Func)> = krate
            .files
            .iter()
            .zip(&scans)
            .flat_map(|(file, scan)| scan.functions.iter().map(move |func| (file, func)))
            .collect();
        let funcs: Vec<&Func> = all.iter().map(|&(_, func)| func).collect();

        let mut findings = Vec::new();
        for (index, &(file, func)) in all.iter().enumerate() {
            if !is_transfer_name(&func.name) {
                continue;
            }
                let Some((map, keys)) = func.crossed_balances() else { continue };
                if compares_accounts(&func.comparisons, &keys) || callers_compare_keys(index, &keys, &funcs) {
                    continue;
                }
                let item = match &func.owner {
                    Some(owner) => format!("{owner}::{}", func.name),
                    None => func.name.clone(),
                };
                findings.push(self.finding(
                    file,
                    func.span,
                    item.clone(),
                    format!(
                        "`{item}` reads `{map}` for {} before writing either, and never checks that they differ, so a transfer to oneself leaves the second write standing and changes the balance by the amount",
                        keys.iter().map(|key| format!("`{key}`")).collect::<Vec<_>>().join(" and "),
                    ),
                ));
        }
        findings
    }
}

/// `transfer` as a whole word of the name, but not a transfer callback.
fn is_transfer_name(name: &str) -> bool {
    let mut words = name.split('_');
    words.clone().any(|word| word == "transfer") && !words.any(|word| word == "on" || word == "resolve")
}

/// The plain values that name the caller of the transfer without being one of its parameters.
const CALLER_IDENTITIES: [&str; 2] = ["predecessor_account_id()", "signer_account_id()"];

/// Whether one of `comparisons` is a self-transfer guard: it has one of `accounts` on a side, and another of them
/// or the caller's identity on the other (`sender_id != receiver_id`, `receiver_id != env::predecessor_account_id()`).
/// A key compared with anything else (`receiver_id != self.treasury`) is some other check.
fn compares_accounts(comparisons: &[(String, String)], accounts: &BTreeSet<&str>) -> bool {
    let is_account = |value: &str| accounts.contains(value) || CALLER_IDENTITIES.contains(&value);
    comparisons.iter().any(|(a, b)| {
        (accounts.contains(a.as_str()) || accounts.contains(b.as_str())) && is_account(a) && is_account(b)
    })
}

/// Whether a function that calls `all[start]`, directly or through other calls, compares an account it passes
/// down as one of `keys`. `carried` is the set of parameter positions that hold the keys; each caller's arguments
/// at those positions are the accounts it names, and the parameters of the caller that hold them are carried on.
fn callers_compare_keys(start: usize, keys: &BTreeSet<&str>, all: &[&Func]) -> bool {
    let carried = |func: &Func, holds: &dyn Fn(&str) -> bool| -> Vec<usize> {
        (0..func.params.len()).filter(|&position| holds(&func.params[position])).collect()
    };
    let mut seen: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut work = vec![(start, carried(all[start], &|param| keys.contains(param)))];
    while let Some((callee_index, positions)) = work.pop() {
        let callee = all[callee_index];
        for (caller_index, caller) in all.iter().enumerate().filter(|&(index, _)| index != callee_index) {
            for site in caller.sites.iter().filter(|site| site.name == callee.name) {
                let receiver_argument = usize::from(site.via_path && callee.has_receiver);
                let passed: BTreeSet<&str> = positions
                    .iter()
                    .filter_map(|&position| site.args.get(position + receiver_argument)?.as_deref())
                    .collect();
                if compares_accounts(&caller.comparisons, &passed) {
                    return true;
                }
                let fresh: Vec<usize> = carried(caller, &|param| passed.contains(param))
                    .into_iter()
                    .filter(|&position| seen.insert((caller_index, position)))
                    .collect();
                if !fresh.is_empty() {
                    work.push((caller_index, fresh));
                }
            }
        }
    }
    false
}

#[derive(PartialEq)]
enum Kind {
    Read,
    Write,
}

/// One `map.get(key)` or `map.insert(key, ..)` / `map.set(key, ..)` on a collection held on `self`.
struct Access {
    kind: Kind,
    map: String,
    key: String,
}

/// A call to `name(..)` or `.name(..)` with the plain value passed at each argument position, if it is one.
struct CallSite {
    name: String,
    /// `Type::name(self, ..)` rather than `x.name(..)`: the receiver is the first argument.
    via_path: bool,
    args: Vec<Option<String>>,
}

/// What the scan keeps of one function.
struct Func {
    /// The type of the impl the function is in; `None` for a free function.
    owner: Option<String>,
    name: String,
    span: Span,
    /// Whether it takes `self`, so a path call `Type::name(self, ..)` passes one argument more than it has typed
    /// parameters.
    has_receiver: bool,
    /// The names of its typed parameters, in order (empty for a pattern that is not a plain name).
    params: Vec<String>,
    /// Every call its body makes, including calls written inside macro arguments.
    sites: Vec<CallSite>,
    /// Both sides of every `==` or `!=` between two plain values.
    comparisons: Vec<(String, String)>,
    /// Reads and writes of collections on `self`, in source order (arguments before the call that takes them).
    accesses: Vec<Access>,
}

impl Func {
    /// The collection, and the keys, for which two different keys are read before the collection is first written
    /// and both are written back; `None` when no collection has that shape.
    fn crossed_balances(&self) -> Option<(&str, BTreeSet<&str>)> {
        let maps: BTreeSet<&str> = self.accesses.iter().map(|access| access.map.as_str()).collect();
        maps.into_iter().find_map(|map| {
            let on_map = || self.accesses.iter().filter(|access| access.map == map);
            let first_write = on_map().position(|access| access.kind == Kind::Write)?;
            let read_before: BTreeSet<&str> = on_map().take(first_write).map(|access| access.key.as_str()).collect();
            let written: BTreeSet<&str> =
                on_map().filter(|access| access.kind == Kind::Write).map(|access| access.key.as_str()).collect();
            let crossed: BTreeSet<&str> = read_before.intersection(&written).copied().collect();
            (crossed.len() >= 2).then_some((map, crossed))
        })
    }
}

#[derive(Default)]
struct FileScan {
    /// Every function with a body in the file.
    functions: Vec<Func>,
}

impl<'ast> Visit<'ast> for FileScan {
    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        let owner = type_name(&item.self_ty);
        for member in &item.items {
            if let ImplItem::Fn(method) = member {
                self.functions.push(func_of(Some(owner.clone()), &method.sig, &method.block));
            }
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.functions.push(func_of(None, &item.sig, &item.block));
        visit::visit_item_fn(self, item);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast TraitItemFn) {
        if let Some(block) = &item.default {
            self.functions.push(func_of(None, &item.sig, block));
        }
        visit::visit_trait_item_fn(self, item);
    }
}

fn type_name(ty: &Type) -> String {
    match ty {
        Type::Path(path) => path.path.segments.last().map_or_else(String::new, |segment| segment.ident.to_string()),
        _ => "<unnamed type>".to_owned(),
    }
}

fn func_of(owner: Option<String>, sig: &Signature, block: &Block) -> Func {
    let mut body = BodyScan::default();
    body.visit_block(block);
    let params = sig
        .inputs
        .iter()
        .filter_map(|arg| match arg {
            FnArg::Typed(typed) => Some(match &*typed.pat {
                Pat::Ident(ident) => ident.ident.to_string(),
                _ => String::new(),
            }),
            FnArg::Receiver(_) => None,
        })
        .collect();
    Func {
        owner,
        name: sig.ident.to_string(),
        span: sig.ident.span(),
        has_receiver: sig.receiver().is_some(),
        params,
        sites: body.sites,
        comparisons: body.comparisons,
        accesses: body.accesses,
    }
}

#[derive(Default)]
struct BodyScan {
    sites: Vec<CallSite>,
    comparisons: Vec<(String, String)>,
    accesses: Vec<Access>,
}

impl BodyScan {
    fn compare(&mut self, left: &Expr, right: &Expr) {
        if let (Some(left), Some(right)) = (plain(left), plain(right)) {
            self.comparisons.push((left, right));
        }
    }
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(func) = &*call.func
            && let Some(last) = func.path.segments.last()
        {
            let args = call.args.iter().map(plain).collect();
            self.sites.push(CallSite { name: last.ident.to_string(), via_path: true, args });
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        // Arguments and receiver first, so a read inside an argument of a write comes before that write.
        visit::visit_expr_method_call(self, call);
        let args = call.args.iter().map(plain).collect();
        self.sites.push(CallSite { name: call.method.to_string(), via_path: false, args });
        let kind = match call.method.to_string().as_str() {
            "get" => Kind::Read,
            "insert" | "set" => Kind::Write,
            _ => return,
        };
        if let (Some(map), Some(key)) = (plain(&call.receiver), call.args.first().and_then(plain))
            && map.starts_with("self.")
        {
            self.accesses.push(Access { kind, map, key });
        }
    }

    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        if matches!(binary.op, BinOp::Eq(_) | BinOp::Ne(_)) {
            self.compare(&binary.left, &binary.right);
        }
        visit::visit_expr_binary(self, binary);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let parsed = Punctuated::<Expr, Token![,]>::parse_terminated.parse2(mac.tokens.clone());
        let Ok(args) = parsed else { return };
        let name = mac.path.segments.last().map(|segment| segment.ident.to_string()).unwrap_or_default();
        if matches!(name.as_str(), "assert_eq" | "assert_ne" | "debug_assert_eq" | "debug_assert_ne")
            && let [left, right, ..] = args.iter().collect::<Vec<_>>()[..]
        {
            self.compare(left, right);
        }
        for arg in &args {
            self.visit_expr(arg);
        }
    }
}

/// A plain value as text: a path, a field chain, or `env::predecessor_account_id()` / `env::signer_account_id()`,
/// with `&`, `*`, parentheses and `.clone()` ignored. `None` for anything else (literals, other calls, sums).
fn plain(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(path) => Some(path.path.segments.iter().map(|segment| segment.ident.to_string()).collect::<Vec<_>>().join("::")),
        Expr::Field(field) => {
            let member = match &field.member {
                syn::Member::Named(name) => name.to_string(),
                syn::Member::Unnamed(index) => index.index.to_string(),
            };
            Some(format!("{}.{member}", plain(&field.base)?))
        }
        Expr::Reference(inner) => plain(&inner.expr),
        Expr::Paren(inner) => plain(&inner.expr),
        Expr::Unary(inner) if matches!(inner.op, syn::UnOp::Deref(_)) => plain(&inner.expr),
        Expr::MethodCall(call) if call.method == "clone" && call.args.is_empty() => plain(&call.receiver),
        Expr::Call(call) if call.args.is_empty() => match &*call.func {
            Expr::Path(path) => {
                let last = path.path.segments.last()?.ident.to_string();
                matches!(last.as_str(), "predecessor_account_id" | "signer_account_id").then(|| format!("{last}()"))
            }
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(sources: &[(&str, &str)]) -> Vec<Finding> {
        let krate = Crate::from_sources(sources.iter().copied()).unwrap();
        RULE.check(&krate)
    }

    fn one(source: &str) -> Vec<Finding> {
        check(&[("src/lib.rs", source)])
    }

    fn items(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|finding| finding.item.as_str()).collect()
    }

    const TOKEN: &str = r#"
        #[near]
        impl Token {
            #[payable]
            pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) {
                assert_one_yocto();
                let sender_id = env::predecessor_account_id();
                let sender_balance = self.balances.get(&sender_id).copied().unwrap_or(0);
                let receiver_balance = self.balances.get(&receiver_id).copied().unwrap_or(0);
                require!(sender_balance >= amount.0, "not enough balance");
                self.balances.insert(sender_id, sender_balance - amount.0);
                self.balances.insert(receiver_id, receiver_balance + amount.0);
            }
        }
    "#;

    #[test]
    fn flags_a_transfer_that_reads_both_balances_before_writing_and_locates_it() {
        let findings = one(TOKEN);
        assert_eq!(items(&findings), ["Token::ft_transfer"]);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF010", Severity::Critical));
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 5, 20));
        assert!(finding.message.contains("`self.balances`"), "{}", finding.message);
        assert!(finding.message.contains("`receiver_id` and `sender_id`"), "{}", finding.message);
    }

    #[test]
    fn every_form_of_the_self_transfer_guard_is_clean() {
        let guards = [
            "require!(sender_id != receiver_id, \"Sender and receiver should be different\");",
            "assert_ne!(sender_id, receiver_id);",
            "assert!(receiver_id != sender_id);",
            "if sender_id == receiver_id { env::panic_str(\"self transfer\"); }",
            "require!(receiver_id != env::predecessor_account_id());",
            "require!(receiver_id.clone() != sender_id.clone());",
            "require!(*receiver_id != *sender_id);",
            "assert_eq!(sender_id.clone(), receiver_id.clone(), \"x\"); ",
        ];
        for guard in guards {
            let source = TOKEN.replace("require!(sender_balance", &format!("{guard} require!(sender_balance"));
            assert!(one(&source).is_empty(), "{guard}");
        }
    }

    #[test]
    fn a_comparison_that_does_not_involve_the_accounts_is_not_a_guard() {
        for unrelated in [
            "require!(amount.0 != 0);",
            "require!(env::attached_deposit() == ONE_YOCTO);",
            "require!(!self.paused);",
            "require!(sender_balance != receiver_balance + 1);",
            "require!(receiver_id != self.treasury);",
            "require!(sender_id != self.banned);",
        ] {
            let source = TOKEN.replace("require!(sender_balance", &format!("{unrelated} require!(sender_balance"));
            assert_eq!(items(&one(&source)), ["Token::ft_transfer"], "{unrelated}");
        }
    }

    #[test]
    fn reading_and_writing_one_account_at_a_time_is_clean() {
        let source = r#"#[near] impl Token {
            pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) {
                let sender_id = env::predecessor_account_id();
                let sender_balance = self.balances.get(&sender_id).copied().unwrap_or(0);
                self.balances.insert(sender_id, sender_balance - amount.0);
                let receiver_balance = self.balances.get(&receiver_id).copied().unwrap_or(0);
                self.balances.insert(receiver_id, receiver_balance + amount.0);
            }
        }"#;
        assert!(one(source).is_empty());
    }

    #[test]
    fn a_read_inside_the_arguments_of_a_write_comes_before_that_write() {
        let source = r#"#[near] impl Token {
            pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) {
                let sender_id = env::predecessor_account_id();
                self.balances.insert(sender_id.clone(), self.balances.get(&sender_id).unwrap() - amount.0);
                self.balances.insert(receiver_id.clone(), self.balances.get(&receiver_id).unwrap_or(0) + amount.0);
            }
        }"#;
        assert!(one(source).is_empty(), "each account is read right before it is written");
    }

    #[test]
    fn flags_a_transfer_that_writes_the_receiver_first() {
        let source = TOKEN
            .replace("self.balances.insert(sender_id, sender_balance - amount.0);", "")
            .replace(
                "self.balances.insert(receiver_id, receiver_balance + amount.0);",
                "self.balances.insert(receiver_id, receiver_balance + amount.0);
                 self.balances.insert(sender_id, sender_balance - amount.0);",
            );
        assert_eq!(items(&one(&source)), ["Token::ft_transfer"]);
    }

    #[test]
    fn reading_two_accounts_but_writing_only_one_is_clean() {
        let source = TOKEN.replace("self.balances.insert(receiver_id, receiver_balance + amount.0);", "log!(\"{}\", receiver_balance);");
        assert!(one(&source).is_empty());
    }

    #[test]
    fn two_different_collections_are_not_a_crossed_balance() {
        let source = TOKEN
            .replace("self.balances.get(&receiver_id)", "self.staked.get(&receiver_id)")
            .replace("self.balances.insert(receiver_id", "self.staked.insert(receiver_id");
        assert!(one(&source).is_empty());
    }

    #[test]
    fn both_set_and_insert_write_and_a_helper_collection_path_is_one_collection() {
        let source = r#"#[near] impl Token {
            pub fn transfer(&mut self, to: AccountId, amount: u128) {
                let from = env::predecessor_account_id();
                let a = self.ledger.balances.get(&from).copied().unwrap_or(0);
                let b = self.ledger.balances.get(&to).copied().unwrap_or(0);
                self.ledger.balances.set(from, Some(a - amount));
                self.ledger.balances.set(to, Some(b + amount));
            }
        }"#;
        let findings = one(source);
        assert_eq!(items(&findings), ["Token::transfer"]);
        assert!(findings[0].message.contains("`self.ledger.balances`"));
    }

    #[test]
    fn every_transfer_name_is_checked_and_callbacks_and_other_names_are_not() {
        for name in ["transfer", "ft_transfer", "internal_transfer", "mt_batch_transfer", "ft_transfer_call", "transfer_from"] {
            let source = TOKEN.replace("ft_transfer", name);
            assert_eq!(items(&one(&source)), [format!("Token::{name}").as_str()], "{name}");
        }
        for name in ["ft_on_transfer", "ft_resolve_transfer", "move_funds", "transferred", "retransfer"] {
            let source = TOKEN.replace("ft_transfer", name);
            assert!(one(&source).is_empty(), "{name}");
        }
    }

    #[test]
    fn a_private_helper_is_checked_too() {
        let helper = r#"impl Token {
            fn internal_transfer(&mut self, sender_id: &AccountId, receiver_id: &AccountId, amount: u128) {
                let sender_balance = self.balances.get(sender_id).copied().unwrap_or(0);
                let receiver_balance = self.balances.get(receiver_id).copied().unwrap_or(0);
                self.balances.insert(sender_id.clone(), sender_balance - amount);
                self.balances.insert(receiver_id.clone(), receiver_balance + amount);
            }
        }"#;
        assert_eq!(items(&one(helper)), ["Token::internal_transfer"]);
    }

    #[test]
    fn a_guard_in_a_caller_covers_the_helper_it_calls() {
        let helper = r#"impl Token {
            fn internal_transfer(&mut self, sender_id: &AccountId, receiver_id: &AccountId, amount: u128) {
                let sender_balance = self.balances.get(sender_id).copied().unwrap_or(0);
                let receiver_balance = self.balances.get(receiver_id).copied().unwrap_or(0);
                self.balances.insert(sender_id.clone(), sender_balance - amount);
                self.balances.insert(receiver_id.clone(), receiver_balance + amount);
            }
        }"#;
        let unguarded = "#[near] impl Token { pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) { self.internal_transfer(&env::predecessor_account_id(), &receiver_id, amount.0); } }";
        let findings = check(&[("src/lib.rs", unguarded), ("src/ledger.rs", helper)]);
        assert_eq!(items(&findings), ["Token::internal_transfer"]);
        assert_eq!(findings[0].file, "src/ledger.rs");

        let guarded = unguarded.replace("self.internal", "require!(receiver_id != env::predecessor_account_id()); self.internal");
        assert!(check(&[("src/lib.rs", &guarded), ("src/ledger.rs", helper)]).is_empty());

        let two_levels = "#[near] impl Token {
            pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) {
                let sender_id = env::predecessor_account_id();
                if sender_id == receiver_id { return; }
                self.route(&sender_id, &receiver_id, amount.0);
            }
            fn route(&mut self, a: &AccountId, b: &AccountId, amount: u128) { self.internal_transfer(a, b, amount); }
        }";
        assert!(check(&[("src/lib.rs", two_levels), ("src/ledger.rs", helper)]).is_empty());

        let free_caller = "fn route(a: &AccountId, b: &AccountId) { assert_ne!(a, b); token().internal_transfer(a, b, 1); }";
        assert!(check(&[("src/lib.rs", free_caller), ("src/ledger.rs", helper)]).is_empty());
    }

    const HELPER: &str = r#"impl Token {
        fn internal_transfer(&mut self, sender_id: &AccountId, receiver_id: &AccountId, amount: u128) {
            let sender_balance = self.balances.get(sender_id).copied().unwrap_or(0);
            let receiver_balance = self.balances.get(receiver_id).copied().unwrap_or(0);
            self.balances.insert(sender_id.clone(), sender_balance - amount);
            self.balances.insert(receiver_id.clone(), receiver_balance + amount);
        }
    }"#;

    #[test]
    fn a_caller_comparison_of_other_values_does_not_hide_the_helper() {
        let callers = [
            "pub fn ft_transfer(&mut self, to: AccountId, amount: u128) { require!(self.owner == self.admin); self.internal_transfer(&env::predecessor_account_id(), &to, amount); }",
            "pub fn ft_transfer(&mut self, to: AccountId, amount: u128) { require!(self.paused == false); require!(amount != MIN); self.internal_transfer(&env::predecessor_account_id(), &to, amount); }",
            "pub fn ft_transfer(&mut self, to: AccountId, amount: u128) { let from = env::predecessor_account_id(); require!(from != self.banned); self.internal_transfer(&from, &to, amount); }",
        ];
        for caller in callers {
            let source = format!("#[near] impl Token {{ {caller} }}");
            let findings = check(&[("src/lib.rs", &source), ("src/ledger.rs", HELPER)]);
            assert_eq!(items(&findings), ["Token::internal_transfer"], "{caller}");
        }
    }

    #[test]
    fn a_caller_comparison_of_a_passed_account_guards_the_helper() {
        let callers = [
            "pub fn ft_transfer(&mut self, to: AccountId, amount: u128) { require!(to != env::predecessor_account_id()); self.internal_transfer(&env::predecessor_account_id(), &to, amount); }",
            "pub fn ft_transfer(&mut self, to: AccountId, amount: u128) { let from = env::predecessor_account_id(); assert_ne!(from, to); self.internal_transfer(&from, &to, amount); }",
            "pub fn ft_transfer(&mut self, to: AccountId, amount: u128) { let from = env::predecessor_account_id(); if from == to { return; } self.internal_transfer(&from, &to.clone(), amount); }",
            "pub fn ft_transfer(&mut self, to: AccountId, amount: u128) { let from = env::predecessor_account_id(); require!(from != to); Self::internal_transfer(self, &from, &to, amount); }",
            "pub fn ft_transfer(&mut self, to: AccountId, amount: u128) { let from = env::predecessor_account_id(); require!(from != to); Token::internal_transfer(self, &from, &to, amount); }",
        ];
        for caller in callers {
            let source = format!("#[near] impl Token {{ {caller} }}");
            let findings = check(&[("src/lib.rs", &source), ("src/ledger.rs", HELPER)]);
            assert!(findings.is_empty(), "{caller}: {findings:?}");
        }
    }

    #[test]
    fn a_guard_carries_through_an_intermediate_function_only_by_its_parameters() {
        let route = "fn route(&mut self, a: &AccountId, b: &AccountId, amount: u128) { self.internal_transfer(a, b, amount); }";
        let guarded = format!(
            "#[near] impl Token {{ {route} pub fn ft_transfer(&mut self, to: AccountId, amount: u128) {{
                let from = env::predecessor_account_id(); require!(from != to); self.route(&from, &to, amount); }} }}"
        );
        assert!(check(&[("src/lib.rs", &guarded), ("src/ledger.rs", HELPER)]).is_empty());

        let other_accounts = guarded.replace("self.route(&from, &to, amount)", "self.route(&self.a, &self.b, amount)");
        assert_eq!(items(&check(&[("src/lib.rs", &other_accounts), ("src/ledger.rs", HELPER)])), ["Token::internal_transfer"]);

        let one_account = guarded.replace("self.route(&from, &to, amount)", "self.route(&from, &self.b, amount)");
        let findings = check(&[("src/lib.rs", &one_account), ("src/ledger.rs", HELPER)]);
        assert_eq!(items(&findings), ["Token::internal_transfer"], "`to` is not passed on, so `from != to` guards nothing");
    }

    #[test]
    fn a_caller_guards_the_one_key_that_is_a_parameter() {
        let transfer = TOKEN.replace("pub fn ft_transfer", "pub fn ft_transfer_inner");
        let caller = "#[near] impl Token { pub fn ft_transfer(&mut self, to: AccountId, a: U128) { require!(to != env::predecessor_account_id()); self.ft_transfer_inner(to, a); } }";
        let findings = check(&[("src/lib.rs", &transfer), ("src/caller.rs", caller)]);
        assert!(findings.is_empty(), "`receiver_id` is a parameter, and `to` is passed for it: {findings:?}");
        let unrelated = caller.replace("to != env::predecessor_account_id()", "a != self.x");
        assert_eq!(items(&check(&[("src/lib.rs", &transfer), ("src/caller.rs", &unrelated)])), ["Token::ft_transfer_inner"]);
    }

    #[test]
    fn a_caller_cycle_with_parameters_terminates() {
        let source = HELPER.to_owned()
            + "fn a(x: AccountId, y: AccountId) { b(x, y); Token::internal_transfer(x, y); } fn b(x: AccountId, y: AccountId) { a(x, y); }";
        assert_eq!(items(&one(&source)), ["Token::internal_transfer"]);
    }

    #[test]
    fn a_caller_cycle_terminates() {
        let source = TOKEN.to_owned() + "fn a() { b(); ft_transfer(); } fn b() { a(); }";
        assert_eq!(items(&one(&source)), ["Token::ft_transfer"]);
    }

    #[test]
    fn a_transfer_calling_itself_is_not_its_own_caller() {
        let source = TOKEN.replace("assert_one_yocto();", "if false { self.ft_transfer(x, y); require!(a == b); }");
        assert_eq!(items(&one(&source)), ["Token::ft_transfer"]);
    }

    #[test]
    fn reports_each_transfer_once() {
        let source = format!("{TOKEN} {}", TOKEN.replace("Token", "Other").replace("ft_transfer", "transfer"));
        assert_eq!(items(&one(&source)), ["Token::ft_transfer", "Other::transfer"]);
    }
}
