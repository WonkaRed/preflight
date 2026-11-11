//! PF009: a token receiver that never checks which contract called it.
//!
//! `ft_on_transfer` (NEP-141), `mt_on_transfer` (NEP-245) and `nft_on_transfer` (NEP-171) are plain public methods:
//! the token contract calls them after moving tokens, but nothing stops anyone else from calling them directly or
//! from deploying a worthless token and calling `ft_transfer_call` on it. Unless the receiver compares
//! `env::predecessor_account_id()` with the token it expects, the `amount` and `sender_id` it is handed are
//! whatever the caller says, and a worthless token buys real credit. Docs:
//! https://docs.near.org/smart-contracts/security/cross-contract-calls/ft-transfer-call
//!
//! A method is checked when the `#[near]` macro exports it (`pub` method of an inherent impl, or any method of a
//! trait impl) and it is named `ft_on_transfer`, `mt_on_transfer` or `nft_on_transfer`. It is reported when it
//! writes contract state and neither it nor a same-crate function it reaches mentions `predecessor_account_id`.
//!
//! Writes state: an assignment or compound assignment (`=`, `+=`, ...) to a place on `self`, or a call of
//! `insert`, `set`, `push`, `push_back`, `push_front`, `extend`, `remove`, `swap_remove`, `get_mut` or `entry` on
//! a place on `self` (`self.balances`, `self.pool.shares`, `self.orders[id]`). A function that does none of these
//! (it only parses `msg` and returns the whole amount, say) credits nothing and is not reported.
//!
//! Mentions `predecessor_account_id`: any path ending in it (`env::predecessor_account_id()`,
//! `near_sdk::env::predecessor_account_id`, a bare imported call), including inside macro arguments such as
//! `require!(env::predecessor_account_id() == self.token)`. Any mention counts, not only a comparison with a
//! stored token: a receiver that keys its balances by the calling token account is correct and stays silent.
//! `signer_account_id()` does not count, since the signer is the user, never the token. Reachable functions are
//! found by name (free function, inherent or trait method, any file of the crate), so a guard in a helper such as
//! `self.assert_token()` is followed.
//!
//! Knowingly missed: a credit made only by forwarding a promise to another contract; a state write inside a macro
//! the scanner cannot read; a receiver registered under another name (`on_transfer`); a write through a local that
//! is not a place on `self`. Knowingly noisy: a guard in another crate or hidden in a macro (the rule sees no
//! mention, so it reports a receiver that is in fact guarded). The name-based call match is lenient on both
//! sides: an unrelated same-named function can hide a missing guard or supply a write.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{Delimiter, Span, TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{
    Attribute, Block, Expr, ExprAssign, ExprBinary, ExprCall, ExprMethodCall, Ident, ImplItem, ImplItemFn, ItemFn,
    ItemImpl, Path, TraitItemFn, Type, Visibility,
};

use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf009UncheckedToken;

pub static RULE: Pf009UncheckedToken = Pf009UncheckedToken;

impl Rule for Pf009UncheckedToken {
    fn id(&self) -> &'static str {
        "PF009"
    }

    fn title(&self) -> &'static str {
        "Token receiver does not check the calling token"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn help(&self) -> &'static str {
        "require env::predecessor_account_id() to equal the expected token contract before crediting anything"
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
        let by_name = functions_by_name(&scans);

        let mut findings = Vec::new();
        for (file, scan) in krate.files.iter().zip(&scans) {
            for func in &scan.functions {
                let Some(export) = &func.export else { continue };
                if !RECEIVERS.contains(&func.name.as_str()) {
                    continue;
                }
                let reach = reach(func, &by_name);
                if reach.writes_state && !reach.mentions_predecessor {
                    findings.push(self.finding(
                        file,
                        export.span,
                        format!("{}::{}", export.owner, func.name),
                        format!(
                            "`{}::{}` writes contract state but never reads `env::predecessor_account_id()`, so any account, or a worthless token contract, can call it and be credited",
                            export.owner, func.name
                        ),
                    ));
                }
            }
        }
        findings
    }
}

/// The NEP receiver hooks: the methods a token contract calls on the account it sends tokens to.
const RECEIVERS: [&str; 3] = ["ft_on_transfer", "mt_on_transfer", "nft_on_transfer"];

/// Methods that change a collection held on `self`.
const WRITE_METHODS: [&str; 10] =
    ["insert", "set", "push", "push_back", "push_front", "extend", "remove", "swap_remove", "get_mut", "entry"];

const PREDECESSOR: &str = "predecessor_account_id";

/// What the scan keeps of one function.
#[derive(Default)]
struct Func {
    name: String,
    /// Names its body calls, including calls written inside macro arguments.
    calls: BTreeSet<String>,
    writes_state: bool,
    mentions_predecessor: bool,
    /// Set when the `#[near]` macro exports the function.
    export: Option<Export>,
}

struct Export {
    owner: String,
    span: Span,
}

#[derive(Default)]
struct FileScan {
    /// Every function with a body in the file, exported or not.
    functions: Vec<Func>,
}

fn functions_by_name(scans: &[FileScan]) -> BTreeMap<&str, Vec<&Func>> {
    let mut by_name: BTreeMap<&str, Vec<&Func>> = BTreeMap::new();
    for func in scans.iter().flat_map(|scan| &scan.functions) {
        by_name.entry(func.name.as_str()).or_default().push(func);
    }
    by_name
}

/// What `start` and the same-crate functions it calls, transitively, do between them.
#[derive(Default)]
struct Reach {
    writes_state: bool,
    mentions_predecessor: bool,
}

fn reach(start: &Func, by_name: &BTreeMap<&str, Vec<&Func>>) -> Reach {
    let mut reach = Reach::default();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut stack = vec![start];
    while let Some(func) = stack.pop() {
        reach.writes_state |= func.writes_state;
        reach.mentions_predecessor |= func.mentions_predecessor;
        for call in &func.calls {
            if let Some((name, defined)) = by_name.get_key_value(call.as_str())
                && seen.insert(name)
            {
                stack.extend(defined);
            }
        }
    }
    reach
}

/// `#[near]`, `#[near(..)]` or `#[near_bindgen]`, possibly path-qualified (`#[near_sdk::near]`).
fn is_near_attr(attr: &Attribute) -> bool {
    attr.path().segments.last().is_some_and(|segment| segment.ident == "near" || segment.ident == "near_bindgen")
}

impl<'ast> Visit<'ast> for FileScan {
    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        let near = item.attrs.iter().any(is_near_attr);
        let owner = type_name(&item.self_ty);
        for member in &item.items {
            if let ImplItem::Fn(method) = member {
                let mut func = func_of(&method.sig.ident, &method.block);
                if near && (item.trait_.is_some() || matches!(method.vis, Visibility::Public(_))) {
                    func.export = Some(export_of(&owner, method));
                }
                self.functions.push(func);
            }
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.functions.push(func_of(&item.sig.ident, &item.block));
        visit::visit_item_fn(self, item);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast TraitItemFn) {
        if let Some(block) = &item.default {
            self.functions.push(func_of(&item.sig.ident, block));
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

fn export_of(owner: &str, method: &ImplItemFn) -> Export {
    Export { owner: owner.to_owned(), span: method.sig.ident.span() }
}

fn func_of(name: &Ident, block: &Block) -> Func {
    let mut body = BodyScan::default();
    body.visit_block(block);
    Func {
        name: name.to_string(),
        calls: body.calls,
        writes_state: body.writes_state,
        mentions_predecessor: body.mentions_predecessor,
        export: None,
    }
}

/// What one function body does, including inside macro arguments.
#[derive(Default)]
struct BodyScan {
    calls: BTreeSet<String>,
    writes_state: bool,
    mentions_predecessor: bool,
}

impl BodyScan {
    /// Reads the tokens of a macro call: names called as `name(..)`, and any mention of the predecessor.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        let mut previous: Option<String> = None;
        for tree in tokens {
            match tree {
                TokenTree::Ident(ident) => {
                    self.mentions_predecessor |= ident == PREDECESSOR;
                    previous = Some(ident.to_string());
                }
                TokenTree::Group(group) => {
                    if group.delimiter() == Delimiter::Parenthesis
                        && let Some(name) = previous.take()
                    {
                        self.calls.insert(name);
                    }
                    previous = None;
                    self.scan_tokens(group.stream());
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => previous = None,
            }
        }
    }
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_path(&mut self, path: &'ast Path) {
        self.mentions_predecessor |= path.segments.last().is_some_and(|segment| segment.ident == PREDECESSOR);
        visit::visit_path(self, path);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(func) = &*call.func
            && let Some(last) = func.path.segments.last()
        {
            self.calls.insert(last.ident.to_string());
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let name = call.method.to_string();
        self.writes_state |= WRITE_METHODS.contains(&name.as_str()) && is_place_on_self(&call.receiver);
        self.calls.insert(name);
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_assign(&mut self, assign: &'ast ExprAssign) {
        self.writes_state |= is_place_on_self(&assign.left);
        visit::visit_expr_assign(self, assign);
    }

    /// `+=` and the other compound assignments are binary expressions in syn.
    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        self.writes_state |= is_compound_assignment(binary) && is_place_on_self(&binary.left);
        visit::visit_expr_binary(self, binary);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.scan_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

fn is_compound_assignment(binary: &ExprBinary) -> bool {
    use syn::BinOp::{AddAssign, BitAndAssign, BitOrAssign, BitXorAssign, DivAssign, MulAssign, RemAssign};
    use syn::BinOp::{ShlAssign, ShrAssign, SubAssign};
    matches!(
        binary.op,
        AddAssign(_)
            | SubAssign(_)
            | MulAssign(_)
            | DivAssign(_)
            | RemAssign(_)
            | BitXorAssign(_)
            | BitAndAssign(_)
            | BitOrAssign(_)
            | ShlAssign(_)
            | ShrAssign(_)
    )
}

/// Whether `expr` is `self` or a field, index, dereference or borrow of a place on it: `self.total`,
/// `self.balances`, `self.orders[id]`, `*self.pool`.
fn is_place_on_self(expr: &Expr) -> bool {
    match expr {
        Expr::Path(path) => path.path.is_ident("self"),
        Expr::Field(field) => is_place_on_self(&field.base),
        Expr::Index(index) => is_place_on_self(&index.expr),
        Expr::Unary(unary) => is_place_on_self(&unary.expr),
        Expr::Paren(paren) => is_place_on_self(&paren.expr),
        Expr::Reference(reference) => is_place_on_self(&reference.expr),
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

    fn one(source: &str) -> Vec<Finding> {
        check(&[("src/lib.rs", source)])
    }

    fn items(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|finding| finding.item.as_str()).collect()
    }

    const VAULT: &str = r#"
        #[near]
        impl Vault {
            pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> PromiseOrValue<U128> {
                let held = self.deposits.get(&sender_id).copied().unwrap_or(0);
                self.deposits.insert(sender_id, held + amount.0);
                PromiseOrValue::Value(U128(0))
            }
        }
    "#;

    #[test]
    fn flags_a_receiver_that_credits_without_checking_the_token_and_locates_it() {
        let findings = one(VAULT);
        assert_eq!(items(&findings), ["Vault::ft_on_transfer"]);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF009", Severity::Critical));
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 4, 20));
        assert!(finding.message.contains("`Vault::ft_on_transfer`") && finding.message.contains("predecessor"));
    }

    #[test]
    fn flags_every_receiver_hook() {
        for hook in ["ft_on_transfer", "mt_on_transfer", "nft_on_transfer"] {
            let source = VAULT.replace("ft_on_transfer", hook);
            assert_eq!(items(&one(&source)), [format!("Vault::{hook}").as_str()], "{hook}");
        }
    }

    #[test]
    fn every_form_of_the_predecessor_check_is_clean() {
        let guards = [
            "require!(env::predecessor_account_id() == self.token, \"wrong token\");",
            "assert_eq!(near_sdk::env::predecessor_account_id(), self.token);",
            "if predecessor_account_id() != self.token { env::panic_str(\"wrong token\"); }",
            "let token = env::predecessor_account_id(); require!(self.allowed.contains(&token));",
            "self.assert_token();",
        ];
        let helper = "impl Vault { fn assert_token(&self) { require!(env::predecessor_account_id() == self.token); } }";
        for guard in guards {
            let source = VAULT.replace("let held", &format!("{guard} let held")) + helper;
            assert!(one(&source).is_empty(), "{guard}");
        }
    }

    #[test]
    fn a_receiver_that_keys_its_balances_by_the_calling_token_is_clean() {
        let source = "#[near] impl Vault {
            pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> U128 {
                let key = (env::predecessor_account_id(), sender_id);
                self.deposits.insert(key, amount.0);
                U128(0)
            }
        }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn a_checked_receiver_that_forwards_a_call_is_clean() {
        let source = "#[near] impl Vault {
            pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> Promise {
                require!(env::predecessor_account_id() == self.token, \"wrong token\");
                self.deposits.insert(sender_id.clone(), amount.0);
                ext_pool::ext(self.pool.clone()).stake(sender_id, amount)
            }
        }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn the_signer_is_not_the_token() {
        let source = VAULT.replace("let held", "require!(env::signer_account_id() == sender_id); let held");
        assert_eq!(items(&one(&source)), ["Vault::ft_on_transfer"]);
    }

    #[test]
    fn a_receiver_that_changes_no_state_is_clean() {
        let source = "#[near] impl Vault {
            pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> PromiseOrValue<U128> {
                log!(\"refusing {} from {}\", amount.0, sender_id);
                PromiseOrValue::Value(amount)
            }
        }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn every_kind_of_state_write_is_found() {
        let writes = [
            "self.total += amount.0;",
            "self.total = amount.0;",
            "self.deposits.set(sender_id, Some(amount.0));",
            "self.queue.push_back(amount.0);",
            "self.orders.remove(&msg);",
            "*self.deposits.get_mut(&sender_id).unwrap() += amount.0;",
            "*self.deposits.entry(sender_id).or_insert(0) += amount.0;",
            "self.pool.shares[0] -= 1;",
            "(*self).total += amount.0;",
        ];
        for write in writes {
            let source = format!(
                "#[near] impl Vault {{ pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> U128 {{ {write} U128(0) }} }}"
            );
            assert_eq!(items(&one(&source)), ["Vault::ft_on_transfer"], "{write}");
        }
    }

    #[test]
    fn writes_to_locals_and_other_receivers_are_not_state_writes() {
        let source = "#[near] impl Vault {
            pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> U128 {
                let mut seen = Vec::new();
                seen.push(amount.0);
                let mut total = 0;
                total += amount.0;
                U128(total)
            }
        }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn follows_a_credit_helper_in_the_crate_and_in_another_file() {
        let receiver = "#[near] impl Vault {
            pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> U128 {
                self.credit(sender_id, amount.0);
                U128(0)
            }
        }";
        assert!(one(receiver).is_empty(), "an undefined helper writes nothing the scan can see");

        let helper = "impl Vault { fn credit(&mut self, who: AccountId, amount: u128) { self.deposits.insert(who, amount); } }";
        let findings = check(&[("src/lib.rs", receiver), ("src/ledger.rs", helper)]);
        assert_eq!(items(&findings), ["Vault::ft_on_transfer"]);
        assert_eq!(findings[0].file, "src/lib.rs");

        let guarded = format!("{helper} fn only_token() {{ require!(env::predecessor_account_id() == TOKEN); }}");
        let guarded_receiver = receiver.replace("self.credit", "only_token(); self.credit");
        assert!(check(&[("src/lib.rs", &guarded_receiver), ("src/ledger.rs", &guarded)]).is_empty());
    }

    #[test]
    fn a_helper_cycle_terminates() {
        let source = VAULT.replace("let held", "ping(); let held") + "fn ping() { pong(); } fn pong() { ping(); }";
        assert_eq!(items(&one(&source)), ["Vault::ft_on_transfer"]);
    }

    #[test]
    fn checks_a_trait_impl_and_both_near_spellings() {
        for attr in ["#[near_bindgen]", "#[near_sdk::near]", "#[near(contract_state)]", "#[near]"] {
            let source = format!(
                "{attr} impl FungibleTokenReceiver for Vault {{
                    fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> U128 {{
                        self.total += amount.0;
                        U128(0)
                    }}
                }}"
            );
            assert_eq!(items(&one(&source)), ["Vault::ft_on_transfer"], "{attr}");
        }
    }

    #[test]
    fn methods_the_near_macro_does_not_export_are_ignored() {
        let source = "
            impl NotNear { pub fn ft_on_transfer(&mut self, amount: U128) { self.total += amount.0; } }
            #[near] impl Vault {
                fn ft_on_transfer(&mut self, amount: U128) { self.total += amount.0; }
                pub(crate) fn mt_on_transfer(&mut self, amount: U128) { self.total += amount.0; }
            }
            fn ft_on_transfer(amount: U128) { STATE.total += amount.0; }
            #[ext_contract(ext_receiver)] trait Receiver { fn nft_on_transfer(&mut self, amount: U128); }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn other_methods_are_not_receiver_hooks() {
        let source = "#[near] impl Vault { pub fn deposit(&mut self, amount: U128) { self.total += amount.0; } }";
        assert!(one(source).is_empty());
    }

    #[test]
    fn reports_each_receiver_once() {
        let source = format!("{VAULT} #[near] impl Pool {{ pub fn mt_on_transfer(&mut self) {{ self.total += 1; }} }}");
        assert_eq!(items(&one(&source)), ["Vault::ft_on_transfer", "Pool::mt_on_transfer"]);
    }
}
