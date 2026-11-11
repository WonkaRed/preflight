//! PF023: a NEP token method that changes state without ever looking at who is calling.
//!
//! The NFT and multi-token standards say who may call their change methods: `nft_transfer`, `nft_transfer_call`,
//! `nft_approve`, `nft_revoke` and `nft_revoke_all` "MUST panic if called by someone other than token owner" (or,
//! for the transfers, an approved account), and so do the NEP-245 `mt_transfer`, `mt_batch_transfer`,
//! `mt_transfer_call` and `mt_batch_transfer_call`. A hand-written implementation whose body never reads the
//! caller lets any account move, approve for, or strip approvals from a token it does not own. Docs:
//! https://github.com/near/NEPs/blob/master/neps/nep-0171.md, nep-0178.md and nep-0245.md; Rustle's `nft-owner-check`
//! and `nft-approval-check` detectors are the same finding.
//!
//! A method is reported when all of these hold:
//! - the `#[near]` / `#[near_bindgen]` macro exports it (`pub` method of an inherent impl, or any method of a
//!   trait impl), it takes `&mut self`, and its name is one of the nine above;
//! - it is not `#[private]` and carries no attribute macro the scanner does not know (`#[payable]`,
//!   `#[handle_result]`, `#[result_serializer]`, `#[init]`, `#[allow]`, `#[expect]`, `#[warn]`, `#[deny]`, `#[doc]`,
//!   `#[inline]`, `#[must_use]` and `#[cfg]` are known; an unknown one, such as near-plugins' `#[only(..)]`, may be
//!   an access guard);
//! - neither it nor a same-crate function it reaches (found by name through bare calls, `Self::f` / `Type::f` /
//!   `module::f` paths, method calls and crate-local `macro_rules!`) mentions `predecessor_account_id` or
//!   `signer_account_id`, including inside macro arguments such as `require!`, and it does not hand the call to a
//!   standard implementation held in a field: `self.tokens.nft_transfer(..)` inside `nft_transfer`;
//! - it changes the contract's state: it, or a function it reaches, assigns a place on `self` (`=`, `+=`, ...),
//!   borrows one as `&mut`, or calls `insert`, `remove`, `push`, `push_back`, `push_front`, `pop`, `extend`,
//!   `clear`, `retain`, `set`, `replace`, `take`, `swap_remove`, `truncate`, `append`, `drain`, `get_mut` or `entry`
//!   on one. A method that changes nothing it can see (it only forwards to another contract, or to a function the
//!   scanner cannot resolve) is not reported.
//!
//! A `signer_account_id()` check counts as a caller check here: it is a wrong one (PF011 reports it), but the
//! method does look at the caller.
//!
//! Relation to PF007 and PF013: PF007 reports an unguarded method only when it writes a field that some other
//! method compares with the caller (or changes the contract's own account), PF013 only a privileged-named method
//! of a trait impl. PF023 needs neither: the NEP name is what says the caller must be checked. A method that
//! matches more than one is reported by each, because each finding is true. PF002 asks for the 1 yoctoNEAR these
//! methods must also require, which is a separate defect.
//!
//! Knowingly missed: a partial check (the owner is checked but the approval id is not, or the other way round);
//! a method that reads the caller but does not compare it with the owner (the rule asks only whether the caller
//! is looked at); a standard implementation that lives in a crate-local struct and is delegated to by name, which
//! counts as trusted; ownership checks hidden in a macro or a function the rule cannot resolve by name, which are
//! reported only if the method also writes state visibly. Knowingly noisy: a guard inside another crate that is
//! reached through a function with a different name from the NEP method, when the method also writes state.

use std::collections::BTreeSet;

use proc_macro2::Span;
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Attribute, BinOp, Expr, ExprAssign, ExprBinary, ExprCall, ExprMethodCall, ExprPath, ExprReference, FnArg,
    ImplItemFn, ItemFn, ItemImpl, ItemMacro, Macro, Signature, Token, TraitItemFn, Visibility,
};

use super::pf007_unguarded_admin::{
    CALLER_FNS, CallRef, call_ref, field_path, is_near_attr, tokens_contain, type_name,
};
use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf023NepMethodAuth;

pub static RULE: Pf023NepMethodAuth = Pf023NepMethodAuth;

impl Rule for Pf023NepMethodAuth {
    fn id(&self) -> &'static str {
        "PF023"
    }

    fn title(&self) -> &'static str {
        "NEP token method that never checks the caller"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn help(&self) -> &'static str {
        "read env::predecessor_account_id() and panic unless it is the token's owner or an approved account, as the NEP requires"
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
            let Some((_, standard)) = NEP_METHODS.iter().find(|(name, _)| *name == function.name) else { continue };
            if !export.mut_self || export.shielded {
                continue;
            }
            let reach = reachable(&fns, id);
            if reach.iter().any(|&reached| fns[reached].checks_caller) {
                continue;
            }
            let written: BTreeSet<&str> =
                reach.iter().flat_map(|&reached| fns[reached].writes.iter().map(String::as_str)).collect();
            if written.is_empty() {
                continue;
            }
            let item = format!("{}::{}", function.owner.as_deref().unwrap_or_default(), function.name);
            let places: Vec<String> = written.iter().map(|place| format!("`self.{place}`")).collect();
            let message = format!(
                "`{item}` implements the {standard} method `{}`, which must panic unless the caller owns the token or \
                 is approved, but it changes {} and never checks the caller (no `env::predecessor_account_id()` or \
                 `env::signer_account_id()` on any path from it), so any account can call it",
                function.name,
                places.join(", ")
            );
            findings.push(self.finding(&krate.files[function.file], export.span, item, message));
        }
        findings
    }
}

/// The NEP methods whose standard says the caller must be the token's owner or an approved account.
const NEP_METHODS: [(&str, &str); 9] = [
    ("nft_transfer", "NEP-171"),
    ("nft_transfer_call", "NEP-171"),
    ("nft_approve", "NEP-178"),
    ("nft_revoke", "NEP-178"),
    ("nft_revoke_all", "NEP-178"),
    ("mt_transfer", "NEP-245"),
    ("mt_batch_transfer", "NEP-245"),
    ("mt_transfer_call", "NEP-245"),
    ("mt_batch_transfer_call", "NEP-245"),
];

/// Attributes on a method that the scanner knows are not access guards.
const KNOWN_ATTRS: [&str; 12] = [
    "payable",
    "handle_result",
    "result_serializer",
    "init",
    "allow",
    "expect",
    "warn",
    "deny",
    "doc",
    "inline",
    "must_use",
    "cfg",
];

/// Methods that change the collection or value they are called on.
const MUTATORS: [&str; 18] = [
    "insert",
    "remove",
    "push",
    "push_back",
    "push_front",
    "pop",
    "extend",
    "clear",
    "retain",
    "set",
    "replace",
    "take",
    "swap_remove",
    "truncate",
    "append",
    "drain",
    "get_mut",
    "entry",
];

struct Export {
    span: Span,
    mut_self: bool,
    /// `#[private]`, or an attribute macro that may be an access guard.
    shielded: bool,
}

#[derive(Default)]
struct FnFacts {
    file: usize,
    /// `name!` for a macro.
    name: String,
    owner: Option<String>,
    has_receiver: bool,
    export: Option<Export>,
    /// Mentions `predecessor_account_id` or `signer_account_id`, or hands the call to a standard implementation.
    checks_caller: bool,
    calls: Vec<CallRef>,
    /// The places on `self` it changes, as `a.b` paths.
    writes: BTreeSet<String>,
}

#[derive(Default)]
struct Collector {
    file: usize,
    fns: Vec<FnFacts>,
    frames: Vec<FnFacts>,
    impl_context: Option<ImplContext>,
}

struct ImplContext {
    owner: String,
    exports: bool,
    is_trait_impl: bool,
}

impl Collector {
    fn begin_fn(&mut self, sig: &Signature, attrs: &[Attribute], exported: bool) {
        let export = exported.then(|| Export {
            span: sig.ident.span(),
            mut_self: sig
                .receiver()
                .is_some_and(|receiver| receiver.reference.is_some() && receiver.mutability.is_some()),
            shielded: attrs.iter().any(|attr| {
                attr.path().is_ident("private")
                    || attr
                        .path()
                        .segments
                        .last()
                        .is_none_or(|segment| !KNOWN_ATTRS.iter().any(|known| segment.ident == known))
            }),
        });
        self.frames.push(FnFacts {
            file: self.file,
            name: sig.ident.to_string(),
            owner: self.impl_context.as_ref().map(|context| context.owner.clone()),
            has_receiver: sig.inputs.iter().any(|arg| matches!(arg, FnArg::Receiver(_))),
            export,
            ..FnFacts::default()
        });
    }

    fn end_fn(&mut self) {
        self.fns.extend(self.frames.pop());
    }

    /// Runs `walk` over a free or trait function, which is never in an impl even when nested inside one.
    fn in_free_fn(&mut self, sig: &Signature, attrs: &[Attribute], walk: impl FnOnce(&mut Self)) {
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

    fn visit_item_macro(&mut self, item: &'ast ItemMacro) {
        match (item.mac.path.get_ident(), &item.ident) {
            (Some(path), Some(name)) if path == "macro_rules" => self.fns.push(FnFacts {
                file: self.file,
                name: format!("{name}!"),
                checks_caller: tokens_contain(&item.mac.tokens, &CALLER_FNS),
                ..FnFacts::default()
            }),
            _ => visit::visit_item_macro(self, item),
        }
    }

    fn visit_expr_path(&mut self, path: &'ast ExprPath) {
        if let (Some(segment), Some(frame)) = (path.path.segments.last(), self.frames.last_mut())
            && CALLER_FNS.iter().any(|name| segment.ident == name)
        {
            frame.checks_caller = true;
        }
        visit::visit_expr_path(self, path);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let (Expr::Path(func), Some(frame)) = (&*call.func, self.frames.last_mut()) {
            let segments: Vec<String> = func.path.segments.iter().map(|segment| segment.ident.to_string()).collect();
            frame.calls.extend(call_ref(&segments, self.impl_context.as_ref().map(|context| context.owner.as_str())));
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if let Some(frame) = self.frames.last_mut() {
            let name = call.method.to_string();
            if CALLER_FNS.contains(&name.as_str()) || (name == frame.name && field_path(&call.receiver).is_some()) {
                frame.checks_caller = true;
            }
            if MUTATORS.contains(&name.as_str()) {
                frame.writes.extend(field_path(&call.receiver).map(|place| place.join(".")));
            }
            frame.calls.push(CallRef::Method(name));
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_assign(&mut self, assign: &'ast ExprAssign) {
        if let Some(frame) = self.frames.last_mut() {
            frame.writes.extend(field_path(&assign.left).map(|place| place.join(".")));
        }
        visit::visit_expr_assign(self, assign);
    }

    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        if let Some(frame) = self.frames.last_mut()
            && is_compound_assignment(&binary.op)
        {
            frame.writes.extend(field_path(&binary.left).map(|place| place.join(".")));
        }
        visit::visit_expr_binary(self, binary);
    }

    fn visit_expr_reference(&mut self, reference: &'ast ExprReference) {
        if reference.mutability.is_some()
            && let Some(frame) = self.frames.last_mut()
        {
            frame.writes.extend(field_path(&reference.expr).map(|place| place.join(".")));
        }
        visit::visit_expr_reference(self, reference);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        let Some(name) = mac.path.segments.last().map(|segment| segment.ident.to_string()) else { return };
        if let Some(frame) = self.frames.last_mut() {
            frame.calls.push(CallRef::Macro(format!("{name}!")));
        }
        // `require!`, `assert!`, `assert_eq!`, `format!` ... take comma-separated expressions: parse and walk them.
        match Punctuated::<Expr, Token![,]>::parse_terminated.parse2(mac.tokens.clone()) {
            Ok(arguments) => arguments.iter().for_each(|argument| self.visit_expr(argument)),
            Err(_) if tokens_contain(&mac.tokens, &CALLER_FNS) => {
                if let Some(frame) = self.frames.last_mut() {
                    frame.checks_caller = true;
                }
            }
            Err(_) => {}
        }
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

    /// `body` as the body of `nft_transfer` in a `#[near]` impl.
    fn transfer(body: &str) -> String {
        format!(
            "#[near] impl Tickets {{ pub fn nft_transfer(&mut self, receiver_id: AccountId, token_id: String) {{ {body} }} }}"
        )
    }

    #[test]
    fn flags_a_transfer_that_never_looks_at_the_caller_and_locates_it() {
        let source = "#[near]\nimpl Tickets {\n    #[payable]\n    pub fn nft_transfer(&mut self, receiver_id: AccountId, token_id: String) {\n        assert_one_yocto();\n        self.owner_by_id.insert(token_id, receiver_id);\n    }\n}";
        let findings = check(&[("src/lib.rs", source)]);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF023", Severity::High));
        assert_eq!(finding.item, "Tickets::nft_transfer");
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 4, 12));
        assert!(
            finding.message.contains("NEP-171 method `nft_transfer`") && finding.message.contains("`self.owner_by_id`"),
            "{}",
            finding.message
        );
    }

    #[test]
    fn flags_every_nep_method_and_names_its_standard() {
        let methods = [
            ("nft_transfer", "NEP-171"),
            ("nft_transfer_call", "NEP-171"),
            ("nft_approve", "NEP-178"),
            ("nft_revoke", "NEP-178"),
            ("nft_revoke_all", "NEP-178"),
            ("mt_transfer", "NEP-245"),
            ("mt_batch_transfer", "NEP-245"),
            ("mt_transfer_call", "NEP-245"),
            ("mt_batch_transfer_call", "NEP-245"),
        ];
        for (name, standard) in methods {
            let source = format!(
                "#[near] impl Tickets {{ pub fn {name}(&mut self, id: String) {{ self.owners.remove(&id); }} }}"
            );
            let findings = check(&[("src/lib.rs", &source)]);
            assert_eq!(findings.len(), 1, "{name}");
            assert!(findings[0].message.contains(&format!("{standard} method `{name}`")), "{}", findings[0].message);
        }
    }

    #[test]
    fn accepts_near_bindgen_path_qualified_near_and_trait_impls() {
        let body = "self.owners.insert(id, who);";
        for attr in ["#[near_bindgen]", "#[near_sdk::near]", "#[near(contract_state)]"] {
            let source = format!("{attr} impl Tickets {{ pub fn nft_revoke_all(&mut self, id: String) {{ {body} }} }}");
            assert_eq!(items(&source), ["Tickets::nft_revoke_all"], "{attr}");
        }
        let trait_impl = format!(
            "#[near] impl NonFungibleTokenCore for Tickets {{ fn nft_revoke_all(&mut self, id: String) {{ {body} }} }}"
        );
        assert_eq!(items(&trait_impl), ["Tickets::nft_revoke_all"]);
    }

    #[test]
    fn flags_every_way_of_changing_state() {
        let writes = [
            "self.owner = receiver_id;",
            "self.state.owner = receiver_id;",
            "self.count += 1;",
            "self.owners.insert(token_id, receiver_id);",
            "self.owners.remove(&token_id);",
            "self.approved.push(token_id);",
            "self.approved.clear();",
            "self.owners.get_mut(&token_id).unwrap().push(1);",
            "*self.owners.entry(token_id).or_insert(0) = 1;",
            "std::mem::take(&mut self.approved);",
            "self.owners[0].insert(token_id);",
            "self.approved.set(0, None);",
        ];
        for write in writes {
            assert_eq!(items(&transfer(write)), ["Tickets::nft_transfer"], "{write}");
        }
    }

    #[test]
    fn follows_a_write_made_by_a_same_crate_helper() {
        let source = "#[near] impl Tickets {
            pub fn nft_transfer(&mut self, receiver_id: AccountId, token_id: String) { self.move_token(token_id, receiver_id); }
        }
        impl Tickets { fn move_token(&mut self, id: String, to: AccountId) { self.owners.insert(id, to); } }";
        let findings = check(&[("src/lib.rs", source)]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`self.owners`"), "{}", findings[0].message);
    }

    #[test]
    fn a_caller_check_anywhere_on_the_path_makes_the_method_clean() {
        let checks = [
            "require!(env::predecessor_account_id() == self.owner);",
            "let sender = env::predecessor_account_id(); require!(self.owners.get(&token_id) == Some(&sender));",
            "require!(near_sdk::env::signer_account_id() == self.owner);",
            "if predecessor_account_id() != self.owner { env::panic_str(\"no\"); }",
            "assert_eq!(env::predecessor_account_id(), self.owner, \"{}\", 1);",
            "let who = env::predecessor_account_id;",
            "let _ = env::predecessor_account_id();",
            "self.assert_owner(token_id.clone());",
            "Self::assert_owner_static(&token_id);",
            "assert_token_owner(&token_id);",
            "tickets::assert_token_owner(&token_id);",
            "owner_only!();",
        ];
        for check in checks {
            let source = format!(
                "#[near] impl Tickets {{
                    pub fn nft_transfer(&mut self, receiver_id: AccountId, token_id: String) {{
                        {check}
                        self.owners.insert(token_id, receiver_id);
                    }}
                }}
                impl Tickets {{
                    fn assert_owner(&self, id: String) {{ require!(env::predecessor_account_id() == self.owner, \"{{}}\", id); }}
                    fn assert_owner_static(id: &str) {{ require!(env::signer_account_id() == id); }}
                }}
                fn assert_token_owner(id: &str) {{ require!(env::predecessor_account_id().as_str() == id); }}
                macro_rules! owner_only {{ () => {{ require!(env::predecessor_account_id() == OWNER) }}; }}"
            );
            assert!(items(&source).is_empty(), "{check}");
        }
    }

    #[test]
    fn a_check_made_two_calls_away_still_counts() {
        let source = "#[near] impl Tickets {
            pub fn nft_transfer(&mut self, receiver_id: AccountId, token_id: String) { self.step_one(token_id, receiver_id); }
        }
        impl Tickets {
            fn step_one(&mut self, id: String, to: AccountId) { self.step_two(&id); self.owners.insert(id, to); }
            fn step_two(&self, id: &str) { require!(self.owners.get(id) == Some(&env::predecessor_account_id())); }
        }";
        assert!(items(source).is_empty());
    }

    #[test]
    fn a_guard_in_a_function_the_method_does_not_reach_does_not_count() {
        let source = "#[near] impl Tickets {
            pub fn nft_transfer(&mut self, receiver_id: AccountId, token_id: String) { self.owners.insert(token_id, receiver_id); }
            pub fn nft_mint(&mut self, id: String) { require!(env::predecessor_account_id() == self.venue); }
        }";
        assert_eq!(items(source), ["Tickets::nft_transfer"]);
    }

    #[test]
    fn a_method_that_hands_the_call_to_a_standard_implementation_is_trusted() {
        let bodies = [
            "self.tokens.nft_transfer(receiver_id, token_id);",
            "self.tokens.nft_transfer(receiver_id, token_id); self.transfers += 1;",
            "self.state.tokens.nft_transfer(receiver_id, token_id); self.log.push(1);",
            "self.tokens[0].nft_transfer(receiver_id, token_id); self.log.push(1);",
        ];
        for body in bodies {
            assert!(items(&transfer(body)).is_empty(), "{body}");
        }
        // Calling the same name on something that is not a field of `self` is not a delegation.
        assert_eq!(
            items(&transfer("other.nft_transfer(receiver_id, token_id); self.transfers += 1;")),
            ["Tickets::nft_transfer"]
        );
        // A different method name on a field is not either: the rule cannot tell what it checks.
        assert_eq!(
            items(&transfer("self.tokens.internal_transfer(receiver_id, token_id); self.transfers += 1;")),
            ["Tickets::nft_transfer"]
        );
    }

    #[test]
    fn a_method_that_changes_nothing_it_can_see_is_clean() {
        let bodies = [
            "self.tokens.internal_transfer(receiver_id, token_id);",
            "ext_receiver::ext(receiver_id).nft_on_transfer(token_id);",
            "let owner = self.owners.get(&token_id); log!(\"{:?}\", owner);",
            "let mut local = Vec::new(); local.push(token_id); local.clear();",
            "let mut copy = self.count; copy += 1;",
            "",
        ];
        for body in bodies {
            assert!(items(&transfer(body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn private_and_unknown_attribute_methods_are_clean_but_known_ones_are_not() {
        let write = "self.owners.insert(token_id, receiver_id);";
        for attr in
            ["#[private]", "#[only(owner)]", "#[access_control_any(roles(Role::Minter))]", "#[near_plugins::pause]"]
        {
            let source = format!(
                "#[near] impl Tickets {{ {attr} pub fn nft_transfer(&mut self, receiver_id: AccountId, token_id: String) {{ {write} }} }}"
            );
            assert!(items(&source).is_empty(), "{attr}");
        }
        for attr in [
            "#[payable]",
            "#[handle_result]",
            "#[result_serializer(borsh)]",
            "#[allow(unused)]",
            "#[inline]",
            "#[must_use]",
            "#[cfg(not(test))]",
            "#[doc = \"text\"]",
        ] {
            let source = format!(
                "#[near] impl Tickets {{ {attr} pub fn nft_transfer(&mut self, receiver_id: AccountId, token_id: String) {{ {write} }} }}"
            );
            assert_eq!(items(&source), ["Tickets::nft_transfer"], "{attr}");
        }
    }

    #[test]
    fn views_other_names_and_unexported_methods_are_clean() {
        let write = "self.owners.insert(id, who);";
        let sources = [
            format!("#[near] impl Tickets {{ pub fn nft_transfer(&self, id: String, who: AccountId) {{ {write} }} }}"),
            format!(
                "#[near] impl Tickets {{ pub fn nft_transfer_ticket(&mut self, id: String, who: AccountId) {{ {write} }} }}"
            ),
            format!("#[near] impl Tickets {{ pub fn nft_token(&mut self, id: String, who: AccountId) {{ {write} }} }}"),
            format!("#[near] impl Tickets {{ fn nft_transfer(&mut self, id: String, who: AccountId) {{ {write} }} }}"),
            format!(
                "#[near] impl Tickets {{ pub(crate) fn nft_transfer(&mut self, id: String, who: AccountId) {{ {write} }} }}"
            ),
            format!("impl Tickets {{ pub fn nft_transfer(&mut self, id: String, who: AccountId) {{ {write} }} }}"),
            format!("fn nft_transfer(id: String, who: AccountId) {{ {write} }}"),
            format!("trait Standard {{ fn nft_transfer(&mut self, id: String, who: AccountId) {{ {write} }} }}"),
        ];
        for source in sources {
            assert!(items(&source).is_empty(), "{source}");
        }
    }

    #[test]
    fn reports_each_unguarded_method_once_across_files() {
        let one = "#[near] impl Tickets { pub fn nft_transfer(&mut self, id: String) { self.owners.remove(&id); self.approved.remove(&id); } }";
        let other = "#[near] impl Shares { pub fn mt_transfer(&mut self, id: String) { self.owners.remove(&id); }
            pub fn mt_batch_transfer(&mut self, id: String) { require!(env::predecessor_account_id() == self.venue); self.owners.remove(&id); } }";
        let findings = check(&[("src/lib.rs", one), ("src/shares.rs", other)]);
        let located: Vec<_> = findings.iter().map(|finding| (finding.file.as_str(), finding.item.as_str())).collect();
        assert_eq!(located, [("src/lib.rs", "Tickets::nft_transfer"), ("src/shares.rs", "Shares::mt_transfer")]);
        assert!(findings[0].message.contains("`self.approved`, `self.owners`"), "{}", findings[0].message);
    }
}
