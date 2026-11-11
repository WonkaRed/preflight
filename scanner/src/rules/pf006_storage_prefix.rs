//! PF006: two persistent collections created with the same storage prefix.
//!
//! `near_sdk::store` and `near_sdk::collections` keep every element under `prefix ++ borsh(element)` (and
//! `prefix ++ index` for vectors). Two collections built with one prefix therefore read and write the same keys:
//! an element inserted into one shows up in the other, and a removal from one deletes it from the other.
//! Docs: https://docs.near.org/smart-contracts/anatomy/collections
//!
//! Two shapes are reported.
//!
//! 1. Within one function body, two constructors of a collection type (`new` or `with_hasher` of `LookupMap`,
//!    `LookupSet`, `UnorderedMap`, `UnorderedSet`, `IterableMap`, `IterableSet`, `TreeMap`, `LegacyTreeMap`,
//!    `Vector`, `LazyOption`, `Lazy`, `FreeList`) that receive the same constant prefix and are not the same slot.
//!    A constant prefix is a byte-string, string, byte or integer literal, or a path to a unit enum variant or a
//!    constant (`StorageKey::Members`, `MEMBERS_PREFIX`), possibly followed by `.try_to_vec()`, `.unwrap()`,
//!    `.to_vec()`, `.into()`, `.as_bytes()` and similar conversions. Byte-strings and strings are compared by
//!    their bytes. A slot is the struct field (`members: ..`, `self.members = ..`) or `let` name the collection
//!    is assigned to; the same slot twice (two branches building the same field) is one collection, while
//!    collections with no slot are always distinct. A variant that carries data (`StorageKey::Inner { hash }`)
//!    is not constant and is never reported.
//! 2. A nested collection: a constructor with a constant prefix whose collection is passed directly (or through a
//!    `let` binding) to `insert`, `push`, `push_back`, `push_front`, `set` or `replace` on a place rooted at `self`,
//!    where the call runs more than once, that is inside a loop or in an exported method that takes `self` and is
//!    not an `#[init]`. An `insert` whose key is a literal is skipped, since it runs for one key. Every collection
//!    stored this way has the same prefix.
//!
//! Knowingly missed: constructors in different functions (a `new` and a `default` that rebuild the same state
//! must not collide, so they are not compared); prefixes that are constants behind a name the rule cannot
//! resolve (`const A: &[u8] = b"x"; const B: &[u8] = b"x";`), or built by `format!`/`concat`; one prefix that is a
//! byte-prefix of another (`b"a"` and `b"ab"` can overlap for some key types); two different enums whose
//! variants serialize to the same byte; a nested collection created through a closure (`or_insert_with(|| ..)`),
//! a helper function, or a non-exported method; and collections created from `LookupMap::new(prefix_variable)`.

use std::collections::BTreeMap;
use std::fmt;

use proc_macro2::Span;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Block, Expr, ExprAssign, ExprCall, ExprForLoop, ExprLit, ExprLoop, ExprMethodCall, ExprWhile,
    FieldValue, ImplItem, ItemFn, ItemImpl, Lit, Local, Member, Pat, Type, UnOp, Visibility,
};

use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::{Crate, SourceFile};

pub struct Pf006StoragePrefix;

pub static RULE: Pf006StoragePrefix = Pf006StoragePrefix;

impl Rule for Pf006StoragePrefix {
    fn id(&self) -> &'static str {
        "PF006"
    }

    fn title(&self) -> &'static str {
        "Storage prefix shared by two collections"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn help(&self) -> &'static str {
        "give every collection its own prefix, a distinct variant of a storage-key enum, and put the key in the prefix of a nested collection"
    }

    fn check(&self, krate: &Crate) -> Vec<Finding> {
        let mut findings = Vec::new();
        for file in &krate.files {
            let mut functions = Functions { found: Vec::new() };
            functions.visit_file(&file.ast);
            for function in &functions.found {
                self.check_function(file, function, &mut findings);
            }
        }
        findings
    }
}

impl Pf006StoragePrefix {
    fn check_function(&self, file: &SourceFile, function: &Function, findings: &mut Vec<Finding>) {
        let mut body = Body::default();
        body.visit_block(function.block);

        for (index, ctor) in body.ctors.iter().enumerate() {
            let earlier = body.ctors[..index].iter().find(|other| other.prefix == ctor.prefix && !other.slot.is_same(&ctor.slot));
            if let Some(other) = earlier {
                findings.push(self.finding(
                    file,
                    ctor.span,
                    function.name.clone(),
                    format!(
                        "`{}` in `{}` uses the same storage prefix as `{}` on line {}, so the two collections read and write the same keys",
                        ctor.text, function.name, other.text, other.span.start().line
                    ),
                ));
            }
        }

        for store in &body.stores {
            let ctor = match &store.value {
                Stored::Direct(call) => body.ctors.iter().find(|ctor| std::ptr::eq(ctor.call, *call)),
                Stored::Local(name) => body.locals.get(name).map(|&index| &body.ctors[index]),
            };
            if let Some(ctor) = ctor
                && (store.in_loop || function.repeatable)
            {
                findings.push(self.finding(
                    file,
                    ctor.span,
                    function.name.clone(),
                    format!(
                        "`{}` stores a new `{}` in `self.{}` for every call, and all of them share one storage prefix, so the collections overwrite each other",
                        function.name, ctor.text, store.field
                    ),
                ));
            }
        }
    }
}

/// A function body to scan, with whether a call to it can run many times in one contract's life.
struct Function<'a> {
    name: String,
    block: &'a Block,
    /// An exported method that takes `self` and is not an initializer.
    repeatable: bool,
}

struct Functions<'a> {
    found: Vec<Function<'a>>,
}

impl<'a> Visit<'a> for Functions<'a> {
    fn visit_item_fn(&mut self, item: &'a ItemFn) {
        self.found.push(Function { name: item.sig.ident.to_string(), block: &item.block, repeatable: false });
    }

    fn visit_item_impl(&mut self, item: &'a ItemImpl) {
        let owner = match &*item.self_ty {
            Type::Path(path) => path.path.segments.last().map_or_else(String::new, |segment| segment.ident.to_string()),
            _ => "<unnamed type>".to_owned(),
        };
        let near = item.attrs.iter().any(is_near_attr);
        for member in &item.items {
            if let ImplItem::Fn(method) = member {
                let exported = near && (item.trait_.is_some() || matches!(method.vis, Visibility::Public(_)));
                let initializer = method.attrs.iter().any(|attr| attr.path().is_ident("init"));
                self.found.push(Function {
                    name: format!("{owner}::{}", method.sig.ident),
                    block: &method.block,
                    repeatable: exported && !initializer && method.sig.receiver().is_some(),
                });
            }
        }
    }
}

/// `#[near]`, `#[near(..)]` or `#[near_bindgen]`, possibly path-qualified (`#[near_sdk::near]`).
fn is_near_attr(attr: &Attribute) -> bool {
    attr.path().segments.last().is_some_and(|segment| segment.ident == "near" || segment.ident == "near_bindgen")
}

/// The constant prefix of a collection.
#[derive(PartialEq, Eq)]
enum Prefix {
    Bytes(Vec<u8>),
    Variant(String),
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(bytes) => {
                f.write_str("b\"")?;
                bytes.iter().try_for_each(|byte| write!(f, "{}", byte.escape_ascii()))?;
                f.write_str("\"")
            }
            Self::Variant(path) => f.write_str(path),
        }
    }
}

/// Where a collection is stored. Two constructors with one prefix are the same collection only in the same slot.
enum Slot {
    Field(String),
    Local(String),
    Nowhere,
}

impl Slot {
    fn is_same(&self, other: &Slot) -> bool {
        matches!((self, other), (Self::Field(a), Self::Field(b)) | (Self::Local(a), Self::Local(b)) if a == b)
    }
}

struct Ctor<'a> {
    call: &'a ExprCall,
    /// `LookupSet::new(b"m")`, for messages.
    text: String,
    prefix: Prefix,
    slot: Slot,
    span: Span,
}

enum Stored<'a> {
    Direct(&'a ExprCall),
    Local(String),
}

/// A `self.field.insert(.., collection)` style call.
struct Store<'a> {
    field: String,
    value: Stored<'a>,
    in_loop: bool,
}

#[derive(Default)]
struct Body<'a> {
    ctors: Vec<Ctor<'a>>,
    stores: Vec<Store<'a>>,
    /// `let` names bound directly to a constructor, as an index into `ctors`.
    locals: BTreeMap<String, usize>,
    /// The slot of the constructor call about to be visited, and that call.
    pending: Option<(Slot, &'a ExprCall)>,
    loop_depth: usize,
}

impl<'a> Visit<'a> for Body<'a> {
    fn visit_field_value(&mut self, field: &'a FieldValue) {
        if let (Member::Named(name), Expr::Call(call)) = (&field.member, &field.expr) {
            self.pending = Some((Slot::Field(name.to_string()), call));
        }
        visit::visit_field_value(self, field);
    }

    fn visit_expr_assign(&mut self, assign: &'a ExprAssign) {
        if let (Expr::Field(target), Expr::Call(call)) = (&*assign.left, &*assign.right)
            && let Member::Named(name) = &target.member
        {
            self.pending = Some((Slot::Field(name.to_string()), call));
        }
        visit::visit_expr_assign(self, assign);
    }

    fn visit_local(&mut self, local: &'a Local) {
        if let Pat::Ident(name) = &local.pat
            && let Some(init) = &local.init
            && let Expr::Call(call) = &*init.expr
        {
            self.pending = Some((Slot::Local(name.ident.to_string()), call));
        }
        visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'a ExprCall) {
        let slot = match self.pending.take_if(|(_, pending)| std::ptr::eq(*pending, call)) {
            Some((slot, _)) => slot,
            None => Slot::Nowhere,
        };
        if let Some((text, prefix, span)) = constructor(call) {
            if let Slot::Local(name) = &slot {
                self.locals.insert(name.clone(), self.ctors.len());
            }
            self.ctors.push(Ctor { call, text, prefix, slot, span });
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'a ExprMethodCall) {
        if STORING_CALLS.contains(&call.method.to_string().as_str())
            && let Some(field) = self_field(&call.receiver)
            && let Some(last) = call.args.last()
            // `insert(1, ..)` with a literal key stores one collection under one key.
            && !(call.args.len() > 1 && matches!(call.args.first(), Some(Expr::Lit(_))))
        {
            let value = match last {
                Expr::Call(inner) => Some(Stored::Direct(inner)),
                Expr::Path(path) => path.path.get_ident().map(|ident| Stored::Local(ident.to_string())),
                _ => None,
            };
            if let Some(value) = value {
                self.stores.push(Store { field, value, in_loop: self.loop_depth > 0 });
            }
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_for_loop(&mut self, node: &'a ExprForLoop) {
        self.in_loop(|body| visit::visit_expr_for_loop(body, node));
    }

    fn visit_expr_while(&mut self, node: &'a ExprWhile) {
        self.in_loop(|body| visit::visit_expr_while(body, node));
    }

    fn visit_expr_loop(&mut self, node: &'a ExprLoop) {
        self.in_loop(|body| visit::visit_expr_loop(body, node));
    }
}

impl<'a> Body<'a> {
    fn in_loop(&mut self, walk: impl FnOnce(&mut Self)) {
        self.loop_depth += 1;
        walk(self);
        self.loop_depth -= 1;
    }
}

const STORING_CALLS: &[&str] = &["insert", "push", "push_back", "push_front", "set", "replace"];

/// Collection types whose `new` and `with_hasher` take the storage prefix first, from `near_sdk::store` and
/// `near_sdk::collections` (near-sdk 5.30).
const COLLECTIONS: &[&str] = &[
    "LookupMap",
    "LookupSet",
    "UnorderedMap",
    "UnorderedSet",
    "IterableMap",
    "IterableSet",
    "TreeMap",
    "LegacyTreeMap",
    "Vector",
    "LazyOption",
    "Lazy",
    "FreeList",
];

/// Conversions that leave the bytes of a prefix as they are.
const KEY_CONVERSIONS: &[&str] =
    &["try_to_vec", "unwrap", "to_vec", "into", "into_storage_key", "as_bytes", "as_slice", "into_bytes", "to_owned"];

/// `Type::new(prefix, ..)` or `Type::with_hasher(prefix)` of a known collection with a constant prefix:
/// the call as text, the prefix, and where to report it.
fn constructor(call: &ExprCall) -> Option<(String, Prefix, Span)> {
    let Expr::Path(func) = &*call.func else { return None };
    let mut segments = func.path.segments.iter().rev();
    let (function, ty) = (segments.next()?, segments.next()?);
    let kind = ty.ident.to_string();
    if !(function.ident == "new" || function.ident == "with_hasher") || !COLLECTIONS.contains(&kind.as_str()) {
        return None;
    }
    let prefix = constant_prefix(call.args.first()?)?;
    let first = func.path.segments.first()?.ident.span();
    Some((format!("{kind}::{}({prefix})", function.ident), prefix, first))
}

fn constant_prefix(expr: &Expr) -> Option<Prefix> {
    match expr {
        Expr::Paren(inner) => constant_prefix(&inner.expr),
        Expr::Group(inner) => constant_prefix(&inner.expr),
        Expr::Reference(inner) => constant_prefix(&inner.expr),
        Expr::Unary(inner) if matches!(inner.op, UnOp::Deref(_)) => constant_prefix(&inner.expr),
        Expr::Index(inner) if matches!(&*inner.index, Expr::Range(range) if range.start.is_none() && range.end.is_none()) => {
            constant_prefix(&inner.expr)
        }
        Expr::MethodCall(call) if KEY_CONVERSIONS.contains(&call.method.to_string().as_str()) => {
            constant_prefix(&call.receiver)
        }
        Expr::Lit(ExprLit { lit, .. }) => match lit {
            Lit::ByteStr(bytes) => Some(Prefix::Bytes(bytes.value())),
            Lit::Str(text) => Some(Prefix::Bytes(text.value().into_bytes())),
            Lit::Byte(byte) => Some(Prefix::Bytes(vec![byte.value()])),
            Lit::Int(int) => int.base10_parse::<u8>().ok().map(|byte| Prefix::Bytes(vec![byte])),
            _ => None,
        },
        Expr::Path(path) if path.qself.is_none() => {
            let segments = &path.path.segments;
            let last = segments.last()?.ident.to_string();
            let variable = last.chars().next()?.is_lowercase();
            // A lone lowercase name is a variable; `Enum::Variant` and `CONSTANT` are constants.
            (!variable).then(|| {
                let names: Vec<String> = segments.iter().rev().take(2).map(|segment| segment.ident.to_string()).collect();
                Prefix::Variant(names.into_iter().rev().collect::<Vec<_>>().join("::"))
            })
        }
        _ => None,
    }
}

/// The `self` field a place such as `self.vaults` or `self.users.get_mut(&id).unwrap()` is rooted at.
fn self_field(place: &Expr) -> Option<String> {
    match place {
        Expr::Field(field) if matches!(&*field.base, Expr::Path(path) if path.path.is_ident("self")) => {
            Some(match &field.member {
                Member::Named(ident) => ident.to_string(),
                Member::Unnamed(index) => index.index.to_string(),
            })
        }
        Expr::Field(field) => self_field(&field.base),
        Expr::MethodCall(call) => self_field(&call.receiver),
        Expr::Index(index) => self_field(&index.expr),
        Expr::Paren(paren) => self_field(&paren.expr),
        Expr::Reference(reference) => self_field(&reference.expr),
        Expr::Unary(unary) if matches!(unary.op, UnOp::Deref(_)) => self_field(&unary.expr),
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

    fn flagged(source: &str) -> usize {
        check(&[("src/lib.rs", source)]).len()
    }

    fn new_fn(body: &str) -> String {
        format!("#[near] impl C {{ #[init] pub fn new() -> Self {{ {body} }} }}")
    }

    #[test]
    fn flags_two_collections_with_one_literal_prefix_and_locates_the_second() {
        let source = new_fn(
            "let mut admins = LookupSet::new(b\"m\");
            admins.insert(a);
            Self { members: LookupSet::new(b\"m\"), admins }",
        );
        let findings = check(&[("src/lib.rs", &source)]);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity, finding.item.as_str()), ("PF006", Severity::High, "C::new"));
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 3, 29));
        assert!(finding.message.contains("LookupSet::new(b\"m\")") && finding.message.contains("line 1"));
    }

    #[test]
    fn flags_each_spelling_of_a_constant_prefix() {
        for (first, second) in [
            ("b\"m\"", "\"m\""),
            ("b\"m\"", "b'm'"),
            ("b\"m\"", "&b\"m\"[..]"),
            ("b\"m\".to_vec()", "b\"m\".as_slice()"),
            ("b\"m\"", "\"m\".as_bytes()"),
            ("7", "7u8"),
            ("StorageKey::Members", "StorageKey::Members"),
            ("StorageKey::Members", "crate::keys::StorageKey::Members"),
            ("StorageKey::Members.try_to_vec().unwrap()", "StorageKey::Members.try_to_vec().unwrap()"),
            ("MEMBERS", "MEMBERS"),
            ("StorageKey::Members.into_storage_key()", "StorageKey::Members"),
        ] {
            let source = new_fn(&format!("Self {{ a: LookupMap::new({first}), b: LookupMap::new({second}) }}"));
            assert_eq!(flagged(&source), 1, "{first} vs {second}");
        }
    }

    #[test]
    fn flags_every_collection_type_and_path_shape() {
        for ctor in [
            "LookupMap::new(b\"x\")",
            "LookupMap::<u8, u8>::new(b\"x\")",
            "near_sdk::store::LookupSet::new(b\"x\")",
            "near_sdk::collections::UnorderedMap::new(b\"x\")",
            "UnorderedSet::new(b\"x\")",
            "IterableMap::new(b\"x\")",
            "IterableSet::new(b\"x\")",
            "TreeMap::new(b\"x\")",
            "LegacyTreeMap::new(b\"x\")",
            "Vector::new(b\"x\")",
            "LazyOption::new(b\"x\", None)",
            "Lazy::new(b\"x\", 0u8)",
            "FreeList::new(b\"x\")",
            "LookupMap::with_hasher(b\"x\")",
        ] {
            let source = new_fn(&format!("Self {{ a: {ctor}, b: {ctor} }}"));
            assert_eq!(flagged(&source), 1, "{ctor}");
        }
    }

    #[test]
    fn flags_each_later_constructor_with_a_prefix_already_used() {
        let source = new_fn("Self { a: Vector::new(b\"v\"), b: Vector::new(b\"v\"), c: Vector::new(b\"v\") }");
        assert_eq!(flagged(&source), 2);
    }

    #[test]
    fn flags_a_collection_assigned_to_a_field_and_one_in_a_let() {
        let source = "fn setup(&mut self) { self.a = LookupMap::new(b\"x\"); let b = LookupMap::new(b\"x\"); }";
        assert_eq!(flagged(source), 1);
    }

    #[test]
    fn silent_for_distinct_prefixes() {
        for (first, second) in [
            ("b\"a\"", "b\"b\""),
            ("b\"m\"", "\"n\""),
            ("StorageKey::Members", "StorageKey::Admins"),
            ("keys::StorageKey::Members", "keys::Other::Members"),
            ("1u8", "2u8"),
        ] {
            let source = new_fn(&format!("Self {{ a: LookupMap::new({first}), b: LookupMap::new({second}) }}"));
            assert_eq!(flagged(&source), 0, "{first} vs {second}");
        }
    }

    #[test]
    fn silent_for_a_variant_that_carries_data_or_a_variable_prefix() {
        for prefix in [
            "StorageKey::Inner { account_hash: h }",
            "StorageKey::Inner { account_hash: h }.try_to_vec().unwrap()",
            "StorageKey::Inner(h)",
            "prefix",
            "format!(\"m{id}\").into_bytes()",
            "[b\"m\", id.as_bytes()].concat()",
            "id.try_to_vec().unwrap()",
        ] {
            let source = new_fn(&format!("Self {{ a: LookupMap::new({prefix}), b: LookupMap::new({prefix}) }}"));
            assert_eq!(flagged(&source), 0, "{prefix}");
        }
    }

    #[test]
    fn silent_for_the_same_literal_in_two_crates() {
        let first = new_fn("Self { a: LookupMap::new(b\"m\"), b: LookupMap::new(b\"n\") }");
        let second = new_fn("Self { a: LookupMap::new(b\"m\"), b: LookupMap::new(b\"o\") }");
        assert_eq!(flagged(&first), 0);
        assert_eq!(flagged(&second), 0);
    }

    #[test]
    fn silent_for_the_same_field_built_twice_or_in_two_functions() {
        let branches = "fn new(flag: bool) -> Self { if flag { Self { a: LookupMap::new(b\"m\") } } else { Self { a: LookupMap::new(b\"m\") } } }";
        assert_eq!(flagged(branches), 0);
        let two_functions = "impl Default for C { fn default() -> Self { Self { a: LookupMap::new(b\"m\") } } }
            impl C { fn new() -> Self { Self { a: LookupMap::new(b\"m\") } } }";
        assert_eq!(flagged(two_functions), 0);
    }

    #[test]
    fn silent_for_other_types_and_non_prefix_calls() {
        let source = new_fn(
            "let a = Vec::new(); let b = Vec::new();             let e = Lazy::new(|| 1); let f = Lazy::new(|| 1); let g = HashMap::new(); let h = HashMap::new();
            Self { a: Foo::new(b\"m\"), b: Foo::new(b\"m\") }",
        );
        assert_eq!(flagged(&source), 0);
    }

    const NESTED: &str = "#[near] impl C { pub fn add_vault(&mut self, id: u64) { BODY } }";

    #[test]
    fn flags_a_constant_prefix_collection_stored_for_every_call() {
        for body in [
            "self.vaults.insert(id, Vector::new(b\"v\"));",
            "self.vaults.insert(id, Vector::new(StorageKey::Vault));",
            "let vault = Vector::new(b\"v\"); self.vaults.insert(id, vault);",
            "self.vaults.get_mut(&id).unwrap().push(UnorderedSet::new(b\"s\"));",
            "self.pending.push_back(Vector::new(b\"v\"));",
        ] {
            let source = NESTED.replace("BODY", body);
            let findings = check(&[("src/lib.rs", &source)]);
            assert_eq!(findings.len(), 1, "{body}");
            assert!(findings[0].message.contains("every call"), "{body}");
            assert_eq!(findings[0].item, "C::add_vault");
        }
    }

    #[test]
    fn flags_a_nested_collection_created_in_a_loop_of_a_helper() {
        let source = "impl C { fn build(&mut self) { for id in 0..3 { self.vaults.insert(id, Vector::new(b\"v\")); } } }";
        assert_eq!(flagged(source), 1);
    }

    #[test]
    fn silent_for_a_nested_collection_that_is_stored_once_or_with_its_key_in_the_prefix() {
        for body in [
            "self.vaults.insert(1, Vector::new(b\"v\"));",
            "self.vaults.insert(id, Vector::new(StorageKey::Vault { id }));",
            "self.vaults.insert(id, Vector::new(format!(\"v{id}\").into_bytes()));",
            "let vault = Vector::new(prefix); self.vaults.insert(id, vault);",
            "let scratch = Vector::new(b\"v\"); self.vaults.insert(id, Vec::new());",
            "self.vaults.insert(id, Vec::new());",
            "self.vaults.entry(id).or_insert_with(|| Vector::new(b\"v\"));",
        ] {
            let source = NESTED.replace("BODY", body);
            assert_eq!(flagged(&source), 0, "{body}");
        }
    }

    #[test]
    fn silent_for_a_nested_collection_in_an_initializer_or_a_method_that_is_not_exported() {
        let init = "#[near] impl C { #[init] pub fn new() -> Self { let mut s = Self::empty(); s.vaults.insert(id, Vector::new(b\"v\")); s } }";
        assert_eq!(flagged(init), 0);
        for hidden in [
            "#[near] impl C { fn add(&mut self, id: u64) { self.vaults.insert(id, Vector::new(b\"v\")); } }",
            "impl C { pub fn add(&mut self, id: u64) { self.vaults.insert(id, Vector::new(b\"v\")); } }",
            "#[near] impl C { pub fn add(id: u64) { VAULTS.insert(id, Vector::new(b\"v\")); } }",
        ] {
            assert_eq!(flagged(hidden), 0, "{hidden}");
        }
    }

    #[test]
    fn accepts_near_bindgen_and_trait_impls() {
        for source in [
            "#[near_bindgen] impl C { pub fn add(&mut self, id: u64) { self.v.insert(id, Vector::new(b\"v\")); } }",
            "#[near_sdk::near] impl C { pub fn add(&mut self, id: u64) { self.v.insert(id, Vector::new(b\"v\")); } }",
            "#[near] impl Vaults for C { fn add(&mut self, id: u64) { self.v.insert(id, Vector::new(b\"v\")); } }",
        ] {
            assert_eq!(flagged(source), 1, "{source}");
        }
    }
}
