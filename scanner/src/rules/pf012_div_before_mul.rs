//! PF012: an integer division whose result is then multiplied.
//!
//! Integer division rounds down, so `amount / 10_000 * fee_bps` is zero for every `amount` below 10_000 and loses
//! up to `fee_bps` for every other one, where `amount * fee_bps / 10_000` is exact to the unit. A fee, reward or
//! share computed this way is rounded in the payer's favour, and an attacker who splits one large payment into
//! many small ones pays nothing. Docs: https://github.com/blocksecteam/rustle/blob/master/docs/detectors/div-before-mul.md
//!
//! A multiplication is reported when one side is a division, in any of these forms:
//! - `a / b * c`, `(a / b) * c`, `c * (a / b)` and `c *= a / b`;
//! - the method forms `a.checked_div(b)..checked_mul(c)`, `saturating_*`, `wrapping_*`, `div`/`mul`;
//! - a local bound to a division and multiplied later in the same function (`let share = a / b; share * c`),
//!   until the name is bound again.
//!
//! The division may be wrapped in parentheses, a cast, `U256::from(..)`, `.into()`, `?` or `.unwrap()`. Not
//! reported: the same expression as divisor and multiplier (`x / UNIT * UNIT` rounds to a multiple of `UNIT` on
//! purpose, compared structurally for paths, fields, integer literals and calls without arguments); any division
//! or multiplication with a float operand, where there is no truncation; and a local named for a count of whole
//! units (`let periods = elapsed / PERIOD; periods * REWARD`, the words in [`WHOLE_UNIT_WORDS`]), where the name
//! says the rounding down is intended. Also not reported: a division of two constants whose remainder is zero
//! (`BIG_DIVISOR / MAX_RATIO` with `const BIG_DIVISOR: u128 = 10u128.pow(27)`, evaluated from literals, `const`
//! items of the crate, casts, `+ - * / %` and `.pow(..)`), which loses nothing; and a product that is divided
//! again by the divisor of its quotient (`q * c / d` with `q = x / d`), which keeps what it multiplied only to
//! give back less than one unit. That holds only while the factor is a constant at most the divisor: when the factor is
//! the larger (`q * 1_000_000 / 10_000`), a field or anything the scanner cannot evaluate (`total * share /
//! 10_000`), the first division can still lose up to `factor / divisor` units, and it is reported.
//!
//! Knowingly missed: a quotient stored in a field or reassigned (`x /= b; x *= c;`), one that crosses a function
//! boundary, arithmetic written inside a macro's arguments, and a multiplication by a variable the scanner cannot
//! tell is the divisor under another name.
//! Knowingly noisy: written inline, `elapsed / PERIOD * REWARD_PER_PERIOD` pays per whole period on purpose but is
//! structurally the same as the bug (`bytes / 1_000 * FEE_PER_KB`); the scanner cannot tell them apart, so the
//! message says to check what the remainder is for.

use std::collections::BTreeMap;

use proc_macro2::Span;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    BinOp, Block, Expr, ExprBinary, ExprMethodCall, ImplItem, ImplItemConst, ItemConst, ItemFn, ItemImpl, ItemTrait,
    Lit, Local, Member, Pat, TraitItem, Type, UnOp,
};

use crate::finding::{Finding, Severity};
use crate::rule::Rule;
use crate::source::Crate;

pub struct Pf012DivBeforeMul;

pub static RULE: Pf012DivBeforeMul = Pf012DivBeforeMul;

impl Rule for Pf012DivBeforeMul {
    fn id(&self) -> &'static str {
        "PF012"
    }

    fn title(&self) -> &'static str {
        "Division before multiplication loses precision"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn help(&self) -> &'static str {
        "multiply first and divide last (a * c / b), widening to a larger integer type if the product could overflow"
    }

    fn check(&self, krate: &Crate) -> Vec<Finding> {
        let mut consts = Consts::default();
        for file in &krate.files {
            consts.visit_file(&file.ast);
        }
        let mut findings = Vec::new();
        for file in &krate.files {
            let mut scan = FileScan { consts: &consts, hits: Vec::new() };
            scan.visit_file(&file.ast);
            for (name, span) in scan.hits {
                findings.push(self.finding(
                    file,
                    span,
                    name.clone(),
                    format!(
                        "`{name}` divides before it multiplies, so the quotient is rounded down before it is scaled \
                         and the result can be much smaller than the true value, even zero; \
                         if it counts whole units on purpose (periods elapsed times a per-period rate) the rounding is \
                         intended, otherwise multiply first"
                    ),
                ));
            }
        }
        findings
    }
}

/// The crate's `const` items by name, to evaluate a division of constants.
#[derive(Default)]
struct Consts(BTreeMap<String, Expr>);

impl<'ast> Visit<'ast> for Consts {
    fn visit_item_const(&mut self, item: &'ast ItemConst) {
        self.0.insert(item.ident.to_string(), (*item.expr).clone());
    }

    fn visit_impl_item_const(&mut self, item: &'ast ImplItemConst) {
        self.0.insert(item.ident.to_string(), item.expr.clone());
    }
}

impl Consts {
    /// The value of an integer constant expression, `None` for anything else or on overflow.
    fn eval(&self, expr: &Expr, depth: u8) -> Option<u128> {
        let depth = depth.checked_sub(1)?;
        match expr {
            Expr::Lit(lit) => match &lit.lit {
                Lit::Int(int) => int.base10_parse().ok(),
                _ => None,
            },
            Expr::Paren(inner) => self.eval(&inner.expr, depth),
            Expr::Group(inner) => self.eval(&inner.expr, depth),
            Expr::Cast(cast) => self.eval(&cast.expr, depth),
            Expr::Path(path) => self.eval(self.0.get(&path.path.segments.last()?.ident.to_string())?, depth),
            Expr::Binary(binary) => {
                let (left, right) = (self.eval(&binary.left, depth)?, self.eval(&binary.right, depth)?);
                match binary.op {
                    BinOp::Add(_) => left.checked_add(right),
                    BinOp::Sub(_) => left.checked_sub(right),
                    BinOp::Mul(_) => left.checked_mul(right),
                    BinOp::Div(_) => left.checked_div(right),
                    BinOp::Rem(_) => left.checked_rem(right),
                    _ => None,
                }
            }
            Expr::MethodCall(call) if call.method == "pow" && call.args.len() == 1 => {
                let exponent = u32::try_from(self.eval(&call.args[0], depth)?).ok()?;
                self.eval(&call.receiver, depth)?.checked_pow(exponent)
            }
            _ => None,
        }
    }

    /// Whether both are constants and `factor` is no larger than `divisor`.
    fn within(&self, factor: &Expr, divisor: &Expr) -> bool {
        const DEPTH: u8 = 8;
        matches!((self.eval(factor, DEPTH), self.eval(divisor, DEPTH)), (Some(factor), Some(divisor)) if factor <= divisor)
    }

    /// Whether `dividend / divisor` is a division of constants that leaves no remainder.
    fn divides_exactly(&self, dividend: &Expr, divisor: &Expr) -> bool {
        const DEPTH: u8 = 8;
        match (self.eval(dividend, DEPTH), self.eval(divisor, DEPTH)) {
            (Some(dividend), Some(divisor)) => divisor != 0 && dividend % divisor == 0,
            _ => false,
        }
    }
}

struct FileScan<'a> {
    consts: &'a Consts,
    /// `(function name, span of the multiplication)`, in source order.
    hits: Vec<(String, Span)>,
}

fn type_name(ty: &Type) -> String {
    match ty {
        Type::Path(path) => path.path.segments.last().map_or_else(String::new, |segment| segment.ident.to_string()),
        _ => "<unnamed type>".to_owned(),
    }
}

impl FileScan<'_> {
    fn scan_body(&mut self, name: String, block: &Block) {
        let mut body = BodyScan { consts: self.consts, hits: Vec::new(), quotients: BTreeMap::new() };
        body.visit_block(block);
        self.hits.extend(body.hits.into_iter().map(|span| (name.clone(), span)));
    }
}

impl<'ast> Visit<'ast> for FileScan<'_> {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.scan_body(item.sig.ident.to_string(), &item.block);
        visit::visit_item_fn(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        let owner = type_name(&item.self_ty);
        for member in &item.items {
            if let ImplItem::Fn(method) = member {
                self.scan_body(format!("{owner}::{}", method.sig.ident), &method.block);
            }
        }
    }

    fn visit_item_trait(&mut self, item: &'ast ItemTrait) {
        for member in &item.items {
            if let TraitItem::Fn(method) = member
                && let Some(block) = &method.default
            {
                self.scan_body(format!("{}::{}", item.ident, method.sig.ident), block);
            }
        }
    }
}

const DIVISIONS: [&str; 4] = ["div", "checked_div", "saturating_div", "wrapping_div"];
const MULTIPLICATIONS: [&str; 4] = ["mul", "checked_mul", "saturating_mul", "wrapping_mul"];
/// Methods that pass a number through unchanged for this rule's purposes.
const TRANSPARENT_METHODS: [&str; 7] = ["into", "unwrap", "expect", "unwrap_or", "unwrap_or_default", "clone", "to_owned"];

/// Strips what does not change the value being divided or multiplied: parentheses, `&`, `*`, `?`, casts,
/// `Type::from(..)` and the methods in [`TRANSPARENT_METHODS`].
fn peel(mut expr: &Expr) -> &Expr {
    loop {
        expr = match expr {
            Expr::Paren(inner) => &inner.expr,
            Expr::Group(inner) => &inner.expr,
            Expr::Reference(inner) => &inner.expr,
            Expr::Try(inner) => &inner.expr,
            Expr::Cast(inner) => &inner.expr,
            Expr::Unary(inner) if matches!(inner.op, UnOp::Deref(_)) => &inner.expr,
            Expr::MethodCall(call) if TRANSPARENT_METHODS.contains(&call.method.to_string().as_str()) => &call.receiver,
            Expr::Call(call) if call.args.len() == 1 && is_from(&call.func) => &call.args[0],
            _ => return expr,
        };
    }
}

/// `from`, `U256::from`, `u128::from`: a lossless conversion.
fn is_from(func: &Expr) -> bool {
    matches!(func, Expr::Path(path) if path.path.segments.last().is_some_and(|last| last.ident == "from"))
}

/// A float literal or a cast to a float type: arithmetic that does not truncate.
fn is_float(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(lit) => matches!(lit.lit, Lit::Float(_)),
        Expr::Cast(cast) => matches!(&*cast.ty, Type::Path(path) if path.path.is_ident("f32") || path.path.is_ident("f64")),
        Expr::Paren(inner) => is_float(&inner.expr),
        Expr::Group(inner) => is_float(&inner.expr),
        _ => false,
    }
}

/// The dividend and divisor when `expr` is an integer division: `a / b` or `a.checked_div(b)`, through [`peel`].
fn division(expr: &Expr) -> Option<(&Expr, &Expr)> {
    let (dividend, divisor) = match peel(expr) {
        Expr::Binary(binary) if matches!(binary.op, BinOp::Div(_)) => (&*binary.left, &*binary.right),
        Expr::MethodCall(call) if DIVISIONS.contains(&call.method.to_string().as_str()) && call.args.len() == 1 => {
            (&*call.receiver, &call.args[0])
        }
        _ => return None,
    };
    (!is_float(dividend) && !is_float(divisor)).then_some((dividend, divisor))
}

/// Whether two operands are certainly the same value: equal paths, fields, integer literals or argument-less calls.
fn same_operand(a: &Expr, b: &Expr) -> bool {
    match (peel(a), peel(b)) {
        (Expr::Path(a), Expr::Path(b)) => {
            a.path.segments.len() == b.path.segments.len()
                && a.path.segments.iter().zip(&b.path.segments).all(|(a, b)| a.ident == b.ident)
        }
        (Expr::Lit(a), Expr::Lit(b)) => match (&a.lit, &b.lit) {
            (Lit::Int(a), Lit::Int(b)) => a.base10_digits() == b.base10_digits(),
            _ => false,
        },
        (Expr::Field(a), Expr::Field(b)) => {
            same_member(&a.member, &b.member) && same_operand(&a.base, &b.base)
        }
        (Expr::MethodCall(a), Expr::MethodCall(b)) => {
            a.args.is_empty() && b.args.is_empty() && a.method == b.method && same_operand(&a.receiver, &b.receiver)
        }
        _ => false,
    }
}

fn same_member(a: &Member, b: &Member) -> bool {
    match (a, b) {
        (Member::Named(a), Member::Named(b)) => a == b,
        (Member::Unnamed(a), Member::Unnamed(b)) => a.index == b.index,
        _ => false,
    }
}

/// Words that name a count of whole units: a local called `periods` or `full_epochs` holds a floored count on purpose.
const WHOLE_UNIT_WORDS: [&str; 14] = [
    "periods", "epochs", "intervals", "days", "weeks", "months", "years", "rounds", "cycles", "lots", "units",
    "steps", "batches", "whole",
];

fn counts_whole_units(name: &str) -> bool {
    name.split('_').any(|word| WHOLE_UNIT_WORDS.contains(&word))
}

fn local_name(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(ident) => Some(ident.ident.to_string()),
        Pat::Type(typed) => local_name(&typed.pat),
        _ => None,
    }
}

struct BodyScan<'a> {
    consts: &'a Consts,
    /// Spans of the multiplications that scale a quotient.
    hits: Vec<Span>,
    /// Locals currently bound to a division, with its divisor.
    quotients: BTreeMap<String, Expr>,
}

impl BodyScan<'_> {
    /// The divisor of `expr` when it is a division that can lose a remainder.
    fn lossy_divisor<'e>(&self, expr: &'e Expr) -> Option<&'e Expr> {
        division(expr).filter(|(dividend, divisor)| !self.consts.divides_exactly(dividend, divisor)).map(|(_, divisor)| divisor)
    }

    /// The divisor of `expr` when it is a lossy division or a local bound to one.
    fn quotient_divisor(&self, expr: &Expr) -> Option<Expr> {
        if let Some(divisor) = self.lossy_divisor(expr) {
            return Some(divisor.clone());
        }
        let Expr::Path(path) = peel(expr) else { return None };
        self.quotients.get(&path.path.get_ident()?.to_string()).cloned()
    }

    /// Records a hit when `a * b` multiplies a quotient by something other than its own divisor. `rescale` is
    /// the divisor when the product is divided again at once, which gives back what the first division lost.
    fn multiply(&mut self, a: &Expr, b: &Expr, span: Span, rescale: Option<&Expr>) {
        let scales_a_quotient = |scan: &Self, quotient: &Expr, factor: &Expr| {
            scan.quotient_divisor(quotient).is_some_and(|divisor| {
                let rescaled = rescale.is_some_and(|again| same_operand(&divisor, again)) && scan.consts.within(factor, &divisor);
                !same_operand(&divisor, factor) && !is_float(factor) && !rescaled
            })
        };
        if scales_a_quotient(self, a, b) || scales_a_quotient(self, b, a) {
            self.hits.push(span);
        }
    }
}

impl<'ast> Visit<'ast> for BodyScan<'_> {
    fn visit_local(&mut self, local: &'ast Local) {
        visit::visit_local(self, local);
        let Some(name) = local_name(&local.pat) else { return };
        match local.init.as_ref().and_then(|init| self.lossy_divisor(&init.expr)) {
            Some(divisor) if !counts_whole_units(&name) => {
                self.quotients.insert(name, divisor.clone());
            }
            _ => {
                self.quotients.remove(&name);
            }
        }
    }

    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        if matches!(binary.op, BinOp::Div(_))
            && let Expr::Binary(product) = peel(&binary.left)
            && matches!(product.op, BinOp::Mul(_))
        {
            self.multiply(&product.left, &product.right, product.op.span(), Some(&binary.right));
            for operand in [&*product.left, &*product.right, &*binary.right] {
                self.visit_expr(operand);
            }
            return;
        }
        if matches!(binary.op, BinOp::Mul(_) | BinOp::MulAssign(_)) {
            self.multiply(&binary.left, &binary.right, binary.op.span(), None);
        }
        visit::visit_expr_binary(self, binary);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if MULTIPLICATIONS.contains(&call.method.to_string().as_str())
            && let Some(factor) = call.args.first()
        {
            self.multiply(&call.receiver, factor, call.method.span(), None);
        }
        visit::visit_expr_method_call(self, call);
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

    /// A function `fee` whose body is `body`.
    fn function(body: &str) -> String {
        format!("fn fee(amount: u128, bps: u128) -> u128 {{ {body} }}")
    }

    const MARKET: &str = r#"
        #[near]
        impl Market {
            pub fn quote(&self, bytes: u128) -> u128 {
                bytes / 1_000 * PRICE_PER_KB
            }
        }
    "#;

    #[test]
    fn flags_a_division_that_is_multiplied_and_locates_the_star() {
        let findings = check(MARKET);
        assert_eq!(items(&findings), ["Market::quote"]);
        let finding = &findings[0];
        assert_eq!((finding.rule_id, finding.severity), ("PF012", Severity::Medium));
        assert_eq!((finding.file.as_str(), finding.line, finding.column), ("src/lib.rs", 5, 31));
        assert!(finding.message.contains("`Market::quote`"), "{}", finding.message);
    }

    #[test]
    fn flags_every_shape_of_division_then_multiplication() {
        for body in [
            "amount / 10_000 * bps",
            "(amount / 10_000) * bps",
            "bps * (amount / 10_000)",
            "(amount / 10_000) as u128 * bps",
            "U256::from(amount / 10_000) * U256::from(bps)",
            "u128::from(amount / 10_000) * bps",
            "(amount / 10_000).into() * bps",
            "amount / 10_000 / 2 * bps",
            "amount.checked_div(10_000).unwrap().checked_mul(bps).unwrap()",
            "bps.saturating_mul(amount.saturating_div(10_000))",
            "amount.wrapping_div(10_000).wrapping_mul(bps)",
            "amount.div(10_000).mul(bps)",
            "amount.checked_div(10_000)?.checked_mul(bps)?",
            "let mut fee = bps; fee *= amount / 10_000; fee",
            "let share = amount / 10_000; share * bps",
            "let share: u128 = amount.checked_div(10_000).unwrap(); bps * share",
            "let share = amount / 10_000; let fee = share * bps; fee",
            "let share = U256::from(amount) / 10_000; (share * bps).as_u128()",
        ] {
            assert_eq!(check(&function(body)).len(), 1, "{body}");
        }
    }

    #[test]
    fn reports_a_chain_once() {
        assert_eq!(check(&function("amount / 10_000 * bps * 2")).len(), 1);
        assert_eq!(check(&function("amount / 10_000 / 2 * bps")).len(), 1);
    }

    #[test]
    fn flags_methods_free_functions_and_trait_default_methods() {
        let source = "
            impl Pool { fn payout(&self, a: u128) -> u128 { a / self.total * self.reward } }
            fn share(a: u128, t: u128, r: u128) -> u128 { a / t * r }
            trait Fees { fn fee(&self, a: u128) -> u128 { a / 100 * 3 } }";
        assert_eq!(items(&check(source)), ["Pool::payout", "share", "Fees::fee"]);
    }

    #[test]
    fn multiplying_before_dividing_is_clean() {
        for body in [
            "amount * bps / 10_000",
            "(amount * bps) / 10_000",
            "amount.checked_mul(bps).unwrap().checked_div(10_000).unwrap()",
            "U256::from(amount) * U256::from(bps) / U256::from(10_000u32)",
            "amount / 10_000 + bps",
            "amount / (10_000 * bps)",
            "amount / 10_000 / bps",
            "let share = amount * bps; share / 10_000",
            "let share = amount / 10_000; share + bps",
            "let share = amount / 10_000; bps",
        ] {
            assert!(check(&function(body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn rounding_to_a_unit_is_clean() {
        for body in [
            "amount / UNIT * UNIT",
            "amount / 1_000 * 1_000",
            "(amount / self.unit) * self.unit",
            "(amount / self.unit()) * self.unit()",
            "(amount / consts::LOT) * consts::LOT",
            "bps * (amount / bps)",
            "let lots = amount / 1_000; lots * 1_000",
            "let lots = amount / UNIT; UNIT * lots",
        ] {
            assert!(check(&function(body)).is_empty(), "{body}");
        }
        assert_eq!(check(&function("amount / 1_000 * 1_001")).len(), 1);
        assert_eq!(check(&function("amount / self.unit * self.other")).len(), 1);
    }

    #[test]
    fn float_arithmetic_does_not_truncate() {
        for body in [
            "amount as f64 / 10_000.0 * 3.0",
            "(amount as f64 / 10_000 as f64) * bps as f64",
            "amount / 2.0 * bps",
            "amount as f64 * (bps / 10_000.0)",
        ] {
            assert!(check(&function(body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn a_local_that_is_bound_again_is_no_longer_a_quotient() {
        assert!(check(&function("let share = amount / 10_000; let share = amount; share * bps")).is_empty());
        assert!(check(&function("let share = amount / 10_000; let share = bps + 1; share * bps")).is_empty());
        assert_eq!(check(&function("let share = 5; let share = amount / 10_000; share * bps")).len(), 1);
    }

    #[test]
    fn a_local_named_for_a_count_of_whole_units_is_an_intended_floor() {
        for name in ["periods", "epochs", "full_days", "whole_units", "elapsed_intervals", "lots"] {
            let body = format!("let {name} = amount / PERIOD; {name} * bps");
            assert!(check(&function(&body)).is_empty(), "{name}");
        }
        for name in ["share", "fee", "periodic", "period", "unit"] {
            let body = format!("let {name} = amount / PERIOD; {name} * bps");
            assert_eq!(check(&function(&body)).len(), 1, "{name}");
        }
        assert_eq!(check(&function("(amount / PERIOD) * bps")).len(), 1, "inline stays reported");
        assert!(check(&function("let periods = amount / PERIOD; let fee = periods * bps; fee")).is_empty());
    }

    #[test]
    fn the_message_says_a_floor_can_be_intended() {
        let findings = check(&function("amount / 10_000 * bps"));
        assert!(findings[0].message.contains("counts whole units on purpose"), "{}", findings[0].message);
    }

    #[test]
    fn test_code_is_skipped() {
        let source = format!("#[cfg(test)] mod tests {{ {} }}", function("amount / 10_000 * bps"));
        assert!(check(&source).is_empty());
        let source = "#[test] fn rounds() { assert_eq!(9_999 / 10_000 * 30, 0); }
            #[cfg(test)] impl Fees { fn fee(a: u128) -> u128 { a / 100 * 3 } }
            impl Fees { #[cfg(test)] fn fee(a: u128) -> u128 { a / 100 * 3 } }";
        assert!(check(source).is_empty());
    }

    /// A common shape in deployed code: `#[test_log::test(tokio::test)]` is a test whatever its path.
    #[test]
    fn a_test_attribute_with_a_path_marks_test_code() {
        let source = "#[test_log::test(tokio::test)] async fn rounds() { let x = a / 100 * 3; }";
        assert!(check(source).is_empty());
        assert_eq!(check("fn rounds() { let x = a / 100 * 3; }").len(), 1);
    }

    /// A common shape in deployed code: a ratio scaled by the exact quotient of two constants.
    #[test]
    fn a_division_of_constants_that_leaves_no_remainder_is_exact() {
        let consts = "const NUM_DECIMALS: u8 = 27; const BIG_DIVISOR: u128 = 10u128.pow(NUM_DECIMALS as u32); const MAX_RATIO: u32 = 10000;";
        let exact = format!("{consts} fn from_ratio(ratio: u32) -> u128 {{ ratio as u128 * (BIG_DIVISOR / (MAX_RATIO as u128)) }}");
        assert!(check(&exact).is_empty());
        let literals = "fn f(r: u128) -> u128 { r * (1_000_000 / 100) }";
        assert!(check(literals).is_empty());
    }

    #[test]
    fn a_division_of_constants_with_a_remainder_or_a_variable_is_still_lossy() {
        for division in ["BIG / THIRD", "BIG / n", "n / MAX_RATIO", "BIG / ZERO", "BIG / UNKNOWN"] {
            let source = format!(
                "const BIG: u128 = 1_000; const THIRD: u128 = 3; const ZERO: u128 = 0; const MAX_RATIO: u128 = 10;
                 fn f(r: u128, n: u128) -> u128 {{ r * ({division}) }}"
            );
            assert_eq!(check(&source).len(), 1, "{division}");
        }
    }

    /// The product is divided by the same divisor again, by a constant factor no larger than it.
    #[test]
    fn a_product_divided_again_by_the_divisor_of_its_quotient_is_rescaled() {
        let rescaled = "fn f(amount: u128) -> u128 {
            let total = amount / 10_000;
            total * 9_000 / 10_000
        }";
        assert!(check(rescaled).is_empty());
        let inline = "fn f(amount: u128) -> u128 { (amount / 10_000 * 10_000) / 10_000 }";
        assert!(check(inline).is_empty());
        let small = "fn f(amount: u128) -> u128 { amount / 10_000 * 9_000 / 10_000 }";
        assert!(check(small).is_empty());
    }

    /// v01: a constant factor larger than the divisor, a field or a parameter all magnify the first division's
    /// remainder, so the second division does not give it back.
    #[test]
    fn a_rescale_by_a_factor_larger_than_the_divisor_or_unknown_is_still_lossy() {
        for source in [
            "fn f(amount: u128) -> u128 { amount / 10_000 * 1_000_000 / 10_000 }",
            "fn f(amount: u128) -> u128 { let total = amount / 10_000; total * 1_000_000 / 10_000 }",
            "fn f(&self, amount: u128) -> u128 { let total = amount / 10_000; total * self.share / 10_000 }",
            "fn f(amount: u128, share: u128) -> u128 { amount / 10_000 * share / 10_000 }",
            "fn f(cut: u128, amount: u128, share: u128) -> u128 { let total = cut * amount / 10_000; total * share / 10_000 }",
        ] {
            assert_eq!(check(source).len(), 1, "{source}");
        }
    }

    #[test]
    fn a_product_that_is_not_divided_by_the_same_divisor_is_still_lossy() {
        for source in [
            "fn f(amount: u128, share: u128) -> u128 { let total = amount / 10_000; total * share }",
            "fn f(amount: u128, share: u128) -> u128 { let total = amount / 10_000; total * share / 100 }",
            "fn f(amount: u128, share: u128) -> u128 { let total = amount / 10_000; total * share + 1 }",
        ] {
            assert_eq!(check(source).len(), 1, "{source}");
        }
    }
}
