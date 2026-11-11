//! What the scanner never looks at: code that is not compiled into the contract.
//!
//! A scan skips, once for every rule:
//! - directories named `tests`, `compilation_tests` or `benches` (Cargo's integration tests, `trybuild` compile fixtures
//!   and benchmarks), see [`is_test_dir`], when they are a direct child of a directory that holds a `Cargo.toml`
//!   and hold none themselves ([`enters_tests`] decides for the filesystem walk and [`is_test_file`] for a file set
//!   given as paths; a `src/tests` module, a workspace member `tests/vault` and a file the manifest names as
//!   `[lib] path` or `[[bin]] path`, see [`declared_targets`], are read); `examples` is not skipped, because
//!   near-sdk-rs keeps whole contracts there;
//! - inside a parsed file, items that only exist in a test build ([`strip_test_code`]): anything under
//!   `#[cfg(test)]`, and any function with an attribute whose last path segment is `test` (`#[test]`,
//!   `#[tokio::test]`, `#[test_log::test(..)]`).
//!
//! A `cfg` predicate is test-only when it cannot hold in a build without `test`: `test`, `all(..)` with a test-only
//! operand, `any(..)` whose operands are all test-only, and the Cargo feature named `test` (`feature = "test"`, the
//! project's switch for test-only helpers). `not(test)`, every other feature and every other predicate are kept,
//! because the scanner cannot know whether they are on.
//!
//! Knowingly missed: an item inside a function body (`fn f() { #[cfg(test)] fn g() {} }`), and an out-of-line
//! `#[cfg(test)] mod tests;` whose file is not in a directory named `tests` (the item is dropped, the file is not).

use std::path::{Component, Path, PathBuf};

use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::{Attribute, File, ImplItem, Item, Meta, Token, TraitItem};
use toml_edit::{DocumentMut, Item as TomlItem, TableLike};

/// Whether a directory called `name` is Cargo's place for test and benchmark code, when it sits beside a `Cargo.toml`.
pub(crate) fn is_test_dir(name: &str) -> bool {
    matches!(name, "tests" | "compilation_tests" | "benches")
}

/// Whether the files below a child directory called `child` are test code, given that the files below its parent
/// are (`in_tests`) and whether the parent holds a `Cargo.toml`. A directory holding its own `Cargo.toml` starts a crate
/// again, whatever it is called and wherever it lies; below a test directory everything is test code until then.
pub(crate) fn enters_tests(in_tests: bool, holds_manifest: bool, child: &str) -> bool {
    if holds_manifest { is_test_dir(child) } else { in_tests }
}

/// [`enters_tests`] for a path in a file set that is not on disk (a pasted file set, a GitHub tree): `path` is relative
/// to the scanned root and `holds_manifest` says whether the directory holds a `Cargo.toml` among the files given.
/// Only the paths given count, so a `tests` directory is test code only when its parent's `Cargo.toml` is in the set.
pub(crate) fn is_test_file(path: &Path, holds_manifest: impl Fn(&Path) -> bool) -> bool {
    let mut dirs: Vec<&Path> = path.parent().into_iter().flat_map(Path::ancestors).collect();
    dirs.reverse();
    let mut in_tests = false;
    for (depth, dir) in dirs.iter().enumerate() {
        let holds = holds_manifest(dir);
        in_tests = match dirs.get(depth + 1) {
            Some(child) => enters_tests(in_tests, holds, &child.file_name().unwrap_or_default().to_string_lossy()),
            None => in_tests && !holds,
        };
    }
    in_tests
}

/// The files a manifest names as its library or binaries (`[lib] path`, `[[bin]] path`), relative to its directory,
/// with `.` and `..` resolved. They are production code wherever they lie, even below `tests` or `benches`. A manifest
/// that does not parse names none: the scan fails on it elsewhere.
pub(crate) fn declared_targets(manifest: &str) -> Vec<PathBuf> {
    let Ok(document) = manifest.parse::<DocumentMut>() else { return Vec::new() };
    let lib = document.get("lib").and_then(TomlItem::as_table_like);
    let bins = document.get("bin").and_then(TomlItem::as_array_of_tables).into_iter().flatten();
    lib.into_iter()
        .chain(bins.map(|bin| bin as &dyn TableLike))
        .filter_map(|target| target.get("path")?.as_str())
        .map(resolve)
        .collect()
}

/// `path` with its `.` parts dropped and its `..` parts applied to what precedes them.
fn resolve(path: &str) -> PathBuf {
    let mut resolved = PathBuf::new();
    for part in Path::new(path).components() {
        match part {
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(part) => resolved.push(part),
            _ => {}
        }
    }
    resolved
}

/// Removes the test-only items from `file`, at the top level and inside inline modules, impls and traits.
pub(crate) fn strip_test_code(file: &mut File) {
    strip_items(&mut file.items);
}

fn strip_items(items: &mut Vec<Item>) {
    items.retain(|item| !is_test_only(item_attrs(item)));
    for item in items {
        match item {
            Item::Mod(module) => {
                if let Some((_, inner)) = &mut module.content {
                    strip_items(inner);
                }
            }
            Item::Impl(item) => item.items.retain(|member| !is_test_only(impl_item_attrs(member))),
            Item::Trait(item) => item.items.retain(|member| !is_test_only(trait_item_attrs(member))),
            _ => {}
        }
    }
}

fn is_test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().segments.last().is_some_and(|segment| segment.ident == "test")
            || attr.path().is_ident("cfg")
                && attr.parse_args::<Meta>().is_ok_and(|predicate| cfg_is_test_only(&predicate))
    })
}

/// Whether the `cfg` predicate is false in every build that is not a test build.
fn cfg_is_test_only(predicate: &Meta) -> bool {
    match predicate {
        Meta::Path(path) => path.is_ident("test"),
        Meta::List(list) => {
            let Ok(operands) = Punctuated::<Meta, Token![,]>::parse_terminated.parse2(list.tokens.clone()) else {
                return false;
            };
            if list.path.is_ident("all") {
                operands.iter().any(cfg_is_test_only)
            } else if list.path.is_ident("any") {
                !operands.is_empty() && operands.iter().all(cfg_is_test_only)
            } else {
                false
            }
        }
        // A Cargo feature named `test` is the project's switch for test-only helpers (a setter marked
        // "only available for testing"). Any other feature may be on in a deployed build.
        Meta::NameValue(pair) => {
            pair.path.is_ident("feature")
                && matches!(&pair.value, syn::Expr::Lit(lit) if matches!(&lit.lit, syn::Lit::Str(name) if name.value() == "test"))
        }
    }
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn impl_item_attrs(item: &ImplItem) -> &[Attribute] {
    match item {
        ImplItem::Const(item) => &item.attrs,
        ImplItem::Fn(item) => &item.attrs,
        ImplItem::Type(item) => &item.attrs,
        ImplItem::Macro(item) => &item.attrs,
        _ => &[],
    }
}

fn trait_item_attrs(item: &TraitItem) -> &[Attribute] {
    match item {
        TraitItem::Const(item) => &item.attrs,
        TraitItem::Fn(item) => &item.attrs,
        TraitItem::Type(item) => &item.attrs,
        TraitItem::Macro(item) => &item.attrs,
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_targets_are_the_lib_and_bin_paths_resolved() {
        let manifest = "[lib]\npath = \"./tests/../benches/lib.rs\"\n[[bin]]\nname = \"a\"\n[[bin]]\npath = \"src/b.rs\"\n[[test]]\npath = \"tests/t.rs\"\n";
        assert_eq!(declared_targets(manifest), [PathBuf::from("benches/lib.rs"), PathBuf::from("src/b.rs")]);
        assert!(declared_targets("[package").is_empty());
    }

    /// The names of the top-level functions left after stripping.
    fn remaining(source: &str) -> Vec<String> {
        let mut file = syn::parse_file(source).unwrap();
        strip_test_code(&mut file);
        let mut names = Vec::new();
        collect(&file.items, &mut names);
        names
    }

    fn collect(items: &[Item], names: &mut Vec<String>) {
        for item in items {
            match item {
                Item::Fn(function) => names.push(function.sig.ident.to_string()),
                Item::Mod(module) => {
                    if let Some((_, inner)) = &module.content {
                        collect(inner, names);
                    }
                }
                Item::Impl(item) => names.extend(item.items.iter().filter_map(|member| match member {
                    ImplItem::Fn(method) => Some(method.sig.ident.to_string()),
                    _ => None,
                })),
                _ => {}
            }
        }
    }

    #[test]
    fn drops_cfg_test_modules_items_and_methods() {
        let source = "
            fn kept() {}
            #[cfg(test)] mod tests { fn in_tests() {} }
            #[cfg(test)] fn only_in_tests() {}
            mod inner { #[cfg(test)] mod tests { fn deep() {} } fn inner_kept() {} }
            impl C { fn method() {} #[cfg(test)] fn test_helper() {} }
            #[cfg(test)] impl D { fn helper() {} }
            trait T { #[cfg(test)] fn only_for_tests() {} }";
        assert_eq!(remaining(source), ["kept", "inner_kept", "method"]);
    }

    #[test]
    fn drops_every_function_whose_last_attribute_segment_is_test() {
        let source = "
            fn kept() {}
            #[test] fn a() {}
            #[tokio::test] async fn b() {}
            #[test_log::test(tokio::test)] async fn c() {}
            #[near_sdk::test(should_panic)] fn d() {}
            #[tests] fn not_a_test_attribute() {}";
        assert_eq!(remaining(source), ["kept", "not_a_test_attribute"]);
    }

    #[test]
    fn a_cfg_predicate_is_test_only_only_when_it_cannot_hold_without_test() {
        for (predicate, test_only) in [
            ("test", true),
            ("all(test, feature = \"x\")", true),
            ("all(feature = \"x\", test)", true),
            ("any(test, test)", true),
            ("any(test, feature = \"x\")", false),
            ("not(test)", false),
            ("feature = \"test\"", true),
            ("all(feature = \"test\", target_arch = \"wasm32\")", true),
            ("any(feature = \"test\", feature = \"x\")", false),
            ("not(feature = \"test\")", false),
            ("feature = \"testing\"", false),
            ("feature = \"mainnet\"", false),
            ("all(not(test), feature = \"x\")", false),
            ("target_arch = \"wasm32\"", false),
        ] {
            let source = format!("#[cfg({predicate})] fn gated() {{}} fn kept() {{}}");
            assert_eq!(remaining(&source).contains(&"gated".to_owned()), !test_only, "cfg({predicate})");
        }
    }

    #[test]
    fn test_directories_are_tests_compilation_tests_and_benches_only() {
        assert!(is_test_dir("tests") && is_test_dir("compilation_tests") && is_test_dir("benches"));
        assert!(!is_test_dir("src") && !is_test_dir("examples") && !is_test_dir("mock-token") && !is_test_dir("test"));
    }

    /// `is_test_file` over `paths` with a `Cargo.toml` in each directory of `manifests`.
    fn test_files<'a>(manifests: &[&str], paths: &[&'a str]) -> Vec<&'a str> {
        let holds = |dir: &Path| manifests.iter().any(|manifest| Path::new(manifest) == dir);
        paths.iter().copied().filter(|path| is_test_file(Path::new(path), holds)).collect()
    }

    #[test]
    fn a_file_set_is_cut_at_test_directories_beside_a_manifest_in_the_set() {
        let paths =
            ["src/lib.rs", "tests/a.rs", "tests/common/mod.rs", "benches/b.rs", "examples/e.rs", "src/tests/m.rs"];
        assert_eq!(test_files(&[""], &paths), ["tests/a.rs", "tests/common/mod.rs", "benches/b.rs"]);
        assert_eq!(test_files(&["c"], &["c/tests/a.rs", "tests/a.rs", "c/src/tests/a.rs"]), ["c/tests/a.rs"]);
    }

    #[test]
    fn a_file_set_with_no_manifest_has_no_test_files() {
        assert_eq!(test_files(&[], &["tests/a.rs", "benches/b.rs", "c/tests/a.rs"]), Vec::<&str>::new());
    }

    #[test]
    fn a_manifest_inside_a_test_directory_starts_a_crate_again() {
        let paths =
            ["tests/vault/src/lib.rs", "tests/helpers.rs", "tests/vault/tests/it.rs", "tests/vault/src/tests/m.rs"];
        assert_eq!(test_files(&["", "tests/vault"], &paths), ["tests/helpers.rs", "tests/vault/tests/it.rs"]);
        assert_eq!(
            test_files(&[""], &paths),
            paths,
            "without the member's manifest everything below tests/ is test code"
        );
    }
}
