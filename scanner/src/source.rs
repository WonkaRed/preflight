use std::collections::{BTreeMap, BTreeSet};

use syn::visit::{self, Visit};
use toml_edit::{DocumentMut, Item};

use crate::scan::ScanError;
use crate::scope;

/// A parsed Rust file.
pub struct SourceFile {
    /// Path relative to the scanned directory, `/`-separated; reported in findings.
    pub path: String,
    pub ast: syn::File,
}

impl SourceFile {
    /// A parsed file with its test-only code removed (see [`scope`]), so no rule sees code that is not compiled
    /// into the contract.
    pub(crate) fn new(path: String, mut ast: syn::File) -> Self {
        scope::strip_test_code(&mut ast);
        Self { path, ast }
    }
}

/// The manifests that decide how a crate is built.
pub struct Manifest {
    /// The crate's own `Cargo.toml`.
    pub package: DocumentMut,
    /// The manifest that holds the build profiles: cargo reads `[profile]` tables only from the workspace root, the
    /// nearest `Cargo.toml` at or above the crate that has a `[workspace]` table. For a crate in no workspace this
    /// is the crate's own manifest.
    pub workspace_root: DocumentMut,
}

impl Manifest {
    /// Parses a crate manifest and the manifest of its workspace root (the same text for a crate in no workspace).
    /// Rule unit tests use this to scan inline manifests.
    pub fn parse(package: &str, workspace_root: &str) -> Result<Self, toml_edit::TomlError> {
        Ok(Self { package: package.parse()?, workspace_root: workspace_root.parse()? })
    }
}

/// The Rust files of one crate (the files under one `Cargo.toml`). Rules see a whole crate at once, so a
/// check can follow a name from the file that defines it to the file that uses it.
pub struct Crate {
    pub files: Vec<SourceFile>,
    /// The crate's manifests. `None` when the files are not under a `Cargo.toml` (a single file, a bare directory
    /// of sources, or a snippet in a unit test); a rule that needs the manifest must stay silent then.
    pub manifest: Option<Manifest>,
    /// The `#[macro_export]` macros of the crates this one depends on by `path` (see [`link_macros`]), which a rule
    /// follows by name like a macro the crate defines itself. They are definitions to read, never files to report.
    pub imported_macros: Vec<syn::ItemMacro>,
}

impl Crate {
    /// Builds a crate from `(path, source text)` pairs, with no manifest. Rule unit tests use this to scan inline
    /// snippets; add a manifest with [`Crate::with_manifest`].
    pub fn from_sources<'a>(sources: impl IntoIterator<Item = (&'a str, &'a str)>) -> Result<Self, ScanError> {
        let files = sources
            .into_iter()
            .map(|(path, text)| {
                let ast = syn::parse_file(text).map_err(|source| ScanError::Parse { path: path.to_owned(), source })?;
                Ok(SourceFile::new(path.to_owned(), ast))
            })
            .collect::<Result<_, ScanError>>()?;
        Ok(Self { files, manifest: None, imported_macros: Vec::new() })
    }

    #[must_use]
    pub fn with_manifest(self, manifest: Manifest) -> Self {
        Self { manifest: Some(manifest), ..self }
    }
}

/// Gives each crate the `#[macro_export]` macros of the crates of this scan that it depends on by `path`, found by the
/// package name in the dependency table (`package = ".."` honoured) and a `path` key, or `workspace = true` for a
/// workspace dependency that has one. A macro is left out when the crate defines one of the same name or two
/// dependencies export it: a call by name could not tell which one runs. A dependency from a registry is never read.
pub(crate) fn link_macros(crates: &mut [Crate]) {
    let exported: Vec<(String, Vec<syn::ItemMacro>)> = crates
        .iter()
        .filter_map(|krate| {
            let name = package_name(krate.manifest.as_ref()?)?;
            Some((name, macros_of(krate).into_iter().filter(|(exported, _)| *exported).map(|(_, mac)| mac).collect()))
        })
        .collect();
    for krate in crates.iter_mut() {
        let Some(manifest) = &krate.manifest else { continue };
        let own: BTreeSet<String> =
            macros_of(krate).into_iter().filter_map(|(_, mac)| Some(mac.ident?.to_string())).collect();
        let mut by_name: BTreeMap<String, Vec<&syn::ItemMacro>> = BTreeMap::new();
        for dependency in path_dependencies(manifest) {
            for mac in exported.iter().filter(|(name, _)| *name == dependency).flat_map(|(_, macros)| macros) {
                by_name.entry(mac.ident.as_ref().map(ToString::to_string).unwrap_or_default()).or_default().push(mac);
            }
        }
        let imported = by_name
            .into_iter()
            .filter(|(name, defined)| defined.len() == 1 && !own.contains(name))
            .map(|(_, defined)| defined[0].clone())
            .collect();
        krate.imported_macros = imported;
    }
}

/// The package name as Cargo compares it: `-` and `_` are one character.
fn package_name(manifest: &Manifest) -> Option<String> {
    let name = manifest.package.get("package")?.get("name")?.as_str()?;
    Some(name.replace('_', "-"))
}

/// The packages `manifest` depends on by a path inside the workspace.
fn path_dependencies(manifest: &Manifest) -> Vec<String> {
    let workspace = manifest.workspace_root.get("workspace").and_then(|workspace| workspace.get("dependencies"));
    let Some(table) = manifest.package.get("dependencies").and_then(Item::as_table_like) else { return Vec::new() };
    table
        .iter()
        .filter(|(key, dependency)| {
            let from_workspace = dependency.get("workspace").and_then(Item::as_bool) == Some(true);
            let declared = if from_workspace {
                workspace.and_then(|dependencies| dependencies.get(key))
            } else {
                Some(*dependency)
            };
            declared.is_some_and(|declared| declared.get("path").is_some())
        })
        .map(|(key, dependency)| {
            let renamed = dependency.get("package").and_then(Item::as_str);
            let declared = workspace
                .and_then(|dependencies| dependencies.get(key))
                .and_then(|declared| declared.get("package")?.as_str());
            renamed.or(declared).unwrap_or(key).replace('_', "-")
        })
        .collect()
}

/// Every `macro_rules!` the crate defines, with whether it carries `#[macro_export]`.
fn macros_of(krate: &Crate) -> Vec<(bool, syn::ItemMacro)> {
    #[derive(Default)]
    struct Macros(Vec<(bool, syn::ItemMacro)>);
    impl<'ast> Visit<'ast> for Macros {
        fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
            if item.mac.path.is_ident("macro_rules") && item.ident.is_some() {
                let exported = item.attrs.iter().any(|attr| attr.path().is_ident("macro_export"));
                self.0.push((exported, item.clone()));
            }
            visit::visit_item_macro(self, item);
        }
    }
    let mut macros = Macros::default();
    krate.files.iter().for_each(|file| macros.visit_file(&file.ast));
    macros.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_that_does_not_parse_is_an_error_naming_the_file() {
        let Err(error) = Crate::from_sources([("src/lib.rs", "fn broken( {")]) else {
            panic!("expected a parse error")
        };
        assert!(error.to_string().starts_with("cannot parse src/lib.rs: "), "{error}");
    }

    fn linked(app_source: &str, app_dependencies: &str, root: &str, libraries: &[(&str, &str)]) -> Vec<String> {
        let manifest = |name: &str, dependencies: &str, root: &str| {
            Manifest::parse(&format!("[package]\nname = \"{name}\"\n[dependencies]\n{dependencies}"), root).unwrap()
        };
        let mut crates = vec![Crate::from_sources([("app/src/lib.rs", app_source)]).unwrap().with_manifest(manifest(
            "app",
            app_dependencies,
            root,
        ))];
        for (name, source) in libraries {
            crates.push(
                Crate::from_sources([("lib/src/lib.rs", *source)]).unwrap().with_manifest(manifest(name, "", root)),
            );
        }
        link_macros(&mut crates);
        crates[0].imported_macros.iter().filter_map(|mac| Some(mac.ident.as_ref()?.to_string())).collect()
    }

    const EXPORTED: &str = "#[macro_export] macro_rules! guard { () => {} }";

    #[test]
    fn a_macro_is_imported_from_a_path_dependency_by_package_name_and_only_then() {
        let libs = [("common-lib", EXPORTED)];
        let root = "[workspace]";
        assert_eq!(linked("", "common-lib = { path = \"../lib\" }", root, &libs), ["guard"]);
        assert_eq!(linked("", "common_lib = { path = \"../lib\" }", root, &libs), ["guard"]);
        assert_eq!(linked("", "renamed = { path = \"../lib\", package = \"common-lib\" }", root, &libs), ["guard"]);
        let workspace = "[workspace.dependencies]\ncommon-lib = { path = \"lib\" }";
        assert_eq!(linked("", "common-lib.workspace = true", workspace, &libs), ["guard"]);
        let registry = "[workspace.dependencies]\ncommon-lib = \"1\"";
        for (dependencies, root) in [
            ("common-lib = \"1\"", root),
            ("common-lib.workspace = true", registry),
            ("", root),
            ("other = { path = \"../lib\" }", root),
        ] {
            assert!(linked("", dependencies, root, &libs).is_empty(), "{dependencies}");
        }
    }

    #[test]
    fn a_macro_that_is_not_exported_defined_twice_or_defined_by_the_crate_itself_is_not_imported() {
        let path = "common-lib = { path = \"../lib\" }, second = { path = \"../lib2\" }".replace(", ", "\n");
        assert!(linked("", &path, "[workspace]", &[("common-lib", "macro_rules! guard { () => {} }")]).is_empty());
        assert!(linked("", &path, "[workspace]", &[("common-lib", EXPORTED), ("second", EXPORTED)]).is_empty());
        assert!(
            linked("macro_rules! guard { () => { 1 } }", &path, "[workspace]", &[("common-lib", EXPORTED)]).is_empty()
        );
        assert_eq!(
            linked(
                "",
                &path,
                "[workspace]",
                &[("common-lib", EXPORTED), ("second", "#[macro_export] macro_rules! other { () => {} }")]
            )
            .len(),
            2
        );
    }
}
