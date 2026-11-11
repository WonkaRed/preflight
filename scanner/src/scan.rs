use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::finding::Finding;
use crate::report::Report;
use crate::rule::Rule;
use crate::scope;
use crate::source::{Crate, Manifest, link_macros};
use toml_edit::DocumentMut;

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("cannot read {path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("cannot parse {path}: {source}")]
    Parse { path: String, source: syn::Error },
    #[error("cannot parse {path}: {source}")]
    Manifest { path: String, source: toml_edit::TomlError },
    /// A scan that read nothing says nothing, so it is an error and never a clean report.
    #[error("no Rust source file to scan under {path}{}", skipped_note(*test_files_skipped))]
    NothingToScan { path: String, test_files_skipped: usize },
}

fn skipped_note(skipped: usize) -> String {
    match skipped {
        0 => String::new(),
        n => format!(" ({n} skipped as test code: scan the crate directory above tests/ to read what is left)"),
    }
}

/// Scans a `.rs` file or a directory tree with `rules`.
///
/// Any file or manifest that cannot be read or parsed fails the whole scan: a file the scanner skipped silently is
/// a file nobody audited. Directories named `target` and dot-directories are not entered, and neither are the
/// test code: the `.rs` files below `tests`, `compilation_tests` and `benches` when that directory is a direct child
/// of one that holds a `Cargo.toml` (see `scope`). A directory that holds a `Cargo.toml` itself is a crate, even
/// when it is called `tests` or lies inside one (a workspace member `tests/vault`), and a `src/tests` module is
/// production code, and so is a file the manifest names as `[lib] path` or `[[bin]] path`: all are read.
/// The skipped files are counted in the report, and a scan that reads no file at all
/// is an error, never a clean report. Symlinks are not followed.
pub fn scan(target: &Path, rules: &[&dyn Rule]) -> Result<Report, ScanError> {
    let meta = fs::metadata(target).map_err(|e| io_error(target, e))?;
    let mut crates: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
    let mut test_files_skipped = 0;
    let root = if meta.is_dir() {
        walk(target, target, false, &[], &mut crates, &mut test_files_skipped)?;
        target
    } else {
        crates.entry(PathBuf::new()).or_default().push(target.to_owned());
        target.parent().unwrap_or(Path::new(""))
    };

    let mut found = Vec::new();
    for (dir, paths) in crates {
        let texts = paths
            .iter()
            .map(|path| {
                let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
                let relative = path.strip_prefix(root).unwrap_or(path);
                Ok((relative.to_string_lossy().replace('\\', "/"), text))
            })
            .collect::<Result<Vec<_>, ScanError>>()?;
        let mut krate = Crate::from_sources(texts.iter().map(|(path, text)| (path.as_str(), text.as_str())))?;
        if meta.is_dir()
            && let Some(manifest) = load_manifest(&dir)?
        {
            krate = krate.with_manifest(manifest);
        }
        found.push(krate);
    }
    link_macros(&mut found);
    check_crates(target.to_string_lossy().into_owned(), root, &found, test_files_skipped, rules)
}

/// Runs `rules` over each crate and builds the report. The one place a scan turns crates into findings, shared by
/// [`scan`] and [`scan_files`](crate::scan_files): the scope rules (test code stripped, test files counted) are
/// applied before it, a scan that read no file is an error here, and the skipped count reaches the report here.
pub(crate) fn check_crates(
    target: String,
    base: &Path,
    crates: &[Crate],
    test_files_skipped: usize,
    rules: &[&dyn Rule],
) -> Result<Report, ScanError> {
    let files_scanned = crates.iter().map(|krate| krate.files.len()).sum();
    if files_scanned == 0 {
        return Err(ScanError::NothingToScan { path: target, test_files_skipped });
    }
    let mut findings: Vec<Finding> =
        crates.iter().flat_map(|krate| rules.iter().flat_map(|rule| rule.check(krate))).collect();
    findings.sort_by(|a, b| (&a.file, a.line, a.column, a.rule_id).cmp(&(&b.file, b.line, b.column, b.rule_id)));
    Ok(Report::new(target, base, files_scanned, test_files_skipped, findings))
}

/// Reads the manifest of the crate in `dir` and of the workspace root above it; `None` when `dir` has no
/// `Cargo.toml`. Like cargo, the workspace root is the nearest `Cargo.toml` at or above `dir` with a `[workspace]`.
fn load_manifest(dir: &Path) -> Result<Option<Manifest>, ScanError> {
    let dir = fs::canonicalize(dir).map_err(|e| io_error(dir, e))?;
    let Some(package) = read_manifest(&dir.join("Cargo.toml"))? else { return Ok(None) };
    let workspace_root = if is_workspace_root(&package) { None } else { find_workspace_root(&dir)? };
    Ok(Some(Manifest { workspace_root: workspace_root.unwrap_or_else(|| package.clone()), package }))
}

fn find_workspace_root(dir: &Path) -> Result<Option<DocumentMut>, ScanError> {
    for ancestor in dir.ancestors().skip(1) {
        if let Some(manifest) = read_manifest(&ancestor.join("Cargo.toml"))?
            && is_workspace_root(&manifest)
        {
            return Ok(Some(manifest));
        }
    }
    Ok(None)
}

pub(crate) fn is_workspace_root(manifest: &DocumentMut) -> bool {
    manifest.get("workspace").is_some_and(|workspace| workspace.is_table_like())
}

fn read_manifest(path: &Path) -> Result<Option<DocumentMut>, ScanError> {
    if !path.is_file() {
        return Ok(None);
    }
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    text.parse().map(Some).map_err(|source| ScanError::Manifest { path: path.display().to_string(), source })
}

/// Collects `.rs` files under `dir`, keyed by the directory of the nearest enclosing `Cargo.toml` (or `top`).
/// Below a test directory (`in_tests`) a file is counted in `skipped` instead, until a directory holding its own
/// `Cargo.toml` starts a crate again, except the `targets` that manifest declares (`[lib] path`, `[[bin]] path`).
fn walk(
    dir: &Path,
    crate_root: &Path,
    in_tests: bool,
    targets: &[PathBuf],
    crates: &mut BTreeMap<PathBuf, Vec<PathBuf>>,
    skipped: &mut usize,
) -> Result<(), ScanError> {
    let holds_manifest = dir.join("Cargo.toml").is_file();
    let crate_root = if holds_manifest { dir } else { crate_root };
    let declared;
    let targets = if holds_manifest {
        let manifest = dir.join("Cargo.toml");
        let text = fs::read_to_string(&manifest).map_err(|e| io_error(&manifest, e))?;
        declared = scope::declared_targets(&text).into_iter().map(|target| dir.join(target)).collect::<Vec<_>>();
        &declared[..]
    } else {
        targets
    };
    let mut entries =
        fs::read_dir(dir).and_then(|entries| entries.collect::<Result<Vec<_>, _>>()).map_err(|e| io_error(dir, e))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        let kind = entry.file_type().map_err(|e| io_error(&path, e))?;
        if kind.is_dir() {
            let name = name.to_string_lossy();
            if name != "target" && !name.starts_with('.') {
                walk(
                    &path,
                    crate_root,
                    scope::enters_tests(in_tests, holds_manifest, &name),
                    targets,
                    crates,
                    skipped,
                )?;
            }
        } else if kind.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            if in_tests && !holds_manifest && !targets.contains(&path) {
                *skipped += 1;
            } else {
                crates.entry(crate_root.to_owned()).or_default().push(path);
            }
        }
    }
    Ok(())
}

fn io_error(path: &Path, source: std::io::Error) -> ScanError {
    ScanError::Io { path: path.display().to_string(), source }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(pair: &str, variant: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures").join(pair).join(variant)
    }

    #[test]
    fn a_crate_gets_its_own_manifest_and_the_workspace_root_above_it() {
        let manifest = load_manifest(&fixture("pf001_callback", "vulnerable")).unwrap().unwrap();
        assert_eq!(manifest.package["package"]["name"].as_str(), Some("pf001-callback-vulnerable"));
        assert!(is_workspace_root(&manifest.workspace_root));
        assert_eq!(manifest.workspace_root["profile"]["release"]["overflow-checks"].as_bool(), Some(true));
    }

    /// Writes `files` (empty) under a fresh directory, walks it and returns what was found and what was skipped.
    fn walked(files: &[&str]) -> (Vec<String>, usize) {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("preflight-walk-{}-{id}", std::process::id()));
        for file in files {
            let path = root.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "").unwrap();
        }
        let mut crates = BTreeMap::new();
        let mut skipped = 0;
        let result = walk(&root, &root, false, &[], &mut crates, &mut skipped);
        let found = crates
            .values()
            .flatten()
            .map(|path| path.strip_prefix(&root).unwrap().to_string_lossy().into_owned())
            .collect();
        fs::remove_dir_all(&root).unwrap();
        result.unwrap();
        (found, skipped)
    }

    #[test]
    fn integration_tests_and_benchmarks_are_not_walked_but_examples_are() {
        let (files, skipped) = walked(&[
            "Cargo.toml",
            "src/lib.rs",
            "tests/workspaces.rs",
            "tests/common/mod.rs",
            "benches/bench.rs",
            "examples/contract.rs",
        ]);
        assert_eq!(files, ["examples/contract.rs", "src/lib.rs"]);
        assert_eq!(skipped, 3);
    }

    /// z07: workspace members called `tests` and `benches` hold their own `Cargo.toml` and are real crates.
    #[test]
    fn a_crate_that_is_itself_called_tests_or_benches_is_walked() {
        let (files, skipped) = walked(&[
            "Cargo.toml",
            "tests/vault/Cargo.toml",
            "tests/vault/src/lib.rs",
            "benches/Cargo.toml",
            "benches/src/lib.rs",
            "tests/helpers.rs",
        ]);
        assert_eq!(files, ["benches/src/lib.rs", "tests/vault/src/lib.rs"]);
        assert_eq!(skipped, 1);
    }

    /// z01: `pub mod tests;` in `src/lib.rs` is compiled into the contract, and `src` holds no `Cargo.toml`.
    #[test]
    fn a_tests_module_below_src_is_production_code() {
        let (files, skipped) = walked(&["Cargo.toml", "src/lib.rs", "src/tests/mod.rs"]);
        assert_eq!(files, ["src/lib.rs", "src/tests/mod.rs"]);
        assert_eq!(skipped, 0);
    }

    /// A directory with no manifest above it is no crate, so nothing marks its `tests` as test code.
    #[test]
    fn a_tests_directory_beside_no_manifest_is_walked() {
        let (files, skipped) = walked(&["contracts/tests/helper.rs"]);
        assert_eq!(files, ["contracts/tests/helper.rs"]);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn a_scan_that_reads_no_file_is_an_error_naming_the_skipped_test_files() {
        let root = std::env::temp_dir().join(format!("preflight-scan-empty-{}", std::process::id()));
        for file in ["Cargo.toml", "tests/it.rs", "benches/b.rs"] {
            let path = root.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "").unwrap();
        }
        let result = scan(&root, &[]);
        fs::remove_dir_all(&root).unwrap();
        let message = result.unwrap_err().to_string();
        assert!(
            message.contains("no Rust source file to scan") && message.contains("2 skipped as test code"),
            "{message}"
        );
    }

    #[test]
    fn a_directory_without_a_manifest_has_none() {
        assert!(load_manifest(Path::new(env!("CARGO_MANIFEST_DIR")).join("src").as_path()).unwrap().is_none());
    }
}
