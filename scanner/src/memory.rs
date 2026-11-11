use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use toml_edit::DocumentMut;

use crate::report::Report;
use crate::rule::Rule;
use crate::scan::{ScanError, check_crates, is_workspace_root};
use crate::scope;
use crate::source::{Crate, Manifest, link_macros};

/// Scans files that are already in memory, with the result [`scan`](crate::scan) gives for the same files on disk.
///
/// `files` are `(path relative to the scanned directory, text)` pairs, `/`-separated. Only `.rs` files are scanned
/// and `Cargo.toml` files are read; every other file is ignored, as are files under a directory named `target` or
/// starting with `.`. A `Cargo.toml` marks where a crate starts, and is the crate's manifest. Cargo reads build
/// profiles from the workspace root, so that is read too: the nearest `Cargo.toml` with a `[workspace]` table in
/// `files` above the crate, or else in `above`, which holds the `Cargo.toml` text of each directory above the
/// scanned one, nearest first (`None` where a directory has none). The filesystem scan finds those on disk. Files
/// with no `Cargo.toml` are scanned as one crate with no manifest. `target` is the label the report carries.
///
/// The scope rules are the filesystem scan's, applied to the paths given: a `.rs` file below `tests`,
/// `compilation_tests` or `benches` is test code, counted in the report and not scanned, when that directory is a
/// direct child of one whose `Cargo.toml` is among `files` (see `scope::is_test_file`); the manifests in `above` do
/// not make the scanned root a crate for this, as the filesystem scan does not look above its root for it either. The
/// files a manifest names as `[lib] path` or `[[bin]] path` are read wherever they lie. A set that leaves no `.rs`
/// file to scan is `ScanError::NothingToScan`, never a clean report.
/// This is the entry point for callers with no filesystem, such as the WebAssembly build.
pub fn scan_files(
    target: &str,
    files: &[(&str, &str)],
    above: &[Option<&str>],
    rules: &[&dyn Rule],
) -> Result<Report, ScanError> {
    let mut files: Vec<(PathBuf, &str, &str)> = files
        .iter()
        .map(|&(path, text)| (PathBuf::from(path), path, text))
        .filter(|(path, _, _)| !path.parent().is_some_and(in_skipped_dir))
        .collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let manifests: BTreeMap<&Path, &str> = files
        .iter()
        .filter(|(path, _, _)| path.file_name().is_some_and(|name| name == "Cargo.toml"))
        .filter_map(|(path, _, text)| Some((path.parent()?, *text)))
        .collect();
    let mut crates: BTreeMap<&Path, Vec<(&str, &str)>> = BTreeMap::new();
    let mut test_files_skipped = 0;
    for (path, name, text) in files.iter().filter(|(path, _, _)| path.extension().is_some_and(|ext| ext == "rs")) {
        let root = path.ancestors().skip(1).find(|dir| manifests.contains_key(dir)).unwrap_or(Path::new(""));
        let declared = || {
            manifests
                .get(root)
                .is_some_and(|text| scope::declared_targets(text).iter().any(|target| root.join(target) == *path))
        };
        if scope::is_test_file(path, |dir| manifests.contains_key(dir)) && !declared() {
            test_files_skipped += 1;
            continue;
        }
        crates.entry(root).or_default().push((name, text));
    }

    let mut found = Vec::new();
    for (root, sources) in crates {
        let mut krate = Crate::from_sources(sources)?;
        if let Some(manifest) = load_manifest(root, &manifests, above)? {
            krate = krate.with_manifest(manifest);
        }
        found.push(krate);
    }
    link_macros(&mut found);
    check_crates(target.to_owned(), Path::new(""), &found, test_files_skipped, rules)
}

/// The in-memory twin of `scan::load_manifest`: the manifest of the crate in `root` and of the workspace root above
/// it, `None` when `root` has no `Cargo.toml`.
fn load_manifest(
    root: &Path,
    manifests: &BTreeMap<&Path, &str>,
    above: &[Option<&str>],
) -> Result<Option<Manifest>, ScanError> {
    let Some(text) = manifests.get(root) else { return Ok(None) };
    let package = parse(&root.join("Cargo.toml"), text)?;
    let workspace_root = if is_workspace_root(&package) { None } else { find_workspace_root(root, manifests, above)? };
    Ok(Some(Manifest { workspace_root: workspace_root.unwrap_or_else(|| package.clone()), package }))
}

fn find_workspace_root(
    root: &Path,
    manifests: &BTreeMap<&Path, &str>,
    above: &[Option<&str>],
) -> Result<Option<DocumentMut>, ScanError> {
    let inside = root.ancestors().skip(1).map(|dir| (dir.join("Cargo.toml"), manifests.get(dir).copied()));
    let outside = above
        .iter()
        .enumerate()
        .map(|(depth, text)| (std::iter::repeat_n("..", depth + 1).collect::<PathBuf>().join("Cargo.toml"), *text));
    for (path, text) in inside.chain(outside) {
        let Some(text) = text else { continue };
        let manifest = parse(&path, text)?;
        if is_workspace_root(&manifest) {
            return Ok(Some(manifest));
        }
    }
    Ok(None)
}

fn parse(path: &Path, text: &str) -> Result<DocumentMut, ScanError> {
    text.parse().map_err(|source| ScanError::Manifest { path: path.display().to_string(), source })
}

fn in_skipped_dir(dir: &Path) -> bool {
    dir.components().any(|part| part.as_os_str() == "target" || part.as_os_str().to_string_lossy().starts_with('.'))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::rules;

    fn collect(dir: &Path, prefix: &str, out: &mut Vec<(String, String)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let name = format!("{prefix}{}", entry.file_name().to_string_lossy());
            if entry.file_type().unwrap().is_dir() {
                collect(&entry.path(), &format!("{name}/"), out);
            } else {
                out.push((name, fs::read_to_string(entry.path()).unwrap_or_default()));
            }
        }
    }

    /// The `Cargo.toml` text of every directory above `dir`, nearest first, as the filesystem scan would find it.
    fn manifests_above(dir: &Path) -> Vec<Option<String>> {
        let dir = fs::canonicalize(dir).unwrap();
        dir.ancestors().skip(1).map(|above| fs::read_to_string(above.join("Cargo.toml")).ok()).collect()
    }

    fn scan_in_memory(label: &str, files: &[(&str, &str)], above: &[Option<&str>]) -> Result<Report, ScanError> {
        let rules: Vec<_> = rules::all().collect();
        scan_files(label, files, above, &rules)
    }

    #[test]
    fn matches_the_filesystem_scan_for_every_fixture_pair() {
        let rules: Vec<_> = rules::all().collect();
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures");
        let rule_dirs: Vec<_> = fs::read_dir(&fixtures)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.is_dir() && path.file_name().unwrap().to_string_lossy().starts_with("pf"))
            .collect();
        assert_eq!(rule_dirs.len(), rules.len(), "every rule has exactly one fixture pair");
        for rule_dir in &rule_dirs {
            for variant in ["vulnerable", "patched"] {
                let dir = rule_dir.join(variant);
                let mut files = Vec::new();
                collect(&dir, "", &mut files);
                let pairs: Vec<_> = files.iter().map(|(p, t)| (p.as_str(), t.as_str())).collect();
                let above = manifests_above(&dir);
                let above: Vec<_> = above.iter().map(Option::as_deref).collect();
                let on_disk = serde_json::to_string(&crate::scan(&dir, &rules).unwrap()).unwrap();
                let in_memory =
                    serde_json::to_string(&scan_files(&dir.to_string_lossy(), &pairs, &above, &rules).unwrap());
                assert_eq!(in_memory.unwrap(), on_disk, "{}", dir.display());
            }
        }
    }

    #[test]
    fn crates_are_split_at_their_cargo_toml_and_target_and_dot_directories_are_skipped() {
        let broken = "fn broken( {";
        let report = scan_in_memory(
            "t",
            &[
                ("Cargo.toml", ""),
                ("src/lib.rs", "pub fn a() {}"),
                ("sub/Cargo.toml", ""),
                ("sub/src/lib.rs", "pub fn b() {}"),
                ("target/debug/build.rs", broken),
                (".git/hooks/x.rs", broken),
                ("README.md", broken),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(report.summary.files_scanned, 2);
    }

    #[test]
    fn a_file_that_does_not_parse_fails_the_scan_naming_the_file() {
        let error = scan_in_memory("t", &[("src/a.rs", "fn broken( {")], &[]).unwrap_err();
        assert!(error.to_string().starts_with("cannot parse src/a.rs: "), "{error}");
    }

    fn pf022_fires(files: &[(&str, &str)], above: &[Option<&str>]) -> bool {
        scan_in_memory("t", files, above).unwrap().findings.iter().any(|finding| finding.rule_id == "PF022")
    }

    #[test]
    fn the_build_profile_comes_from_the_nearest_workspace_root_in_the_files_or_above_them() {
        let patched = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/pf022_overflow_checks_off/patched");
        let source = fs::read_to_string(patched.join("src/lib.rs")).unwrap();
        let package = "[package]\nname = \"pf022-overflow-checks-off-patched\"\n";
        let checked = "[workspace]\n[profile.release]\noverflow-checks = true\n";
        let files = [("Cargo.toml", package), ("src/lib.rs", source.as_str())];
        assert!(pf022_fires(&files, &[]), "no workspace root: the crate's own manifest has no profile");
        assert!(!pf022_fires(&files, &[None, Some(checked)]), "a workspace root above the scanned directory");
        assert!(pf022_fires(&files, &[Some("[package]\nname = \"x\"\n"), Some("")]), "no [workspace] table above");
        let nested = [("Cargo.toml", checked), ("member/Cargo.toml", package), ("member/src/lib.rs", source.as_str())];
        assert!(!pf022_fires(&nested, &[]), "a workspace root in the files, above the crate");
        let loose = [("src/lib.rs", source.as_str())];
        assert!(
            !pf022_fires(&loose, &[Some(checked)]),
            "files with no Cargo.toml have no manifest: PF022 stays silent"
        );
    }

    #[test]
    fn a_manifest_that_does_not_parse_fails_the_scan_naming_it() {
        let error = scan_in_memory("t", &[("Cargo.toml", "[package"), ("src/lib.rs", "")], &[]).unwrap_err();
        assert!(error.to_string().starts_with("cannot parse Cargo.toml: "), "{error}");
        let files = [("Cargo.toml", "[package]"), ("src/lib.rs", "")];
        let error = scan_in_memory("t", &files, &[None, Some("[workspace")]).unwrap_err();
        assert!(error.to_string().starts_with("cannot parse ../../Cargo.toml: "), "{error}");
    }

    const OFF_FOR_A: &str = "[workspace]\n[profile.release]\noverflow-checks = true\n[profile.release.package.a]\noverflow-checks = false\n";

    fn vault() -> String {
        let patched = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/pf022_overflow_checks_off/patched");
        fs::read_to_string(patched.join("src/lib.rs")).unwrap()
    }

    #[test]
    fn a_rs_file_directly_in_a_crate_directory_belongs_to_that_crate() {
        let source = vault();
        let package = "[package]\nname = \"a\"\n";
        let build_script = [("Cargo.toml", OFF_FOR_A), ("a/Cargo.toml", package), ("a/build.rs", source.as_str())];
        assert!(
            pf022_fires(&build_script, &[]),
            "build.rs takes crate a's profile, which is set per package at the root"
        );
        let loose = [("Cargo.toml", OFF_FOR_A), ("a/Cargo.toml", package), ("loose.rs", source.as_str())];
        assert!(!pf022_fires(&loose, &[]), "a file beside the workspace manifest belongs to the root, not to a");
    }

    #[test]
    fn a_package_that_is_itself_a_workspace_root_uses_its_own_profile() {
        let source = vault();
        let checked = "[workspace]\n[profile.release]\noverflow-checks = true\n";
        let own_root = "[package]\nname = \"n\"\n[workspace]\n[profile.release]\noverflow-checks = false\n";
        let files = [("Cargo.toml", checked), ("n/Cargo.toml", own_root), ("n/src/lib.rs", source.as_str())];
        assert!(pf022_fires(&files, &[]), "n is a workspace root: the outer workspace's profile does not apply");
        let member = "[package]\nname = \"n\"\n";
        let files = [("Cargo.toml", checked), ("n/Cargo.toml", member), ("n/src/lib.rs", source.as_str())];
        assert!(!pf022_fires(&files, &[]), "the same package without its own [workspace] is a member of the outer one");
    }

    #[test]
    fn the_input_order_does_not_change_the_result() {
        let broken = "fn broken( {";
        for files in
            [[("b/src/x.rs", broken), ("a/src/x.rs", broken)], [("a/src/x.rs", broken), ("b/src/x.rs", broken)]]
        {
            let error = scan_in_memory("t", &files, &[]).unwrap_err();
            assert!(error.to_string().starts_with("cannot parse a/src/x.rs: "), "{error}");
        }
    }

    #[test]
    fn only_a_file_named_exactly_cargo_toml_is_a_manifest() {
        let files = [
            ("a/oldCargo.toml", "[package"),
            ("a/Cargo.toml.bak", "[package"),
            ("a/cargo.toml", "[package"),
            ("a/src/lib.rs", "pub fn ok() {}"),
        ];
        assert_eq!(scan_in_memory("t", &files, &[]).unwrap().summary.files_scanned, 1);
    }

    #[test]
    fn findings_are_ordered_by_file_line_column_and_rule_not_by_the_order_rules_run_in() {
        let fixture = |name: &str| {
            fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures").join(name).join("vulnerable/src/lib.rs"),
            )
            .unwrap()
        };
        let (pf001, pf002) = (fixture("pf001_callback"), fixture("pf002_one_yocto"));
        // PF001 runs before PF002, but the file PF002 flags sorts first.
        let files = [("b.rs", pf001.as_str()), ("a.rs", pf002.as_str())];
        let report = scan_in_memory("t", &files, &[]).unwrap();
        let flagged: Vec<_> = report.findings.iter().map(|finding| (finding.file.as_str(), finding.rule_id)).collect();
        assert!(flagged.contains(&("a.rs", "PF002")) && flagged.contains(&("b.rs", "PF001")), "{flagged:?}");
        let order: Vec<_> = report.findings.iter().map(|f| (f.file.clone(), f.line, f.column, f.rule_id)).collect();
        let mut sorted = order.clone();
        sorted.sort();
        assert_eq!(order, sorted);
        assert!(order.first().unwrap().0.starts_with("a.rs"), "{order:?}");
    }

    /// Writes `files` (each holding `pub fn a() {}`, or empty for a `Cargo.toml`) under a fresh directory and returns
    /// the filesystem scan and the in-memory scan of the same paths, as JSON or error text.
    fn disk_and_memory(files: &[&str]) -> (Result<String, String>, Result<String, String>) {
        let pairs: Vec<_> =
            files.iter().map(|file| (*file, if file.ends_with(".rs") { "pub fn a() {}" } else { "" })).collect();
        disk_and_memory_texts(&pairs)
    }

    /// [`disk_and_memory`] with the text of each file given.
    fn disk_and_memory_texts(files: &[(&str, &str)]) -> (Result<String, String>, Result<String, String>) {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("preflight-memory-{}-{id}", std::process::id()));
        for (file, text) in files {
            let path = root.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        let rules: Vec<_> = rules::all().collect();
        let label = root.to_string_lossy().into_owned();
        let show = |result: Result<Report, ScanError>| match result {
            Ok(report) => Ok(serde_json::to_string(&report).unwrap()),
            Err(error) => Err(error.to_string()),
        };
        let on_disk = show(crate::scan(&root, &rules));
        let in_memory = show(scan_files(&label, files, &[], &rules));
        fs::remove_dir_all(&root).unwrap();
        (on_disk, in_memory)
    }

    #[test]
    fn test_directories_are_cut_in_memory_exactly_as_on_disk() {
        for layout in [
            &["Cargo.toml", "src/lib.rs", "tests/it.rs", "tests/common/mod.rs", "benches/b.rs", "examples/e.rs"][..],
            &[
                "Cargo.toml",
                "tests/vault/Cargo.toml",
                "tests/vault/src/lib.rs",
                "benches/Cargo.toml",
                "benches/src/lib.rs",
            ],
            &["Cargo.toml", "tests/vault/Cargo.toml", "tests/vault/tests/it.rs", "tests/helpers.rs", "src/lib.rs"],
            &["Cargo.toml", "src/lib.rs", "src/tests/mod.rs"],
            &["contracts/tests/helper.rs", "contracts/src/lib.rs"],
            &["ws/Cargo.toml", "ws/src/lib.rs", "ws/tests/it.rs", "other/tests/it.rs"],
            &["tests/it.rs", "benches/b.rs"],
            &["Cargo.toml", "tests/it.rs", "benches/b.rs", "README.md"],
            &["Cargo.toml"],
        ] {
            let (on_disk, in_memory) = disk_and_memory(layout);
            assert!(on_disk.is_ok() || on_disk.as_ref().is_err_and(|e| e.starts_with("no Rust source")), "{layout:?}");
            assert_eq!(in_memory, on_disk, "{layout:?}");
        }
    }

    /// A crate whose `[lib] path` or `[[bin]] path` lies below `tests` or `benches` is read, on disk and in memory.
    #[test]
    fn a_target_the_manifest_declares_below_a_test_directory_is_read() {
        let manifest = "[package]\nname = \"n\"\n[lib]\npath = \"./benches/../tests/lib.rs\"\n[[bin]]\nname = \"b\"\npath = \"benches/main.rs\"\n";
        let files = [
            ("Cargo.toml", manifest),
            ("tests/lib.rs", "pub fn a() {}"),
            ("benches/main.rs", "fn main() {}"),
            ("benches/other.rs", "pub fn c() {}"),
        ];
        let (on_disk, in_memory) = disk_and_memory_texts(&files);
        assert_eq!(in_memory, on_disk);
        let report: serde_json::Value = serde_json::from_str(&on_disk.unwrap()).unwrap();
        assert_eq!(report["summary"]["files_scanned"], 2);
        assert_eq!(report["summary"]["test_files_skipped"], 1);
    }

    #[test]
    fn skipped_test_files_are_counted_and_a_set_with_only_tests_is_nothing_to_scan() {
        let report = scan_in_memory("t", &[("Cargo.toml", ""), ("src/lib.rs", ""), ("tests/it.rs", "")], &[]).unwrap();
        assert_eq!((report.summary.files_scanned, report.summary.test_files_skipped), (1, 1));

        let files = [("Cargo.toml", ""), ("tests/it.rs", "fn broken( {"), ("benches/b.rs", "")];
        let error = scan_in_memory("t", &files, &[]).unwrap_err().to_string();
        assert!(error.starts_with("no Rust source file to scan under t (2 skipped as test code"), "{error}");
        let error = scan_in_memory("t", &[("README.md", "")], &[]).unwrap_err().to_string();
        assert_eq!(error, "no Rust source file to scan under t");
        assert!(matches!(scan_in_memory("t", &[], &[]), Err(ScanError::NothingToScan { .. })));
    }
}
