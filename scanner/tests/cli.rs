//! Runs the real `preflight` binary on the PF001 fixture pair.

use std::process::{Command, Output};

fn preflight(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_preflight")).args(args).output().unwrap()
}

fn fixture(variant: &str) -> String {
    format!("{}/../fixtures/pf001_callback/{variant}", env!("CARGO_MANIFEST_DIR"))
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn vulnerable_fixture_exits_1_with_a_pf001_finding() {
    let output = preflight(&[&fixture("vulnerable")]);
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    assert!(text.contains("pf001_callback/vulnerable/src/lib.rs:"), "{text}");
    assert!(text.contains("PF001 [high] Callback not marked #[private]"), "{text}");
    assert!(text.contains("1 finding in 1 file scanned (1 high)"), "{text}");
}

#[test]
fn patched_fixture_exits_0_with_no_findings() {
    let output = preflight(&[&fixture("patched")]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "No findings (1 file scanned)\n");
}

#[test]
fn json_report_follows_the_schema_in_spec() {
    let output = preflight(&["--json", &fixture("vulnerable")]);
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["tool"]["name"], "preflight");
    assert_eq!(report["summary"]["files_scanned"], 1);
    assert_eq!(report["summary"]["findings"], 1);
    assert_eq!(report["summary"]["by_severity"]["high"], 1);
    assert_eq!(report["summary"]["by_severity"]["critical"], 0);
    let finding = &report["findings"][0];
    assert_eq!(finding["rule_id"], "PF001");
    assert_eq!(finding["severity"], "high");
    assert_eq!(finding["file"], "src/lib.rs");
    assert_eq!(finding["item"], "Escrow::on_release");
    assert!(finding["line"].as_u64().unwrap() > 0 && finding["column"].as_u64().unwrap() > 0);
}

#[test]
fn json_report_for_the_patched_fixture_has_an_empty_findings_array() {
    let output = preflight(&["--json", &fixture("patched")]);
    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(report["findings"], serde_json::json!([]));
}

#[test]
fn a_missing_path_exits_2_and_says_why() {
    let output = preflight(&["no/such/path"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stderr).unwrap().contains("cannot read no/such/path"));
}

/// Writes the empty `files` under a fresh directory below the system temp dir and returns it.
fn tree(name: &str, files: &[&str]) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("preflight-cli-{name}-{}", std::process::id()));
    for file in files {
        let path = root.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "").unwrap();
    }
    root
}

/// z07: a scan that reads no file must not look like a clean one.
#[test]
fn a_scan_that_reads_no_file_exits_2_and_names_the_skipped_test_files() {
    let root = tree("nothing", &["Cargo.toml", "tests/it.rs", "benches/b.rs"]);
    let output = preflight(&[root.to_str().unwrap()]);
    std::fs::remove_dir_all(&root).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("no Rust source file to scan") && stderr.contains("2 skipped as test code"), "{stderr}");
}

#[test]
fn the_report_counts_the_test_files_it_skipped() {
    let root = tree("skipped", &["Cargo.toml", "src/lib.rs", "tests/it.rs", "tests/common/mod.rs"]);
    let text = preflight(&[root.to_str().unwrap()]);
    let json = preflight(&["--json", root.to_str().unwrap()]);
    std::fs::remove_dir_all(&root).unwrap();
    assert_eq!(text.status.code(), Some(0));
    assert_eq!(stdout(&text), "No findings (1 file scanned, 2 skipped as test code)\n");
    let report: serde_json::Value = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(report["summary"]["files_scanned"], 1);
    assert_eq!(report["summary"]["test_files_skipped"], 2);
}
