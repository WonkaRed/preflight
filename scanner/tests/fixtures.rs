//! Conventions every `fixtures/pfNNN_<slug>/{vulnerable,patched}` pair must keep (see SPEC.md), so a new rule's
//! pair is checked the moment it is added.

use std::fs;
use std::path::{Path, PathBuf};

use preflight::rules;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// `(directory name, rule id)` for every `fixtures/pf*` directory, sorted.
fn fixture_pairs() -> Vec<(String, String)> {
    let mut pairs: Vec<_> = fs::read_dir(repo().join("fixtures"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("pf"))
        .map(|name| {
            let id = name[..5].to_uppercase();
            (name, id)
        })
        .collect();
    pairs.sort();
    pairs
}

fn scan(pair: &str, variant: &str) -> preflight::Report {
    let rules: Vec<_> = rules::all().collect();
    preflight::scan(&repo().join("fixtures").join(pair).join(variant), &rules).unwrap()
}

#[test]
fn every_rule_has_a_fixture_pair_and_every_fixture_pair_has_a_rule() {
    let rule_ids: Vec<String> = rules::all().map(|rule| rule.id().to_owned()).collect();
    let fixture_ids: Vec<String> = fixture_pairs().into_iter().map(|(_, id)| id).collect();
    assert_eq!(rule_ids, fixture_ids);
}

#[test]
fn each_vulnerable_fixture_triggers_its_rule_and_each_patched_fixture_is_clean() {
    for (pair, id) in fixture_pairs() {
        let vulnerable = scan(&pair, "vulnerable");
        assert!(vulnerable.findings.iter().any(|f| f.rule_id == id), "{pair}/vulnerable has no {id} finding");
        let patched = scan(&pair, "patched");
        assert!(patched.is_clean(), "{pair}/patched has findings:\n{patched}");
    }
}

#[test]
fn each_fixture_pair_has_an_exploit_test() {
    for (pair, _) in fixture_pairs() {
        let test = repo().join("exploits/tests").join(format!("{pair}.rs"));
        assert!(test.is_file(), "missing {}", test.display());
    }
}
