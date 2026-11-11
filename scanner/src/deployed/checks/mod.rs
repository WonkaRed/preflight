//! The checks, in id order. Adding one is a file here and a line in [`ALL`].

mod pfw01_access_keys;
mod pfw02_upgrade_surface;
mod pfw03_source_metadata;
mod pfw04_never_initialized;
mod pfw05_storage_floor;
mod pfw06_token_shape;

use super::check::{Check, Finding, NotEvaluated};
use super::snapshot::Snapshot;

/// Every check with the file stem of its module.
const ALL: &[(&str, &dyn Check)] = &[
    ("pfw01_access_keys", &pfw01_access_keys::CHECK),
    ("pfw02_upgrade_surface", &pfw02_upgrade_surface::CHECK),
    ("pfw03_source_metadata", &pfw03_source_metadata::CHECK),
    ("pfw04_never_initialized", &pfw04_never_initialized::CHECK),
    ("pfw05_storage_floor", &pfw05_storage_floor::CHECK),
    ("pfw06_token_shape", &pfw06_token_shape::CHECK),
];

/// Runs every check; a check that reaches no verdict is listed, not dropped.
pub(super) fn run(snapshot: &Snapshot) -> (Vec<Finding>, Vec<NotEvaluated>) {
    let mut findings = Vec::new();
    let mut not_evaluated = Vec::new();
    for (_, check) in ALL {
        match check.check(snapshot) {
            Ok(mut found) => findings.append(&mut found),
            Err(note) => not_evaluated.push(note),
        }
    }
    (findings, not_evaluated)
}

/// The ids of the checks that ran, for the report's closing line.
pub(super) fn ids() -> Vec<&'static str> {
    ALL.iter().map(|(_, check)| check.id()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_match_file_names_are_unique_and_ordered() {
        let ids = ids();
        for (stem, check) in ALL {
            let number = check.id().strip_prefix("PFW").expect("ids start with PFW");
            assert!(stem.starts_with(&format!("pfw{number}_")), "{} is in {stem}.rs", check.id());
        }
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, ids);
        assert_eq!(ids, ["PFW01", "PFW02", "PFW03", "PFW04", "PFW05", "PFW06"]);
    }

    #[test]
    fn every_check_states_what_it_read_and_what_it_does_not_prove() {
        for (_, check) in ALL {
            assert!(check.read().len() > 20 && check.limits().len() > 20 && check.help().len() > 20, "{}", check.id());
        }
    }

    #[test]
    fn a_clean_sample_yields_only_the_informational_metadata_finding() {
        let (findings, not_evaluated) = run(&Snapshot::sample());
        assert!(not_evaluated.is_empty());
        let ids: Vec<_> = findings.iter().map(|f| (f.rule_id, f.severity)).collect();
        assert_eq!(ids, [("PFW03", crate::finding::Severity::Info)]);
    }
}
