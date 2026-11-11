//! The rule registry. `build.rs` declares a module for every `pfNNN_<slug>.rs` file here and lists its
//! `RULE` in [`ALL`]; to add a rule, add the file (see `SPEC.md`).

use crate::rule::Rule;

include!(concat!(env!("OUT_DIR"), "/rules_generated.rs"));

/// Every registered rule, in rule-id order.
pub fn all() -> impl Iterator<Item = &'static dyn Rule> {
    ALL.iter().map(|&(_, rule)| rule)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_ids_match_their_file_names_and_are_unique_and_ordered() {
        let ids: Vec<&str> = ALL.iter().map(|(_, rule)| rule.id()).collect();
        for (stem, rule) in ALL {
            assert!(stem.starts_with(&rule.id().to_lowercase()), "{stem}.rs defines {}", rule.id());
        }
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids, sorted, "ids must be unique and in file-name order");
    }

    #[test]
    fn every_rule_has_a_row_in_the_readme_rules_table() {
        let readme = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../README.md")).unwrap();
        for rule in all() {
            assert!(
                readme.lines().any(|line| line.starts_with('|') && line.contains(rule.id())),
                "README.md rules table has no row for {}",
                rule.id()
            );
        }
    }
}
