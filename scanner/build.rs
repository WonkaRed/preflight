//! Generates the rule registry from the files in `src/rules/`, so adding a rule is adding one file.
//!
//! Every `src/rules/pfNNN_<slug>.rs` must define `pub static RULE: <type implementing Rule>`. The generated
//! `rules_generated.rs` declares one module per file and lists the rules in file-name order.

use std::path::Path;
use std::{env, fs};

fn is_rule_file_name(stem: &str) -> bool {
    let Some(rest) = stem.strip_prefix("pf") else {
        return false;
    };
    let (digits, slug) = rest.split_at(rest.find('_').unwrap_or(0));
    digits.len() == 3
        && digits.bytes().all(|b| b.is_ascii_digit())
        && slug.len() > 1
        && slug[1..].bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn main() {
    let rules_dir = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("src/rules");
    println!("cargo:rerun-if-changed={}", rules_dir.display());

    let mut stems: Vec<String> = fs::read_dir(&rules_dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", rules_dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .map(|path| path.file_stem().unwrap().to_string_lossy().into_owned())
        .filter(|stem| stem != "mod")
        .collect();
    stems.sort();
    for stem in &stems {
        assert!(
            is_rule_file_name(stem),
            "src/rules/{stem}.rs: rule files are named pfNNN_<slug>.rs (three digits, lowercase slug)"
        );
    }

    let mut out = String::new();
    for stem in &stems {
        out += &format!("#[path = \"{}/{stem}.rs\"]\nmod {stem};\n", rules_dir.display());
    }
    out += "\n/// Every rule, with the file stem of its module, in rule-id order.\n";
    out += "pub(crate) static ALL: &[(&str, &dyn Rule)] = &[\n";
    for stem in &stems {
        out += &format!("    (\"{stem}\", &{stem}::RULE),\n");
    }
    out += "];\n";
    fs::write(Path::new(&env::var("OUT_DIR").unwrap()).join("rules_generated.rs"), out).unwrap();
}
