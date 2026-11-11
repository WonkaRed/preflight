use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::finding::{Finding, Severity};

/// Version of the JSON layout documented in `SPEC.md`; bumped on any breaking change to it.
const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub tool: Tool,
    /// The path that was scanned, as given.
    pub target: String,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    /// Directory the findings' `file` paths are relative to; text output prefixes it so locations are clickable.
    #[serde(skip)]
    base: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct Tool {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub files_scanned: usize,
    /// Files under `tests`, `compilation_tests` and `benches` directories of a crate, which are not scanned.
    pub test_files_skipped: usize,
    pub findings: usize,
    /// Count per severity; every severity is present, including zeros.
    pub by_severity: BTreeMap<Severity, usize>,
}

impl Tool {
    pub(crate) fn current() -> Self {
        Self { name: env!("CARGO_PKG_NAME"), version: env!("CARGO_PKG_VERSION") }
    }
}

/// How many of `severities` fall in each severity; every severity is present, zeros included.
pub(crate) fn count_by_severity(severities: impl Iterator<Item = Severity>) -> BTreeMap<Severity, usize> {
    let mut counts: BTreeMap<Severity, usize> =
        [Severity::Info, Severity::Low, Severity::Medium, Severity::High, Severity::Critical]
            .into_iter()
            .map(|severity| (severity, 0))
            .collect();
    for severity in severities {
        *counts.entry(severity).or_default() += 1;
    }
    counts
}

impl Report {
    pub(crate) fn new(
        target: String,
        base: &Path,
        files_scanned: usize,
        test_files_skipped: usize,
        findings: Vec<Finding>,
    ) -> Self {
        let by_severity = count_by_severity(findings.iter().map(|finding| finding.severity));
        Self {
            schema_version: SCHEMA_VERSION,
            tool: Tool::current(),
            target,
            summary: Summary { files_scanned, test_files_skipped, findings: findings.len(), by_severity },
            findings,
            base: base.to_owned(),
        }
    }

    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let plural = |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
        for finding in &self.findings {
            writeln!(
                f,
                "{}:{}:{}: {} [{}] {}\n    {}\n    fix: {}",
                self.base.join(&finding.file).display(),
                finding.line,
                finding.column,
                finding.rule_id,
                finding.severity.as_str(),
                finding.title,
                finding.message,
                finding.help,
            )?;
        }
        let mut scanned = plural(self.summary.files_scanned, "file");
        if self.summary.test_files_skipped > 0 {
            scanned = format!("{scanned} scanned, {} skipped as test code", self.summary.test_files_skipped);
        } else {
            scanned.push_str(" scanned");
        }
        if self.is_clean() {
            return writeln!(f, "No findings ({scanned})");
        }
        let breakdown: Vec<String> = self
            .summary
            .by_severity
            .iter()
            .rev()
            .filter(|&(_, &count)| count > 0)
            .map(|(severity, count)| format!("{} {}", count, severity.as_str()))
            .collect();
        writeln!(f, "{} in {scanned} ({})", plural(self.findings.len(), "finding"), breakdown.join(", "))
    }
}
