use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use super::check::{Finding, NotEvaluated};
use super::display::{clean, near};
use super::snapshot::{CodeSource, Snapshot};
use crate::finding::Severity;
use crate::report::{Tool, count_by_severity};

/// Version of the JSON layout documented in `SPEC.md`, "Deployed contracts"; bumped on any breaking change to it.
const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
pub struct AccountReport {
    pub schema_version: u32,
    /// Always `"deployed"`, so a consumer can tell this document from a source-scan report.
    pub kind: &'static str,
    pub tool: Tool,
    /// The account that was checked.
    pub target: String,
    /// Scheme, host and port of the RPC endpoint that answered; never a path or key.
    pub rpc: String,
    pub block: Block,
    pub account: AccountInfo,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    /// Checks that reached no verdict, with the reason. Empty when every check ran.
    pub not_evaluated: Vec<NotEvaluated>,
    /// Ids of the checks that ran, for the closing line of a clean report.
    #[serde(skip)]
    checks_run: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct Block {
    pub height: u64,
    pub hash: String,
}

#[derive(Debug, Serialize)]
pub struct AccountInfo {
    pub code_hash: String,
    pub code_bytes: usize,
    pub exported_functions: usize,
    /// Amounts are decimal strings of yoctoNEAR: they do not fit a JSON number.
    pub amount: String,
    pub locked: String,
    pub storage_usage: u64,
    /// Set when the account's code is a global contract identified by its hash, which has one fixed content.
    pub global_contract_hash: Option<String>,
    /// Set when the account's code is the global contract published by this account, which can replace it.
    pub global_contract_account_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub findings: usize,
    /// Count per severity; every severity is present, including zeros.
    pub by_severity: BTreeMap<Severity, usize>,
}

impl AccountReport {
    pub(super) fn new(
        rpc: &str,
        snapshot: &Snapshot,
        findings: Vec<Finding>,
        not_evaluated: Vec<NotEvaluated>,
        checks_run: Vec<&'static str>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            kind: "deployed",
            tool: Tool::current(),
            target: snapshot.account_id.clone(),
            rpc: rpc.to_owned(),
            block: Block { height: snapshot.block_height, hash: snapshot.block_hash.clone() },
            account: AccountInfo {
                code_hash: snapshot.code_hash.clone(),
                code_bytes: snapshot.code_bytes,
                exported_functions: snapshot.exports.len(),
                amount: snapshot.amount.to_string(),
                locked: snapshot.locked.to_string(),
                storage_usage: snapshot.storage_usage,
                global_contract_hash: match &snapshot.code_source {
                    CodeSource::GlobalByHash(hash) => Some(hash.clone()),
                    _ => None,
                },
                global_contract_account_id: match &snapshot.code_source {
                    CodeSource::GlobalByAccount(publisher) => Some(publisher.clone()),
                    _ => None,
                },
            },
            summary: Summary {
                findings: findings.len(),
                by_severity: count_by_severity(findings.iter().map(|finding| finding.severity)),
            },
            findings,
            not_evaluated,
            checks_run,
        }
    }

    /// True when nothing worth acting on was found: no finding of `low` or above. Informational findings are
    /// printed but do not count, so that a contract with an upgrade method or declared metadata exits 0.
    pub fn is_clean(&self) -> bool {
        self.findings.iter().all(|finding| finding.severity == Severity::Info)
    }
}

impl fmt::Display for AccountReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let plural = |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
        let account = &self.account;
        writeln!(f, "{} at block {} ({}, read-only)", self.target, self.block.height, self.rpc)?;
        writeln!(
            f,
            "  code {}: {} bytes, {}",
            account.code_hash,
            account.code_bytes,
            plural(account.exported_functions, "exported function"),
        )?;
        if let Some(hash) = &account.global_contract_hash {
            writeln!(f, "  code is the global contract with hash {hash}, which cannot change")?;
        }
        if let Some(publisher) = &account.global_contract_account_id {
            writeln!(
                f,
                "  code follows the global contract published by {publisher}; {publisher} can replace it (not checked)"
            )?;
        }
        let yocto = |text: &str| text.parse().map(near).unwrap_or_else(|_| clean(text, 40));
        writeln!(
            f,
            "  balance {} ({} locked), storage {} bytes",
            yocto(&account.amount),
            yocto(&account.locked),
            account.storage_usage,
        )?;
        for finding in &self.findings {
            writeln!(
                f,
                "\n{} [{}] {}\n    {}\n    {}\n    read: {}\n    limits: {}\n    fix: {}",
                finding.rule_id,
                finding.severity.as_str(),
                finding.title,
                finding.item,
                finding.message,
                finding.read,
                finding.limits,
                finding.help,
            )?;
        }
        for note in &self.not_evaluated {
            writeln!(f, "\n{} not evaluated: {}", note.rule_id, note.reason)?;
        }
        writeln!(f)?;
        if self.findings.is_empty() {
            let ran = format!("{}-{}", self.checks_run.first().unwrap_or(&""), self.checks_run.last().unwrap_or(&""));
            write!(f, "No findings from checks {ran}. That is not a safety audit")?;
        } else {
            let breakdown: Vec<String> = self
                .summary
                .by_severity
                .iter()
                .rev()
                .filter(|&(_, &count)| count > 0)
                .map(|(severity, count)| format!("{} {}", count, severity.as_str()))
                .collect();
            write!(f, "{} ({})", plural(self.findings.len(), "finding"), breakdown.join(", "))?;
        }
        if !self.not_evaluated.is_empty() {
            write!(f, "; {} not evaluated", self.not_evaluated.len())?;
        }
        writeln!(f)
    }
}
