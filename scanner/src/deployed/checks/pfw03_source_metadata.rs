//! PFW03: NEP-330 `contract_source_metadata`.

use crate::deployed::check::{Check, Finding, NotEvaluated};
use crate::deployed::snapshot::{Metadata, Snapshot};
use crate::finding::Severity;

pub(crate) static CHECK: SourceMetadata = SourceMetadata;

pub(crate) struct SourceMetadata;

impl Check for SourceMetadata {
    fn id(&self) -> &'static str {
        "PFW03"
    }

    fn title(&self) -> &'static str {
        "NEP-330 source metadata"
    }

    fn read(&self) -> &'static str {
        "RPC query view_code (is contract_source_metadata exported) and, if so, RPC query call_function \
         contract_source_metadata, a read-only view call that changes no state"
    }

    fn limits(&self) -> &'static str {
        "The metadata is written by the contract itself and Preflight does not check it against the deployed \
         code: it can be stale or wrong. Its absence does not mean the contract is unsafe, only that this \
         account's code cannot be tied to published source from chain data alone."
    }

    fn help(&self) -> &'static str {
        "Build with cargo-near so the contract exports NEP-330 metadata with the version and a link to the exact \
         source commit"
    }

    fn check(&self, snapshot: &Snapshot) -> Result<Vec<Finding>, NotEvaluated> {
        let account = &snapshot.account_id;
        let finding = match &snapshot.metadata {
            Metadata::NotExported => self.finding(
                Severity::Info,
                account,
                "the contract does not export contract_source_metadata, so this check cannot tie its code to \
                 published source from chain data alone",
            ),
            Metadata::Unusable(why) => self.finding(
                Severity::Low,
                account,
                format!("the contract exports contract_source_metadata but it is unusable: {why}"),
            ),
            Metadata::Declared { version: None, link: None } => self.finding(
                Severity::Low,
                account,
                "the contract exports contract_source_metadata but declares neither a version nor a link",
            ),
            Metadata::Declared { version, link } => self.finding(
                Severity::Info,
                account,
                format!(
                    "the contract declares version {} and link {}. This is self-declared and was not verified \
                     against the code hash",
                    version.as_deref().unwrap_or("(none)"),
                    link.as_deref().unwrap_or("(none)"),
                ),
            ),
        };
        Ok(vec![finding])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_with(metadata: Metadata) -> Finding {
        let mut snapshot = Snapshot::sample();
        snapshot.metadata = metadata;
        CHECK.check(&snapshot).unwrap().remove(0)
    }

    #[test]
    fn declared_metadata_is_information_and_says_it_is_self_declared() {
        let finding =
            check_with(Metadata::Declared { version: Some("1.2.0".into()), link: Some("https://x/y".into()) });
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.message.contains("version 1.2.0 and link https://x/y"), "{}", finding.message);
        assert!(finding.message.contains("self-declared"));
    }

    #[test]
    fn absent_metadata_is_information_because_nep_330_is_optional() {
        let finding = check_with(Metadata::NotExported);
        assert_eq!(finding.severity, Severity::Info);
        assert!(
            finding.message.contains("so this check cannot tie its code to published source from chain data alone")
        );
    }

    #[test]
    fn unusable_or_empty_metadata_is_low() {
        assert_eq!(check_with(Metadata::Unusable("the call failed: x".into())).severity, Severity::Low);
        assert_eq!(check_with(Metadata::Declared { version: None, link: None }).severity, Severity::Low);
    }

    #[test]
    fn a_version_alone_is_still_information() {
        let finding = check_with(Metadata::Declared { version: Some("v1".into()), link: None });
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.message.contains("link (none)"));
    }
}
