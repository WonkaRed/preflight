use proc_macro2::Span;

use crate::finding::{Finding, Severity};
use crate::source::{Crate, SourceFile};

/// A check over one crate's source. Implement it in `src/rules/pfNNN_<slug>.rs` and export it as
/// `pub static RULE`; `build.rs` registers it.
pub trait Rule: Sync {
    /// Stable id, `PF` and three digits. Never reused for a different check.
    fn id(&self) -> &'static str;
    fn title(&self) -> &'static str;
    fn severity(&self) -> Severity;
    /// How to fix what this rule reports.
    fn help(&self) -> &'static str;
    fn check(&self, krate: &Crate) -> Vec<Finding>;

    /// A finding for `item`, located at `span` in `file`, carrying this rule's id, title, severity and help.
    fn finding(&self, file: &SourceFile, span: Span, item: String, message: String) -> Finding {
        let start = span.start();
        Finding {
            rule_id: self.id(),
            title: self.title(),
            severity: self.severity(),
            file: file.path.clone(),
            line: start.line,
            column: start.column + 1,
            item,
            message,
            help: self.help(),
        }
    }
}
