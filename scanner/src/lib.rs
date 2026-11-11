//! Preflight: a security scanner for NEAR smart contract source.
//!
//! [`scan`] parses every Rust file under a path, groups the files into crates, runs each [`Rule`] over each
//! crate, and returns a [`Report`]. The report serializes to the JSON documented in `SPEC.md`.
//!
//! [`deployed::check_account`] is the second mode: it checks a contract already on chain by account id. It is
//! behind the default-on `deployed` feature, so a build that only scans source (the wasm one) leaves it out.

#![forbid(unsafe_code)]

#[cfg(feature = "deployed")]
pub mod deployed;
mod finding;
mod guards;
mod memory;
mod report;
mod rule;
pub mod rules;
mod scan;
mod scope;
mod source;

pub use finding::{Finding, Severity};
pub use memory::scan_files;
pub use report::Report;
pub use rule::Rule;
pub use scan::{ScanError, scan};
pub use source::{Crate, SourceFile};
