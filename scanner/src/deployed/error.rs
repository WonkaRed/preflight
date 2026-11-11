use std::time::Duration;

use super::transport::TransportError;

/// Why a deployed-contract check produced no report. A contract that could not be read must never look clean,
/// so every one of these is an error and none is "no findings".
#[derive(Debug, thiserror::Error)]
pub enum DeployedError {
    #[error("{account} does not exist on this network")]
    UnknownAccount { account: String },
    #[error("{account} exists but has no contract code deployed, so there is nothing to check")]
    NoContract { account: String },
    #[error("{call}: {source}")]
    Transport { call: &'static str, source: TransportError },
    /// The node answered with a JSON-RPC error object. `cause` is `error.cause.name`, such as `UNKNOWN_BLOCK`.
    #[error("{call}: the node returned an error: {message}")]
    Node { call: &'static str, cause: Option<String>, message: String },
    #[error("{call}: unusable response: {detail}")]
    Malformed { call: &'static str, detail: String },
    /// The whole run took too long: a node that answers slowly, or keeps sending pages, cannot hold it open.
    #[error("stopped before {call}: the run took longer than {limit:?} in total")]
    Deadline { call: &'static str, limit: Duration },
}

impl DeployedError {
    /// True when the chain could not be read, as opposed to the input naming nothing checkable.
    pub fn is_read_failure(&self) -> bool {
        !matches!(self, Self::UnknownAccount { .. } | Self::NoContract { .. })
    }

    pub(super) fn malformed(call: &'static str, detail: impl Into<String>) -> Self {
        Self::Malformed { call, detail: detail.into() }
    }
}
