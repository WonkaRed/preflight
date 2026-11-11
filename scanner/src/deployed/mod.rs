//! Deployed-contract mode: [`check_account`] reads a contract that is already on chain by account id, over
//! public JSON-RPC, and runs checks `PFW01` to `PFW06` over what it read. It is the counterpart of the source
//! scan for the case where an agent about to pay a contract has only an account id.
//!
//! Every request is a read: `query` with `view_account`, `view_code`, `view_access_key_list`, `view_state` or
//! `call_function` (a view call, executed by the node and never a transaction), and
//! `EXPERIMENTAL_protocol_config`. Nothing is signed, sent or spent, and no key is ever needed. All reads of one
//! run are pinned to one block, and every failure to read is a [`DeployedError`]: a contract that could not be
//! read never looks clean.

use std::time::Duration;

mod check;
mod checks;
mod display;
mod error;
mod report;
mod rpc;
mod snapshot;
mod transport;

pub use check::{Finding, NotEvaluated};
pub use error::DeployedError;
pub use near_account_id::AccountId;
pub use report::AccountReport;
pub use transport::{HttpTransport, RpcUrl, Transport, TransportError};

/// How long a whole run may take before it is stopped.
pub const RUN_LIMIT: Duration = Duration::from_secs(120);

/// Reads `account` through `transport` and checks it, giving up after [`RUN_LIMIT`].
pub fn check_account(transport: &dyn Transport, account: &AccountId) -> Result<AccountReport, DeployedError> {
    check_account_within(transport, account, RUN_LIMIT)
}

/// [`check_account`] with its own time limit for the whole run.
pub fn check_account_within(
    transport: &dyn Transport,
    account: &AccountId,
    limit: Duration,
) -> Result<AccountReport, DeployedError> {
    let snapshot = snapshot::read(&rpc::Rpc::new(transport, limit), account)?;
    let (findings, not_evaluated) = checks::run(&snapshot);
    Ok(AccountReport::new(transport.endpoint(), &snapshot, findings, not_evaluated, checks::ids()))
}
