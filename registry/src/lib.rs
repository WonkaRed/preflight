//! Preflight verdict registry: one security verdict per contract code hash, published by an allowlisted auditor.
//!
//! The allowlist is fixed in [`Registry::new`]. There is no owner, no setter and no upgrade method, so the
//! rules below hold for the life of the deployment. See `README.md` and `SPEC.md` section 6.

mod validate;

use near_sdk::json_types::U64;
use near_sdk::store::LookupMap;
use near_sdk::{AccountId, BorshStorageKey, PanicOnDefault, Promise, env, near, require};

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerdictStatus {
    Safe,
    Warn,
    Unsafe,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// Base58 SHA-256 of the deployed wasm, the form NEAR RPC reports as an account's `code_hash`.
    pub code_hash: String,
    pub status: VerdictStatus,
    /// Ids of the rules that fired, such as `["PF001"]`; empty for `Safe`.
    pub rule_ids: Vec<String>,
    /// Where the full scan report JSON is published.
    pub report_url: String,
    /// Lowercase hex SHA-256 of that report, so a reader can check it.
    pub report_sha256: String,
    /// The account that published this verdict; set by the contract, never an argument.
    pub auditor: AccountId,
    /// Block timestamp of the publication in milliseconds; set by the contract.
    pub published_at_ms: U64,
}

#[near(serializers = [borsh])]
#[derive(BorshStorageKey)]
enum StorageKey {
    Verdicts,
}

/// NEP-297 event logged on every publication.
#[near(event_json(standard = "preflight"))]
pub enum Event<'a> {
    #[event_version("1.0.0")]
    VerdictPublished { code_hash: &'a str, status: &'a VerdictStatus, auditor: &'a AccountId },
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Registry {
    auditors: Vec<AccountId>,
    verdicts: LookupMap<String, Verdict>,
}

#[near]
impl Registry {
    /// Fixes the auditor allowlist for the life of the contract: 1 to 16 distinct accounts.
    /// Deploy and call this in one transaction so nobody can initialise the contract in between.
    #[init]
    pub fn new(auditors: Vec<AccountId>) -> Self {
        validate::auditors(&auditors).unwrap_or_else(|reason| env::panic_str(&reason));
        Self { auditors, verdicts: LookupMap::new(StorageKey::Verdicts) }
    }

    /// Panics unless the caller is in the allowlist. A later verdict for the same `code_hash` replaces the earlier.
    ///
    /// The caller pays for any storage the verdict adds: attach enough NEAR, the excess is refunded. Replacing a
    /// verdict with one of the same size or smaller costs nothing.
    #[payable]
    pub fn publish_verdict(
        &mut self,
        code_hash: String,
        status: VerdictStatus,
        rule_ids: Vec<String>,
        report_url: String,
        report_sha256: String,
    ) {
        let auditor = env::predecessor_account_id();
        require!(self.auditors.contains(&auditor), format!("{auditor} is not an allowlisted auditor"));
        validate::publication(&code_hash, &status, &rule_ids, &report_url, &report_sha256)
            .unwrap_or_else(|reason| env::panic_str(&reason));

        let event = Event::VerdictPublished { code_hash: &code_hash, status: &status, auditor: &auditor };
        let verdict = Verdict {
            code_hash: code_hash.clone(),
            status: status.clone(),
            rule_ids,
            report_url,
            report_sha256,
            auditor: auditor.clone(),
            published_at_ms: env::block_timestamp_ms().into(),
        };

        let usage_before = env::storage_usage();
        self.verdicts.insert(code_hash.clone(), verdict);
        self.verdicts.flush();
        let added_bytes = env::storage_usage().saturating_sub(usage_before);
        let cost = env::storage_byte_cost().saturating_mul(u128::from(added_bytes));
        let deposit = env::attached_deposit();
        require!(deposit >= cost, format!("attach at least {cost} to pay for the storage; attached {deposit}"));
        if deposit > cost {
            Promise::new(auditor.clone()).transfer(deposit.saturating_sub(cost)).detach();
        }
        event.emit();
    }

    pub fn get_verdict(&self, code_hash: String) -> Option<Verdict> {
        self.verdicts.get(&code_hash).cloned()
    }

    pub fn get_auditors(&self) -> Vec<AccountId> {
        self.auditors.clone()
    }
}

#[cfg(test)]
mod tests;
