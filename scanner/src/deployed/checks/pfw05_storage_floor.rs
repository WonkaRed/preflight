//! PFW05: balance against the cost of the storage the account uses.

use crate::deployed::check::{Check, Finding, NotEvaluated};
use crate::deployed::display::near;
use crate::deployed::snapshot::Snapshot;
use crate::finding::Severity;

pub(crate) static CHECK: StorageFloor = StorageFloor;

pub(crate) struct StorageFloor;

/// An account that uses no more than this many bytes needs no balance for its storage (NEP-448, zero-balance
/// accounts). nearcore 2.14.0, `runtime/runtime/src/verifier.rs`: `ZERO_BALANCE_ACCOUNT_STORAGE_LIMIT = 770`
/// (line 25), applied by `is_zero_balance_account` (lines 88-90) when `check_storage_stake` finds the balance
/// short (line 77). It is not gated on a protocol version there.
const ZERO_BALANCE_STORAGE_LIMIT: u64 = 770;

impl Check for StorageFloor {
    fn id(&self) -> &'static str {
        "PFW05"
    }

    fn title(&self) -> &'static str {
        "Balance below the storage cost"
    }

    fn read(&self) -> &'static str {
        "RPC query view_account (amount, locked, storage_usage) and RPC EXPERIMENTAL_protocol_config \
         (runtime_config.storage_amount_per_byte), at the block shown in the report"
    }

    fn limits(&self) -> &'static str {
        "It compares one account's balance with its own storage at one block. Funds can sit in other accounts, \
         and the rule the network enforces (balance plus locked stake must cover storage_usage times the price \
         per byte, except zero-balance accounts (NEP-448, at most 770 bytes)) is applied when state changes, so \
         a shortfall here is unusual and worth a second look rather than proof of a problem."
    }

    fn help(&self) -> &'static str {
        "Keep enough NEAR on the account to pay for its storage, and charge users a storage deposit for state they add"
    }

    fn check(&self, snapshot: &Snapshot) -> Result<Vec<Finding>, NotEvaluated> {
        let Some(required) = u128::from(snapshot.storage_usage).checked_mul(snapshot.storage_amount_per_byte) else {
            return Err(self.not_evaluated("the storage cost does not fit in 128 bits"));
        };
        let available = snapshot.amount.saturating_add(snapshot.locked);
        if available >= required || snapshot.storage_usage <= ZERO_BALANCE_STORAGE_LIMIT {
            return Ok(Vec::new());
        }
        Ok(vec![self.finding(
            Severity::Low,
            &snapshot.account_id,
            format!(
                "the account holds {} ({available} yoctoNEAR, including {} locked) but its {} bytes of storage cost \
                 {} ({required} yoctoNEAR at {} yoctoNEAR per byte)",
                near(available),
                near(snapshot.locked),
                snapshot.storage_usage,
                near(required),
                snapshot.storage_amount_per_byte,
            ),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_balance_that_covers_storage_has_no_finding() {
        assert_eq!(CHECK.check(&Snapshot::sample()).unwrap(), []);
    }

    #[test]
    fn exactly_the_storage_cost_is_enough() {
        let mut snapshot = Snapshot::sample();
        snapshot.amount = u128::from(snapshot.storage_usage) * snapshot.storage_amount_per_byte;
        assert_eq!(CHECK.check(&snapshot).unwrap(), []);
    }

    #[test]
    fn a_balance_below_the_storage_cost_is_a_finding_with_the_numbers() {
        let mut snapshot = Snapshot::sample();
        snapshot.amount = 5 * 10u128.pow(24);
        snapshot.storage_usage = 1_000_000;
        let findings = CHECK.check(&snapshot).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(
            findings[0].message,
            "the account holds 5.0000 NEAR (5000000000000000000000000 yoctoNEAR, including 0.0000 NEAR locked) but its \
             1000000 bytes of storage cost 10.0000 NEAR (10000000000000000000000000 yoctoNEAR at 10000000000000000000 \
             yoctoNEAR per byte)"
        );
    }

    #[test]
    fn a_zero_balance_account_is_exempt_up_to_the_nep_448_limit() {
        let mut snapshot = Snapshot::sample();
        snapshot.amount = 0;
        snapshot.storage_usage = 300;
        assert_eq!(CHECK.check(&snapshot).unwrap(), []);
        snapshot.storage_usage = 770;
        assert_eq!(CHECK.check(&snapshot).unwrap(), [], "770 bytes is still exempt");
        snapshot.storage_usage = 771;
        assert_eq!(CHECK.check(&snapshot).unwrap().len(), 1, "771 bytes is not");
    }

    #[test]
    fn the_limits_text_states_the_threshold_the_check_applies() {
        assert!(CHECK.limits().contains(&format!("at most {ZERO_BALANCE_STORAGE_LIMIT} bytes")));
    }

    #[test]
    fn locked_stake_counts_towards_the_floor() {
        let mut snapshot = Snapshot::sample();
        snapshot.amount = 0;
        snapshot.locked = 10 * 10u128.pow(24);
        assert_eq!(CHECK.check(&snapshot).unwrap(), []);
    }

    #[test]
    fn a_cost_that_overflows_is_not_evaluated_rather_than_wrapped() {
        let mut snapshot = Snapshot::sample();
        snapshot.storage_amount_per_byte = u128::MAX;
        assert!(CHECK.check(&snapshot).is_err());
    }
}
