//! PF004 fixture (attacker): the "third-party receiver" that a deposit names in `msg`, written to fail.
//!
//! It has the same `on_deposit` signature as an honest receiver and always panics. A vault that returns the
//! notification promise from `ft_on_transfer` sees that promise fail, and the token contract then refunds the
//! deposit to the sender. See `vulnerable` for what the vault does with the credit it already wrote.

use near_sdk::json_types::U128;
use near_sdk::{AccountId, PanicOnDefault, env, near};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Attacker {}

#[near]
impl Attacker {
    #[init]
    pub fn new() -> Self {
        Self {}
    }

    /// Refuses every notification.
    pub fn on_deposit(&mut self, sender_id: AccountId, amount: U128) -> U128 {
        env::panic_str(&format!("{} refuses the deposit of {} from {sender_id}", env::current_account_id(), amount.0));
    }
}
