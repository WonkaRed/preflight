//! PF004 fixture (helper): an honest third-party receiver that a depositor can name in `msg`.
//!
//! It counts the deposits it is told about, as a rewards or accounting contract would. It accepts every
//! notification, so a deposit that names it behaves like a plain deposit plus one recorded notification.

use near_sdk::json_types::U128;
use near_sdk::{AccountId, PanicOnDefault, env, log, near};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Receiver {
    deposits: u64,
    volume: u128,
}

#[near]
impl Receiver {
    #[init]
    pub fn new() -> Self {
        Self { deposits: 0, volume: 0 }
    }

    /// Records that `sender_id` deposited `amount` into the notifying vault, and reports none of it as unused.
    pub fn on_deposit(&mut self, sender_id: AccountId, amount: U128) -> U128 {
        log!("{} deposited {} into {}", sender_id, amount.0, env::predecessor_account_id());
        self.deposits += 1;
        self.volume += amount.0;
        U128(0)
    }

    /// `(number of notifications, total amount they reported)`.
    pub fn summary(&self) -> (u64, U128) {
        (self.deposits, U128(self.volume))
    }
}
