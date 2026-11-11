//! PF018 fixture (helper): a contract that accepts every token its token contract sends with `ft_transfer_call`.
//!
//! It counts the tokens it received, as a staking or payment contract would, and reports none of them as unused.

use near_sdk::json_types::U128;
use near_sdk::{AccountId, PanicOnDefault, env, log, near, require};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Receiver {
    token: AccountId,
    received: u128,
}

#[near]
impl Receiver {
    #[init]
    pub fn new(token: AccountId) -> Self {
        Self { token, received: 0 }
    }

    /// Keeps all of `amount`, if the token contract it was set up with is the caller.
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> U128 {
        require!(env::predecessor_account_id() == self.token, "only the token contract can notify the receiver");
        log!("{sender_id} sent {} ({msg})", amount.0);
        self.received += amount.0;
        U128(0)
    }

    pub fn received(&self) -> U128 {
        U128(self.received)
    }
}
