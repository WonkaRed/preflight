//! PF011 fixture (patched): the same treasury, checking the account that called `withdraw`.
//!
//! `env::predecessor_account_id()` is the direct caller. A contract the owner was tricked into calling is the
//! predecessor of its own cross-contract call, so it is no longer mistaken for the owner.

use near_sdk::json_types::U128;
use near_sdk::{AccountId, NearToken, PanicOnDefault, Promise, env, near, require};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Treasury {
    owner: AccountId,
}

#[near]
impl Treasury {
    #[init]
    pub fn new(owner: AccountId) -> Self {
        Self { owner }
    }

    /// Pays `amount` of the treasury's balance to `to`. Owner only.
    pub fn withdraw(&mut self, to: AccountId, amount: U128) -> Promise {
        require!(env::predecessor_account_id() == self.owner, "only the owner can withdraw");
        Promise::new(to).transfer(NearToken::from_yoctonear(amount.0))
    }

    pub fn owner(&self) -> AccountId {
        self.owner.clone()
    }
}
