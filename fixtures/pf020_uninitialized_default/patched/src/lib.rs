//! PF020 fixture (patched): the grant treasury with `PanicOnDefault` instead of a `Default` that picks the owner.
//!
//! Every method now panics until `new` has run, so nobody can call `withdraw` in the window between deploying the
//! treasury and setting it up, and `new` can still be run by the deployer afterwards.

use near_sdk::{AccountId, NearToken, PanicOnDefault, Promise, env, near, require};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Treasury {
    owner_id: AccountId,
}

#[near]
impl Treasury {
    #[init]
    pub fn new(owner_id: AccountId) -> Self {
        Self { owner_id }
    }

    /// Pays `amount` of the treasury's balance to the owner.
    pub fn withdraw(&mut self, amount: NearToken) -> Promise {
        require!(env::predecessor_account_id() == self.owner_id, "only the owner can withdraw");
        Promise::new(self.owner_id.clone()).transfer(amount)
    }

    pub fn owner(&self) -> AccountId {
        self.owner_id.clone()
    }
}
