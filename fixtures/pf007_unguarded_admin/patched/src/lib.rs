//! PF007 fixture (patched): the treasury's ownership setter checks the caller.
//!
//! Same contract as `vulnerable`, with the one line that was missing: `set_owner` calls `assert_owner`, so only
//! the current owner can hand the treasury over.

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

    /// Anyone can top the treasury up.
    #[payable]
    pub fn fund(&mut self) {}

    pub fn set_owner(&mut self, new_owner: AccountId) {
        self.assert_owner();
        self.owner_id = new_owner;
    }

    /// Pays `amount` out of the treasury to `to`; only the owner may.
    pub fn payout(&mut self, to: AccountId, amount: NearToken) -> Promise {
        self.assert_owner();
        Promise::new(to).transfer(amount)
    }

    pub fn get_owner(&self) -> AccountId {
        self.owner_id.clone()
    }
}

impl Treasury {
    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner_id, "only the owner can do this");
    }
}
