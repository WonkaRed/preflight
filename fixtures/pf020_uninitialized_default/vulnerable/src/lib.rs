//! PF020 fixture (vulnerable): a grant treasury whose `Default` makes the first caller the owner.
//!
//! The treasury is deployed with a balance and set up afterwards by `new`. Until `new` has run, near-sdk does not
//! refuse calls: it builds the state with `Default`, which here takes the owner from whoever is calling. An account
//! that calls `withdraw` in that window passes the owner check, drains the treasury and leaves its own id as the
//! stored owner, so the deployer's `new` then fails because the state already exists.

use near_sdk::{AccountId, NearToken, Promise, env, near, require};

#[near(contract_state)]
pub struct Treasury {
    owner_id: AccountId,
}

// PF020: the default owner is whoever calls first, and `new` below is not required to run before that call.
impl Default for Treasury {
    fn default() -> Self {
        Self { owner_id: env::predecessor_account_id() }
    }
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
