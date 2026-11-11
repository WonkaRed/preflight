//! PF007 fixture (vulnerable): a treasury whose ownership setter is open to everyone.
//!
//! `payout` is owner-only and checks the caller, but `set_owner` hands the contract to whoever asks: an outsider
//! makes themselves the owner and then pays the whole treasury out to themselves.

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

    // PF007: changes who is in charge without asking who is calling.
    pub fn set_owner(&mut self, new_owner: AccountId) {
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
