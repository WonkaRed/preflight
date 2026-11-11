//! PF011 fixture (vulnerable): a treasury that decides who may withdraw from the transaction's signer.
//!
//! `withdraw` compares `env::signer_account_id()`, the account that signed the transaction, to the owner. If the
//! owner signs a call to any other contract, that contract can call `withdraw` and the check still sees the owner.

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
    // PF011: the signer is whoever started the transaction, not whoever called this method.
    pub fn withdraw(&mut self, to: AccountId, amount: U128) -> Promise {
        require!(env::signer_account_id() == self.owner, "only the owner can withdraw");
        Promise::new(to).transfer(NearToken::from_yoctonear(amount.0))
    }

    pub fn owner(&self) -> AccountId {
        self.owner.clone()
    }
}
