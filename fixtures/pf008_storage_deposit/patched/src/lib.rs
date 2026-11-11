//! PF008 fixture (patched): `sign` makes the caller pay for the storage it uses.
//!
//! Same contract as `vulnerable`, but `sign` is `#[payable]`: it measures how many bytes the signature added,
//! requires the attached deposit to cover them at the storage price, and refunds the rest.

use near_sdk::store::Vector;
use near_sdk::{AccountId, NearToken, PanicOnDefault, Promise, env, near, require};

#[near(serializers = [borsh, json])]
pub struct Entry {
    author: AccountId,
    text: String,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct GuestBook {
    owner_id: AccountId,
    entries: Vector<Entry>,
}

#[near]
impl GuestBook {
    #[init]
    pub fn new(owner_id: AccountId) -> Self {
        Self { owner_id, entries: Vector::new(b"e") }
    }

    /// Leaves a tip: the attached deposit stays in the contract until the owner withdraws it.
    #[payable]
    pub fn tip(&mut self) {}

    /// Signs the book. The attached deposit must cover the storage the entry takes; the excess is refunded.
    #[payable]
    pub fn sign(&mut self, text: String) {
        let before = env::storage_usage();
        self.entries.push(Entry { author: env::predecessor_account_id(), text });
        // `store::Vector` writes on flush, so flush before measuring.
        self.entries.flush();
        let cost = env::storage_byte_cost().saturating_mul(u128::from(env::storage_usage() - before));
        let deposit = env::attached_deposit();
        require!(deposit >= cost, format!("attach at least {cost} to pay for the storage"));
        let refund = deposit.saturating_sub(cost);
        if !refund.is_zero() {
            Promise::new(env::predecessor_account_id()).transfer(refund).detach();
        }
    }

    /// Pays `amount` of the tips out to the owner.
    pub fn withdraw(&mut self, amount: NearToken) -> Promise {
        require!(env::predecessor_account_id() == self.owner_id, "only the owner can withdraw");
        Promise::new(self.owner_id.clone()).transfer(amount)
    }

    pub fn entry_count(&self) -> u32 {
        self.entries.len()
    }
}
