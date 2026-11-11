//! PF008 fixture (vulnerable): a guest book with a tip jar whose `sign` stores text for free.
//!
//! Visitors leave tips with `tip` and sign the book with `sign`; the owner withdraws the tips. Every signature
//! is stored in the contract's state, and the contract's own balance pays for those bytes, so anyone who signs
//! with a huge message for the price of gas locks the tips up until `withdraw` has nothing it may spend.

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

    // PF008: stores the caller's text and charges nothing for the storage it takes.
    pub fn sign(&mut self, text: String) {
        self.entries.push(Entry { author: env::predecessor_account_id(), text });
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
