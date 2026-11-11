//! PF013 fixture (vulnerable): a vault whose pause switch is a trait method exported by `#[near]`.
//!
//! `Pausable` was written to organise the vault's code, and `pause` and `resume` were meant for the owner. But
//! `#[near]` on a trait impl exports every method of it as a public contract method, and these two check nothing,
//! so any account can freeze the vault. The inherent `transfer_ownership` shows the guard the author did write.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{AccountId, NearToken, PanicOnDefault, Promise, env, near, require};

pub trait Pausable {
    fn is_paused(&self) -> bool;
    fn pause(&mut self);
    fn resume(&mut self);
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Vault {
    owner: AccountId,
    paused: bool,
    balances: LookupMap<AccountId, u128>,
}

#[near]
impl Vault {
    #[init]
    pub fn new(owner: AccountId) -> Self {
        Self { owner, paused: false, balances: LookupMap::new(b"b") }
    }

    /// The attached deposit is added to the caller's balance.
    #[payable]
    pub fn deposit(&mut self) {
        require!(!self.paused, "vault is paused");
        let depositor = env::predecessor_account_id();
        let held = self.balances.get(&depositor).copied().unwrap_or(0);
        self.balances.insert(depositor, held + env::attached_deposit().as_yoctonear());
    }

    /// Pays `amount` of the caller's balance back to the caller.
    pub fn withdraw(&mut self, amount: U128) -> Promise {
        require!(!self.paused, "vault is paused");
        let depositor = env::predecessor_account_id();
        let held = self.balances.get(&depositor).copied().unwrap_or(0);
        require!(held >= amount.0, "insufficient balance");
        self.balances.insert(depositor.clone(), held - amount.0);
        Promise::new(depositor).transfer(NearToken::from_yoctonear(amount.0))
    }

    pub fn balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.balances.get(&account_id).copied().unwrap_or(0))
    }

    pub fn transfer_ownership(&mut self, new_owner: AccountId) {
        self.assert_owner();
        self.owner = new_owner;
    }
}

impl Vault {
    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner, "only the owner");
    }
}

// PF013: every method below is exported, `pause` and `resume` included, and neither checks the caller.
#[near]
impl Pausable for Vault {
    fn is_paused(&self) -> bool {
        self.paused
    }

    fn pause(&mut self) {
        self.paused = true;
    }

    fn resume(&mut self) {
        self.paused = false;
    }
}
