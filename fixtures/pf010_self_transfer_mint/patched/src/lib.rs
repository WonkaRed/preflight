//! PF010 fixture (patched): the same token, with `ft_transfer` refusing a transfer to oneself.
//!
//! `ft_transfer` requires `sender_id != receiver_id`, as near-contract-standards does, so the two writes always
//! go to different accounts and the transfer only moves balance.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{AccountId, PanicOnDefault, assert_one_yocto, env, near, require};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Coin {
    balances: LookupMap<AccountId, u128>,
    total_supply: u128,
}

#[near]
impl Coin {
    /// The whole supply starts with `owner_id`.
    #[init]
    pub fn new(owner_id: AccountId, total_supply: U128) -> Self {
        let mut balances = LookupMap::new(b"b");
        balances.insert(owner_id, total_supply.0);
        Self { balances, total_supply: total_supply.0 }
    }

    /// Moves `amount` from the caller to `receiver_id`. Requires exactly 1 yoctoNEAR.
    #[payable]
    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) {
        assert_one_yocto();
        let sender_id = env::predecessor_account_id();
        let sender_balance = self.balances.get(&sender_id).copied().unwrap_or(0);
        let receiver_balance = self.balances.get(&receiver_id).copied().unwrap_or(0);
        require!(sender_id != receiver_id, "Sender and receiver should be different");
        require!(sender_balance >= amount.0, "not enough balance");
        self.balances.insert(sender_id, sender_balance - amount.0);
        self.balances.insert(receiver_id, receiver_balance + amount.0);
    }

    pub fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.balances.get(&account_id).copied().unwrap_or(0))
    }

    pub fn ft_total_supply(&self) -> U128 {
        U128(self.total_supply)
    }
}
