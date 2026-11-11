//! PF021 fixture (helper): the smallest fungible token a reward pool can pay out in.
//!
//! The whole supply is minted to `owner_id` by `new`. `ft_transfer` follows NEP-141 where the exploit touches it
//! (one yoctoNEAR attached, a positive amount, the sender's balance must cover it); accounts need no storage
//! registration, which the pool's loop does not depend on.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{AccountId, PanicOnDefault, assert_one_yocto, env, near, require};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Token {
    balances: LookupMap<AccountId, u128>,
}

#[near]
impl Token {
    #[init]
    pub fn new(owner_id: AccountId, total_supply: U128) -> Self {
        let mut balances = LookupMap::new(b"b");
        balances.insert(owner_id, total_supply.0);
        Self { balances }
    }

    #[payable]
    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        assert_one_yocto();
        let _ = memo;
        require!(amount.0 > 0, "The amount should be a positive number");
        let sender_id = env::predecessor_account_id();
        let sender_balance = self.ft_balance_of(sender_id.clone()).0;
        require!(sender_balance >= amount.0, "The account doesn't have enough balance");
        self.balances.insert(sender_id, sender_balance - amount.0);
        let receiver_balance = self.ft_balance_of(receiver_id.clone()).0;
        self.balances.insert(receiver_id, receiver_balance + amount.0);
    }

    pub fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.balances.get(&account_id).copied().unwrap_or(0))
    }
}
