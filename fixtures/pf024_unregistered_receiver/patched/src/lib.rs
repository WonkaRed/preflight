//! PF024 fixture (patched): the same token, with `ft_transfer` refusing a receiver that has not registered.
//!
//! `ft_transfer` requires the receiver to have a record already, so the only way to create one is
//! `storage_deposit`, which the new holder (or whoever pays for them) funds.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{AccountId, NearToken, PanicOnDefault, assert_one_yocto, env, near, require};

/// What a record in the ledger costs a holder to register: 0.00125 NEAR.
const STORAGE_COST: NearToken = NearToken::from_yoctonear(1_250_000_000_000_000_000_000);

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct GoldToken {
    balances: LookupMap<AccountId, u128>,
}

#[near]
impl GoldToken {
    #[init]
    pub fn new(owner_id: AccountId, total_supply: U128) -> Self {
        let mut balances = LookupMap::new(b"b");
        balances.insert(owner_id, total_supply.0);
        Self { balances }
    }

    /// Registers `account_id` (the caller by default) for exactly the storage a record costs.
    #[payable]
    pub fn storage_deposit(&mut self, account_id: Option<AccountId>) {
        require!(env::attached_deposit() == STORAGE_COST, "attach exactly 0.00125 NEAR");
        let account_id = account_id.unwrap_or_else(env::predecessor_account_id);
        require!(self.balances.insert(account_id, 0).is_none(), "account is already registered");
    }

    #[payable]
    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        assert_one_yocto();
        let _ = memo;
        let sender = env::predecessor_account_id();
        require!(sender != receiver_id, "sender and receiver must differ");
        require!(self.balances.contains_key(&receiver_id), "the receiver is not registered");
        let sender_balance = self.balance(&sender);
        require!(sender_balance >= amount.0, "not enough balance");
        self.balances.insert(sender, sender_balance - amount.0);
        let receiver_balance = self.balance(&receiver_id);
        self.balances.insert(receiver_id, receiver_balance + amount.0);
    }

    pub fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.balance(&account_id))
    }
}

impl GoldToken {
    fn balance(&self, account_id: &AccountId) -> u128 {
        self.balances.get(account_id).copied().unwrap_or(0)
    }
}
