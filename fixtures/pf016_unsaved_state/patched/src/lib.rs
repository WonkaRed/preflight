//! PF016 fixture (patched): the same savings bank, with `withdraw` saving the changed account.
//!
//! `withdraw` writes the changed copy back with `insert`, so the debit sticks and a second withdrawal of the same
//! balance is refused.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{AccountId, NearToken, PanicOnDefault, Promise, assert_one_yocto, env, near, require};

#[near(serializers = [borsh])]
#[derive(Clone, Default)]
pub struct Account {
    balance: u128,
    withdrawals: u32,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Bank {
    accounts: LookupMap<AccountId, Account>,
}

#[near]
impl Bank {
    #[init]
    pub fn new() -> Self {
        Self { accounts: LookupMap::new(b"a") }
    }

    /// The attached deposit is added to the caller's balance.
    #[payable]
    pub fn deposit(&mut self) {
        let caller = env::predecessor_account_id();
        let mut account = self.accounts.get(&caller).cloned().unwrap_or_default();
        account.balance += env::attached_deposit().as_yoctonear();
        self.accounts.insert(caller, account);
    }

    /// Pays `amount` of the caller's balance to the caller.
    #[payable]
    pub fn withdraw(&mut self, amount: U128) -> Promise {
        assert_one_yocto();
        let caller = env::predecessor_account_id();
        let mut account = self.accounts.get(&caller).cloned().unwrap_or_default();
        require!(account.balance >= amount.0, "not enough balance");
        account.balance -= amount.0;
        account.withdrawals += 1;
        env::log_str(&format!(
            "{caller} withdrew {}, {} left after {} withdrawals",
            amount.0, account.balance, account.withdrawals
        ));
        self.accounts.insert(caller.clone(), account);
        Promise::new(caller).transfer(NearToken::from_yoctonear(amount.0))
    }

    pub fn balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.accounts.get(&account_id).map_or(0, |account| account.balance))
    }

    pub fn withdrawals_of(&self, account_id: AccountId) -> u32 {
        self.accounts.get(&account_id).map_or(0, |account| account.withdrawals)
    }
}
