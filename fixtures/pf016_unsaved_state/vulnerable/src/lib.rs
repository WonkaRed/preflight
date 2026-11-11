//! PF016 fixture (vulnerable): a savings bank whose `withdraw` changes a copy of the account and never saves it.
//!
//! `withdraw` copies the caller's account out of the map, subtracts the amount from the copy and pays out, but
//! never writes the copy back. The stored balance does not change, so the same balance can be withdrawn again and
//! again until the bank holds nothing, and everybody else's deposits are what gets paid.

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
        // PF016: the debit lands on this local copy; nothing writes it back to `self.accounts`.
        account.balance -= amount.0;
        account.withdrawals += 1;
        env::log_str(&format!(
            "{caller} withdrew {}, {} left after {} withdrawals",
            amount.0, account.balance, account.withdrawals
        ));
        Promise::new(caller).transfer(NearToken::from_yoctonear(amount.0))
    }

    pub fn balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.accounts.get(&account_id).map_or(0, |account| account.balance))
    }

    pub fn withdrawals_of(&self, account_id: AccountId) -> u32 {
        self.accounts.get(&account_id).map_or(0, |account| account.withdrawals)
    }
}
