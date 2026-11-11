//! PF003 fixture helper: the prepaid-balance ledger that the ticket shop charges.
//!
//! Customers top up a balance here. Only the shop may `charge` it, and a charge fails when the balance is too
//! small, which is the failed cross-contract call the shop's callback has to notice.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{AccountId, PanicOnDefault, env, near, require};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Ledger {
    shop: AccountId,
    balances: LookupMap<AccountId, u128>,
    revenue: u128,
}

#[near]
impl Ledger {
    #[init]
    pub fn new(shop: AccountId) -> Self {
        Self { shop, balances: LookupMap::new(b"b"), revenue: 0 }
    }

    /// The attached deposit is added to the caller's balance.
    #[payable]
    pub fn top_up(&mut self) {
        let customer = env::predecessor_account_id();
        let held = self.balances.get(&customer).copied().unwrap_or(0);
        self.balances.insert(customer, held + env::attached_deposit().as_yoctonear());
    }

    /// Takes `amount` from `account_id` for the shop and returns what is left. Panics when the balance is short.
    pub fn charge(&mut self, account_id: AccountId, amount: U128) -> U128 {
        require!(env::predecessor_account_id() == self.shop, "only the shop can charge");
        let held = self.balances.get(&account_id).copied().unwrap_or(0);
        require!(held >= amount.0, "insufficient balance");
        self.balances.insert(account_id, held - amount.0);
        self.revenue += amount.0;
        U128(held - amount.0)
    }

    pub fn balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.balances.get(&account_id).copied().unwrap_or(0))
    }

    /// Everything the shop has been paid so far.
    pub fn revenue(&self) -> U128 {
        U128(self.revenue)
    }
}
