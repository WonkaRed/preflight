use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{AccountId, NearToken, PanicOnDefault, Promise, env, near};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Vault {
    balances: LookupMap<AccountId, u128>,
}

#[near]
impl Vault {
    #[init]
    pub fn new() -> Self {
        Self { balances: LookupMap::new(b"b") }
    }

    /// Credits the attached deposit to the caller.
    #[payable]
    pub fn deposit(&mut self) {
        let account_id = env::predecessor_account_id();
        let balance = self.balances.get(&account_id).copied().unwrap_or(0);
        self.balances.insert(account_id, balance + env::attached_deposit().as_yoctonear());
    }


    pub fn withdraw(&mut self, amount: U128) -> Promise {
        let account_id = env::predecessor_account_id();
        let balance = self.balances.get(&account_id).copied().unwrap_or(0);
        self.balances.insert(account_id.clone(), balance - amount.0);
        Promise::new(account_id).transfer(NearToken::from_yoctonear(amount.0))
    }

    pub fn balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.balances.get(&account_id).copied().unwrap_or(0))
    }
}
