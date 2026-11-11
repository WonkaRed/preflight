//! PF022 fixture (vulnerable): a shared vault whose `withdraw` relies on overflow checks the build does not have.
//!
//! Depositors park NEAR in the vault and take it back with `withdraw`. The subtraction in `withdraw` is the only
//! thing that stops an account from taking more than it put in, and it only stops it when overflow checks are on.
//! Cargo reads the build profile from the workspace root, `fixtures/Cargo.toml`, which keeps `overflow-checks`
//! on for every fixture except this crate: its `[profile.release.package.pf022-overflow-checks-off-vulnerable]`
//! override turns them off, as a contract that never set the flag is built. There, `0 - amount` wraps around to
//! a balance of nearly `u128::MAX` and the vault pays out other depositors' money.

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

    // PF022: with overflow checks off, an amount above the balance wraps the balance around instead of failing.
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
