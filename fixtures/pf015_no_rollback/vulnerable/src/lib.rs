//! PF015 fixture (vulnerable): a payout vault that lowers the balance first and never restores it.
//!
//! `withdraw_to` debits the caller, sends the NEAR to a recipient the caller names, and schedules `on_withdrawn`.
//! When the transfer fails (a mistyped recipient that is not an account) `on_withdrawn` only logs it, so the
//! caller's balance stays at zero and the NEAR stays in the vault with nobody able to claim it.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{
    AccountId, Gas, NearToken, PanicOnDefault, Promise, assert_one_yocto, env, is_promise_success, near, require,
};

const CALLBACK_GAS: Gas = Gas::from_tgas(10);

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct PayoutVault {
    balances: LookupMap<AccountId, u128>,
}

#[near]
impl PayoutVault {
    #[init]
    pub fn new() -> Self {
        Self { balances: LookupMap::new(b"b") }
    }

    /// The attached deposit is added to the caller's balance.
    #[payable]
    pub fn deposit(&mut self) {
        let caller = env::predecessor_account_id();
        let held = self.balance(&caller);
        self.balances.insert(caller, held + env::attached_deposit().as_yoctonear());
    }

    /// Sends `amount` of the caller's balance to `recipient`.
    #[payable]
    pub fn withdraw_to(&mut self, recipient: AccountId, amount: U128) -> Promise {
        assert_one_yocto();
        let caller = env::predecessor_account_id();
        let balance = self.balances.get_mut(&caller).unwrap_or_else(|| env::panic_str("no balance"));
        require!(*balance >= amount.0, "not enough balance");
        *balance -= amount.0;
        Promise::new(recipient)
            .transfer(NearToken::from_yoctonear(amount.0))
            .then(Self::ext(env::current_account_id()).with_static_gas(CALLBACK_GAS).on_withdrawn(caller, amount))
    }

    // PF015: a failed transfer is noticed here and then forgotten; the debit above is never restored.
    #[private]
    pub fn on_withdrawn(&mut self, account_id: AccountId, amount: U128) {
        if !is_promise_success() {
            env::log_str(&format!("withdrawal of {} yocto for {account_id} failed", amount.0));
        }
    }

    pub fn balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.balance(&account_id))
    }
}

impl PayoutVault {
    fn balance(&self, account_id: &AccountId) -> u128 {
        self.balances.get(account_id).copied().unwrap_or(0)
    }
}
