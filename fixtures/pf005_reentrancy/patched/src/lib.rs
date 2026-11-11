//! PF005 fixture (patched): the same pool, with the balance debited before the payout leaves.
//!
//! `withdraw` removes the balance before it sends the transfer, so a second `withdraw` before the receipt settles
//! finds nothing to pay. `on_withdraw` puts the amount back only when the transfer failed.

use near_sdk::store::LookupMap;
use near_sdk::{AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseError, env, near, require};

const CALLBACK_GAS: Gas = Gas::from_tgas(10);

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Pool {
    balances: LookupMap<AccountId, NearToken>,
}

#[near]
impl Pool {
    #[init]
    pub fn new() -> Self {
        Self { balances: LookupMap::new(b"b") }
    }

    /// Credits the attached deposit to the caller.
    #[payable]
    pub fn deposit(&mut self) {
        let amount = env::attached_deposit();
        require!(!amount.is_zero(), "attach a deposit");
        self.credit(env::predecessor_account_id(), amount);
    }

    /// Sends the caller's whole balance to `to`; `on_withdraw` gives it back if the transfer failed.
    pub fn withdraw(&mut self, to: AccountId) -> Promise {
        let account = env::predecessor_account_id();
        let amount = self.balance_of(account.clone());
        require!(!amount.is_zero(), "nothing to withdraw");
        self.balances.remove(&account);
        Promise::new(to)
            .transfer(amount)
            .then(Self::ext(env::current_account_id()).with_static_gas(CALLBACK_GAS).on_withdraw(account, amount))
    }

    #[private]
    pub fn on_withdraw(
        &mut self,
        account: AccountId,
        amount: NearToken,
        #[callback_result] paid: Result<(), PromiseError>,
    ) {
        if paid.is_err() {
            self.credit(account, amount);
        }
    }

    pub fn balance_of(&self, account: AccountId) -> NearToken {
        self.balances.get(&account).copied().unwrap_or(NearToken::ZERO)
    }
}

impl Pool {
    fn credit(&mut self, account: AccountId, amount: NearToken) {
        let total =
            self.balance_of(account.clone()).checked_add(amount).unwrap_or_else(|| env::panic_str("balance overflow"));
        self.balances.insert(account, total);
    }
}
