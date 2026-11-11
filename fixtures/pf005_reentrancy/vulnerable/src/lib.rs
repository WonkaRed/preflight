//! PF005 fixture (vulnerable): a pool that clears a balance only after the payout has gone through.
//!
//! `withdraw` reads the caller's balance and sends it with a transfer, and `on_withdraw` removes the balance when
//! the transfer receipt succeeded. The receipt and the callback run blocks after `withdraw` returned, so until
//! then the balance is still on the books and the caller can withdraw it again.

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

    /// Sends the caller's whole balance to `to`; `on_withdraw` clears it once the transfer receipt succeeded.
    // PF005: the balance is only cleared in the callback.
    pub fn withdraw(&self, to: AccountId) -> Promise {
        let account = env::predecessor_account_id();
        let amount = self.balance_of(account.clone());
        require!(!amount.is_zero(), "nothing to withdraw");
        Promise::new(to)
            .transfer(amount)
            .then(Self::ext(env::current_account_id()).with_static_gas(CALLBACK_GAS).on_withdraw(account))
    }

    #[private]
    pub fn on_withdraw(&mut self, account: AccountId, #[callback_result] paid: Result<(), PromiseError>) {
        if paid.is_ok() {
            self.balances.remove(&account);
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
