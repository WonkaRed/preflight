//! The Swap, chameleon (vulnerable build): a deposit vault whose settlement callback is exported to everyone.
//!
//! `deposit` sends a 1% fee to the treasury and schedules `on_deposit` to credit the rest once the fee transfer
//! settles. `on_deposit` is a public method like any other, so any account can call it directly and credit itself
//! any balance with no payment, then `withdraw` what other depositors put in.
//! The patched build differs from this file in one line of code: it has `#[private]` on `on_deposit`.
//!
//! Both builds read the same state, so the switch can swap one for the other with `upgrade`.

use near_sdk::store::LookupMap;
use near_sdk::{AccountId, NearToken, PanicOnDefault, Promise, assert_one_yocto, env, is_promise_success, near, require};

/// The fee is one part in this many of every deposit.
const FEE_DIVISOR: u128 = 100;

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Vault {
    /// The only account that may replace this contract's code.
    switch: AccountId,
    /// Receives the deposit fees.
    treasury: AccountId,
    balances: LookupMap<AccountId, NearToken>,
}

#[near]
impl Vault {
    #[init]
    pub fn new(switch: AccountId, treasury: AccountId) -> Self {
        Self { switch, treasury, balances: LookupMap::new(b"b") }
    }

    /// Replaces this contract's code with `code`, a wasm module (Borsh `Vec<u8>`: a 4-byte length, then the bytes).
    /// The state stays. Only the switch may call it.
    pub fn upgrade(&mut self, #[serializer(borsh)] code: Vec<u8>) -> Promise {
        require!(env::predecessor_account_id() == self.switch, "only the switch may upgrade this contract");
        Promise::new(env::current_account_id()).deploy_contract(code)
    }

    /// Locks the attached deposit for the caller, less the fee, which goes to the treasury.
    #[payable]
    pub fn deposit(&mut self) -> Promise {
        let depositor = env::predecessor_account_id();
        let gross = env::attached_deposit();
        require!(!gross.is_zero(), "attach a deposit");
        let fee = NearToken::from_yoctonear(gross.as_yoctonear() / FEE_DIVISOR);
        // The depositor's balance entry is created here, where the deposit pays for its storage.
        self.balances.entry(depositor.clone()).or_default();
        Promise::new(self.treasury.clone())
            .transfer(fee)
            .then(Self::ext(env::current_account_id()).on_deposit(depositor, gross, gross.saturating_sub(fee)))
    }

    // PF001: a callback that anyone can call.
    pub fn on_deposit(&mut self, depositor: AccountId, gross: NearToken, net: NearToken) {
        // A failed fee transfer credits nothing: the deposit goes back whole.
        if env::promise_results_count() > 0 && !is_promise_success() {
            Promise::new(depositor).transfer(gross).detach();
            return;
        }
        if let Some(balance) = self.balances.get_mut(&depositor) {
            *balance = balance.saturating_add(net);
        }
    }

    /// Pays the caller `amount` out of their balance. Needs exactly 1 yoctoNEAR attached.
    #[payable]
    pub fn withdraw(&mut self, amount: NearToken) -> Promise {
        assert_one_yocto();
        let account = env::predecessor_account_id();
        let balance = self.balances.get(&account).copied().unwrap_or(NearToken::from_yoctonear(0));
        let left = balance.checked_sub(amount).unwrap_or_else(|| env::panic_str("insufficient balance"));
        self.balances.insert(account.clone(), left);
        Promise::new(account).transfer(amount)
    }

    pub fn balance_of(&self, account_id: AccountId) -> NearToken {
        self.balances.get(&account_id).copied().unwrap_or(NearToken::from_yoctonear(0))
    }
}
