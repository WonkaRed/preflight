//! The Swap, chameleon (patched build): a deposit vault whose settlement callback is restricted by `#[private]`.
//!
//! `deposit` sends a 1% fee to the treasury and schedules `on_deposit` to credit the rest once the fee transfer
//! settles. `on_deposit` can only be called by the contract itself, so the only way to credit a balance is to pay.
//! The vulnerable build differs from this file in one line of code: it has `#[private]` on `on_deposit`.
//!
//! Whatever the ledger says, no transfer leaves the account with less than its storage cost plus a reserve, so a
//! forged credit can take what depositors put in but never the money that pays for this contract's own code.
//!
//! Both builds read the same state, so the switch can swap one for the other with `upgrade`.

use near_sdk::store::LookupMap;
use near_sdk::{AccountId, NearToken, PanicOnDefault, Promise, assert_one_yocto, env, is_promise_success, near, require};

/// The fee is one part in this many of every deposit.
const FEE_DIVISOR: u128 = 100;

/// What the account keeps above its own storage cost, whatever the ledger says: it pays for an `upgrade` and its gas.
const RESERVE: NearToken = NearToken::from_millinear(500);

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

    /// Locks the attached deposit for the caller, less the fee, which goes to the treasury, and less the storage of
    /// the caller's balance entry the first time they deposit.
    #[payable]
    pub fn deposit(&mut self) -> Promise {
        let depositor = env::predecessor_account_id();
        let gross = env::attached_deposit();
        let fee = NearToken::from_yoctonear(gross.as_yoctonear() / FEE_DIVISOR);
        // The depositor's balance entry is created here, and what it adds to the account's storage is paid out of their deposit.
        let before = env::storage_usage();
        self.balances.entry(depositor.clone()).or_default();
        self.balances.flush();
        let storage = storage_cost(env::storage_usage().saturating_sub(before));
        let net = gross.checked_sub(fee).and_then(|rest| rest.checked_sub(storage)).filter(|net| !net.is_zero());
        let net = net.unwrap_or_else(|| env::panic_str("the deposit must cover the fee and the storage of your balance entry"));
        Promise::new(self.treasury.clone())
            .transfer(fee)
            .then(Self::ext(env::current_account_id()).on_deposit(depositor, gross.saturating_sub(storage), net))
    }

    #[private]
    pub fn on_deposit(&mut self, depositor: AccountId, refund: NearToken, net: NearToken) {
        // A failed fee transfer credits nothing: the deposit goes back, less the storage it paid for.
        if env::promise_results_count() > 0 && !is_promise_success() {
            pay_out(depositor, refund).detach();
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
        pay_out(account, amount)
    }

    pub fn balance_of(&self, account_id: AccountId) -> NearToken {
        self.balances.get(&account_id).copied().unwrap_or(NearToken::from_yoctonear(0))
    }
}

fn storage_cost(bytes: u64) -> NearToken {
    env::storage_byte_cost().saturating_mul(u128::from(bytes))
}

/// Every transfer out of the contract goes through here. The ledger can be wrong (a forged credit is the whole
/// point of the vulnerable build), so this refuses to spend the account's own storage money or the reserve.
fn pay_out(to: AccountId, amount: NearToken) -> Promise {
    let kept = storage_cost(env::storage_usage()).saturating_add(RESERVE);
    require!(amount <= env::account_balance().saturating_sub(kept), "that would spend the storage money and the reserve the contract keeps");
    Promise::new(to).transfer(amount)
}
