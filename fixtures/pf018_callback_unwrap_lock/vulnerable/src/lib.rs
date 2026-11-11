//! PF018 fixture (vulnerable): a token vault that sends a withdrawal to a contract and refunds what it did not use.
//!
//! Users deposit a NEP-141 token with `ft_transfer_call`. `withdraw_and_call` debits the caller's balance, then
//! sends the tokens to a receiver contract with `ft_transfer_call` and schedules `on_withdraw_and_call`, which
//! credits back whatever the receiver did not use. The callback takes the token's answer with
//! `#[callback_unwrap]`. When the transfer itself fails (the receiver is not registered with the token, say) there
//! is no answer: the macro panics, the callback never runs its refund, and the balance debited by
//! `withdraw_and_call` is gone while the tokens stay in the vault.

use near_contract_standards::fungible_token::core::ext_ft_core;
use near_contract_standards::fungible_token::receiver::FungibleTokenReceiver;
use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{
    AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseOrValue, assert_one_yocto, env, near, require,
};

const TRANSFER_GAS: Gas = Gas::from_tgas(40);
const CALLBACK_GAS: Gas = Gas::from_tgas(10);

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Vault {
    token: AccountId,
    balances: LookupMap<AccountId, u128>,
    total_credited: u128,
}

#[near]
impl Vault {
    #[init]
    pub fn new(token: AccountId) -> Self {
        Self { token, balances: LookupMap::new(b"b"), total_credited: 0 }
    }

    /// Sends `amount` of the caller's credit to the contract `receiver_id`, which may use all of it or give some back.
    #[payable]
    pub fn withdraw_and_call(&mut self, receiver_id: AccountId, amount: U128, msg: String) -> Promise {
        assert_one_yocto();
        let account = env::predecessor_account_id();
        self.debit(&account, amount.0);
        ext_ft_core::ext(self.token.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(TRANSFER_GAS)
            .ft_transfer_call(receiver_id, amount, None, msg)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(CALLBACK_GAS)
                    .on_withdraw_and_call(account, amount),
            )
    }

    /// Credits back the part of `amount` the receiver did not use. `used` is what the token reports as used.
    // PF018: when the call failed, `used` cannot be read, so the macro panics here and nothing is credited back.
    #[private]
    pub fn on_withdraw_and_call(&mut self, account_id: AccountId, amount: U128, #[callback_unwrap] used: U128) -> U128 {
        let unused = amount.0 - used.0;
        if unused > 0 {
            self.credit(&account_id, unused);
        }
        used
    }

    pub fn balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.balances.get(&account_id).copied().unwrap_or(0))
    }

    /// The sum of every credit: what the vault owes its depositors.
    pub fn total_credited(&self) -> U128 {
        U128(self.total_credited)
    }
}

#[near]
impl FungibleTokenReceiver for Vault {
    fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> PromiseOrValue<U128> {
        require!(env::predecessor_account_id() == self.token, "only the vault's token can be deposited");
        require!(msg.is_empty(), "a deposit takes no message");
        self.credit(&sender_id, amount.0);
        PromiseOrValue::Value(U128(0))
    }
}

impl Vault {
    fn credit(&mut self, account: &AccountId, amount: u128) {
        let balance = self.balances.get(account).copied().unwrap_or(0);
        self.balances.insert(account.clone(), balance + amount);
        self.total_credited += amount;
    }

    fn debit(&mut self, account: &AccountId, amount: u128) {
        let balance = self.balances.get(account).copied().unwrap_or(0);
        require!(balance >= amount, "insufficient balance");
        self.balances.insert(account.clone(), balance - amount);
        self.total_credited -= amount;
    }
}
