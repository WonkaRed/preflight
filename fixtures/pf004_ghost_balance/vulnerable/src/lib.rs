//! PF004 fixture (vulnerable): a token vault that credits a deposit and then forwards a notification.
//!
//! Users deposit a NEP-141 token with `ft_transfer_call`. The token calls `ft_on_transfer`, which credits the
//! sender's internal balance and, if `msg` names an account, notifies that account with `on_deposit`. The
//! notification promise is returned, so the token contract's `ft_resolve_transfer` takes the receiver's answer
//! as the unused amount, and refunds the whole deposit to the sender if the notification fails. The credit
//! written by `ft_on_transfer` is not undone: the sender holds the tokens again and a balance the vault can
//! withdraw. This is a minimal model of the bug class behind the NEAR Intents deposit loss of 2026-10-01, not
//! that contract's code.

use near_contract_standards::fungible_token::core::ext_ft_core;
use near_contract_standards::fungible_token::receiver::FungibleTokenReceiver;
use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{
    AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseOrValue, assert_one_yocto, env, ext_contract, near,
    require,
};

const NOTIFY_GAS: Gas = Gas::from_tgas(10);
const TRANSFER_GAS: Gas = Gas::from_tgas(15);

/// What a depositor can ask the vault to tell after a deposit: a rewards, accounting or bridge contract.
#[ext_contract(ext_receiver)]
pub trait DepositReceiver {
    /// Returns the part of `amount` the receiver did not take, as `ft_on_transfer` does.
    fn on_deposit(&mut self, sender_id: AccountId, amount: U128) -> U128;
}

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

    /// Pays `amount` of the caller's credit out in tokens.
    #[payable]
    pub fn withdraw(&mut self, amount: U128) -> Promise {
        assert_one_yocto();
        let account = env::predecessor_account_id();
        self.debit(&account, amount.0);
        ext_ft_core::ext(self.token.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(TRANSFER_GAS)
            .ft_transfer(account, amount, None)
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
    /// `msg` is empty for a plain deposit, or names the account to notify about it.
    fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> PromiseOrValue<U128> {
        require!(env::predecessor_account_id() == self.token, "only the vault's token can be deposited");
        // PF004: the credit is final once this receipt succeeds, whatever happens to the notification below.
        self.credit(&sender_id, amount.0);
        if msg.is_empty() {
            return PromiseOrValue::Value(U128(0));
        }
        let receiver: AccountId = msg.parse().unwrap_or_else(|_| env::panic_str("msg must name the account to notify"));
        PromiseOrValue::Promise(ext_receiver::ext(receiver).with_static_gas(NOTIFY_GAS).on_deposit(sender_id, amount))
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
