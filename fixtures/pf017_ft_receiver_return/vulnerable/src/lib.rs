//! PF017 fixture (vulnerable): a token vault whose deposit hook reports the whole deposit as unused.
//!
//! Users deposit a NEP-141 token with `ft_transfer_call`. The token moves the tokens to the vault, calls
//! `ft_on_transfer`, and then refunds whatever that returns to the sender: the return value is the amount the
//! vault did NOT take. This hook credits the deposit and returns `amount`, reading the value as "how much I
//! accepted". The sender is credited and refunded at once, and the credit is redeemable against the tokens the
//! operator keeps in the vault as a withdrawal reserve.

use near_contract_standards::fungible_token::core::ext_ft_core;
use near_contract_standards::fungible_token::receiver::FungibleTokenReceiver;
use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{
    AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseOrValue, assert_one_yocto, env, near, require,
};

const TRANSFER_GAS: Gas = Gas::from_tgas(15);

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
    fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> PromiseOrValue<U128> {
        require!(env::predecessor_account_id() == self.token, "only the vault's token can be deposited");
        require!(msg.is_empty(), "a deposit takes no message");
        self.credit(&sender_id, amount.0);
        // PF017: the token refunds what this returns, so the sender gets the whole deposit back and keeps the credit.
        PromiseOrValue::Value(amount)
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
