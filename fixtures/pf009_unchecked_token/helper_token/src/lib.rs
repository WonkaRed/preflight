//! PF009 fixture helper: a minimal NEP-141 fungible token.
//!
//! The vault fixtures are deployed next to two instances of this contract: the real token the vault is built
//! for, and a worthless one that its attacker deploys and mints from freely. `ft_transfer_call` follows the
//! standard: move the tokens, call `ft_on_transfer` on the receiver, and let `ft_resolve_transfer` give back
//! whatever the receiver did not use, or everything when the receiver's call failed. Account registration
//! (NEP-145) is left out. Only the owner can `mint`.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{
    AccountId, Gas, PanicOnDefault, PromiseError, PromiseOrValue, assert_one_yocto, env, ext_contract, near, require,
};

const RESOLVE_GAS: Gas = Gas::from_tgas(5);

#[ext_contract(ext_receiver)]
pub trait Receiver {
    fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> PromiseOrValue<U128>;
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Token {
    owner: AccountId,
    balances: LookupMap<AccountId, u128>,
}

#[near]
impl Token {
    #[init]
    pub fn new(owner: AccountId) -> Self {
        Self { owner, balances: LookupMap::new(b"b") }
    }

    /// Creates `amount` tokens for `account_id`. Only the owner can.
    pub fn mint(&mut self, account_id: AccountId, amount: U128) {
        require!(env::predecessor_account_id() == self.owner, "only the owner can mint");
        self.deposit(&account_id, amount.0);
    }

    #[payable]
    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) {
        assert_one_yocto();
        self.internal_transfer(&env::predecessor_account_id(), &receiver_id, amount.0);
    }

    /// Moves the tokens, then tells the receiver with `ft_on_transfer`; the unused part comes back.
    #[payable]
    pub fn ft_transfer_call(&mut self, receiver_id: AccountId, amount: U128, msg: String) -> PromiseOrValue<U128> {
        assert_one_yocto();
        let sender_id = env::predecessor_account_id();
        self.internal_transfer(&sender_id, &receiver_id, amount.0);
        ext_receiver::ext(receiver_id.clone())
            .with_unused_gas_weight(1)
            .ft_on_transfer(sender_id.clone(), amount, msg)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(RESOLVE_GAS)
                    .with_unused_gas_weight(0)
                    .ft_resolve_transfer(sender_id, receiver_id, amount),
            )
            .into()
    }

    /// Returns the amount the receiver kept. A failed `ft_on_transfer` counts as keeping nothing.
    #[private]
    pub fn ft_resolve_transfer(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        #[callback_result] unused: Result<U128, PromiseError>,
    ) -> U128 {
        let unused = match unused {
            Ok(unused) => unused.0.min(amount.0),
            Err(_) => amount.0,
        };
        let refund = unused.min(self.balance(&receiver_id));
        if refund > 0 {
            self.withdraw(&receiver_id, refund);
            self.deposit(&sender_id, refund);
        }
        U128(amount.0 - refund)
    }

    pub fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.balance(&account_id))
    }

    fn balance(&self, account_id: &AccountId) -> u128 {
        self.balances.get(account_id).copied().unwrap_or(0)
    }

    fn withdraw(&mut self, account_id: &AccountId, amount: u128) {
        let held = self.balance(account_id);
        require!(held >= amount, "The account doesn't have enough balance");
        self.balances.insert(account_id.clone(), held - amount);
    }

    fn deposit(&mut self, account_id: &AccountId, amount: u128) {
        let held = self.balance(account_id);
        self.balances.insert(account_id.clone(), held + amount);
    }

    fn internal_transfer(&mut self, sender_id: &AccountId, receiver_id: &AccountId, amount: u128) {
        require!(sender_id != receiver_id, "Sender and receiver should be different");
        require!(amount > 0, "The amount should be a positive number");
        self.withdraw(sender_id, amount);
        self.deposit(receiver_id, amount);
    }
}
