//! PF014 fixture helper: a minimal fungible token, so the treasury can hold and pay out real token balances.
//!
//! It keeps balances, lets its owner mint, and implements `ft_transfer` and `ft_transfer_call` (which calls
//! `ft_on_transfer` on the receiver, as NEP-141 does). It leaves out everything a real token needs and the
//! treasury does not.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{AccountId, Gas, PanicOnDefault, Promise, assert_one_yocto, env, ext_contract, near, require};

const RECEIVER_GAS: Gas = Gas::from_tgas(30);

#[ext_contract(ext_receiver)]
pub trait Receiver {
    fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> U128;
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

    /// Creates `amount` tokens for `account_id`. Only the owner may.
    pub fn mint(&mut self, account_id: AccountId, amount: U128) {
        require!(env::predecessor_account_id() == self.owner, "only the owner can mint");
        let held = self.balance(&account_id);
        self.balances.insert(account_id, held + amount.0);
    }

    #[payable]
    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        assert_one_yocto();
        let _ = memo;
        self.move_tokens(env::predecessor_account_id(), receiver_id, amount.0);
    }

    /// Moves the tokens, then tells the receiver with `ft_on_transfer`.
    #[payable]
    pub fn ft_transfer_call(&mut self, receiver_id: AccountId, amount: U128, msg: String) -> Promise {
        assert_one_yocto();
        let sender_id = env::predecessor_account_id();
        self.move_tokens(sender_id.clone(), receiver_id.clone(), amount.0);
        ext_receiver::ext(receiver_id).with_static_gas(RECEIVER_GAS).ft_on_transfer(sender_id, amount, msg)
    }

    pub fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.balance(&account_id))
    }
}

impl Token {
    fn balance(&self, account_id: &AccountId) -> u128 {
        self.balances.get(account_id).copied().unwrap_or(0)
    }

    fn move_tokens(&mut self, from: AccountId, to: AccountId, amount: u128) {
        let held = self.balance(&from);
        require!(held >= amount, "not enough tokens");
        self.balances.insert(from, held - amount);
        let received = self.balance(&to);
        self.balances.insert(to, received + amount);
    }
}
