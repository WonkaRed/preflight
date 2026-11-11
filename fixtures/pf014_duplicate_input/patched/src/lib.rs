//! PF014 fixture (patched): the same treasury, with `redeem` rejecting a list that names a token twice.
//!
//! `redeem` collects the list into a `BTreeSet` and requires it to be as long as the list, so every token is paid
//! at most once for the shares burned.

use std::collections::BTreeSet;

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{
    AccountId, Gas, NearToken, PanicOnDefault, assert_one_yocto, env, ext_contract, is_promise_success, near, require,
};

const ONE_YOCTO: NearToken = NearToken::from_yoctonear(1);
const TRANSFER_GAS: Gas = Gas::from_tgas(10);
const CALLBACK_GAS: Gas = Gas::from_tgas(10);

#[ext_contract(ext_token)]
pub trait Token {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Treasury {
    shares: LookupMap<AccountId, u128>,
    total_shares: u128,
    /// What the treasury holds of each token, counted as tokens arrive with `ft_on_transfer`.
    reserves: LookupMap<AccountId, u128>,
}

#[near]
impl Treasury {
    #[init]
    pub fn new(holders: Vec<(AccountId, U128)>) -> Self {
        let mut shares = LookupMap::new(b"s");
        let mut total_shares = 0;
        for (holder, amount) in holders {
            shares.insert(holder, amount.0);
            total_shares += amount.0;
        }
        Self { shares, total_shares, reserves: LookupMap::new(b"r") }
    }

    /// Called by a token contract when tokens are sent to the treasury with `ft_transfer_call`.
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> U128 {
        let _ = (sender_id, msg);
        let token = env::predecessor_account_id();
        let held = self.reserve(&token);
        self.reserves.insert(token, held + amount.0);
        U128(0)
    }

    /// Burns `shares` of the caller's shares for their pro rata part of the reserve of each token in `tokens`.
    #[payable]
    pub fn redeem(&mut self, shares: U128, tokens: Vec<AccountId>) {
        assert_one_yocto();
        let holder = env::predecessor_account_id();
        let held = self.shares.get(&holder).copied().unwrap_or(0);
        require!(held >= shares.0, "not enough shares");
        let distinct: BTreeSet<&AccountId> = tokens.iter().collect();
        require!(distinct.len() == tokens.len(), "duplicate token");
        for token in tokens {
            let reserve = self.reserve(&token);
            let payout = reserve * shares.0 / self.total_shares;
            self.reserves.insert(token.clone(), reserve - payout);
            ext_token::ext(token.clone())
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(TRANSFER_GAS)
                .ft_transfer(holder.clone(), U128(payout), None)
                .then(Self::ext(env::current_account_id()).with_static_gas(CALLBACK_GAS).on_paid(token, U128(payout)))
                .detach();
        }
        self.shares.insert(holder, held - shares.0);
        self.total_shares -= shares.0;
    }

    /// Puts a payout back into the reserve when the token refused to send it.
    #[private]
    pub fn on_paid(&mut self, token: AccountId, amount: U128) {
        if !is_promise_success() {
            let reserve = self.reserve(&token);
            self.reserves.insert(token, reserve + amount.0);
        }
    }

    pub fn shares_of(&self, account_id: AccountId) -> U128 {
        U128(self.shares.get(&account_id).copied().unwrap_or(0))
    }

    pub fn reserve_of(&self, token: AccountId) -> U128 {
        U128(self.reserve(&token))
    }
}

impl Treasury {
    fn reserve(&self, token: &AccountId) -> u128 {
        self.reserves.get(token).copied().unwrap_or(0)
    }
}
