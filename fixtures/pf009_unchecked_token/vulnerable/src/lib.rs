//! PF009 fixture (vulnerable): a vault that holds one token for its depositors.
//!
//! Depositors send the token with `ft_transfer_call`; the token contract then calls `ft_on_transfer` here and
//! the vault records the deposit. `ft_on_transfer` never checks who is calling it, so any contract can claim to
//! have sent tokens: an attacker deploys a worthless token of their own, "sends" the vault a thousand of it,
//! and withdraws a thousand of the real token that other depositors left in the vault.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{
    AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseError, PromiseOrValue, assert_one_yocto, env,
    ext_contract, near, require,
};

const TRANSFER_GAS: Gas = Gas::from_tgas(10);
const RESTORE_GAS: Gas = Gas::from_tgas(10);

#[ext_contract(ext_token)]
pub trait Token {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128);
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct TokenVault {
    token: AccountId,
    deposits: LookupMap<AccountId, u128>,
}

#[near]
impl TokenVault {
    #[init]
    pub fn new(token: AccountId) -> Self {
        Self { token, deposits: LookupMap::new(b"d") }
    }

    /// Called by a token contract after `sender_id` sent it `amount` with `ft_transfer_call`. Keeps all of it.
    // PF009: nothing checks that the caller is `self.token`, so `amount` and `sender_id` are whatever the caller says.
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> PromiseOrValue<U128> {
        require!(msg.is_empty(), "this vault takes no message");
        let held = self.deposits.get(&sender_id).copied().unwrap_or(0);
        self.deposits.insert(sender_id, held + amount.0);
        PromiseOrValue::Value(U128(0))
    }

    /// Pays `amount` of the caller's deposit back out in the token; `on_withdrawn` restores it if the token refuses.
    #[payable]
    pub fn withdraw(&mut self, amount: U128) -> Promise {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        let held = self.deposits.get(&account_id).copied().unwrap_or(0);
        require!(held >= amount.0, "not enough deposited");
        self.deposits.insert(account_id.clone(), held - amount.0);
        ext_token::ext(self.token.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(TRANSFER_GAS)
            .ft_transfer(account_id.clone(), amount)
            .then(Self::ext(env::current_account_id()).with_static_gas(RESTORE_GAS).on_withdrawn(account_id, amount))
    }

    #[private]
    pub fn on_withdrawn(
        &mut self,
        account_id: AccountId,
        amount: U128,
        #[callback_result] sent: Result<(), PromiseError>,
    ) {
        if sent.is_err() {
            let held = self.deposits.get(&account_id).copied().unwrap_or(0);
            self.deposits.insert(account_id, held + amount.0);
        }
    }

    pub fn deposit_of(&self, account_id: AccountId) -> U128 {
        U128(self.deposits.get(&account_id).copied().unwrap_or(0))
    }
}
