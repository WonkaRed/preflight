//! PF019 fixture (patched): the same token with the refund capped.
//!
//! The resolver reads the receiver's reported unused amount as before, then caps it at the amount that was sent
//! and at what the receiver still holds, as near-contract-standards does. The rest of the token is unchanged.

use near_contract_standards::fungible_token::{FungibleToken, FungibleTokenCore, FungibleTokenResolver};
use near_contract_standards::storage_management::{StorageBalance, StorageBalanceBounds, StorageManagement};
use near_sdk::json_types::U128;
use near_sdk::{AccountId, NearToken, PanicOnDefault, PromiseOrValue, env, near, serde_json};

/// The longest value `ft_on_transfer` can return: a quoted `u128`.
const MAX_RESULT_LENGTH: usize = 41;

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Token {
    token: FungibleToken,
}

#[near]
impl Token {
    #[init]
    pub fn new(owner_id: AccountId, total_supply: U128) -> Self {
        let mut this = Self { token: FungibleToken::new(b"t".to_vec()) };
        this.token.internal_register_account(&owner_id);
        this.token.internal_deposit(&owner_id, total_supply.0);
        this
    }
}

#[near]
impl FungibleTokenCore for Token {
    #[payable]
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        self.token.ft_transfer(receiver_id, amount, memo)
    }

    #[payable]
    fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        self.token.ft_transfer_call(receiver_id, amount, memo, msg)
    }

    fn ft_total_supply(&self) -> U128 {
        self.token.ft_total_supply()
    }

    fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        self.token.ft_balance_of(account_id)
    }
}

#[near]
impl FungibleTokenResolver for Token {
    /// Returns the amount the receiver used.
    #[private]
    fn ft_resolve_transfer(&mut self, sender_id: AccountId, receiver_id: AccountId, amount: U128) -> U128 {
        let unused = env::promise_result_checked(0, MAX_RESULT_LENGTH)
            .ok()
            .and_then(|value| serde_json::from_slice::<U128>(&value).ok())
            .map_or(amount.0, |reported| reported.0)
            .min(amount.0);
        let receiver_balance = self.token.ft_balance_of(receiver_id.clone()).0;
        let refund = unused.min(receiver_balance);
        self.token.accounts.insert(&receiver_id, &(receiver_balance - refund));
        let sender_balance = self.token.ft_balance_of(sender_id.clone()).0;
        self.token.accounts.insert(&sender_id, &(sender_balance + refund));
        U128(amount.0 - refund)
    }
}

#[near]
impl StorageManagement for Token {
    #[payable]
    fn storage_deposit(&mut self, account_id: Option<AccountId>, registration_only: Option<bool>) -> StorageBalance {
        self.token.storage_deposit(account_id, registration_only)
    }

    #[payable]
    fn storage_withdraw(&mut self, amount: Option<NearToken>) -> StorageBalance {
        self.token.storage_withdraw(amount)
    }

    #[payable]
    fn storage_unregister(&mut self, force: Option<bool>) -> bool {
        self.token.storage_unregister(force)
    }

    fn storage_balance_bounds(&self) -> StorageBalanceBounds {
        self.token.storage_balance_bounds()
    }

    fn storage_balance_of(&self, account_id: AccountId) -> Option<StorageBalance> {
        self.token.storage_balance_of(account_id)
    }
}
