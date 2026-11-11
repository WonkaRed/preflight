//! PF002 fixture (patched): the same arcade, with `transfer` requiring one yoctoNEAR.
//!
//! `transfer` is `#[payable]` and calls `assert_one_yocto()` first. A function-call access key cannot attach a
//! deposit, so only a full-access signature (a wallet confirmation) reaches it.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{AccountId, NearToken, PanicOnDefault, Promise, assert_one_yocto, env, near, require};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Arcade {
    credits: LookupMap<AccountId, u128>,
}

#[near]
impl Arcade {
    #[init]
    pub fn new() -> Self {
        Self { credits: LookupMap::new(b"c") }
    }

    /// The attached deposit becomes credits for the caller, one credit per yoctoNEAR.
    #[payable]
    pub fn buy_credits(&mut self) {
        let player = env::predecessor_account_id();
        let held = self.credits.get(&player).copied().unwrap_or(0);
        self.credits.insert(player, held + env::attached_deposit().as_yoctonear());
    }

    /// Gives credits to another player. Requires exactly 1 yoctoNEAR, which only a full-access key can attach.
    #[payable]
    pub fn transfer(&mut self, receiver_id: AccountId, amount: U128) {
        assert_one_yocto();
        let sender = env::predecessor_account_id();
        let held = self.credits.get(&sender).copied().unwrap_or(0);
        require!(held >= amount.0, "not enough credits");
        self.credits.insert(sender, held - amount.0);
        let receiver_held = self.credits.get(&receiver_id).copied().unwrap_or(0);
        self.credits.insert(receiver_id, receiver_held + amount.0);
    }

    /// Pays the caller's credits back out as NEAR, to the caller only.
    pub fn cash_out(&mut self, amount: U128) -> Promise {
        let player = env::predecessor_account_id();
        let held = self.credits.get(&player).copied().unwrap_or(0);
        require!(held >= amount.0, "not enough credits");
        self.credits.insert(player.clone(), held - amount.0);
        Promise::new(player).transfer(NearToken::from_yoctonear(amount.0))
    }

    pub fn credits_of(&self, account_id: AccountId) -> U128 {
        U128(self.credits.get(&account_id).copied().unwrap_or(0))
    }
}
