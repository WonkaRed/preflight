//! PF002 fixture (vulnerable): an arcade whose credit transfer does not require one yoctoNEAR.
//!
//! Players buy credits with NEAR, gift them to each other with `transfer`, and cash them out. `transfer` is a
//! plain call that needs no deposit, so a function-call access key for this contract on a player's account
//! (the key a game or an agent asks for so it can play on the player's behalf) is enough to give every one of
//! the player's credits to any account, with no wallet confirmation.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{AccountId, NearToken, PanicOnDefault, Promise, env, near, require};

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

    // PF002: gives away the caller's credits and needs no deposit, so a function-call key can call it.
    pub fn transfer(&mut self, receiver_id: AccountId, amount: U128) {
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
