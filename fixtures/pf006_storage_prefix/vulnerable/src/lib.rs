//! PF006 fixture (vulnerable): a treasury whose member list and admin list share one storage prefix.
//!
//! `LookupSet` stores each element under `prefix ++ borsh(element)`. `members` and `admins` are both created
//! with the prefix `b"m"`, so they are one set under two names: joining as a member also makes the caller an
//! admin, and `withdraw` pays the treasury out to them.

use near_sdk::store::LookupSet;
use near_sdk::{AccountId, NearToken, PanicOnDefault, Promise, env, near, require};

const MEMBERSHIP_FEE: NearToken = NearToken::from_millinear(100);

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Treasury {
    members: LookupSet<AccountId>,
    admins: LookupSet<AccountId>,
}

#[near]
impl Treasury {
    #[init]
    pub fn new(admin: AccountId) -> Self {
        // PF006: both sets use the prefix `b"m"`.
        let mut admins = LookupSet::new(b"m");
        admins.insert(admin);
        Self { members: LookupSet::new(b"m"), admins }
    }

    /// Anyone can become a member by paying the dues, which go into the treasury.
    #[payable]
    pub fn join(&mut self) {
        require!(env::attached_deposit() >= MEMBERSHIP_FEE, "membership costs 0.1 NEAR");
        self.members.insert(env::predecessor_account_id());
    }

    /// Admins pay `amount` out of the treasury.
    pub fn withdraw(&self, to: AccountId, amount: NearToken) -> Promise {
        require!(self.is_admin(env::predecessor_account_id()), "only admins can withdraw");
        Promise::new(to).transfer(amount)
    }

    pub fn is_member(&self, account: AccountId) -> bool {
        self.members.contains(&account)
    }

    pub fn is_admin(&self, account: AccountId) -> bool {
        self.admins.contains(&account)
    }
}
