//! PF006 fixture (patched): the same treasury, with a prefix of its own for each set.
//!
//! `members` keeps its elements under `b"m"` and `admins` under `b"a"`, so joining as a member says nothing
//! about who is an admin.

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
        let mut admins = LookupSet::new(b"a");
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
