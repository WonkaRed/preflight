//! PF023 fixture (vulnerable): a ticket collection whose `nft_transfer` never checks who is calling.
//!
//! The venue mints numbered tickets to buyers, and holders can approve a marketplace to sell theirs or transfer
//! them. NEP-171 says `nft_transfer` must panic unless the caller owns the token or holds an approval, but this
//! `nft_transfer` takes the token from whoever owns it and gives it to `receiver_id` for 1 yoctoNEAR, so any
//! account can take any ticket. The approval methods check the owner and show what the missing check looks like.

use near_sdk::json_types::U64;
use near_sdk::store::LookupMap;
use near_sdk::{AccountId, PanicOnDefault, assert_one_yocto, env, near, require};

pub type TokenId = String;

#[near(serializers = [json])]
pub struct Token {
    pub token_id: TokenId,
    pub owner_id: AccountId,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Tickets {
    venue_id: AccountId,
    owner_by_id: LookupMap<TokenId, AccountId>,
    /// The account approved to sell each token, if any, and the id of that approval.
    approved: LookupMap<TokenId, (AccountId, u64)>,
    next_approval_id: u64,
}

#[near]
impl Tickets {
    #[init]
    pub fn new(venue_id: AccountId) -> Self {
        Self { venue_id, owner_by_id: LookupMap::new(b"o"), approved: LookupMap::new(b"a"), next_approval_id: 1 }
    }

    /// Mints a ticket to `receiver_id`. Only the venue can.
    pub fn nft_mint(&mut self, token_id: TokenId, receiver_id: AccountId) {
        require!(env::predecessor_account_id() == self.venue_id, "only the venue can mint");
        require!(self.owner_by_id.insert(token_id, receiver_id).is_none(), "token already exists");
    }

    // PF023: NEP-171 says to panic unless the caller owns the token or is approved; nothing here looks at the caller.
    #[payable]
    pub fn nft_transfer(
        &mut self,
        receiver_id: AccountId,
        token_id: TokenId,
        approval_id: Option<u64>,
        memo: Option<String>,
    ) {
        assert_one_yocto();
        let _ = (approval_id, memo);
        require!(self.owner_by_id.contains_key(&token_id), "no such token");
        self.owner_by_id.insert(token_id.clone(), receiver_id);
        self.approved.remove(&token_id);
    }

    /// Approves `account_id` to sell the token on the owner's behalf.
    #[payable]
    pub fn nft_approve(&mut self, token_id: TokenId, account_id: AccountId) {
        assert_one_yocto();
        let owner = self.owner_by_id.get(&token_id).unwrap_or_else(|| env::panic_str("no such token"));
        require!(*owner == env::predecessor_account_id(), "only the token's owner can approve");
        let approval_id = self.next_approval_id;
        self.next_approval_id += 1;
        self.approved.insert(token_id, (account_id, approval_id));
    }

    /// Removes every approval on the token.
    #[payable]
    pub fn nft_revoke_all(&mut self, token_id: TokenId) {
        assert_one_yocto();
        let owner = self.owner_by_id.get(&token_id).unwrap_or_else(|| env::panic_str("no such token"));
        require!(*owner == env::predecessor_account_id(), "only the token's owner can revoke");
        self.approved.remove(&token_id);
    }

    pub fn nft_token(&self, token_id: TokenId) -> Option<Token> {
        self.owner_by_id.get(&token_id).map(|owner_id| Token { token_id, owner_id: owner_id.clone() })
    }

    pub fn nft_approval_id(&self, token_id: TokenId) -> Option<U64> {
        self.approved.get(&token_id).map(|(_, approval_id)| U64(*approval_id))
    }
}
