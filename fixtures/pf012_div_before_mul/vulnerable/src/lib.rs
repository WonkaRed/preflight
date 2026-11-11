//! PF012 fixture (vulnerable): a marketplace whose listing fee divides before it multiplies.
//!
//! Sellers pay for the storage their listing takes, 0.01 NEAR per KB of description. `listing_fee` computes
//! `bytes / 1_000 * FEE_PER_KB`, which rounds the byte count down to whole KB first, so a description under
//! 1_000 bytes is free and every other one is undercharged by up to a KB. Splitting a large description over
//! several small listings stores the same data for nothing.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{AccountId, PanicOnDefault, env, near, require};

/// 0.01 NEAR, the cost of storing a KB.
const FEE_PER_KB: u128 = 10_000_000_000_000_000_000_000;

#[near(serializers = [borsh, json])]
pub struct Listing {
    seller: AccountId,
    title: String,
    description: String,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Marketplace {
    listings: LookupMap<u64, Listing>,
    next_id: u64,
}

#[near]
impl Marketplace {
    #[init]
    pub fn new() -> Self {
        Self { listings: LookupMap::new(b"l"), next_id: 0 }
    }

    /// What it costs to list a description of `bytes` bytes.
    // PF012: the byte count is rounded down to whole KB before it is priced.
    pub fn listing_fee(&self, bytes: u32) -> U128 {
        U128(u128::from(bytes) / 1_000 * FEE_PER_KB)
    }

    /// Lists an item and returns its id. The attached deposit must be exactly the listing fee.
    #[payable]
    pub fn list_item(&mut self, title: String, description: String) -> u64 {
        let bytes = u32::try_from(description.len()).unwrap_or(u32::MAX);
        let fee = self.listing_fee(bytes).0;
        require!(env::attached_deposit().as_yoctonear() == fee, "attach exactly the listing fee");
        let id = self.next_id;
        self.next_id += 1;
        self.listings.insert(id, Listing { seller: env::predecessor_account_id(), title, description });
        id
    }

    pub fn get_listing(&self, id: u64) -> Option<&Listing> {
        self.listings.get(&id)
    }

    pub fn listing_count(&self) -> u64 {
        self.next_id
    }
}
