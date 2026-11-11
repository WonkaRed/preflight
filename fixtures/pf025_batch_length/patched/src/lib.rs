//! PF025 fixture (patched): the same voucher shop, with `redeem_batch` rejecting lists of different lengths.
//!
//! `redeem_batch` requires `series_ids` and `amounts` to have the same length, so every amount that is paid out is
//! also taken off a voucher balance.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{AccountId, NearToken, PanicOnDefault, Promise, env, near, require};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct VoucherShop {
    /// Value, in yoctoNEAR, of each customer's vouchers in each series.
    vouchers: LookupMap<(AccountId, u64), u128>,
}

#[near]
impl VoucherShop {
    #[init]
    pub fn new() -> Self {
        Self { vouchers: LookupMap::new(b"v") }
    }

    /// Buys vouchers in `series` worth the attached deposit.
    #[payable]
    pub fn buy_vouchers(&mut self, series: u64) {
        let key = (env::predecessor_account_id(), series);
        let held = self.vouchers.get(&key).copied().unwrap_or(0);
        self.vouchers.insert(key, held + env::attached_deposit().as_yoctonear());
    }

    /// Cashes in `amounts[i]` yoctoNEAR of the caller's vouchers in `series_ids[i]` and pays the total to the caller.
    pub fn redeem_batch(&mut self, series_ids: Vec<u64>, amounts: Vec<U128>) -> Promise {
        require!(series_ids.len() == amounts.len(), "series_ids and amounts must have the same length");
        let caller = env::predecessor_account_id();
        let total: u128 = amounts.iter().map(|amount| amount.0).sum();
        for (series, amount) in series_ids.iter().zip(amounts.iter()) {
            let held = self
                .vouchers
                .get_mut(&(caller.clone(), *series))
                .unwrap_or_else(|| env::panic_str("no vouchers in that series"));
            require!(*held >= amount.0, "not enough vouchers in that series");
            *held -= amount.0;
        }
        Promise::new(caller).transfer(NearToken::from_yoctonear(total))
    }

    pub fn vouchers_of(&self, account_id: AccountId, series: u64) -> U128 {
        U128(self.vouchers.get(&(account_id, series)).copied().unwrap_or(0))
    }
}
