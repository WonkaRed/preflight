//! PF025 fixture (vulnerable): a voucher shop whose `redeem_batch` pairs two lists without checking their lengths.
//!
//! Customers buy vouchers in numbered series with NEAR, and cash them in later. `redeem_batch` takes a list of
//! series and a list of amounts, takes each amount off the customer's vouchers in the matching series, and pays
//! out the total. The debit loop zips the two lists, so it stops at the shorter one, but the payout is summed over
//! the whole `amounts` list: a longer `amounts` is paid in full while only its first entries are ever taken off a
//! voucher balance.

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
        let caller = env::predecessor_account_id();
        let total: u128 = amounts.iter().map(|amount| amount.0).sum();
        // PF025: stops at the shorter list, while `total` above counts every amount.
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
