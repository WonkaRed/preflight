//! PF026 fixture (patched): the same ticket desk, with `on_seat_checked` refunding the buyer and finishing
//! normally.
//!
//! When the seat is taken, or the allocator could not be reached, `on_seat_checked` schedules the refund and
//! returns. The callback receipt succeeds, so the refund is sent, and nothing is recorded for the buyer.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{
    AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseError, env, ext_contract, log, near, require,
};

const SEAT_GAS: Gas = Gas::from_tgas(10);
const CALLBACK_GAS: Gas = Gas::from_tgas(20);

#[ext_contract(ext_seats)]
pub trait Seats {
    fn is_free(&self, seat: u32) -> bool;
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct TicketDesk {
    seats: AccountId,
    paid: LookupMap<AccountId, u128>,
    buyers: u32,
}

#[near]
impl TicketDesk {
    #[init]
    pub fn new(seats: AccountId) -> Self {
        Self { seats, paid: LookupMap::new(b"p"), buyers: 0 }
    }

    /// Keeps the attached deposit and has `on_seat_checked` record it once the seat allocator has said the seat is free.
    #[payable]
    pub fn buy(&mut self, seat: u32) -> Promise {
        let buyer = env::predecessor_account_id();
        let deposit = env::attached_deposit();
        require!(!deposit.is_zero(), "attach the price of the ticket");
        ext_seats::ext(self.seats.clone()).with_static_gas(SEAT_GAS).is_free(seat).then(
            Self::ext(env::current_account_id())
                .with_static_gas(CALLBACK_GAS)
                .on_seat_checked(buyer, U128(deposit.as_yoctonear())),
        )
    }

    /// Records the payment, or returns it to the buyer when the seat is taken. It never panics after the refund.
    #[private]
    pub fn on_seat_checked(
        &mut self,
        buyer: AccountId,
        deposit: U128,
        #[callback_result] answer: Result<bool, PromiseError>,
    ) {
        if answer.is_err() {
            log!("seat check failed, refund of {} yocto queued for {}", deposit.0, buyer);
            Promise::new(buyer).transfer(NearToken::from_yoctonear(deposit.0)).detach();
            return;
        }
        if !answer.unwrap_or_default() {
            log!("seat is taken, refund of {} yocto queued for {}", deposit.0, buyer);
            Promise::new(buyer).transfer(NearToken::from_yoctonear(deposit.0)).detach();
            return;
        }
        let held = self.paid.get(&buyer).copied().unwrap_or(0);
        if held == 0 {
            self.buyers += 1;
        }
        self.paid.insert(buyer, held + deposit.0);
    }

    pub fn paid_by(&self, account_id: AccountId) -> U128 {
        U128(self.paid.get(&account_id).copied().unwrap_or(0))
    }

    pub fn buyer_count(&self) -> u32 {
        self.buyers
    }
}
