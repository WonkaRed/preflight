//! PF001 fixture (vulnerable): an escrow whose payout callback is exported to everyone.
//!
//! `release` pays the seller and schedules `on_release` to record the settlement. `on_release` is a public
//! method like any other, so any account can call it directly and mark an order released with no payout.

use near_sdk::store::LookupMap;
use near_sdk::{AccountId, NearToken, PanicOnDefault, Promise, env, is_promise_success, near, require};

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Funded,
    Releasing,
    Released,
}

#[near(serializers = [borsh])]
pub struct Order {
    buyer: AccountId,
    seller: AccountId,
    amount: NearToken,
    status: Status,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Escrow {
    orders: LookupMap<u64, Order>,
}

#[near]
impl Escrow {
    #[init]
    pub fn new() -> Self {
        Self { orders: LookupMap::new(b"o") }
    }

    /// The buyer locks the attached deposit for `seller` under order `id`.
    #[payable]
    pub fn fund_order(&mut self, id: u64, seller: AccountId) {
        require!(!self.orders.contains_key(&id), "order already exists");
        let amount = env::attached_deposit();
        require!(!amount.is_zero(), "attach a deposit");
        let buyer = env::predecessor_account_id();
        self.orders.insert(id, Order { buyer, seller, amount, status: Status::Funded });
    }

    /// The buyer pays the seller; `on_release` records the settlement once the transfer receipt is processed.
    pub fn release(&mut self, id: u64) -> Promise {
        let order = self.orders.get_mut(&id).unwrap_or_else(|| env::panic_str("no such order"));
        require!(env::predecessor_account_id() == order.buyer, "only the buyer can release");
        require!(order.status == Status::Funded, "order is not funded");
        order.status = Status::Releasing;
        Promise::new(order.seller.clone())
            .transfer(order.amount)
            .then(Self::ext(env::current_account_id()).on_release(id))
    }

    // PF001: a callback that anyone can call.
    pub fn on_release(&mut self, id: u64) {
        let order = self.orders.get_mut(&id).unwrap_or_else(|| env::panic_str("no such order"));
        // A direct call carries no promise result; a real callback must not record a transfer that failed.
        let transfer_failed = env::promise_results_count() > 0 && !is_promise_success();
        order.status = if transfer_failed { Status::Funded } else { Status::Released };
    }

    pub fn get_status(&self, id: u64) -> Option<Status> {
        self.orders.get(&id).map(|order| order.status)
    }
}
