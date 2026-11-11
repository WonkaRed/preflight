//! PF003 fixture (patched): the same ticket shop, with `on_charged` checking the payment result.
//!
//! `on_charged` takes the charge result with `#[callback_result]` and stops when the charge failed, so a ticket is
//! handed over only for a payment that went through.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{AccountId, Gas, PanicOnDefault, Promise, PromiseError, env, ext_contract, near, require};

const PRICE: u128 = 2_000_000_000_000_000_000_000_000;
const CHARGE_GAS: Gas = Gas::from_tgas(10);
const GRANT_GAS: Gas = Gas::from_tgas(10);

#[ext_contract(ext_ledger)]
pub trait Ledger {
    fn charge(&mut self, account_id: AccountId, amount: U128) -> U128;
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct TicketShop {
    ledger: AccountId,
    remaining: u32,
    tickets: LookupMap<AccountId, u32>,
}

#[near]
impl TicketShop {
    #[init]
    pub fn new(ledger: AccountId, tickets: u32) -> Self {
        Self { ledger, remaining: tickets, tickets: LookupMap::new(b"t") }
    }

    /// Charges the caller `PRICE` on the ledger; `on_charged` hands over the ticket.
    pub fn buy(&mut self) -> Promise {
        require!(self.remaining > 0, "sold out");
        let buyer = env::predecessor_account_id();
        ext_ledger::ext(self.ledger.clone())
            .with_static_gas(CHARGE_GAS)
            .charge(buyer.clone(), U128(PRICE))
            .then(Self::ext(env::current_account_id()).with_static_gas(GRANT_GAS).on_charged(buyer))
    }

    #[private]
    pub fn on_charged(&mut self, buyer: AccountId, #[callback_result] charged: Result<U128, PromiseError>) {
        require!(charged.is_ok(), "payment failed");
        require!(self.remaining > 0, "sold out");
        self.remaining -= 1;
        let held = self.tickets.get(&buyer).copied().unwrap_or(0);
        self.tickets.insert(buyer, held + 1);
    }

    pub fn tickets_of(&self, account_id: AccountId) -> u32 {
        self.tickets.get(&account_id).copied().unwrap_or(0)
    }

    pub fn remaining(&self) -> u32 {
        self.remaining
    }
}
