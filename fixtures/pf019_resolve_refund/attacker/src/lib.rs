//! PF019 fixture (attacker): a token receiver that reports as unused whatever its `msg` says.
//!
//! `ft_on_transfer` keeps every token it is sent and returns the number in `msg` as the unused amount. With
//! an honest number (at most `amount`) it is an ordinary partial refund; with a huge one it is the attack on a
//! resolver that trusts the return value.

use near_sdk::json_types::U128;
use near_sdk::{AccountId, PanicOnDefault, log, near};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Attacker {}

#[near]
impl Attacker {
    #[init]
    pub fn new() -> Self {
        Self {}
    }

    /// Reports `msg`, a decimal amount, as the part of `amount` that was not used.
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> U128 {
        log!("{sender_id} sent {}, reporting {msg} unused", amount.0);
        U128(msg.parse().expect("msg must be a decimal amount"))
    }
}
