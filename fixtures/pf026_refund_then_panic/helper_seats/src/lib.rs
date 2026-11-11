//! PF026 fixture helper: the seat allocator that the ticket desk asks before it sells a ticket.
//!
//! It answers every `is_free` query with the answer it was created with, so a test chooses whether seats are free.

use near_sdk::{PanicOnDefault, near};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct SeatMap {
    free: bool,
}

#[near]
impl SeatMap {
    #[init]
    pub fn new(free: bool) -> Self {
        Self { free }
    }

    pub fn is_free(&self, seat: u32) -> bool {
        let _ = seat;
        self.free
    }
}
