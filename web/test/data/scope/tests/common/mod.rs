use near_sdk::{Promise, env, is_promise_success, near};

#[near]
impl Contract {
    pub fn pay(&mut self) -> Promise {
        Promise::new(env::predecessor_account_id()).transfer(self.owed).then(Self::ext(env::current_account_id()).on_done())
    }

    pub fn on_done(&mut self) {
        if is_promise_success() {
            self.done = env::block_height();
        }
    }
}
