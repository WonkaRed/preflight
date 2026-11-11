//! PF021 fixture (patched): the staking pool with `distribute` paying one page of stakers per call.
//!
//! The owner calls `distribute(from, limit)` for successive pages, so no call walks more stakers than fit in its
//! gas, however many accounts have staked.

use near_sdk::json_types::U128;
use near_sdk::store::IterableMap;
use near_sdk::{AccountId, Gas, NearToken, PanicOnDefault, env, ext_contract, near, require};

/// Gas reserved for each payout, generous for a plain `ft_transfer` as contracts that pay into unknown tokens usually are.
const GAS_FOR_FT_TRANSFER: Gas = Gas::from_tgas(30);
const ONE_YOCTO: NearToken = NearToken::from_yoctonear(1);

#[ext_contract(ext_ft)]
pub trait FungibleToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128);
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct RewardPool {
    owner_id: AccountId,
    token_id: AccountId,
    reward_per_round: u128,
    total_staked: u128,
    paid_out: u128,
    stakes: IterableMap<AccountId, u128>,
}

#[near]
impl RewardPool {
    #[init]
    pub fn new(owner_id: AccountId, token_id: AccountId, reward_per_round: U128) -> Self {
        Self {
            owner_id,
            token_id,
            reward_per_round: reward_per_round.0,
            total_staked: 0,
            paid_out: 0,
            stakes: IterableMap::new(b"s"),
        }
    }

    /// Adds the attached deposit to the caller's stake.
    #[payable]
    pub fn stake(&mut self) {
        let deposit = env::attached_deposit().as_yoctonear();
        require!(deposit > 0, "attach a deposit to stake");
        let account_id = env::predecessor_account_id();
        let stake = self.stakes.get(&account_id).copied().unwrap_or(0);
        self.stakes.insert(account_id, stake + deposit);
        self.total_staked += deposit;
    }

    /// Pays the stakers from position `from`, at most `limit` of them, their share of one round of rewards in
    /// proportion to their stake; the owner pages through the stakers until all are paid.
    pub fn distribute(&mut self, from: u32, limit: u32) {
        require!(env::predecessor_account_id() == self.owner_id, "only the owner can distribute");
        for (account_id, stake) in self.stakes.iter().skip(from as usize).take(limit as usize) {
            let share = self.reward_per_round * stake / self.total_staked;
            if share == 0 {
                continue;
            }
            self.paid_out += share;
            ext_ft::ext(self.token_id.clone())
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(GAS_FOR_FT_TRANSFER)
                .ft_transfer(account_id.clone(), U128(share))
                .detach();
        }
    }

    pub fn staker_count(&self) -> u32 {
        self.stakes.len()
    }
}
