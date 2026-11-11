//! PF021 fixture (vulnerable): a staking pool whose `distribute` pays every staker in one call.
//!
//! Anyone can stake NEAR; the owner pays out each round of rewards in a fungible token with `distribute`, which
//! sends every staker their share. Each payout is an `ft_transfer` promise that reserves 30 Tgas, and a call can
//! prepay at most 1000 Tgas (the sandbox's `max_total_prepaid_gas`; 300 Tgas before protocol version 83), so
//! `distribute` stops working once about 30 accounts are staking. Anyone can bring the pool to that size with
//! dust stakes, after which no round can ever be paid out and the pool's tokens are stuck.

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

    // PF021: one call walks every staker, and anyone can add stakers with `stake`.
    /// Pays each staker their share of one round of rewards, in proportion to their stake.
    pub fn distribute(&mut self) {
        require!(env::predecessor_account_id() == self.owner_id, "only the owner can distribute");
        for (account_id, stake) in self.stakes.iter() {
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
