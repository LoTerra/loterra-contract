use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, CanonicalAddr, Order, StdError, StdResult, Storage, Uint128};
use cosmwasm_storage::{bucket, bucket_read, Bucket, ReadonlyBucket};
use cw_storage_plus::Item;
use std::ops::Add;

const COMBINATION_KEY: &[u8] = b"combination";
const WINNER_KEY: &[u8] = b"winner";
const WINNER_RANK_KEY: &[u8] = b"rank";
const POLL_KEY: &[u8] = b"poll";
const VOTE_KEY: &[u8] = b"user";
const WINNING_COMBINATION_KEY: &[u8] = b"winning";
const PLAYER_COUNT_KEY: &[u8] = b"player";
const TICKET_COUNT_KEY: &[u8] = b"ticket";
const JACKPOT_KEY: &[u8] = b"jackpot";
const PLAYERS_KEY: &[u8] = b"players";
const ADDRESS_KEY: &[u8] = b"address";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Config {
    pub admin: CanonicalAddr,
    pub block_time_play: u64,
    pub every_block_time_play: u64,
    pub denom_stable: String,
    pub combination_len: u8,
    pub jackpot_percentage_reward: u8,
    pub token_holder_percentage_fee_reward: u8,
    pub fee_for_drand_worker_in_percentage: u8,
    pub prize_rank_winner_percentage: Vec<u8>,
    pub poll_count: u64,
    pub poll_default_end_height: u64,
    pub price_per_ticket_to_register: Uint128,
    pub terrand_contract_address: CanonicalAddr,
    pub loterra_cw20_contract_address: CanonicalAddr,
    pub loterra_staking_contract_address: CanonicalAddr,
    pub altered_contract_address: CanonicalAddr,
    pub safe_lock: bool,
    pub lottery_counter: u64,
    pub holders_bonus_block_time_end: u64,
    pub bonus_burn_rate: u8,
    pub bonus: u8,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum PollStatus {
    InProgress,
    Passed,
    Rejected,
    RejectedByCreator,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum Proposal {
    LotteryEveryBlockTime,
    HolderFeePercentage,
    DrandWorkerFeePercentage,
    PrizePerRank,
    JackpotRewardPercentage,
    AmountToRegister,
    SecurityMigration,
    DaoFunding,
    StakingContractMigration,
    PollSurvey,
    BonusBurnRate,
    Bonus,
    // test purpose
    NotExist,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PollInfoState {
    pub creator: CanonicalAddr,
    pub status: PollStatus,
    pub end_height: u64,
    pub start_height: u64,
    pub description: String,
    pub weight_yes_vote: Uint128,
    pub weight_no_vote: Uint128,
    pub yes_vote: u64,
    pub no_vote: u64,
    pub amount: Uint128,
    pub prize_rank: Vec<u8>,
    pub proposal: Proposal,
    pub migration_address: Option<Addr>,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct WinnerRewardClaims {
    pub claimed: bool,
    pub ranks: Vec<u8>,
}

pub const CONFIG: Item<Config> = Item::new("\u{0}\u{6}config");

pub fn store_config(storage: &mut dyn Storage, config: &Config) -> StdResult<()> {
    CONFIG.save(storage, config)
}

pub fn read_config(storage: &dyn Storage) -> StdResult<Config> {
    CONFIG.load(storage)
}

pub fn combination_save(
    storage: &mut dyn Storage,
    lottery_id: u64,
    address: CanonicalAddr,
    combination: Vec<String>,
) -> StdResult<()> {
    let mut exist = true;
    // Save combination by senders
    user_combination_bucket(storage, lottery_id).update::<_, StdError>(
        address.as_slice(),
        |exists| match exists {
            Some(combinations) => {
                let mut modified = combinations;
                modified.extend(combination.clone());
                Ok(modified)
            }
            None => {
                exist = false;
                Ok(combination.clone())
            }
        },
    )?;
    match address_players_read(storage).may_load(&address.as_slice())? {
        None => {
            address_players(storage).save(&address.as_slice(), &true)?;
        }
        Some(_) => {}
    };

    if !exist {
        all_players_storage(storage).update::<_, StdError>(&lottery_id.to_be_bytes(), |exist| {
            match exist {
                None => Ok(vec![address]),
                Some(players) => {
                    let mut data = players;
                    data.push(address);
                    Ok(data)
                }
            }
        })?;
        count_player_by_lottery(storage)
            .update::<_, StdError>(&lottery_id.to_be_bytes(), |exists| match exists {
                None => Ok(Uint128::from(1_u128)),
                Some(p) => Ok(p.add(Uint128::from(1_u128))),
            })
            .map(|_| ())?
    }

    count_total_ticket_by_lottery(storage)
        .update(&lottery_id.to_be_bytes(), |exists| match exists {
            None => Ok(Uint128::from(combination.len() as u128)),
            Some(p) => Ok(p.add(Uint128::from(combination.len() as u128))),
        })
        .map(|_| ())
}

pub fn user_combination_bucket(storage: &mut dyn Storage, lottery_id: u64) -> Bucket<Vec<String>> {
    Bucket::multilevel(storage, &[COMBINATION_KEY, &lottery_id.to_be_bytes()])
}

pub fn user_combination_bucket_read(
    storage: &dyn Storage,
    lottery_id: u64,
) -> ReadonlyBucket<Vec<String>> {
    ReadonlyBucket::multilevel(storage, &[COMBINATION_KEY, &lottery_id.to_be_bytes()])
}

// index: lottery_id | count
pub fn count_player_by_lottery(storage: &mut dyn Storage) -> Bucket<Uint128> {
    bucket(storage, PLAYER_COUNT_KEY)
}
// index: lottery_id | count
pub fn count_player_by_lottery_read(storage: &dyn Storage) -> ReadonlyBucket<Uint128> {
    bucket_read(storage, PLAYER_COUNT_KEY)
}

// index: lottery_id | count
pub fn count_total_ticket_by_lottery(storage: &mut dyn Storage) -> Bucket<Uint128> {
    bucket(storage, TICKET_COUNT_KEY)
}
// index: lottery_id | count
pub fn count_total_ticket_by_lottery_read(storage: &dyn Storage) -> ReadonlyBucket<Uint128> {
    bucket_read(storage, TICKET_COUNT_KEY)
}

// if an address won a lottery in this round, saved by rank
// index address -> winner claim
pub fn winner_storage(storage: &mut dyn Storage, lottery_id: u64) -> Bucket<WinnerRewardClaims> {
    Bucket::multilevel(storage, &[WINNER_KEY, &lottery_id.to_be_bytes()])
}

pub fn winner_storage_read(
    storage: &dyn Storage,
    lottery_id: u64,
) -> ReadonlyBucket<WinnerRewardClaims> {
    ReadonlyBucket::multilevel(storage, &[WINNER_KEY, &lottery_id.to_be_bytes()])
}

// save winner
pub fn save_winner(
    storage: &mut dyn Storage,
    lottery_id: u64,
    addr: CanonicalAddr,
    rank: u8,
) -> StdResult<()> {
    winner_storage(storage, lottery_id).update::<_, StdError>(addr.as_slice(), |exists| {
        match exists {
            None => Ok(WinnerRewardClaims {
                claimed: false,
                ranks: vec![rank],
            }),
            Some(claims) => {
                let mut ranks = claims.ranks;
                ranks.push(rank);
                Ok(WinnerRewardClaims {
                    claimed: false,
                    ranks,
                })
            }
        }
    })?;
    winner_count_by_rank(storage, lottery_id)
        .update(&rank.to_be_bytes(), |exists| match exists {
            None => Ok(Uint128::from(1_u128)),
            Some(r) => Ok(r.add(Uint128::from(1_u128))),
        })
        .map(|_| ())
}

pub fn all_winners(
    storage: &dyn Storage,
    lottery_id: u64,
) -> StdResult<Vec<(CanonicalAddr, WinnerRewardClaims)>> {
    winner_storage_read(storage, lottery_id)
        .range(None, None, Order::Ascending)
        .map(|item| {
            let (addr, claim) = item?;
            Ok((CanonicalAddr::from(addr), claim))
        })
        .collect()
}

// index: lottery_id | rank -> count
pub fn winner_count_by_rank_read(
    storage: &dyn Storage,
    lottery_id: u64,
) -> ReadonlyBucket<Uint128> {
    ReadonlyBucket::multilevel(storage, &[WINNER_RANK_KEY, &lottery_id.to_be_bytes()])
}

// index: lottery_id | rank -> count
pub fn winner_count_by_rank(storage: &mut dyn Storage, lottery_id: u64) -> Bucket<Uint128> {
    Bucket::multilevel(storage, &[WINNER_RANK_KEY, &lottery_id.to_be_bytes()])
}

pub fn poll_storage(storage: &mut dyn Storage) -> Bucket<PollInfoState> {
    bucket(storage, POLL_KEY)
}

pub fn poll_storage_read(storage: &dyn Storage) -> ReadonlyBucket<PollInfoState> {
    bucket_read(storage, POLL_KEY)
}

// poll vote storage index = VOTE_KEY:poll_id:address -> bool
pub fn poll_vote_storage(storage: &mut dyn Storage, poll_id: u64) -> Bucket<bool> {
    Bucket::multilevel(storage, &[VOTE_KEY, &poll_id.to_be_bytes()])
}

pub fn poll_vote_storage_read(storage: &dyn Storage, poll_id: u64) -> ReadonlyBucket<bool> {
    ReadonlyBucket::multilevel(storage, &[VOTE_KEY, &poll_id.to_be_bytes()])
}

pub fn lottery_winning_combination_storage(storage: &mut dyn Storage) -> Bucket<String> {
    bucket(storage, WINNING_COMBINATION_KEY)
}

pub fn lottery_winning_combination_storage_read(storage: &dyn Storage) -> ReadonlyBucket<String> {
    bucket_read(storage, WINNING_COMBINATION_KEY)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct JackpotInfo {
    pub ust: Uint128,
    pub alte: Uint128,
}
pub fn jackpot_storage(storage: &mut dyn Storage) -> Bucket<JackpotInfo> {
    bucket(storage, JACKPOT_KEY)
}

pub fn jackpot_storage_read(storage: &dyn Storage) -> ReadonlyBucket<JackpotInfo> {
    bucket_read(storage, JACKPOT_KEY)
}

pub fn all_players_storage(storage: &mut dyn Storage) -> Bucket<Vec<CanonicalAddr>> {
    bucket(storage, PLAYERS_KEY)
}
pub fn all_players_storage_read(storage: &dyn Storage) -> ReadonlyBucket<Vec<CanonicalAddr>> {
    bucket_read(storage, PLAYERS_KEY)
}

/// Get all players
pub fn address_players(storage: &mut dyn Storage) -> Bucket<bool> {
    bucket(storage, ADDRESS_KEY)
}

/// Read all players
pub fn address_players_read(storage: &dyn Storage) -> ReadonlyBucket<bool> {
    bucket_read(storage, ADDRESS_KEY)
}
