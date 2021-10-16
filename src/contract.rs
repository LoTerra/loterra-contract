use crate::helpers::{
    count_match, encode_msg_execute, encode_msg_query, is_lower_hex, reject_proposal, total_weight,
    user_total_weight, wrapper_msg_loterra, wrapper_msg_terrand,
};
use crate::msg::{
    AllCombinationResponse, AllWinnersResponse, ConfigResponse, ExecuteMsg, GetPollResponse,
    InitMsg, MigrateMsg, QueryMsg, ReceiveMsg, RoundResponse, WinnerResponse,
};
use crate::state::{
    address_players_read, all_players_storage_read, all_winners, combination_save,
    count_player_by_lottery_read, count_total_ticket_by_lottery_read, jackpot_storage,
    jackpot_storage_alte, jackpot_storage_read, jackpot_storage_read_alte,
    lottery_winning_combination_storage, lottery_winning_combination_storage_read, poll_storage,
    poll_storage_read, poll_vote_storage, read_config, save_winner, store_config,
    user_combination_bucket_read, winner_count_by_rank_read, winner_storage, winner_storage_read,
    Config, PollInfoState, PollStatus, Proposal,
};
use crate::taxation::deduct_tax;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;

use cosmwasm_std::{
    from_binary, to_binary, Addr, BankMsg, Binary, CanonicalAddr, Coin, CosmosMsg, Decimal, Deps,
    DepsMut, Env, MessageInfo, Order, Response, StdError, StdResult, SubMsg, Uint128, WasmMsg,
    WasmQuery,
};
use cw0::calc_range_start;
use cw20::{BalanceResponse, Cw20ExecuteMsg, Cw20QueryMsg, Cw20ReceiveMsg};
use std::ops::{Add, Mul, Sub};

const DRAND_GENESIS_TIME: u64 = 1595431050;
const DRAND_PERIOD: u64 = 30;
const DRAND_NEXT_ROUND_SECURITY: u64 = 3;
const MAX_DESCRIPTION_LEN: u64 = 255;
const MIN_DESCRIPTION_LEN: u64 = 6;
const HOLDERS_MAX_REWARD: u8 = 100;
const WORKER_MAX_REWARD: u8 = 10;
const DIV_BLOCK_TIME_BY_X: u64 = 2;
const BONUS_MAX: u8 = 100;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InitMsg,
) -> StdResult<Response> {
    let config = Config {
        admin: deps.api.addr_canonicalize(info.sender.as_str())?,
        block_time_play: msg.block_time_play,
        every_block_time_play: msg.every_block_time_play,
        denom_stable: msg.denom_stable,
        poll_default_end_height: msg.poll_default_end_height,
        combination_len: 6,
        jackpot_percentage_reward: 20,
        token_holder_percentage_fee_reward: 50,
        fee_for_drand_worker_in_percentage: 1,
        prize_rank_winner_percentage: vec![87, 10, 2, 1, 1, 1],
        poll_count: 0,
        price_per_ticket_to_register: Uint128::from(1_000_000u128),
        terrand_contract_address: deps
            .api
            .addr_canonicalize(&msg.terrand_contract_address.to_string())?,
        loterra_cw20_contract_address: deps
            .api
            .addr_canonicalize(&msg.loterra_cw20_contract_address.to_string())?,
        loterra_staking_contract_address: deps
            .api
            .addr_canonicalize(&msg.loterra_staking_contract_address.to_string())?,
        altered_contract_address: deps
            .api
            .addr_canonicalize(&msg.altered_contract_address.to_string())?,
        safe_lock: false,
        lottery_counter: 1,
        holders_bonus_block_time_end: msg.holders_bonus_block_time_end,
        bonus_burn_rate: 10,
        bonus: 0,
        // counter_claim: 0,
    };
    store_config(deps.storage, &config)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::Register {
            address,
            altered_bonus,
            combination,
        } => execute_register(deps, env, info, address, altered_bonus, combination),
        ExecuteMsg::Play {} => execute_play(deps, env, info),
        ExecuteMsg::Claim { addresses } => execute_claim(deps, env, info, addresses),
        ExecuteMsg::Collect { address } => execute_collect(deps, env, info, address),
        ExecuteMsg::Poll {
            description,
            proposal,
            amount,
            prize_per_rank,
            recipient,
        } => execute_proposal(
            deps,
            env,
            info,
            description,
            proposal,
            amount,
            prize_per_rank,
            recipient,
        ),
        ExecuteMsg::Vote { poll_id, approve } => execute_vote(deps, env, info, poll_id, approve),
        ExecuteMsg::PresentPoll { poll_id } => execute_present_proposal(deps, env, info, poll_id),
        ExecuteMsg::RejectPoll { poll_id } => execute_reject_proposal(deps, env, info, poll_id),
        ExecuteMsg::SafeLock {} => execute_safe_lock(deps, env, info),
        ExecuteMsg::Renounce {} => execute_renounce(deps, env, info),
        ExecuteMsg::Receive(msg) => handle_receive(deps, env, info, msg),
    }
}

fn execute_renounce(deps: DepsMut, env: Env, info: MessageInfo) -> StdResult<Response> {
    // Load the state
    let mut state = read_config(deps.storage)?;
    let sender = deps.api.addr_canonicalize(&info.sender.to_string())?;
    if state.admin != sender {
        return Err(StdError::generic_err("Unauthorized"));
    }
    if state.safe_lock {
        return Err(StdError::generic_err("Contract is locked"));
    }

    state.admin = deps
        .api
        .addr_canonicalize(&env.contract.address.to_string())?;
    store_config(deps.storage, &state)?;
    Ok(Response::default())
}

fn execute_safe_lock(deps: DepsMut, _env: Env, info: MessageInfo) -> StdResult<Response> {
    // Load the state
    let mut state = read_config(deps.storage)?;
    let sender = deps.api.addr_canonicalize(&info.sender.to_string())?;
    if state.admin != sender {
        return Err(StdError::generic_err("Unauthorized"));
    }

    state.safe_lock = !state.safe_lock;
    store_config(deps.storage, &state)?;

    Ok(Response::default())
}
pub fn handle_receive(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    wrapper: Cw20ReceiveMsg,
) -> StdResult<Response> {
    let state = read_config(deps.storage)?;

    // only loterra cw20 contract can send receieve msg
    if info.sender != deps.api.addr_humanize(&state.altered_contract_address)? {
        return Err(StdError::generic_err(
            "only altered contract can send receive messages",
        ));
    }

    let msg: ReceiveMsg = from_binary(&wrapper.msg)?;
    match msg {
        ReceiveMsg::RegisterAlte {
            gift_address,
            combination,
        } => execute_register_alte(
            deps,
            env,
            info,
            wrapper.sender,
            gift_address,
            combination,
            wrapper.amount,
        ),
    }
}
fn execute_register_alte(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    address: String,
    gift_address: Option<String>,
    combination: Vec<String>,
    amount: Uint128,
) -> StdResult<Response> {
    let state = read_config(deps.storage)?;
    if state.safe_lock {
        return Err(StdError::generic_err(
            "Contract deactivated for update or/and preventing security issue",
        ));
    }
    // Check if the lottery is about to play and cancel new ticket to enter until play
    if env.block.time.seconds() > state.block_time_play {
        return Err(StdError::generic_err(
            "Lottery is about to start wait until the end before register",
        ));
    }
    // Check if address filled as param
    let addr = match gift_address {
        None => address,
        Some(addr) => addr,
    };

    for combo in combination.clone() {
        // Regex to check if the combination is allowed
        if !is_lower_hex(&combo, state.combination_len) {
            return Err(StdError::generic_err(format!(
                "Not authorized use combination of [a-f] and [0-9] with length {}",
                state.combination_len
            )));
        }
    }

    if amount.is_zero() {
        return Err(StdError::generic_err(format!(
            "you need to send {}ALTE per combination in order to register",
            state.price_per_ticket_to_register.clone()
        )));
    }

    // Bonus amount
    let bonus: Uint128 = Uint128::from(
        state.price_per_ticket_to_register.clone().u128() * combination.len() as u128,
    )
    .multiply_ratio(Uint128::from(state.bonus as u128), Uint128::from(100u128));

    // Handle the player is not sending too much or too less
    if amount.u128()
        != Uint128::from(
            state.price_per_ticket_to_register.clone().u128() * combination.len() as u128,
        )
        .sub(bonus)
        .u128()
    {
        return Err(StdError::generic_err(format!(
            "send {}ALTE",
            Uint128::from(
                state.price_per_ticket_to_register.clone().u128() * combination.len() as u128,
            )
            .sub(bonus)
            .u128()
        )));
    }

    // save combination
    let addr_raw = deps.api.addr_canonicalize(&addr.to_string())?;
    combination_save(deps.storage, state.lottery_counter, addr_raw, combination)?;

    Ok(Response::new()
        .add_attribute("action", "register")
        .add_attribute("pay-in", "ALTE"))
}

fn execute_register(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    address: Option<Addr>,
    altered_bonus: Option<bool>,
    combination: Vec<String>,
) -> StdResult<Response> {
    // Load the state
    let state = read_config(deps.storage)?;
    if state.safe_lock {
        return Err(StdError::generic_err(
            "Contract deactivated for update or/and preventing security issue",
        ));
    }

    // Check if the lottery is about to play and cancel new ticket to enter until play
    if env.block.time.seconds() > state.block_time_play {
        return Err(StdError::generic_err(
            "Lottery is about to start wait until the end before register",
        ));
    }

    // Check if address filled as param
    let addr = match address {
        None => info.sender.clone(),
        Some(addr) => addr,
    };

    for combo in combination.clone() {
        // Regex to check if the combination is allowed
        if !is_lower_hex(&combo, state.combination_len) {
            return Err(StdError::generic_err(format!(
                "Not authorized use combination of [a-f] and [0-9] with length {}",
                state.combination_len
            )));
        }
    }

    // Check if some funds are sent
    let sent = match info.funds.len() {
        0 => Err(StdError::generic_err(format!(
            "you need to send {}{} per combination in order to register",
            state.price_per_ticket_to_register.clone(),
            state.denom_stable
        ))),
        1 => {
            if info.funds[0].denom == state.denom_stable {
                Ok(info.funds[0].amount)
            } else {
                Err(StdError::generic_err(format!(
                    "To register you need to send {}{} per combination",
                    state.price_per_ticket_to_register,
                    state.denom_stable.clone()
                )))
            }
        }
        _ => Err(StdError::generic_err(format!(
            "Only send {} to register",
            state.denom_stable
        ))),
    }?;

    if sent.is_zero() {
        return Err(StdError::generic_err(format!(
            "you need to send {}{} per combination in order to register",
            state.price_per_ticket_to_register.clone(),
            state.denom_stable
        )));
    }
    let mut execute_msg: Vec<CosmosMsg> = vec![];
    match altered_bonus {
        None => {
            // Handle the player is not sending too much or too less
            if sent.u128() != state.price_per_ticket_to_register.u128() * combination.len() as u128
            {
                return Err(StdError::generic_err(format!(
                    "send {}{}",
                    state.price_per_ticket_to_register.clone().u128() * combination.len() as u128,
                    state.denom_stable
                )));
            }
        }
        Some(_) => {
            if Uint128::from(state.bonus_burn_rate as u128).is_zero() {
                return Err(StdError::generic_err("Altered bonus disabled"));
            }
            // Ratio is a decimal 0.5
            let bonus_burn: Uint128 = Uint128::from(
                state.price_per_ticket_to_register.clone().u128() * combination.len() as u128,
            )
            .mul(Decimal::from_ratio(
                Uint128::from(state.bonus_burn_rate as u128),
                Uint128::from(100u128),
            ));
            // Bonus amount
            let bonus: Uint128 = bonus_burn
                .multiply_ratio(Uint128::from(state.bonus as u128), Uint128::from(100u128));
            // Verify if player is sending correct amount
            if sent.u128()
                != Uint128::from(
                    state.price_per_ticket_to_register.clone().u128() * combination.len() as u128,
                )
                .sub(bonus_burn)
                .u128()
            {
                return Err(StdError::generic_err(format!(
                    "send {}{}",
                    Uint128::from(
                        state.price_per_ticket_to_register.clone().u128()
                            * combination.len() as u128
                    )
                    .sub(bonus_burn)
                    .u128(),
                    state.denom_stable
                )));
            }

            /*
               Prepare the burn message
            */

            let altered_human = deps.api.addr_humanize(&state.altered_contract_address)?;
            let burn_msg = Cw20ExecuteMsg::BurnFrom {
                owner: info.sender.to_string(),
                amount: bonus_burn - bonus,
            };
            let wasm_msg = CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: altered_human.to_string(),
                msg: to_binary(&burn_msg)?,
                funds: vec![],
            });
            execute_msg.push(wasm_msg);
        }
    }

    // save combination
    let addr_raw = deps.api.addr_canonicalize(&addr.to_string())?;
    combination_save(deps.storage, state.lottery_counter, addr_raw, combination)?;

    Ok(Response::new()
        .add_messages(execute_msg)
        .add_attribute("action", "register")
        .add_attribute("pay-in", "UST"))
}

fn execute_play(deps: DepsMut, env: Env, info: MessageInfo) -> StdResult<Response> {
    // Ensure the sender not sending funds accidentally
    if !info.funds.is_empty() {
        return Err(StdError::generic_err("Do not send funds with play"));
    }

    // Load the state
    let mut state = read_config(deps.storage)?;

    if state.safe_lock {
        return Err(StdError::generic_err(
            "Contract deactivated for update or/and preventing security issue",
        ));
    }

    // calculate next round randomness
    let from_genesis = state.block_time_play - DRAND_GENESIS_TIME;
    let next_round = (from_genesis / DRAND_PERIOD) + DRAND_NEXT_ROUND_SECURITY;

    // Make the contract callable for everyone every x blocks
    if env.block.time.seconds() > state.block_time_play {
        // Update the state
        state.block_time_play = env.block.time.seconds() + state.every_block_time_play;
    } else {
        return Err(StdError::generic_err(format!(
            "Lottery registration is still in progress... Retry after block time {}",
            state.block_time_play
        )));
    }

    let msg = QueryMsg::GetRandomness { round: next_round };
    let terrand_human = deps.api.addr_humanize(&state.terrand_contract_address)?;
    let res = encode_msg_query(msg, terrand_human)?;
    let res = wrapper_msg_terrand(&deps.as_ref(), res)?;
    let randomness_hash = hex::encode(res.randomness.as_slice());

    let n = randomness_hash
        .char_indices()
        .rev()
        .nth(state.combination_len as usize - 1)
        .map(|(i, _)| i)
        .unwrap();
    let winning_combination = &randomness_hash[n..];

    // Save the combination for the current lottery count
    lottery_winning_combination_storage(deps.storage).save(
        &state.lottery_counter.to_be_bytes(),
        &winning_combination.to_string(),
    )?;

    // Set jackpot amount
    let balance = deps
        .querier
        .query_balance(&env.contract.address, &state.denom_stable)
        .unwrap();
    // Max amount winners can claim
    let jackpot = balance
        .amount
        .mul(Decimal::percent(state.jackpot_percentage_reward as u64));
    // Get Altered balance and set altered jackpot
    let prepare_msg_jackpot_altered = Cw20QueryMsg::Balance {
        address: env.contract.address.to_string(),
    };
    let msg_jackpot_altered = WasmQuery::Smart {
        contract_addr: deps
            .api
            .addr_humanize(&state.altered_contract_address)?
            .to_string(),
        msg: to_binary(&prepare_msg_jackpot_altered)?,
    };
    let response_jackpot_altered: BalanceResponse =
        deps.querier.query(&msg_jackpot_altered.into())?;
    let jackpot_altered = response_jackpot_altered
        .balance
        .mul(Decimal::percent(state.jackpot_percentage_reward as u64));

    // Drand worker fee
    let fee_for_drand_worker = jackpot
        .mul(Decimal::percent(
            state.fee_for_drand_worker_in_percentage as u64,
        ))
        .mul(Decimal::percent(
            state.fee_for_drand_worker_in_percentage as u64,
        ));

    // The jackpot after worker fee applied
    let jackpot_after = jackpot.sub(fee_for_drand_worker);

    if env.block.time.seconds() > state.holders_bonus_block_time_end
        && state.token_holder_percentage_fee_reward > HOLDERS_MAX_REWARD
    {
        state.token_holder_percentage_fee_reward = 20;
    }
    // Save jackpot to storage
    jackpot_storage(deps.storage).save(&state.lottery_counter.to_be_bytes(), &jackpot_after)?;
    jackpot_storage_alte(deps.storage)
        .save(&state.lottery_counter.to_be_bytes(), &jackpot_altered)?;

    // Update the state
    state.lottery_counter += 1;
    // state.counter_claim = 0;

    // Save the new state
    store_config(deps.storage, &state)?;

    Ok(Response::new()
        .add_message(CosmosMsg::Bank(BankMsg::Send {
            to_address: res.worker.to_string(),
            amount: vec![deduct_tax(
                &deps.as_ref(),
                Coin {
                    denom: state.denom_stable,
                    amount: fee_for_drand_worker,
                },
            )?],
        }))
        .add_attribute("action", "reward")
        .add_attribute("by", &info.sender.to_string())
        .add_attribute("to", &res.worker.to_string()))
}

fn execute_claim(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    addresses: Option<Vec<Addr>>,
) -> StdResult<Response> {
    let state = read_config(deps.storage)?;

    if state.safe_lock {
        return Err(StdError::generic_err(
            "Contract deactivated for update or/and preventing security issue",
        ));
    }

    if env.block.time.seconds()
        > state.block_time_play - state.every_block_time_play / DIV_BLOCK_TIME_BY_X
    {
        return Err(StdError::generic_err("Claiming is closed"));
    }
    let last_lottery_counter_round = state.lottery_counter - 1;

    let lottery_winning_combination = match lottery_winning_combination_storage(deps.storage)
        .may_load(&last_lottery_counter_round.to_be_bytes())?
    {
        Some(combination) => Some(combination),
        None => {
            return Err(StdError::NotFound {
                kind: "No winning combination".to_string(),
            });
        }
    }
    .unwrap();

    let addr = deps.api.addr_canonicalize(&info.sender.to_string())?;

    let mut combination: Vec<(CanonicalAddr, Vec<String>)> = vec![];

    match addresses {
        None => {
            match user_combination_bucket_read(deps.storage, last_lottery_counter_round)
                .may_load(addr.as_slice())?
            {
                None => {}
                Some(combo) => combination.push((addr, combo)),
            };
        }
        Some(addresses) => {
            for address in addresses {
                let addr = deps.api.addr_canonicalize(&address.to_string())?;
                match user_combination_bucket_read(deps.storage, last_lottery_counter_round)
                    .may_load(addr.as_slice())?
                {
                    None => {}
                    Some(combo) => combination.push((addr, combo)),
                };
            }
        }
    }

    if combination.is_empty() {
        return Err(StdError::NotFound {
            kind: "No combination found".to_string(),
        });
    }

    let mut some_winner = 0;
    // let mut add_claim = 0;
    for (addr, comb_raw) in combination {
        match winner_storage_read(deps.storage, last_lottery_counter_round)
            .may_load(addr.as_slice())?
        {
            None => {
                // Add amount claimed in order to track claims and unlock faster collect
                // add_claim = add_claim + 1;
                for combo in comb_raw {
                    let match_count = count_match(&combo, &lottery_winning_combination);
                    let rank = match match_count {
                        count if count == lottery_winning_combination.len() => 1,
                        count if count == lottery_winning_combination.len() - 1 => 2,
                        count if count == lottery_winning_combination.len() - 2 => 3,
                        count if count == lottery_winning_combination.len() - 3 => 4,
                        count if count == lottery_winning_combination.len() - 4 => 5,
                        count if count == lottery_winning_combination.len() - 5 => 6,
                        _ => 0,
                    } as u8;

                    if rank > 0 {
                        save_winner(deps.storage, last_lottery_counter_round, addr.clone(), rank)?;
                        some_winner += 1;
                    }
                }
            }
            Some(_) => {}
        }
    }

    if some_winner == 0 {
        return Err(StdError::NotFound {
            kind: "No winning combination or already claimed".to_string(),
        });
    }

    // state.counter_claim = state.counter_claim + add_claim;
    // store_config(deps.storage, &state)?;

    Ok(Response::new().add_attribute("action", "claim"))
}
// Players claim the jackpot
fn execute_collect(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    address: Option<Addr>,
) -> StdResult<Response> {
    // Ensure the sender is not sending funds
    if !info.funds.is_empty() {
        return Err(StdError::generic_err("Do not send funds with jackpot"));
    }

    // Load state
    let state = read_config(deps.storage)?;
    let last_lottery_counter_round = state.lottery_counter - 1;
    let jackpot_reward = jackpot_storage_read(deps.storage)
        .load(&last_lottery_counter_round.to_be_bytes())
        .unwrap_or_else(|_| Uint128::zero());
    let jackpot_reward_alte = jackpot_storage_read_alte(deps.storage)
        .load(&last_lottery_counter_round.to_be_bytes())
        .unwrap_or_else(|_| Uint128::zero());

    // let player_amount = match count_player_by_lottery_read(deps.storage)
    //     .may_load(&last_lottery_counter_round.to_be_bytes())?
    // {
    //     None => Uint128::zero(),
    //     Some(players) => players,
    // };

    if state.safe_lock {
        return Err(StdError::generic_err(
            "Contract deactivated for update or/and preventing security issue",
        ));
    }
    if env.block.time.seconds()
        < state.block_time_play - state.every_block_time_play / DIV_BLOCK_TIME_BY_X
    {
        // if player_amount.u128() as u64 != state.counter_claim {
        //     return Err(StdError::generic_err("Collecting jackpot is closed"));
        // }
        return Err(StdError::generic_err("Collecting jackpot is closed"));
    }

    // Ensure there is jackpot reward to claim
    if jackpot_reward.is_zero() && jackpot_reward_alte.is_zero() {
        return Err(StdError::generic_err("No jackpot reward"));
    }
    let addr = match address {
        None => info.sender.clone(),
        Some(addr) => addr,
    };

    // Get the contract balance
    let balance = deps
        .querier
        .query_balance(&env.contract.address, &state.denom_stable)
        .unwrap();
    // Ensure the contract have the balance
    if balance.amount.is_zero() {
        return Err(StdError::generic_err("Empty contract balance"));
    }

    let canonical_addr = deps.api.addr_canonicalize(&addr.to_string())?;
    // Load winner
    let may_claim = winner_storage_read(deps.storage, last_lottery_counter_round)
        .may_load(canonical_addr.as_slice())?;

    if may_claim.is_none() {
        return Err(StdError::generic_err("Address is not a winner"));
    }

    let mut rewards = may_claim.unwrap();

    if rewards.claimed {
        return Err(StdError::generic_err("Already claimed"));
    }

    let mut total_prize: u128 = 0;
    let mut total_alte_prize: u128 = 0;
    for rank in rewards.clone().ranks {
        let rank_count = winner_count_by_rank_read(deps.storage, last_lottery_counter_round)
            .load(&rank.to_be_bytes())?;

        let prize = jackpot_reward
            .mul(Decimal::percent(
                state.prize_rank_winner_percentage[rank as usize - 1] as u64,
            ))
            .u128()
            / rank_count.u128() as u128;
        // TODO: We probably here need to verify if there is no ALTE balance
        let alte_prize = jackpot_reward_alte
            .mul(Decimal::percent(
                state.prize_rank_winner_percentage[rank as usize - 1] as u64,
            ))
            .u128()
            / rank_count.u128() as u128;

        total_prize += prize;
        total_alte_prize += alte_prize;
    }

    // update the winner to claimed true
    rewards.claimed = true;
    winner_storage(deps.storage, last_lottery_counter_round)
        .save(canonical_addr.as_slice(), &rewards)?;

    let total_prize = Uint128::from(total_prize);
    let total_alte_prize = Uint128::from(total_alte_prize);
    /*
        TODO : Add staking rewards fees we will probably need to migrate our staking smart contract
    */

    // Amount token holders can claim of the reward as fee
    let token_holder_fee_reward = total_prize.mul(Decimal::percent(
        state.token_holder_percentage_fee_reward as u64,
    ));

    let loterra_human = deps
        .api
        .addr_humanize(&state.loterra_staking_contract_address)?;
    let total_prize_after = total_prize.sub(token_holder_fee_reward);

    let msg_update_global_index = QueryMsg::UpdateGlobalIndex {};

    let res_update_global_index = encode_msg_execute(
        msg_update_global_index,
        loterra_human,
        vec![deduct_tax(
            &deps.as_ref(),
            Coin {
                denom: state.denom_stable.clone(),
                amount: token_holder_fee_reward,
            },
        )?],
    )?;

    let msg_prepare_transfer = Cw20ExecuteMsg::Transfer {
        recipient: addr.to_string(),
        amount: total_alte_prize,
    };
    let wasm_msg = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: deps
            .api
            .addr_humanize(&state.altered_contract_address)?
            .to_string(),
        msg: to_binary(&msg_prepare_transfer)?,
        funds: vec![],
    });

    // Build the amount transaction
    let mut res = Response::new()
        .add_attribute("action", "handle_collect")
        .add_attribute("by", &info.sender.to_string())
        .add_attribute("to", &addr.to_string())
        .add_attribute("collecting_jackpot_prize", "yes");

    let mut msg_cw = vec![];
    if !total_alte_prize.is_zero() {
        msg_cw.push(SubMsg::new(wasm_msg));
    };

    if !total_prize.is_zero() {
        // Add fee message
        msg_cw.push(SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
            to_address: addr.to_string(),
            amount: vec![deduct_tax(
                &deps.as_ref(),
                Coin {
                    denom: state.denom_stable,
                    amount: total_prize_after,
                },
            )?],
        })));
        msg_cw.push(SubMsg::new(res_update_global_index));
        // res.add_message(CosmosMsg::Bank(BankMsg::Send {
        //     to_address: addr.to_string(),
        //     amount: vec![deduct_tax(
        //         &deps.as_ref(),
        //         Coin {
        //             denom: state.denom_stable,
        //             amount: total_prize_after,
        //         },
        //     )?],
        // })).add_message(res_update_global_index);
    }

    res.messages = msg_cw;

    // Send the jackpot
    Ok(res)
}

#[allow(clippy::too_many_arguments)]
fn execute_proposal(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    description: String,
    proposal: Proposal,
    amount: Option<Uint128>,
    prize_per_rank: Option<Vec<u8>>,
    recipient: Option<Addr>,
) -> StdResult<Response> {
    let mut state = read_config(deps.storage)?;
    // Increment and get the new poll id for bucket key
    let poll_id = state.poll_count + 1;
    // Set the new counter
    state.poll_count = poll_id;

    //Handle sender is not sending funds
    if !info.funds.is_empty() {
        return Err(StdError::generic_err("Do not send funds with proposal"));
    }

    // Handle the description is respecting length
    if (description.len() as u64) < MIN_DESCRIPTION_LEN {
        return Err(StdError::generic_err(format!(
            "Description min length {}",
            MIN_DESCRIPTION_LEN.to_string()
        )));
    } else if (description.len() as u64) > MAX_DESCRIPTION_LEN {
        return Err(StdError::generic_err(format!(
            "Description max length {}",
            MAX_DESCRIPTION_LEN.to_string()
        )));
    }

    let mut proposal_amount: Uint128 = Uint128::zero();
    let mut proposal_prize_rank: Vec<u8> = vec![];
    let mut proposal_human_address: Option<Addr> = None;

    let proposal_type = if let Proposal::HolderFeePercentage = proposal {
        match amount {
            Some(percentage) => {
                if percentage.u128() as u8 > HOLDERS_MAX_REWARD {
                    return Err(StdError::generic_err(format!(
                        "Amount between 0 to {}",
                        HOLDERS_MAX_REWARD
                    )));
                }
                proposal_amount = percentage;
            }
            None => {
                return Err(StdError::generic_err("Amount is required"));
            }
        }

        Proposal::HolderFeePercentage
    } else if let Proposal::DrandWorkerFeePercentage = proposal {
        match amount {
            Some(percentage) => {
                if percentage.u128() as u8 > WORKER_MAX_REWARD {
                    return Err(StdError::generic_err(format!(
                        "Amount between 0 to {}",
                        WORKER_MAX_REWARD
                    )));
                }
                proposal_amount = percentage;
            }
            None => {
                return Err(StdError::generic_err("Amount is required"));
            }
        }

        Proposal::DrandWorkerFeePercentage
    } else if let Proposal::JackpotRewardPercentage = proposal {
        match amount {
            Some(percentage) => {
                if percentage.u128() as u8 > 100 {
                    return Err(StdError::generic_err("Amount between 0 to 100".to_string()));
                }
                proposal_amount = percentage;
            }
            None => {
                return Err(StdError::generic_err("Amount is required".to_string()));
            }
        }

        Proposal::JackpotRewardPercentage
    } else if let Proposal::LotteryEveryBlockTime = proposal {
        match amount {
            Some(block_time) => {
                proposal_amount = block_time;
            }
            None => {
                return Err(StdError::generic_err("Amount block time required"));
            }
        }

        Proposal::LotteryEveryBlockTime
    } else if let Proposal::PrizePerRank = proposal {
        match prize_per_rank {
            Some(ranks) => {
                if ranks.len() != 6 {
                    return Err(StdError::generic_err(
                        "Ranks need to be in this format [0, 90, 10, 0, 0, 0] numbers between 0 to 100"
                    ));
                }
                let mut total_percentage = 0;
                for rank in ranks.clone() {
                    if (rank as u8) > 100 {
                        return Err(StdError::generic_err("Numbers between 0 to 100"));
                    }
                    total_percentage += rank;
                }
                // Ensure the repartition sum is 100%
                if total_percentage != 100 {
                    return Err(StdError::generic_err(
                        "Numbers total sum need to be equal to 100",
                    ));
                }

                proposal_prize_rank = ranks;
            }
            None => {
                return Err(StdError::generic_err("Rank is required"));
            }
        }
        Proposal::PrizePerRank
    } else if let Proposal::AmountToRegister = proposal {
        match amount {
            Some(amount_to_register) => {
                proposal_amount = amount_to_register;
            }
            None => {
                return Err(StdError::generic_err("Amount is required"));
            }
        }
        Proposal::AmountToRegister
    } else if let Proposal::Bonus = proposal {
        match amount {
            Some(bonus_amount) => {
                if bonus_amount.u128() as u8 > BONUS_MAX {
                    return Err(StdError::generic_err("Amount between 0 to 100"));
                }
                proposal_amount = bonus_amount;
            }
            None => {
                return Err(StdError::generic_err("Amount is required"));
            }
        }
        Proposal::Bonus
    } else if let Proposal::BonusBurnRate = proposal {
        match amount {
            Some(bonus_burn_amount) => {
                if bonus_burn_amount.u128() as u8 > BONUS_MAX {
                    return Err(StdError::generic_err("Amount between 0 to 100"));
                }
                proposal_amount = bonus_burn_amount;
            }
            None => {
                return Err(StdError::generic_err("Amount is required"));
            }
        }
        Proposal::BonusBurnRate
    } else if let Proposal::SecurityMigration = proposal {
        match recipient {
            Some(migration_address) => {
                let sender = deps.api.addr_canonicalize(&info.sender.to_string())?;
                let contract_address = deps
                    .api
                    .addr_canonicalize(&env.contract.address.to_string())?;
                if state.admin != contract_address && state.admin != sender {
                    return Err(StdError::generic_err("Unauthorized"));
                }

                proposal_human_address = Option::from(migration_address);
            }
            None => {
                return Err(StdError::generic_err("Migration address is required"));
            }
        }
        Proposal::SecurityMigration
    } else if let Proposal::DaoFunding = proposal {
        match amount {
            Some(amount) => {
                let sender = deps.api.addr_canonicalize(&info.sender.to_string())?;
                let contract_address = deps
                    .api
                    .addr_canonicalize(&env.contract.address.to_string())?;
                if state.admin != contract_address && state.admin != sender {
                    return Err(StdError::generic_err("Unauthorized"));
                }
                if amount.is_zero() {
                    return Err(StdError::generic_err("Amount be higher than 0"));
                }

                // Get the contract balance prepare the tx
                let msg_balance = QueryMsg::Balance {
                    address: env.contract.address,
                };
                let loterra_human = deps
                    .api
                    .addr_humanize(&state.loterra_cw20_contract_address)?;
                let res_balance = encode_msg_query(msg_balance, loterra_human)?;
                let loterra_balance = wrapper_msg_loterra(&deps.as_ref(), res_balance)?;

                if loterra_balance.balance.is_zero() {
                    return Err(StdError::generic_err("No more funds to fund project"));
                }
                if loterra_balance.balance.u128() < amount.u128() {
                    return Err(StdError::generic_err(format!(
                        "You need {} we only can fund you up to {}",
                        amount, loterra_balance.balance
                    )));
                }

                proposal_amount = amount;
                proposal_human_address = match recipient {
                    None => None,
                    Some(address) => Option::from(address),
                }
            }
            None => {
                return Err(StdError::generic_err("Amount required"));
            }
        }
        Proposal::DaoFunding
    } else if let Proposal::StakingContractMigration = proposal {
        match recipient {
            Some(migration_address) => {
                let sender = deps.api.addr_canonicalize(&info.sender.to_string())?;
                let contract_address = deps
                    .api
                    .addr_canonicalize(&env.contract.address.to_string())?;
                if state.admin != contract_address && state.admin != sender {
                    return Err(StdError::generic_err("Unauthorized"));
                }
                proposal_human_address = Option::from(migration_address);
            }
            None => {
                return Err(StdError::generic_err("Migration address is required"));
            }
        }
        Proposal::StakingContractMigration
    } else if let Proposal::PollSurvey = proposal {
        Proposal::PollSurvey
    } else {
        return Err(StdError::generic_err("Proposal type not founds"));
    };

    let sender_to_canonical = deps
        .api
        .addr_canonicalize(&info.sender.to_string())
        .unwrap();

    let new_poll = PollInfoState {
        creator: sender_to_canonical,
        status: PollStatus::InProgress,
        end_height: env.block.height + state.poll_default_end_height,
        start_height: env.block.height,
        description,
        weight_yes_vote: Uint128::zero(),
        weight_no_vote: Uint128::zero(),
        yes_vote: 0,
        no_vote: 0,
        amount: proposal_amount,
        prize_rank: proposal_prize_rank,
        proposal: proposal_type,
        migration_address: proposal_human_address,
    };

    // Save poll
    poll_storage(deps.storage).save(&state.poll_count.to_be_bytes(), &new_poll)?;

    // Save state
    store_config(deps.storage, &state)?;
    Ok(Response::new()
        .add_attribute("action", "create a proposal")
        .add_attribute("proposal_id", &poll_id.to_string())
        .add_attribute("proposal_creator", &info.sender.to_string())
        .add_attribute("proposal_creation_result", "success"))
}

fn execute_vote(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    poll_id: u64,
    approve: bool,
) -> StdResult<Response> {
    // Ensure the sender not sending funds accidentally
    if !info.funds.is_empty() {
        return Err(StdError::generic_err("Do not send funds with vote"));
    }

    let sender = deps.api.addr_canonicalize(&info.sender.to_string())?;
    let state = read_config(deps.storage)?;
    let mut poll_info = poll_storage_read(deps.storage).load(&poll_id.to_be_bytes())?;

    // Ensure the poll is still valid
    if env.block.height > poll_info.end_height {
        return Err(StdError::generic_err("Proposal expired"));
    }
    // Ensure the poll is still valid
    if poll_info.status != PollStatus::InProgress {
        return Err(StdError::generic_err("Proposal is deactivated"));
    }

    // if user voted fail, else store the vote
    poll_vote_storage(deps.storage, poll_id).update(&sender.as_slice(), |exists| match exists {
        None => Ok(approve),
        Some(_) => Err(StdError::generic_err("Already voted")),
    })?;

    // Get the sender weight
    let weight = user_total_weight(&deps.as_ref(), &state, &sender);

    // Only stakers can vote
    if weight.is_zero() {
        return Err(StdError::generic_err("Only stakers can vote"));
    }

    // save weight
    let voice = 1;
    if approve {
        poll_info.yes_vote += voice;
        poll_info.weight_yes_vote = poll_info.weight_yes_vote.add(weight);
    } else {
        poll_info.no_vote += voice;
        poll_info.weight_no_vote = poll_info.weight_no_vote.add(weight);
    }
    // overwrite poll info
    poll_storage(deps.storage).save(&poll_id.to_be_bytes(), &poll_info)?;

    Ok(Response::new()
        .add_attribute("action", "vote")
        .add_attribute("proposalId", &poll_id.to_string())
        .add_attribute("voting_result", "success"))
}

fn execute_reject_proposal(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    poll_id: u64,
) -> StdResult<Response> {
    let store = poll_storage_read(deps.storage).load(&poll_id.to_be_bytes())?;
    let sender = deps
        .api
        .addr_canonicalize(&info.sender.to_string())
        .unwrap();

    // Ensure the sender not sending funds accidentally
    if !info.funds.is_empty() {
        return Err(StdError::generic_err(
            "Do not send funds with reject proposal",
        ));
    }
    // Ensure end proposal height is not expired
    if store.end_height < env.block.height {
        return Err(StdError::generic_err("Proposal expired"));
    }
    // Ensure only the creator can reject a proposal OR the status of the proposal is still in progress
    if store.creator != sender || store.status != PollStatus::InProgress {
        return Err(StdError::generic_err("Unauthorized"));
    }

    poll_storage(deps.storage).update::<_, StdError>(&poll_id.to_be_bytes(), |poll| {
        let mut poll_data = poll.unwrap();
        // Update the status to rejected by the creator
        poll_data.status = PollStatus::RejectedByCreator;
        // Update the end eight to now
        poll_data.end_height = env.block.height;
        Ok(poll_data)
    })?;

    Ok(Response::new()
        .add_attribute("action", "creator reject the proposal")
        .add_attribute("proposal_id", &poll_id.to_string()))
}

fn execute_present_proposal(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    poll_id: u64,
) -> StdResult<Response> {
    // Load storage
    let mut state = read_config(deps.storage)?;
    let store = poll_storage_read(deps.storage)
        .load(&poll_id.to_be_bytes())
        .unwrap();

    // Ensure the sender not sending funds accidentally
    if !info.funds.is_empty() {
        return Err(StdError::generic_err(
            "Do not send funds with present proposal",
        ));
    }
    // Ensure the proposal is still in Progress
    if store.status != PollStatus::InProgress {
        return Err(StdError::generic_err("Unauthorized"));
    }

    let total_weight_bonded = total_weight(&deps.as_ref(), &state);
    let total_vote_weight = store.weight_yes_vote.add(store.weight_no_vote);
    let total_yes_weight_percentage = if !store.weight_yes_vote.is_zero() {
        store.weight_yes_vote.u128() * 100 / total_vote_weight.u128()
    } else {
        0
    };
    let total_no_weight_percentage = if !store.weight_no_vote.is_zero() {
        store.weight_no_vote.u128() * 100 / total_vote_weight.u128()
    } else {
        0
    };

    if store.weight_yes_vote.add(store.weight_no_vote).u128() * 100 / total_weight_bonded.u128()
        < 50
    {
        // Ensure the proposal is ended
        if store.end_height > env.block.height {
            return Err(StdError::generic_err("Proposal still in progress"));
        }
    }

    // Reject the proposal
    // Based on the recommendation of security audit
    // We recommend to not reject votes based on the number of votes, but rather by the stake of the voters.
    if total_yes_weight_percentage < 50 || total_no_weight_percentage > 33 {
        return reject_proposal(deps.storage, poll_id);
    }

    let mut msgs = vec![];
    // Valid the proposal
    match store.proposal {
        Proposal::LotteryEveryBlockTime => {
            state.every_block_time_play = store.amount.u128() as u64;
        }
        Proposal::DrandWorkerFeePercentage => {
            state.fee_for_drand_worker_in_percentage = store.amount.u128() as u8;
        }
        Proposal::JackpotRewardPercentage => {
            state.jackpot_percentage_reward = store.amount.u128() as u8;
        }
        Proposal::AmountToRegister => {
            state.price_per_ticket_to_register = store.amount;
        }
        Proposal::PrizePerRank => {
            state.prize_rank_winner_percentage = store.prize_rank;
        }
        Proposal::Bonus => {
            state.bonus = store.amount.u128() as u8;
        }
        Proposal::BonusBurnRate => {
            state.bonus_burn_rate = store.amount.u128() as u8;
        }
        Proposal::HolderFeePercentage => {
            state.token_holder_percentage_fee_reward = store.amount.u128() as u8
        }
        Proposal::SecurityMigration => {
            let contract_balance = deps
                .querier
                .query_balance(&env.contract.address, &state.denom_stable)?;

            let msg = BankMsg::Send {
                to_address: store.migration_address.unwrap().to_string(),
                amount: vec![deduct_tax(
                    &deps.as_ref(),
                    Coin {
                        denom: state.denom_stable.to_string(),
                        amount: contract_balance.amount,
                    },
                )?],
            };
            msgs.push(msg.into())
        }
        Proposal::DaoFunding => {
            let recipient = match store.migration_address {
                None => deps.api.addr_humanize(&store.creator)?,
                Some(address) => address,
            };

            // Get the contract balance prepare the tx
            let msg_balance = QueryMsg::Balance {
                address: env.contract.address,
            };
            let loterra_human = deps
                .api
                .addr_humanize(&state.loterra_cw20_contract_address)?;
            let res_balance = encode_msg_query(msg_balance, loterra_human)?;
            let loterra_balance = wrapper_msg_loterra(&deps.as_ref(), res_balance)?;

            if loterra_balance.balance.u128() < store.amount.u128() {
                return reject_proposal(deps.storage, poll_id);
            }

            let msg_transfer = QueryMsg::Transfer {
                recipient,
                amount: store.amount,
            };
            let loterra_human = deps
                .api
                .addr_humanize(&state.loterra_cw20_contract_address)?;
            let res_transfer = encode_msg_execute(msg_transfer, loterra_human, vec![])?;

            msgs.push(res_transfer)
        }
        Proposal::StakingContractMigration => {
            state.loterra_staking_contract_address = deps
                .api
                .addr_canonicalize(&store.migration_address.unwrap().to_string())?;
        }
        Proposal::PollSurvey => {}
        _ => {
            return Err(StdError::generic_err("Proposal not funds"));
        }
    }

    // Save to storage
    poll_storage(deps.storage).update::<_, StdError>(&poll_id.to_be_bytes(), |poll| {
        let mut poll_data = poll.unwrap();
        // Update the status to passed
        poll_data.status = PollStatus::Passed;
        Ok(poll_data)
    })?;

    store_config(deps.storage, &state)?;
    Ok(Response::new()
        .add_messages(msgs)
        .add_attribute("action", "present the proposal")
        .add_attribute("proposal_id", &poll_id.to_string())
        .add_attribute("proposal_result", "approved"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    let response = match msg {
        QueryMsg::Config {} => to_binary(&query_config(deps)?)?,
        QueryMsg::Combination {
            lottery_id,
            address,
        } => to_binary(&query_all_combination(deps, lottery_id, address)?)?,
        QueryMsg::Winner { lottery_id } => to_binary(&query_all_winner(deps, lottery_id)?)?,
        QueryMsg::GetPoll { poll_id } => to_binary(&query_poll(deps, poll_id)?)?,
        QueryMsg::GetRound {} => to_binary(&query_round(deps)?)?,
        QueryMsg::CountPlayer { lottery_id } => to_binary(&query_count_player(deps, lottery_id)?)?,
        QueryMsg::CountTicket { lottery_id } => to_binary(&query_count_ticket(deps, lottery_id)?)?,
        QueryMsg::WinningCombination { lottery_id } => {
            to_binary(&query_winning_combination(deps, lottery_id)?)?
        }
        QueryMsg::CountWinner { lottery_id, rank } => {
            to_binary(&query_winner_rank(deps, lottery_id, rank)?)?
        }
        QueryMsg::Jackpot { lottery_id } => to_binary(&query_jackpot(deps, lottery_id)?)?,
        QueryMsg::JackpotAlte { lottery_id } => to_binary(&query_jackpot_alte(deps, lottery_id)?)?,
        QueryMsg::Players { lottery_id } => {
            to_binary(&query_all_players_by_lottery(deps, lottery_id)?)?
        }
        QueryMsg::AllPlayers { start_after, limit } => {
            to_binary(&query_all_players(deps, start_after, limit)?)?
        }
        _ => to_binary(&())?,
    };
    Ok(response)
}

fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let state = read_config(deps.storage)?;
    Ok(state)
}
fn query_winner_rank(deps: Deps, lottery_id: u64, rank: u8) -> StdResult<Uint128> {
    let amount =
        match winner_count_by_rank_read(deps.storage, lottery_id).may_load(&rank.to_be_bytes())? {
            None => Uint128::zero(),
            Some(winners) => winners,
        };
    Ok(amount)
}

// settings for pagination
const MAX_LIMIT: u32 = 30;
const DEFAULT_LIMIT: u32 = 10;
fn query_all_players(
    deps: Deps,
    start_after: Option<Addr>,
    limit: Option<u32>,
) -> StdResult<Vec<Addr>> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start = calc_range_start(start_after);

    let all_players: StdResult<Vec<_>> = address_players_read(deps.storage)
        .range(start.as_deref(), None, Order::Ascending)
        .take(limit)
        .map(|elem| {
            let (k, _) = elem?;
            let address: Addr = deps.api.addr_humanize(&CanonicalAddr::from(k))?;
            Ok(address)
        })
        .collect();

    Ok(all_players.unwrap())
}
fn query_all_players_by_lottery(deps: Deps, lottery_id: u64) -> StdResult<Vec<Addr>> {
    let players =
        match all_players_storage_read(deps.storage).may_load(&lottery_id.to_be_bytes())? {
            None => {
                return Err(StdError::NotFound {
                    kind: "not found".to_string(),
                })
            }
            Some(players) => players
                .iter()
                .map(|e| deps.api.addr_humanize(&e).unwrap())
                .collect(),
        };
    Ok(players)
}

fn query_jackpot(deps: Deps, lottery_id: u64) -> StdResult<Uint128> {
    let jackpot = match jackpot_storage_read(deps.storage).may_load(&lottery_id.to_be_bytes())? {
        None => Uint128::zero(),
        Some(jackpot) => jackpot,
    };
    Ok(jackpot)
}

fn query_jackpot_alte(deps: Deps, lottery_id: u64) -> StdResult<Uint128> {
    let jackpot =
        match jackpot_storage_read_alte(deps.storage).may_load(&lottery_id.to_be_bytes())? {
            None => Uint128::zero(),
            Some(jackpot) => jackpot,
        };
    Ok(jackpot)
}

fn query_count_ticket(deps: Deps, lottery_id: u64) -> StdResult<Uint128> {
    let amount = match count_total_ticket_by_lottery_read(deps.storage)
        .may_load(&lottery_id.to_be_bytes())?
    {
        None => Uint128::zero(),
        Some(ticket) => ticket,
    };
    Ok(amount)
}
fn query_count_player(deps: Deps, lottery_id: u64) -> StdResult<Uint128> {
    let amount =
        match count_player_by_lottery_read(deps.storage).may_load(&lottery_id.to_be_bytes())? {
            None => Uint128::zero(),
            Some(players) => players,
        };
    Ok(amount)
}
fn query_winning_combination(deps: Deps, lottery_id: u64) -> StdResult<String> {
    let combination = match lottery_winning_combination_storage_read(deps.storage)
        .may_load(&lottery_id.to_be_bytes())?
    {
        None => {
            return Err(StdError::NotFound {
                kind: "not found".to_string(),
            })
        }
        Some(combo) => combo,
    };
    Ok(combination)
}
fn query_all_combination(
    deps: Deps,
    lottery_id: u64,
    address: Addr,
) -> StdResult<AllCombinationResponse> {
    let addr = deps.api.addr_canonicalize(&address.to_string())?;
    let combo =
        match user_combination_bucket_read(deps.storage, lottery_id).may_load(addr.as_slice())? {
            None => {
                return Err(StdError::NotFound {
                    kind: "not found".to_string(),
                })
            }
            Some(combination) => combination,
        };

    Ok(AllCombinationResponse { combination: combo })
}

fn query_all_winner(deps: Deps, lottery_id: u64) -> StdResult<AllWinnersResponse> {
    let winners = all_winners(deps.storage, lottery_id)?;
    let res: StdResult<Vec<WinnerResponse>> = winners
        .into_iter()
        .map(|(can_addr, claims)| {
            Ok(WinnerResponse {
                address: deps.api.addr_humanize(&can_addr)?,
                claims,
            })
        })
        .collect();

    Ok(AllWinnersResponse { winners: res? })
}

fn query_poll(deps: Deps, poll_id: u64) -> StdResult<GetPollResponse> {
    let store = poll_storage_read(deps.storage);

    let poll = match store.may_load(&poll_id.to_be_bytes())? {
        Some(poll) => Some(poll),
        None => {
            return Err(StdError::NotFound {
                kind: "not found".to_string(),
            })
        }
    }
    .unwrap();

    Ok(GetPollResponse {
        creator: deps.api.addr_humanize(&poll.creator).unwrap(),
        status: poll.status,
        end_height: poll.end_height,
        start_height: poll.start_height,
        description: poll.description,
        amount: poll.amount,
        prize_per_rank: poll.prize_rank,
        migration_address: poll.migration_address,
        weight_yes_vote: poll.weight_yes_vote,
        weight_no_vote: poll.weight_no_vote,
        yes_vote: poll.yes_vote,
        no_vote: poll.no_vote,
        proposal: poll.proposal,
    })
}

fn query_round(deps: Deps) -> StdResult<RoundResponse> {
    let state = read_config(deps.storage)?;
    let from_genesis = state.block_time_play - DRAND_GENESIS_TIME;
    let next_round = (from_genesis / DRAND_PERIOD) + DRAND_NEXT_ROUND_SECURITY;

    Ok(RoundResponse { next_round })
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> StdResult<Response> {
    Ok(Response::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_querier::mock_dependencies_custom;
    use crate::msg::{ExecuteMsg, InitMsg};
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::StdError::GenericErr;
    use cosmwasm_std::{Addr, Api, CosmosMsg, SubMsg, Timestamp, Uint128, WasmMsg};

    struct BeforeAll {
        default_sender: Addr,
        default_sender_two: Addr,
        default_sender_owner: Addr,
    }
    fn before_all() -> BeforeAll {
        BeforeAll {
            default_sender: Addr::unchecked("terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5s20q007"),
            default_sender_two: Addr::unchecked("terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5s20q008"),
            default_sender_owner: Addr::unchecked("terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5s20qu3k"),
        }
    }

    fn default_init(deps: DepsMut) {
        const DENOM_STABLE: &str = "ust";
        const BLOCK_TIME_PLAY: u64 = 1610566920;
        const EVERY_BLOCK_TIME_PLAY: u64 = 50000;
        // const PUBLIC_SALE_END_BLOCK_TIME: u64 = 1610566920;
        const POLL_DEFAULT_END_HEIGHT: u64 = 40_000;
        const BONUS_BLOCK_TIME_END: u64 = 1610567920;

        let init_msg = InitMsg {
            denom_stable: DENOM_STABLE.to_string(),
            block_time_play: BLOCK_TIME_PLAY,
            every_block_time_play: EVERY_BLOCK_TIME_PLAY,
            poll_default_end_height: POLL_DEFAULT_END_HEIGHT,
            terrand_contract_address: Addr::unchecked(
                "terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5terrand",
            ),
            loterra_cw20_contract_address: Addr::unchecked(
                "terra1q88h7ewu6h3am4mxxeqhu3srt7zloterracw20",
            ),
            loterra_staking_contract_address: Addr::unchecked(
                "terra1q88h7ewu6h3am4mxxeqhu3srloterrastaking",
            ),
            altered_contract_address: Addr::unchecked("altered"),
            holders_bonus_block_time_end: BONUS_BLOCK_TIME_END,
        };

        let info = mock_info("terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5s20qu3k", &[]);
        instantiate(deps, mock_env(), info.clone(), init_msg).unwrap();
    }

    #[test]
    fn proper_init() {
        let mut deps = mock_dependencies(&[]);
        default_init(deps.as_mut());
    }
    #[test]
    fn get_round_play() {
        let mut deps = mock_dependencies(&[]);
        default_init(deps.as_mut());
        let res = query_round(deps.as_ref()).unwrap();
        println!("{:?}", res.next_round);
    }

    #[test]
    fn testing_saved_address_winner() {
        let mut deps = mock_dependencies(&[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128::from(100_000_000u128),
        }]);
        default_init(deps.as_mut());

        let winner_address = deps.api.addr_canonicalize("address").unwrap();
        let winner_address2 = deps.api.addr_canonicalize("address2").unwrap();
        save_winner(deps.as_mut().storage, 1u64, winner_address, 2).unwrap();
        save_winner(deps.as_mut().storage, 1u64, winner_address2, 2).unwrap();

        let res = query_all_winner(deps.as_ref(), 1u64).unwrap();
        println!("{:?}", res);
    }
    mod claim {
        // handle_claim
        use super::*;
        #[test]
        fn claim_is_closed() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let msg = ExecuteMsg::Claim { addresses: None };

            let state = read_config(&deps.storage).unwrap();
            let mut env = mock_env();
            env.block.time = Timestamp::from_seconds(state.block_time_play);
            let info = mock_info(&before_all.default_sender.to_string(), &[]);

            let res = execute(deps.as_mut(), env, info, msg.clone());
            match res {
                Err(GenericErr { msg, .. }) => assert_eq!(msg, "Claiming is closed"),
                _ => panic!("Unexpected error"),
            }
        }

        #[test]
        fn no_winning_combination() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let msg = ExecuteMsg::Claim { addresses: None };
            let res = execute(deps.as_mut(), env, info, msg.clone());
            match res {
                Err(StdError::NotFound { kind }) => assert_eq!(kind, "No winning combination"),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn no_combination() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let mut state = read_config(&deps.storage).unwrap();
            state.lottery_counter = 2;
            store_config(deps.as_mut().storage, &state).unwrap();
            let last_lottery_counter_round = state.lottery_counter - 1;
            // Save winning combination
            lottery_winning_combination_storage(deps.as_mut().storage)
                .save(
                    &last_lottery_counter_round.to_be_bytes(),
                    &"123456".to_string(),
                )
                .unwrap();
            let msg = ExecuteMsg::Claim { addresses: None };
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(&before_all.default_sender.to_string(), &[]),
                msg.clone(),
            );
            match res {
                Err(StdError::NotFound { kind }) => assert_eq!(kind, "No combination found"),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn success() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let addr = deps
                .api
                .addr_canonicalize(&before_all.default_sender.to_string())
                .unwrap();
            let mut state = read_config(&deps.storage).unwrap();
            // Save combination by senders
            combination_save(
                deps.as_mut().storage,
                state.lottery_counter,
                addr.clone(),
                vec![
                    "123456".to_string(),
                    "12345f".to_string(),
                    "1234a6".to_string(),
                    "000000".to_string(),
                    "023456".to_string(),
                    "100000".to_string(),
                    "120000".to_string(),
                    "123000".to_string(),
                ],
            )
            .unwrap();

            // Save winning combination
            lottery_winning_combination_storage(deps.as_mut().storage)
                .save(&state.lottery_counter.to_be_bytes(), &"123456".to_string())
                .unwrap();
            state.lottery_counter = 2;
            store_config(deps.as_mut().storage, &state).unwrap();

            let msg = ExecuteMsg::Claim { addresses: None };
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(&before_all.default_sender.to_string(), &[]),
                msg.clone(),
            )
            .unwrap();
            println!("{:?}", res);
            assert_eq!(res, Response::new().add_attribute("action", "claim"));
            // Claim again is not possible
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(&before_all.default_sender.to_string(), &[]),
                msg.clone(),
            );
            match res {
                Err(StdError::NotFound { kind }) => {
                    assert_eq!(kind, "No winning combination or already claimed")
                }
                _ => panic!("Unexpected error"),
            }

            let last_lottery_counter_round = state.lottery_counter - 1;
            let winners = winner_storage_read(&deps.storage, last_lottery_counter_round)
                .load(&addr.as_slice())
                .unwrap();
            println!("{:?}", winners);
            assert!(!winners.claimed);
            assert_eq!(winners.ranks.len(), 6);
            assert_eq!(winners.ranks[0], 1);
            assert_eq!(winners.ranks[1], 2);
            assert_eq!(winners.ranks[2], 3);
            assert_eq!(winners.ranks[3], 6);
            assert_eq!(winners.ranks[4], 5);
            assert_eq!(winners.ranks[5], 4);
        }
    }

    mod register_alte {
        use super::*;

        #[test]
        fn register_alte() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());

            // Register error not valid combination
            let exec_msg = ReceiveMsg::RegisterAlte {
                gift_address: None,
                combination: vec![
                    "1e3fab".to_string(),
                    "abcdek".to_string(),
                    "123456".to_string(),
                ],
            };
            let msg = Cw20ReceiveMsg {
                sender: before_all.default_sender.to_string(),
                amount: Uint128::from(3_000_000_u128),
                msg: to_binary(&exec_msg).unwrap(),
            };
            let receive_msg = ExecuteMsg::Receive(msg);

            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(&"altered".to_string(), &[]),
                receive_msg.clone(),
            )
            .unwrap_err();
            assert_eq!(
                res,
                StdError::generic_err(
                    "Not authorized use combination of [a-f] and [0-9] with length 6"
                )
            );

            // Register error not enough money
            let exec_msg = ReceiveMsg::RegisterAlte {
                gift_address: None,
                combination: vec![
                    "1e3fab".to_string(),
                    "abcdef".to_string(),
                    "123456".to_string(),
                ],
            };
            let msg = Cw20ReceiveMsg {
                sender: before_all.default_sender.to_string(),
                amount: Uint128::from(1_000_000_u128),
                msg: to_binary(&exec_msg).unwrap(),
            };
            let receive_msg = ExecuteMsg::Receive(msg);

            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(&"altered".to_string(), &[]),
                receive_msg.clone(),
            )
            .unwrap_err();
            assert_eq!(res, StdError::generic_err("send 3000000ALTE"));

            // Register success without bonus with a gift
            let exec_msg = ReceiveMsg::RegisterAlte {
                gift_address: Some(before_all.default_sender_two.to_string()),
                combination: vec![
                    "1e3fab".to_string(),
                    "abcdef".to_string(),
                    "123456".to_string(),
                ],
            };
            let msg = Cw20ReceiveMsg {
                sender: before_all.default_sender.to_string(),
                amount: Uint128::from(3_000_000_u128),
                msg: to_binary(&exec_msg).unwrap(),
            };
            let receive_msg = ExecuteMsg::Receive(msg);

            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(&"altered".to_string(), &[]),
                receive_msg.clone(),
            )
            .unwrap();
            assert_eq!(
                res,
                Response::new()
                    .add_attribute("action", "register")
                    .add_attribute("pay-in", "ALTE")
            );
            // Check combination added with success
            let addr = deps
                .api
                .addr_canonicalize(&before_all.default_sender_two.to_string())
                .unwrap();
            let store_two = user_combination_bucket_read(deps.as_mut().storage, 1u64)
                .load(&addr.as_slice())
                .unwrap();
            assert_eq!(3, store_two.len());
            let msg_query = QueryMsg::Players { lottery_id: 1 };
            let res = query(deps.as_ref(), mock_env(), msg_query).unwrap();
            let formated_binary = String::from_utf8(res.into()).unwrap();
            println!("sdsds {:?}", formated_binary);

            // Register success without bonus
            let exec_msg = ReceiveMsg::RegisterAlte {
                gift_address: None,
                combination: vec![
                    "1e3fab".to_string(),
                    "abcdef".to_string(),
                    "123456".to_string(),
                ],
            };
            let msg = Cw20ReceiveMsg {
                sender: before_all.default_sender.to_string(),
                amount: Uint128::from(3_000_000_u128),
                msg: to_binary(&exec_msg).unwrap(),
            };
            let receive_msg = ExecuteMsg::Receive(msg);

            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(&"altered".to_string(), &[]),
                receive_msg.clone(),
            )
            .unwrap();
            assert_eq!(
                res,
                Response::new()
                    .add_attribute("action", "register")
                    .add_attribute("pay-in", "ALTE")
            );
            // Check combination added with success
            let addr = deps
                .api
                .addr_canonicalize(&before_all.default_sender.to_string())
                .unwrap();
            let store_two = user_combination_bucket_read(deps.as_mut().storage, 1u64)
                .load(&addr.as_slice())
                .unwrap();
            assert_eq!(3, store_two.len());
            let msg_query = QueryMsg::Players { lottery_id: 1 };
            let res = query(deps.as_ref(), mock_env(), msg_query).unwrap();
            let formated_binary = String::from_utf8(res.into()).unwrap();
            println!("sdsds {:?}", formated_binary);

            // Register success with bonus active 50% bonus
            let exec_msg = ReceiveMsg::RegisterAlte {
                gift_address: None,
                combination: vec![
                    "1e3fab".to_string(),
                    "abcdef".to_string(),
                    "123456".to_string(),
                ],
            };
            let msg = Cw20ReceiveMsg {
                sender: before_all.default_sender.to_string(),
                amount: Uint128::from(3_000_000_u128),
                msg: to_binary(&exec_msg).unwrap(),
            };
            let receive_msg = ExecuteMsg::Receive(msg);
            let mut state = read_config(deps.as_ref().storage).unwrap();
            state.bonus = 50;
            store_config(deps.as_mut().storage, &state).unwrap();

            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(&"altered".to_string(), &[]),
                receive_msg.clone(),
            )
            .unwrap_err();
            assert_eq!(res, StdError::generic_err("send 1500000ALTE"));

            let msg = Cw20ReceiveMsg {
                sender: before_all.default_sender.to_string(),
                amount: Uint128::from(1_500_000_u128),
                msg: to_binary(&exec_msg).unwrap(),
            };
            let receive_msg = ExecuteMsg::Receive(msg);
            let mut state = read_config(deps.as_ref().storage).unwrap();
            state.bonus = 50;
            store_config(deps.as_mut().storage, &state).unwrap();

            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(&"altered".to_string(), &[]),
                receive_msg.clone(),
            )
            .unwrap();
            assert_eq!(
                res,
                Response::new()
                    .add_attribute("action", "register")
                    .add_attribute("pay-in", "ALTE")
            );
        }
    }
    mod register {
        // handle_register
        use super::*;
        #[test]
        fn security_active() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            //let r = CanonicalAddr(&"DZuks7zPRv9wp2lJTEKdihcInQc=");
            let f = deps
                .api
                .addr_canonicalize(
                    &Addr::unchecked("terra1umd70qd4jv686wjrsnk92uxgewca3805dxd46p").to_string(),
                )
                .unwrap();
            println!("{}", f);
            let mut state = read_config(&deps.storage).unwrap();
            state.safe_lock = true;
            store_config(deps.as_mut().storage, &state).unwrap();
            let msg = ExecuteMsg::Register {
                address: None,
                altered_bonus: None,
                combination: vec!["1e3fab".to_string()],
            };
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    &before_all.default_sender.to_string(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(1_000_000u128),
                    }],
                ),
                msg.clone(),
            );
            match res {
                Err(GenericErr { msg }) => assert_eq!(
                    msg,
                    "Contract deactivated for update or/and preventing security issue"
                ),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn register_success() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let msg = ExecuteMsg::Register {
                address: None,
                altered_bonus: None,
                combination: vec![
                    "1e3fab".to_string(),
                    "abcdef".to_string(),
                    "123456".to_string(),
                ],
            };
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    &before_all.default_sender.to_string(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(3_000_000u128),
                    }],
                ),
                msg.clone(),
            )
            .unwrap();
            assert_eq!(
                res,
                Response::new()
                    .add_attribute("action", "register")
                    .add_attribute("pay-in", "UST")
            );
            // Check combination added with success
            let addr = deps
                .api
                .addr_canonicalize(&before_all.default_sender.to_string())
                .unwrap();
            let store_two = user_combination_bucket_read(deps.as_mut().storage, 1u64)
                .load(&addr.as_slice())
                .unwrap();
            assert_eq!(3, store_two.len());
            let msg_query = QueryMsg::Players { lottery_id: 1 };
            let res = query(deps.as_ref(), mock_env(), msg_query).unwrap();
            let formated_binary = String::from_utf8(res.into()).unwrap();
            println!("sdsds {:?}", formated_binary);

            /*let store_three = all_players_storage_read(deps.storage, 1u64)
                .load(&1u64.to_be_bytes())
                .unwrap();
            assert_eq!(store_three.len(), 1);
            assert_eq!(store_three[0], addr);
            */

            // Play 2 more combination
            let msg = ExecuteMsg::Register {
                address: None,
                altered_bonus: None,
                combination: vec!["affe3b".to_string(), "098765".to_string()],
            };
            let _res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    &before_all.default_sender.to_string(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(2_000_000u128),
                    }],
                ),
                msg.clone(),
            )
            .unwrap();
            // Check combination added with success
            let addr = deps
                .api
                .addr_canonicalize(&before_all.default_sender.to_string())
                .unwrap();
            let store_two = user_combination_bucket_read(deps.as_mut().storage, 1u64)
                .load(addr.as_slice())
                .unwrap();
            assert_eq!(5, store_two.len());
            assert_eq!(store_two[3], "affe3b".to_string());
            assert_eq!(store_two[4], "098765".to_string());

            // Someone registering combination for other player
            let msg = ExecuteMsg::Register {
                address: Some(before_all.default_sender_two.clone()),
                altered_bonus: None,
                combination: vec!["aaaaaa".to_string(), "bbbbbb".to_string()],
            };
            // default_sender_two sending combination for default_sender
            let _res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    &before_all.default_sender.to_string(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(2_000_000u128),
                    }],
                ),
                msg.clone(),
            )
            .unwrap();

            // Check combination added with success
            let addr = deps
                .api
                .addr_canonicalize(&before_all.default_sender_two.to_string())
                .unwrap();
            let store_two = user_combination_bucket_read(deps.as_mut().storage, 1u64)
                .load(addr.as_slice())
                .unwrap();
            assert_eq!(2, store_two.len());
            assert_eq!(store_two[0], "aaaaaa".to_string());
            assert_eq!(store_two[1], "bbbbbb".to_string());

            let msg = QueryMsg::CountPlayer { lottery_id: 1 };
            let res = query(deps.as_ref(), mock_env(), msg).unwrap();
            let r = String::from_utf8(res.into()).unwrap();

            assert_eq!("\"2\"", r);
        }
        #[test]
        fn register_fail_if_sender_sent_empty_funds() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let msg = ExecuteMsg::Register {
                address: None,
                altered_bonus: None,
                combination: vec!["1e3fab".to_string()],
            };
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    &before_all.default_sender.to_string(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(0u128),
                    }],
                ),
                msg.clone(),
            );
            match res {
                Err(GenericErr { msg }) => assert_eq!(
                    msg,
                    "you need to send 1000000ust per combination in order to register"
                ),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn register_fail_if_sender_sent_multiple_denom() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let msg = ExecuteMsg::Register {
                address: None,
                altered_bonus: None,
                combination: vec!["1e3fab".to_string()],
            };
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    &before_all.default_sender.to_string(),
                    &[
                        Coin {
                            denom: "ust".to_string(),
                            amount: Uint128::from(1_000_000u128),
                        },
                        Coin {
                            denom: "wrong".to_string(),
                            amount: Uint128::from(10u128),
                        },
                    ],
                ),
                msg.clone(),
            );

            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Only send ust to register"),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn register_fail_if_sender_sent_wrong_denom() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let msg = ExecuteMsg::Register {
                address: None,
                altered_bonus: None,
                combination: vec!["1e3fab".to_string()],
            };
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    &before_all.default_sender.to_string(),
                    &[Coin {
                        denom: "wrong".to_string(),
                        amount: Uint128::from(1_000_000u128),
                    }],
                ),
                msg.clone(),
            );

            match res {
                Err(GenericErr { msg }) => assert_eq!(
                    msg,
                    "To register you need to send 1000000ust per combination"
                ),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn register_fail_wrong_combination() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let msg = ExecuteMsg::Register {
                address: None,
                altered_bonus: None,
                combination: vec!["1e3far".to_string()],
            };
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    &before_all.default_sender.to_string(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(1_000_000u128),
                    }],
                ),
                msg.clone(),
            );
            match res {
                Err(GenericErr { msg }) => assert_eq!(
                    msg,
                    "Not authorized use combination of [a-f] and [0-9] with length 6"
                ),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn register_fail_multiple_wrong_combination() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let msg = ExecuteMsg::Register {
                address: None,
                altered_bonus: None,
                combination: vec!["1e3far".to_string(), "1e3fac".to_string()],
            };
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    &before_all.default_sender.to_string(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(1_000_000u128),
                    }],
                ),
                msg.clone(),
            );
            match res {
                Err(GenericErr { msg }) => assert_eq!(
                    msg,
                    "Not authorized use combination of [a-f] and [0-9] with length 6"
                ),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn register_fail_sent_too_much_or_less() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let msg = ExecuteMsg::Register {
                address: None,
                altered_bonus: None,
                combination: vec!["1e3fae".to_string(), "1e3fa2".to_string()],
            };
            // Fail sending less than required (1_000_000)
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    &before_all.default_sender.to_string(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(1_000_000u128),
                    }],
                ),
                msg.clone(),
            );
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "send 2000000ust"),
                _ => panic!("Unexpected error"),
            }
            // Fail sending more than required (2_000_000)
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    &before_all.default_sender.to_string(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(3_000_000u128),
                    }],
                ),
                msg.clone(),
            );
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "send 2000000ust"),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn register_fail_lottery_about_to_start() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let msg = ExecuteMsg::Register {
                address: None,
                altered_bonus: None,
                combination: vec!["1e3fae".to_string()],
            };
            let state = read_config(&deps.storage).unwrap();
            let mut env = mock_env();
            let info = mock_info(
                &before_all.default_sender.to_string(),
                &[Coin {
                    denom: "ust".to_string(),
                    amount: Uint128::from(1_000_000u128),
                }],
            );
            // Block time is superior to block_time_play so the lottery is about to start
            env.block.time = Timestamp::from_seconds(state.block_time_play + 1000);
            let res = execute(deps.as_mut(), env, info.clone(), msg.clone());
            match res {
                Err(GenericErr { msg }) => assert_eq!(
                    msg,
                    "Lottery is about to start wait until the end before register"
                ),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn register_bonus_combination() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let msg = ExecuteMsg::Register {
                address: None,
                altered_bonus: Some(true),
                // 30 tickets
                combination: vec![
                    "1e3fa1".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                    "1e3fac".to_string(),
                ],
            };
            let burn = Cw20ExecuteMsg::BurnFrom {
                owner: before_all.default_sender.to_string(),
                amount: Uint128::from(3000000u128),
            };
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    &before_all.default_sender.to_string(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(27_000_000u128),
                    }],
                ),
                msg.clone(),
            )
            .unwrap();
            assert_eq!(
                res.messages[0],
                SubMsg::new(CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr: "altered".to_string(),
                    msg: to_binary(&burn).unwrap(),
                    funds: vec![]
                }))
            );

            // Check combination added with success
            let addr = deps
                .api
                .addr_canonicalize(&before_all.default_sender.to_string())
                .unwrap();
            let store = user_combination_bucket_read(deps.as_mut().storage, 1u64)
                .load(addr.as_slice())
                .unwrap();
            assert_eq!(30, store.len());
            assert_eq!(store[3], "1e3fac".to_string());
            assert_eq!(store[4], "1e3fac".to_string());
            println!("{:?}", res);
            // Check the player address is added to the vector of all players
            let all_players = address_players_read(&deps.storage)
                .load(addr.as_slice())
                .unwrap();
            assert!(all_players);
        }
    }
    mod play {
        use super::*;
        use crate::state::lottery_winning_combination_storage_read;

        #[test]
        fn security_active() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let mut state = read_config(&deps.storage).unwrap();
            state.safe_lock = true;
            store_config(deps.as_mut().storage, &state).unwrap();
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let res = execute_play(deps.as_mut(), env, info.clone());
            match res {
                Err(GenericErr { msg }) => assert_eq!(
                    msg,
                    "Contract deactivated for update or/and preventing security issue"
                ),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn not_allowed_registration_in_progress() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let res = execute_play(deps.as_mut(), env.clone(), info.clone());
            match res {
                Err(GenericErr { msg }) => {
                    assert_eq!(msg, "Lottery registration is still in progress... Retry after block time 1610566920")
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn do_not_send_funds() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let state = read_config(&deps.storage).unwrap();
            let mut env = mock_env();
            let info = mock_info(
                &before_all.default_sender.to_string(),
                &[Coin {
                    denom: "ust".to_string(),
                    amount: Uint128::from(9u128),
                }],
            );
            env.block.time = Timestamp::from_seconds(state.block_time_play + 1000);
            let res = execute_play(deps.as_mut(), env.clone(), info.clone());
            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Do not send funds with play"),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn multi_contract_call_terrand() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);

            default_init(deps.as_mut());
            let state = read_config(&deps.storage).unwrap();
            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender_owner.to_string(), &[]);
            env.block.time = Timestamp::from_seconds(state.block_time_play + 1000);
            let res = execute_play(deps.as_mut(), env.clone(), info.clone()).unwrap();
            assert_eq!(res.messages.len(), 1);
        }

        #[test]
        fn success() {
            let before_all = before_all();
            let contract_balance = Uint128::from(9_000_000u128);
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: contract_balance.clone(),
            }]);

            default_init(deps.as_mut());
            // register some combination
            let msg = ExecuteMsg::Register {
                address: None,
                altered_bonus: None,
                combination: vec!["1e3fab".to_string()],
            };
            execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    &before_all.default_sender.to_string(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(1_000_000u128),
                    }],
                ),
                msg.clone(),
            )
            .unwrap();

            let msg = ExecuteMsg::Register {
                address: None,
                altered_bonus: None,
                combination: vec!["39493d".to_string()],
            };
            execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    &before_all.default_sender_two.to_string(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(1_000_000u128),
                    }],
                ),
                msg.clone(),
            )
            .unwrap();

            let state = read_config(&deps.storage).unwrap();
            jackpot_storage(deps.as_mut().storage)
                .save(&(state.lottery_counter - 1).to_be_bytes(), &Uint128::zero())
                .unwrap();
            jackpot_storage_alte(deps.as_mut().storage)
                .save(&(state.lottery_counter - 1).to_be_bytes(), &Uint128::zero())
                .unwrap();
            let jackpot_reward_before = jackpot_storage_read(&deps.storage)
                .load(&(state.lottery_counter - 1).to_be_bytes())
                .unwrap();
            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender_owner.to_string(), &[]);
            env.block.time = Timestamp::from_seconds(state.block_time_play + 1000);
            let res = execute_play(deps.as_mut(), env.clone(), info.clone()).unwrap();
            println!("{:?}", res);
            assert_eq!(res.messages.len(), 1);
            assert_eq!(
                res.messages[0],
                SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
                    to_address: "terra1q88h7ewu6h3am4mxxeqhu3srxterrandworker".to_string(),
                    amount: vec![Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(179u128)
                    }]
                }))
            );

            let store = lottery_winning_combination_storage_read(&deps.storage)
                .load(&state.lottery_counter.to_be_bytes())
                .unwrap();
            assert_eq!(store, "39493d");
            let state_after = read_config(&deps.storage).unwrap();
            let jackpot_reward_after = jackpot_storage_read(&deps.storage)
                .load(&state.lottery_counter.to_be_bytes())
                .unwrap();

            // TODO add winner checks

            println!("{:?}", jackpot_reward_after);
            assert_eq!(50, state_after.token_holder_percentage_fee_reward);
            assert_eq!(jackpot_reward_before, Uint128::zero());
            assert_ne!(jackpot_reward_after, jackpot_reward_before);
            // 720720 total fees
            assert_eq!(jackpot_reward_after, Uint128::from(1_799_820u128));
            assert_eq!(state_after.lottery_counter, 2);
            assert_ne!(state_after.lottery_counter, state.lottery_counter);
        }

        #[test]
        fn success_no_big_winner() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);

            default_init(deps.as_mut());
            // register some combination
            let msg = ExecuteMsg::Register {
                address: None,
                altered_bonus: None,
                combination: vec!["39498d".to_string()],
            };
            execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    &before_all.default_sender_two.to_string(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(1_000_000u128),
                    }],
                ),
                msg.clone(),
            )
            .unwrap();

            let state = read_config(&deps.storage).unwrap();
            jackpot_storage(deps.as_mut().storage)
                .save(&(state.lottery_counter - 1).to_be_bytes(), &Uint128::zero())
                .unwrap();
            jackpot_storage_alte(deps.as_mut().storage)
                .save(&(state.lottery_counter - 1).to_be_bytes(), &Uint128::zero())
                .unwrap();
            let jackpot_reward_before = jackpot_storage_read(&deps.storage)
                .load(&(state.lottery_counter - 1).to_be_bytes())
                .unwrap();
            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender_owner.to_string(), &[]);
            env.block.time = Timestamp::from_seconds(state.block_time_play + 1000);
            let res = execute_play(deps.as_mut(), env.clone(), info.clone()).unwrap();
            println!("{:?}", res);
            assert_eq!(res.messages.len(), 1);
            assert_eq!(
                res.messages[0],
                SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
                    to_address: "terra1q88h7ewu6h3am4mxxeqhu3srxterrandworker".to_string(),
                    amount: vec![Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(179u128)
                    }]
                }))
            );

            // TODO add winner check
            let state_after = read_config(&deps.storage).unwrap();
            let jackpot_reward_after = jackpot_storage_read(&deps.storage)
                .load(&state.lottery_counter.to_be_bytes())
                .unwrap();

            println!("{:?}", jackpot_reward_after);
            assert_eq!(50, state_after.token_holder_percentage_fee_reward);
            assert_eq!(jackpot_reward_before, Uint128::zero());
            assert_ne!(jackpot_reward_after, jackpot_reward_before);
            // 720720 total fees
            assert_eq!(jackpot_reward_after, Uint128::from(1_799_820u128));
            assert_eq!(state_after.lottery_counter, 2);
            assert_ne!(state_after.lottery_counter, state.lottery_counter);
        }
        #[test]
        fn success_bonus_holder_end_fee_superior_20_percent() {
            let before_all = before_all();
            let contract_balance = Uint128::from(9_000_000u128);
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: contract_balance.clone(),
            }]);

            default_init(deps.as_mut());
            // register some combination
            let msg = ExecuteMsg::Register {
                address: None,
                altered_bonus: None,
                combination: vec!["1e3fab".to_string()],
            };
            execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    &before_all.default_sender.to_string(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(1_000_000u128),
                    }],
                ),
                msg.clone(),
            )
            .unwrap();

            let msg = ExecuteMsg::Register {
                address: None,
                altered_bonus: None,
                combination: vec!["39493d".to_string()],
            };
            execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    &before_all.default_sender_two.to_string(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(1_000_000u128),
                    }],
                ),
                msg.clone(),
            )
            .unwrap();

            let state = read_config(&deps.storage).unwrap();
            assert_eq!(50, state.token_holder_percentage_fee_reward);
            jackpot_storage(deps.as_mut().storage)
                .save(&(state.lottery_counter - 1).to_be_bytes(), &Uint128::zero())
                .unwrap();
            jackpot_storage_alte(deps.as_mut().storage)
                .save(&(state.lottery_counter - 1).to_be_bytes(), &Uint128::zero())
                .unwrap();
            let jackpot_reward_before = jackpot_storage_read(&deps.storage)
                .load(&(state.lottery_counter - 1).to_be_bytes())
                .unwrap();

            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender_owner.to_string(), &[]);
            env.block.time = Timestamp::from_seconds(state.block_time_play + 10_000);
            let res = execute_play(deps.as_mut(), env.clone(), info.clone()).unwrap();
            println!("{:?}", res);

            assert_eq!(res.messages.len(), 1);
            assert_eq!(
                res.messages[0],
                SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
                    to_address: "terra1q88h7ewu6h3am4mxxeqhu3srxterrandworker".to_string(),
                    amount: vec![Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(179u128)
                    }]
                }))
            );

            let store = lottery_winning_combination_storage_read(&deps.storage)
                .load(&state.lottery_counter.to_be_bytes())
                .unwrap();
            assert_eq!(store, "39493d");

            // TODO add winner checks
            let state_after = read_config(&deps.storage).unwrap();
            let jackpot_reward_after = jackpot_storage_read(&deps.storage)
                .load(&state.lottery_counter.to_be_bytes())
                .unwrap();

            println!("{:?}", jackpot_reward_after);
            assert_eq!(50, state_after.token_holder_percentage_fee_reward);
            assert_eq!(jackpot_reward_before, Uint128::zero());
            assert_ne!(jackpot_reward_after, jackpot_reward_before);
            // 720720 total fees
            assert_eq!(jackpot_reward_after, Uint128::from(1_799_820u128));
            assert_eq!(state_after.lottery_counter, 2);
            assert_ne!(state_after.lottery_counter, state.lottery_counter);
        }
    }
    mod collect {
        use super::*;
        use crate::state::count_player_by_lottery;

        #[test]
        fn security_active() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let mut state = read_config(&deps.storage).unwrap();
            jackpot_storage(deps.as_mut().storage)
                .save(&(state.lottery_counter - 1).to_be_bytes(), &Uint128::zero())
                .unwrap();
            jackpot_storage_alte(deps.as_mut().storage)
                .save(&(state.lottery_counter - 1).to_be_bytes(), &Uint128::zero())
                .unwrap();
            state.safe_lock = true;
            store_config(deps.as_mut().storage, &state).unwrap();
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env, info.clone(), msg);
            match res {
                Err(GenericErr { msg }) => assert_eq!(
                    msg,
                    "Contract deactivated for update or/and preventing security issue"
                ),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn do_not_send_funds() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(
                &before_all.default_sender.to_string(),
                &[Coin {
                    denom: "uluna".to_string(),
                    amount: Uint128::from(1_000u128),
                }],
            );
            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Do not send funds with jackpot"),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn collect_jackpot_is_closed() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let state = read_config(deps.as_mut().storage).unwrap();
            // Add 1 player here
            count_player_by_lottery(deps.as_mut().storage)
                .save(
                    &(state.lottery_counter - 1).to_be_bytes(),
                    &Uint128::from(1u128),
                )
                .unwrap();

            jackpot_storage(deps.as_mut().storage)
                .save(&(state.lottery_counter - 1).to_be_bytes(), &Uint128::zero())
                .unwrap();
            jackpot_storage_alte(deps.as_mut().storage)
                .save(&(state.lottery_counter - 1).to_be_bytes(), &Uint128::zero())
                .unwrap();
            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            env.block.time =
                Timestamp::from_seconds(state.block_time_play - state.every_block_time_play);
            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Collecting jackpot is closed"),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn no_jackpot_rewards() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let state = read_config(deps.as_mut().storage).unwrap();
            jackpot_storage(deps.as_mut().storage)
                .save(&(state.lottery_counter - 1).to_be_bytes(), &Uint128::zero())
                .unwrap();
            jackpot_storage_alte(deps.as_mut().storage)
                .save(&(state.lottery_counter - 1).to_be_bytes(), &Uint128::zero())
                .unwrap();

            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            env.block.time =
                Timestamp::from_seconds(state.block_time_play - state.every_block_time_play / 2);

            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "No jackpot reward"),
                _ => panic!("Unexpected error"),
            }
        }

        #[test]
        fn no_winners() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let state = read_config(&deps.storage).unwrap();
            jackpot_storage(deps.as_mut().storage)
                .save(
                    &(state.lottery_counter - 1).to_be_bytes(),
                    &Uint128::from(1_000_000_u128),
                )
                .unwrap();
            jackpot_storage_alte(deps.as_mut().storage)
                .save(&(state.lottery_counter - 1).to_be_bytes(), &Uint128::zero())
                .unwrap();

            let state = read_config(deps.as_mut().storage).unwrap();
            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            env.block.time =
                Timestamp::from_seconds(state.block_time_play - state.every_block_time_play / 2);

            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);

            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Address is not a winner"),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn contract_balance_empty() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(0u128),
            }]);

            default_init(deps.as_mut());
            let state_before = read_config(&deps.storage).unwrap();
            jackpot_storage(deps.as_mut().storage)
                .save(
                    &(state_before.lottery_counter - 1).to_be_bytes(),
                    &Uint128::from(1_000_000_u128),
                )
                .unwrap();
            jackpot_storage_alte(deps.as_mut().storage)
                .save(
                    &(state_before.lottery_counter - 1).to_be_bytes(),
                    &Uint128::zero(),
                )
                .unwrap();

            let addr1 = deps
                .api
                .addr_canonicalize(&Addr::unchecked("address1").to_string())
                .unwrap();
            let addr2 = deps
                .api
                .addr_canonicalize(&before_all.default_sender.to_string())
                .unwrap();
            println!(
                "{:?}",
                deps.api
                    .addr_canonicalize(&Addr::unchecked("address1").to_string())
                    .unwrap()
            );

            save_winner(deps.as_mut().storage, 1u64, addr1.clone(), 1).unwrap();
            println!(
                "{:?}",
                winner_storage_read(&deps.storage, 1u64)
                    .load(addr1.as_slice())
                    .unwrap()
            );

            save_winner(deps.as_mut().storage, 1u64, addr2, 1).unwrap();
            let state = read_config(&deps.storage).unwrap();
            let mut env = mock_env();
            let info = mock_info("address1", &[]);
            env.block.time =
                Timestamp::from_seconds(state.block_time_play - state.every_block_time_play / 2);

            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);

            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Empty contract balance"),
                _ => panic!("Unexpected error"),
            }
            /*
            let store = winner_storage(deps.as_mut().storage, 1u64)
                .load(&1_u8.to_be_bytes())
                .unwrap();
            let claimed_address = deps
                .api
                .addr_canonicalize(&before_all.default_sender)
                .unwrap();
            assert_eq!(store.winners[1].address, claimed_address);
            //assert!(!store.winners[1].claimed);
            println!("{:?}", store.winners[1].claimed);

             */
        }
        #[test]
        fn some_winner_sender_excluded() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let state_before = read_config(&deps.storage).unwrap();
            jackpot_storage(deps.as_mut().storage)
                .save(
                    &(state_before.lottery_counter - 1).to_be_bytes(),
                    &Uint128::from(1_000_000_u128),
                )
                .unwrap();
            jackpot_storage_alte(deps.as_mut().storage)
                .save(
                    &(state_before.lottery_counter - 1).to_be_bytes(),
                    &Uint128::zero(),
                )
                .unwrap();

            let addr = deps
                .api
                .addr_canonicalize(&Addr::unchecked("address").to_string())
                .unwrap();
            let addr_default = deps
                .api
                .addr_canonicalize(&before_all.default_sender.to_string())
                .unwrap();

            save_winner(deps.as_mut().storage, 1u64, addr.clone(), 1).unwrap();
            save_winner(deps.as_mut().storage, 1u64, addr_default.clone(), 1).unwrap();

            save_winner(deps.as_mut().storage, 1u64, addr.clone(), 4).unwrap();
            save_winner(deps.as_mut().storage, 1u64, addr_default.clone(), 4).unwrap();

            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender_two.to_string(), &[]);
            env.block.time = Timestamp::from_seconds(
                state_before.block_time_play - state_before.every_block_time_play / 2,
            );
            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);

            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Address is not a winner"),
                _ => panic!("Unexpected error"),
            }
        }

        #[test]
        fn success() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());

            let mut state_before = read_config(&deps.storage).unwrap();
            state_before.lottery_counter = 2;
            store_config(deps.as_mut().storage, &state_before).unwrap();
            jackpot_storage(deps.as_mut().storage)
                .save(
                    &(state_before.lottery_counter - 1).to_be_bytes(),
                    &Uint128::from(1_000_000_u128),
                )
                .unwrap();
            jackpot_storage_alte(deps.as_mut().storage)
                .save(
                    &(state_before.lottery_counter - 1).to_be_bytes(),
                    &Uint128::zero(),
                )
                .unwrap();

            let addr2 = deps
                .api
                .addr_canonicalize(&Addr::unchecked("address2").to_string())
                .unwrap();
            let default_addr = deps
                .api
                .addr_canonicalize(&before_all.default_sender.to_string())
                .unwrap();
            let addr3 = deps
                .api
                .addr_canonicalize(&Addr::unchecked("address3").to_string())
                .unwrap();
            save_winner(deps.as_mut().storage, 1u64, addr2.clone(), 1).unwrap();
            save_winner(deps.as_mut().storage, 1u64, default_addr.clone(), 1).unwrap();
            save_winner(deps.as_mut().storage, 1u64, addr3.clone(), 6).unwrap();

            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            env.block.time = Timestamp::from_seconds(
                state_before.block_time_play - state_before.every_block_time_play / 2,
            );

            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
            println!("{:?}", res);
            assert_eq!(res.messages.len(), 2);
            let amount_claimed = Uint128::from(217499u128);
            assert_eq!(
                res.messages[0],
                SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
                    to_address: before_all.default_sender.to_string(),
                    amount: vec![Coin {
                        denom: "ust".to_string(),
                        amount: amount_claimed.clone()
                    }]
                }))
            );
            assert_eq!(
                res.messages[1],
                SubMsg::new(CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr: deps
                        .api
                        .addr_humanize(&state_before.loterra_staking_contract_address)
                        .unwrap()
                        .to_string(),
                    msg: Binary::from(r#"{"update_global_index":{}}"#.as_bytes()),
                    funds: vec![Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(217499u128)
                    }]
                }))
            );
            // Handle can't claim multiple times
            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);

            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Already claimed"),
                _ => panic!("Unexpected error"),
            }

            let claimed_address = deps
                .api
                .addr_canonicalize(&before_all.default_sender.to_string())
                .unwrap();
            let winner_claim = winner_storage(deps.as_mut().storage, 1u64)
                .load(claimed_address.as_slice())
                .unwrap();

            assert_eq!(winner_claim.claimed, true);

            let not_claimed = winner_storage(deps.as_mut().storage, 1u64)
                .load(addr2.as_slice())
                .unwrap();
            assert_eq!(not_claimed.claimed, false);

            let state_after = read_config(&deps.storage).unwrap();
            let _jackpot_before = jackpot_storage_read(&deps.storage)
                .load(&(state_before.lottery_counter - 1).to_be_bytes())
                .unwrap();
            let _jackpot_after = jackpot_storage_read(&deps.storage)
                .load(&(state_after.lottery_counter - 1).to_be_bytes())
                .unwrap();
            assert_eq!(state_after, state_before);

            let mut env = mock_env();
            let info = mock_info("address3", &[]);
            env.block.time = Timestamp::from_seconds(
                state_before.block_time_play - state_before.every_block_time_play / 2,
            );
            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
            println!("{:?}", res);
            assert_eq!(res.messages.len(), 2);
        }
        #[test]
        fn success_collecting_for_someone() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());

            let mut state_before = read_config(&deps.storage).unwrap();
            state_before.lottery_counter = 2;
            store_config(deps.as_mut().storage, &state_before).unwrap();
            jackpot_storage(deps.as_mut().storage)
                .save(
                    &(state_before.lottery_counter - 1).to_be_bytes(),
                    &Uint128::from(1_000_000u128),
                )
                .unwrap();
            jackpot_storage_alte(deps.as_mut().storage)
                .save(
                    &(state_before.lottery_counter - 1).to_be_bytes(),
                    &Uint128::from(1_000_000u128),
                )
                .unwrap();

            let addr2 = deps
                .api
                .addr_canonicalize(&Addr::unchecked("address2").to_string())
                .unwrap();
            let default_addr = deps
                .api
                .addr_canonicalize(&before_all.default_sender.to_string())
                .unwrap();

            save_winner(deps.as_mut().storage, 1u64, addr2.clone(), 1).unwrap();
            save_winner(deps.as_mut().storage, 1u64, default_addr.clone(), 1).unwrap();

            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender_two.to_string(), &[]);
            env.block.time = Timestamp::from_seconds(
                state_before.block_time_play - state_before.every_block_time_play / 2,
            );

            let msg = ExecuteMsg::Collect {
                address: Some(before_all.default_sender.clone()),
            };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
            println!("{:?}", res);

            assert_eq!(res.messages.len(), 3);
            let amount_claimed = Uint128::from(217499u128);

            assert_eq!(
                res.messages[0],
                SubMsg::new(CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr: "altered".to_string(),
                    msg: Binary::from(r#"{"transfer":{"recipient":"terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5s20q007","amount":"435000"}}"#.as_bytes()),
                    funds: vec![]
                }))
            );
            assert_eq!(
                res.messages[1],
                SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
                    to_address: before_all.default_sender.to_string(),
                    amount: vec![Coin {
                        denom: "ust".to_string(),
                        amount: amount_claimed.clone()
                    }]
                }))
            );
            assert_eq!(
                res.messages[2],
                SubMsg::new(CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr: deps
                        .api
                        .addr_humanize(&state_before.loterra_staking_contract_address)
                        .unwrap()
                        .to_string(),
                    msg: Binary::from(r#"{"update_global_index":{}}"#.as_bytes()),
                    funds: vec![Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(217499u128)
                    }]
                }))
            );
            // Handle can't claim multiple times
            let msg = ExecuteMsg::Collect {
                address: Some(before_all.default_sender.clone()),
            };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);

            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Already claimed"),
                _ => panic!("Unexpected error"),
            }

            let claimed_address = deps
                .api
                .addr_canonicalize(&before_all.default_sender.to_string())
                .unwrap();
            let winner_claim = winner_storage(deps.as_mut().storage, 1u64)
                .load(claimed_address.as_slice())
                .unwrap();

            assert_eq!(winner_claim.claimed, true);

            let not_claimed = winner_storage(deps.as_mut().storage, 1u64)
                .load(addr2.as_slice())
                .unwrap();
            assert_eq!(not_claimed.claimed, false);

            let state_after = read_config(&deps.storage).unwrap();
            let _jackpot_before = jackpot_storage_read(&deps.storage)
                .load(&(state_before.lottery_counter - 1).to_be_bytes())
                .unwrap();
            let _jackpot_after = jackpot_storage_read(&deps.storage)
                .load(&(state_after.lottery_counter - 1).to_be_bytes())
                .unwrap();
            assert_eq!(state_after, state_before);
        }
        #[test]
        fn success_multiple_win() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());

            let mut state_before = read_config(&deps.storage).unwrap();
            state_before.lottery_counter = 2;
            store_config(deps.as_mut().storage, &state_before).unwrap();
            jackpot_storage(deps.as_mut().storage)
                .save(
                    &(state_before.lottery_counter - 1).to_be_bytes(),
                    &Uint128::from(1_000_000u128),
                )
                .unwrap();

            jackpot_storage_alte(deps.as_mut().storage)
                .save(
                    &(state_before.lottery_counter - 1).to_be_bytes(),
                    &Uint128::zero(),
                )
                .unwrap();

            let addr2 = deps
                .api
                .addr_canonicalize(&Addr::unchecked("address2").to_string())
                .unwrap();
            let default_addr = deps
                .api
                .addr_canonicalize(&before_all.default_sender.to_string())
                .unwrap();

            // rank 1
            save_winner(deps.as_mut().storage, 1u64, addr2.clone(), 1).unwrap();
            save_winner(deps.as_mut().storage, 1u64, default_addr.clone(), 1).unwrap();

            // rank 5
            save_winner(deps.as_mut().storage, 1u64, addr2.clone(), 2).unwrap();
            save_winner(deps.as_mut().storage, 1u64, default_addr.clone(), 2).unwrap();
            save_winner(deps.as_mut().storage, 1u64, default_addr.clone(), 2).unwrap();

            let state = read_config(deps.as_mut().storage).unwrap();
            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            env.block.time =
                Timestamp::from_seconds(state.block_time_play - state.every_block_time_play / 2);

            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

            assert_eq!(res.messages.len(), 2);
            let amount_claimed = Uint128::from(250832u128);
            assert_eq!(
                res.messages[0],
                SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
                    to_address: before_all.default_sender.to_string(),
                    amount: vec![Coin {
                        denom: "ust".to_string(),
                        amount: amount_claimed.clone()
                    }]
                }))
            );
            assert_eq!(
                res.messages[1],
                SubMsg::new(CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr: deps
                        .api
                        .addr_humanize(&state_before.loterra_staking_contract_address)
                        .unwrap()
                        .to_string(),
                    msg: Binary::from(r#"{"update_global_index":{}}"#.as_bytes()),
                    funds: vec![Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::from(250832u128)
                    }]
                }))
            );
            // Handle can't claim multiple times
            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);

            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Already claimed"),
                _ => panic!("Unexpected error"),
            }

            let claimed_address = deps
                .api
                .addr_canonicalize(&before_all.default_sender.to_string())
                .unwrap();

            let claimed = winner_storage(deps.as_mut().storage, 1u64)
                .load(claimed_address.as_slice())
                .unwrap();
            assert_eq!(claimed.claimed, true);

            let not_claimed = winner_storage(deps.as_mut().storage, 1u64)
                .load(addr2.as_slice())
                .unwrap();
            assert_eq!(not_claimed.claimed, false);

            let state_after = read_config(&deps.storage).unwrap();
            let _jackpot_before = jackpot_storage_read(&deps.storage)
                .load(&(state_before.lottery_counter - 1).to_be_bytes())
                .unwrap();
            let _jackpot_after = jackpot_storage_read(&deps.storage)
                .load(&(state_after.lottery_counter - 1).to_be_bytes())
                .unwrap();
            assert_eq!(state_after, state_before);
        }
    }

    mod proposal {
        use super::*;
        // handle_proposal
        #[test]
        fn description_min_error() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let msg = ExecuteMsg::Poll {
                description: "This".to_string(),
                proposal: Proposal::LotteryEveryBlockTime,
                amount: Option::from(Uint128::from(22u128)),
                prize_per_rank: None,
                recipient: None,
            };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Description min length 6"),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn description_max_error() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let msg = ExecuteMsg::Poll {
                description: "let e;\
                let info = mock_info(nv = mock_env(before_all.default_sender.clone(), &[]));
                 let env = mock_env( \
                 let info = mock_info(&before_all.default_sender.to_string(), &[]); let env);
                 = mock_env(before_a;\
                 let info = mock_info(ll.default_sender.clone(), &[]); let env = mock_env(before_all.default_sender.clone(), &[]));
                 let env = mock_env();
                 let info = mock_info(&before_all.default_sender.to_string(), &[]);let env = mock_env(before_all.default_sender.clone(), &[]);
                 ".to_string(),
                proposal: Proposal::LotteryEveryBlockTime,
                amount: Option::from(Uint128::from(22u128)),
                prize_per_rank: None,
                recipient: None
            };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Description max length 255"),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn do_not_send_funds() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(
                &before_all.default_sender.to_string(),
                &[Coin {
                    denom: "ust".to_string(),
                    amount: Uint128::from(1_000u128),
                }],
            );
            let msg = ExecuteMsg::Poll {
                description: "This is my first proposal".to_string(),
                proposal: Proposal::LotteryEveryBlockTime,
                amount: Option::from(Uint128::from(22u128)),
                prize_per_rank: None,
                recipient: None,
            };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Do not send funds with proposal"),
                _ => panic!("Unexpected error"),
            }
        }

        fn msg_constructor_none(proposal: Proposal) -> ExecuteMsg {
            ExecuteMsg::Poll {
                description: "This is my first proposal".to_string(),
                proposal,
                amount: None,
                prize_per_rank: None,
                recipient: None,
            }
        }
        fn msg_constructor_amount_out(proposal: Proposal) -> ExecuteMsg {
            ExecuteMsg::Poll {
                description: "This is my first proposal".to_string(),
                proposal,
                amount: Option::from(Uint128::from(250u128)),
                prize_per_rank: None,
                recipient: None,
            }
        }

        fn msg_constructor_prize_len_out(proposal: Proposal) -> ExecuteMsg {
            ExecuteMsg::Poll {
                description: "This is my first proposal".to_string(),
                proposal,
                amount: None,
                prize_per_rank: Option::from(vec![10, 20, 23, 23, 23, 23, 23]),
                recipient: None,
            }
        }

        fn msg_constructor_prize_sum_out(proposal: Proposal) -> ExecuteMsg {
            ExecuteMsg::Poll {
                description: "This is my first proposal".to_string(),
                proposal,
                amount: None,
                prize_per_rank: Option::from(vec![100, 20, 23, 23, 0, 0]),
                recipient: None,
            }
        }

        #[test]
        fn all_proposal_amount_error() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);

            let msg_drand_worker_fee_percentage =
                msg_constructor_none(Proposal::DrandWorkerFeePercentage);
            let msg_lottery_every_block_time =
                msg_constructor_none(Proposal::LotteryEveryBlockTime);
            let msg_jackpot_reward_percentage =
                msg_constructor_none(Proposal::JackpotRewardPercentage);
            let msg_prize_per_rank = msg_constructor_none(Proposal::PrizePerRank);
            let msg_holder_fee_per_percentage = msg_constructor_none(Proposal::HolderFeePercentage);
            let msg_amount_to_register = msg_constructor_none(Proposal::AmountToRegister);
            let msg_security_migration = msg_constructor_none(Proposal::SecurityMigration);
            let msg_dao_funding = msg_constructor_none(Proposal::DaoFunding);
            let msg_staking_contract_migration =
                msg_constructor_none(Proposal::StakingContractMigration);

            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg_dao_funding);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Amount required"),
                _ => panic!("Unexpected error"),
            }

            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_security_migration,
            );
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Migration address is required"),
                _ => panic!("Unexpected error"),
            }

            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_staking_contract_migration,
            );
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Migration address is required"),
                _ => panic!("Unexpected error"),
            }

            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_lottery_every_block_time,
            );
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Amount block time required"),
                _ => panic!("Unexpected error"),
            }

            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_drand_worker_fee_percentage,
            );
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Amount is required"),
                _ => panic!("Unexpected error"),
            }

            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_jackpot_reward_percentage,
            );
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Amount is required"),
                _ => panic!("Unexpected error"),
            }

            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_holder_fee_per_percentage,
            );
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Amount is required"),
                _ => panic!("Unexpected error"),
            }

            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg_prize_per_rank);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Rank is required"),
                _ => panic!("Unexpected error"),
            }

            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_amount_to_register,
            );
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Amount is required"),
                _ => panic!("Unexpected error"),
            }

            let msg_drand_worker_fee_percentage =
                msg_constructor_amount_out(Proposal::DrandWorkerFeePercentage);
            let msg_jackpot_reward_percentage =
                msg_constructor_amount_out(Proposal::JackpotRewardPercentage);
            let msg_holder_fee_per_percentage =
                msg_constructor_amount_out(Proposal::HolderFeePercentage);

            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_drand_worker_fee_percentage,
            );
            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Amount between 0 to 10"),
                _ => panic!("Unexpected error"),
            }
            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_jackpot_reward_percentage,
            );
            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Amount between 0 to 100"),
                _ => panic!("Unexpected error"),
            }
            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_holder_fee_per_percentage,
            );
            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Amount between 0 to 100"),
                _ => panic!("Unexpected error"),
            }

            let msg_prize_per_rank = msg_constructor_prize_len_out(Proposal::PrizePerRank);
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg_prize_per_rank);
            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => assert_eq!(
                    msg,
                    "Ranks need to be in this format [0, 90, 10, 0, 0, 0] numbers between 0 to 100"
                ),
                _ => panic!("Unexpected error"),
            }
            let msg_prize_per_rank = msg_constructor_prize_sum_out(Proposal::PrizePerRank);
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg_prize_per_rank);
            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => {
                    assert_eq!(msg, "Numbers total sum need to be equal to 100")
                }
                _ => panic!("Unexpected error"),
            }
        }
        fn msg_constructor_success(
            proposal: Proposal,
            amount: Option<Uint128>,
            prize_per_rank: Option<Vec<u8>>,
            recipient: Option<Addr>,
        ) -> ExecuteMsg {
            ExecuteMsg::Poll {
                description: "This is my first proposal".to_string(),
                proposal,
                amount,
                prize_per_rank,
                recipient,
            }
        }

        #[test]
        fn success() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            deps.querier.with_token_balances(Uint128::from(200_000u128));
            default_init(deps.as_mut());
            let state = read_config(&deps.storage).unwrap();
            assert_eq!(state.poll_count, 0);
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);

            let msg_lottery_every_block_time = msg_constructor_success(
                Proposal::LotteryEveryBlockTime,
                Option::from(Uint128::from(22u128)),
                None,
                None,
            );
            let msg_amount_to_register = msg_constructor_success(
                Proposal::AmountToRegister,
                Option::from(Uint128::from(22u128)),
                None,
                None,
            );
            let msg_holder_fee_percentage = msg_constructor_success(
                Proposal::HolderFeePercentage,
                Option::from(Uint128::from(20u128)),
                None,
                None,
            );
            let msg_prize_rank = msg_constructor_success(
                Proposal::PrizePerRank,
                None,
                Option::from(vec![10, 10, 10, 70, 0, 0]),
                None,
            );
            let msg_jackpot_reward_percentage = msg_constructor_success(
                Proposal::JackpotRewardPercentage,
                Option::from(Uint128::from(80u128)),
                None,
                None,
            );
            let msg_drand_fee_worker = msg_constructor_success(
                Proposal::DrandWorkerFeePercentage,
                Option::from(Uint128::from(10u128)),
                None,
                None,
            );
            let msg_security_migration = msg_constructor_success(
                Proposal::SecurityMigration,
                None,
                None,
                Option::from(before_all.default_sender_two.clone()),
            );
            let msg_dao_funding = msg_constructor_success(
                Proposal::DaoFunding,
                Option::from(Uint128::from(200_000u128)),
                None,
                None,
            );

            let msg_staking_contract_migration = msg_constructor_success(
                Proposal::StakingContractMigration,
                None,
                None,
                Option::from(before_all.default_sender_two.clone()),
            );

            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_lottery_every_block_time,
            )
            .unwrap();
            assert_eq!(res.attributes.len(), 4);
            let poll_state = poll_storage(deps.as_mut().storage)
                .load(&1_u64.to_be_bytes())
                .unwrap();
            assert_eq!(
                poll_state.creator,
                deps.api
                    .addr_canonicalize(&before_all.default_sender.to_string())
                    .unwrap()
            );
            let state = read_config(&deps.storage).unwrap();
            assert_eq!(state.poll_count, 1);

            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_amount_to_register,
            )
            .unwrap();
            assert_eq!(res.attributes.len(), 4);
            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_holder_fee_percentage,
            )
            .unwrap();
            assert_eq!(res.attributes.len(), 4);
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg_prize_rank).unwrap();
            assert_eq!(res.attributes.len(), 4);
            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_jackpot_reward_percentage,
            )
            .unwrap();
            assert_eq!(res.attributes.len(), 4);
            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_drand_fee_worker,
            )
            .unwrap();
            assert_eq!(res.attributes.len(), 4);

            // Admin create proposal migration
            let env = mock_env();
            let info = mock_info(&before_all.default_sender_owner.to_string(), &[]);
            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_security_migration.clone(),
            )
            .unwrap();
            assert_eq!(res.attributes.len(), 4);
            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_staking_contract_migration.clone(),
            )
            .unwrap();
            assert_eq!(res.attributes.len(), 4);
            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_dao_funding.clone(),
            )
            .unwrap();
            assert_eq!(res.attributes.len(), 4);

            // Admin renounce so all can create proposal migration
            execute_renounce(deps.as_mut(), env.clone(), info.clone()).unwrap();
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);

            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_security_migration,
            )
            .unwrap();
            assert_eq!(res.attributes.len(), 4);
            let res = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                msg_staking_contract_migration,
            )
            .unwrap();
            assert_eq!(res.attributes.len(), 4);
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg_dao_funding).unwrap();
            assert_eq!(res.attributes.len(), 4);
        }
    }
    mod vote {
        use super::*;
        // handle_vote
        fn create_poll(deps: DepsMut, env: Env, info: MessageInfo) {
            let msg = ExecuteMsg::Poll {
                description: "This is my first proposal".to_string(),
                proposal: Proposal::LotteryEveryBlockTime,
                amount: Option::from(Uint128::from(22u128)),
                prize_per_rank: None,
                recipient: None,
            };
            let _res = execute(deps, env, info, msg).unwrap();
        }
        #[test]
        fn do_not_send_funds() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            create_poll(deps.as_mut(), env.clone(), info.clone());

            let env = mock_env();
            let info = mock_info(
                &before_all.default_sender.to_string(),
                &[Coin {
                    denom: "ust".to_string(),
                    amount: Uint128::from(9_000_000u128),
                }],
            );

            let msg = ExecuteMsg::Vote {
                poll_id: 1,
                approve: false,
            };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Do not send funds with vote"),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn poll_deactivated() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            create_poll(deps.as_mut(), env.clone(), info.clone());

            // Save to storage
            poll_storage(deps.as_mut().storage)
                .update::<_, StdError>(&1_u64.to_be_bytes(), |poll| {
                    let mut poll_data = poll.unwrap();
                    // Update the status to passed
                    poll_data.status = PollStatus::RejectedByCreator;
                    Ok(poll_data)
                })
                .unwrap();

            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let msg = ExecuteMsg::Vote {
                poll_id: 1,
                approve: false,
            };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Proposal is deactivated"),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn poll_expired() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            create_poll(deps.as_mut(), env.clone(), info.clone());

            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let poll_state = poll_storage(deps.as_mut().storage)
                .load(&1_u64.to_be_bytes())
                .unwrap();
            env.block.height = poll_state.end_height + 1;

            let msg = ExecuteMsg::Vote {
                poll_id: 1,
                approve: false,
            };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Proposal expired"),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn only_stakers_with_bonded_tokens_can_vote() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            deps.querier.with_holder(
                before_all.default_sender.clone(),
                Uint128::from(0u128),
                Decimal::zero(),
                Decimal::zero(),
            );

            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            create_poll(deps.as_mut(), env.clone(), info.clone());

            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let msg = ExecuteMsg::Vote {
                poll_id: 1,
                approve: false,
            };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone());
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Only stakers can vote"),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn success() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            deps.querier.with_holder(
                before_all.default_sender.clone(),
                Uint128::from(150_000u128),
                Decimal::zero(),
                Decimal::zero(),
            );
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            create_poll(deps.as_mut(), env.clone(), info.clone());

            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let poll_id: u64 = 1;
            let approve = false;
            let msg = ExecuteMsg::Vote { poll_id, approve };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone()).unwrap();
            let poll_state = poll_storage(deps.as_mut().storage)
                .load(&poll_id.to_be_bytes())
                .unwrap();
            assert_eq!(res.attributes.len(), 3);
            assert_eq!(poll_state.no_vote, 1);
            assert_eq!(poll_state.yes_vote, 0);
            assert_eq!(poll_state.weight_yes_vote, Uint128::zero());
            assert_eq!(poll_state.weight_no_vote, Uint128::from(150_000u128));

            let sender_to_canonical = deps
                .api
                .addr_canonicalize(&before_all.default_sender.to_string())
                .unwrap();
            let vote_state = poll_vote_storage(deps.as_mut().storage, poll_id.clone())
                .load(sender_to_canonical.as_slice())
                .unwrap();
            assert_eq!(vote_state, approve);

            // Try to vote multiple times
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Already voted"),
                _ => panic!("Unexpected error"),
            }
        }
    }
    mod reject {
        use super::*;
        // handle_reject
        fn create_poll(deps: DepsMut, env: Env, info: MessageInfo) {
            let msg = ExecuteMsg::Poll {
                description: "This is my first proposal".to_string(),
                proposal: Proposal::LotteryEveryBlockTime,
                amount: Option::from(Uint128::from(22u128)),
                prize_per_rank: None,
                recipient: None,
            };
            let _res = execute(deps, env, info, msg).unwrap();
        }
        #[test]
        fn do_not_send_funds() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            create_poll(deps.as_mut(), env.clone(), info.clone());
            let env = mock_env();
            let info = mock_info(
                &before_all.default_sender.to_string(),
                &[Coin {
                    denom: "ust".to_string(),
                    amount: Uint128::from(1_000u128),
                }],
            );
            let msg = ExecuteMsg::RejectPoll { poll_id: 1 };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => {
                    assert_eq!(msg, "Do not send funds with reject proposal")
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn poll_expired() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            create_poll(deps.as_mut(), env.clone(), info.clone());
            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);

            let poll_state = poll_storage(deps.as_mut().storage)
                .load(&1_u64.to_be_bytes())
                .unwrap();
            env.block.height = poll_state.end_height + 1;
            let msg = ExecuteMsg::RejectPoll { poll_id: 1 };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Proposal expired"),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn only_creator_can_reject() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            create_poll(deps.as_mut(), env.clone(), info.clone());
            let msg = ExecuteMsg::RejectPoll { poll_id: 1 };
            let env = mock_env();
            let info = mock_info(&before_all.default_sender_two.to_string(), &[]);
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
            println!("{:?}", res);
            match res {
                Err(StdError::GenericErr { .. }) => {}
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn success() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            create_poll(deps.as_mut(), env.clone(), info.clone());
            let msg = ExecuteMsg::RejectPoll { poll_id: 1 };

            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
            assert_eq!(res.messages.len(), 0);
            assert_eq!(res.attributes.len(), 2);
            let poll_state = poll_storage(deps.as_mut().storage)
                .load(&1_u64.to_be_bytes())
                .unwrap();
            assert_eq!(poll_state.status, PollStatus::RejectedByCreator);
        }
    }
    mod present {
        use super::*;
        // handle_present
        fn create_poll(deps: DepsMut, env: Env, info: MessageInfo) {
            let msg = ExecuteMsg::Poll {
                description: "This is my first proposal".to_string(),
                proposal: Proposal::LotteryEveryBlockTime,
                amount: Option::from(Uint128::from(22u128)),
                prize_per_rank: None,
                recipient: None,
            };
            let _res = execute(deps, env, info, msg).unwrap();
        }
        fn create_poll_security_migration(deps: DepsMut, env: Env, info: MessageInfo) {
            let msg = ExecuteMsg::Poll {
                description: "This is my first proposal".to_string(),
                proposal: Proposal::SecurityMigration,
                amount: None,
                prize_per_rank: None,
                recipient: Option::from(Addr::unchecked("newAddress".to_string())),
            };
            let _res = execute(deps, env, info, msg).unwrap();
            println!("{:?}", _res);
        }
        fn create_poll_dao_funding(deps: DepsMut, env: Env, info: MessageInfo) {
            let msg = ExecuteMsg::Poll {
                description: "This is my first proposal".to_string(),
                proposal: Proposal::DaoFunding,
                amount: Option::from(Uint128::from(22u128)),
                prize_per_rank: None,
                recipient: None,
            };
            let _res = execute(deps, env, info, msg).unwrap();
        }
        fn create_poll_statking_contract_migration(deps: DepsMut, env: Env, info: MessageInfo) {
            let msg = ExecuteMsg::Poll {
                description: "This is my first proposal".to_string(),
                proposal: Proposal::StakingContractMigration,
                amount: None,
                prize_per_rank: None,
                recipient: Option::from(Addr::unchecked("newAddress".to_string())),
            };
            let _res = execute(deps, env, info, msg).unwrap();
            println!("{:?}", _res);
        }
        #[test]
        fn do_not_send_funds() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            create_poll(deps.as_mut(), env.clone(), info.clone());

            let env = mock_env();
            let info = mock_info(
                &before_all.default_sender.to_string(),
                &[Coin {
                    denom: "ust".to_string(),
                    amount: Uint128::from(9_000_000u128),
                }],
            );
            let msg = ExecuteMsg::PresentPoll { poll_id: 1 };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => {
                    assert_eq!(msg, "Do not send funds with present proposal")
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn poll_expired() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            create_poll(deps.as_mut(), env.clone(), info.clone());
            // Save to storage
            poll_storage(deps.as_mut().storage)
                .update::<_, StdError>(&1_u64.to_be_bytes(), |poll| {
                    let mut poll_data = poll.unwrap();
                    // Update the status to passed
                    poll_data.status = PollStatus::Rejected;
                    Ok(poll_data)
                })
                .unwrap();
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let msg = ExecuteMsg::PresentPoll { poll_id: 1 };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
            println!("{:?}", res);
            match res {
                Err(StdError::GenericErr { .. }) => {}
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn poll_still_in_progress() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            create_poll(deps.as_mut(), env.clone(), info.clone());

            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let msg = ExecuteMsg::PresentPoll { poll_id: 1 };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
            println!("{:?}", res);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Proposal still in progress"),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn success_with_reject() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            deps.querier.with_token_balances(Uint128::from(200_000u128));
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            create_poll(deps.as_mut(), env.clone(), info.clone());

            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let poll_state = poll_storage(deps.as_mut().storage)
                .load(&1_u64.to_be_bytes())
                .unwrap();
            env.block.height = poll_state.end_height + 1;

            let msg = ExecuteMsg::PresentPoll { poll_id: 1 };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
            assert_eq!(res.attributes.len(), 3);
            assert_eq!(res.messages.len(), 0);

            let poll_state = poll_storage(deps.as_mut().storage)
                .load(&1_u64.to_be_bytes())
                .unwrap();
            assert_eq!(poll_state.status, PollStatus::Rejected);
        }
        #[test]
        fn success_dao_funding() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            deps.querier.with_token_balances(Uint128::from(200_000u128));
            deps.querier.with_holder(
                before_all.default_sender.clone(),
                Uint128::from(150_000u128),
                Decimal::zero(),
                Decimal::zero(),
            );

            default_init(deps.as_mut());
            // with admin renounce
            let env = mock_env();
            let info = mock_info(&before_all.default_sender_owner.to_string(), &[]);
            let _res = execute_renounce(deps.as_mut(), env, info.clone());

            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            create_poll_dao_funding(deps.as_mut(), env.clone(), info.clone());

            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let msg = ExecuteMsg::Vote {
                poll_id: 1,
                approve: true,
            };

            let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg);

            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let poll_state = poll_storage(deps.as_mut().storage)
                .load(&1_u64.to_be_bytes())
                .unwrap();
            env.block.height = poll_state.end_height + 1;
            let state_before = read_config(&deps.storage).unwrap();

            let msg = ExecuteMsg::PresentPoll { poll_id: 1 };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
            println!("{:?}", res);
            assert_eq!(res.attributes.len(), 3);
            assert_eq!(res.messages.len(), 1);
            assert_eq!(
                res.messages[0],
                SubMsg::new(CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr: deps.api.addr_humanize(&state_before.loterra_cw20_contract_address).unwrap().to_string(),
                    msg: Binary::from(r#"{"transfer":{"recipient":"terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5s20q007","amount":"22"}}"#.as_bytes()),
                    funds: vec![]
                }))
            );

            let poll_state = poll_storage(deps.as_mut().storage)
                .load(&1_u64.to_be_bytes())
                .unwrap();
            assert_eq!(poll_state.status, PollStatus::Passed);
        }
        #[test]
        fn success_staking_migration() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            deps.querier.with_token_balances(Uint128::from(200_000u128));
            deps.querier.with_holder(
                before_all.default_sender.clone(),
                Uint128::from(150_000u128),
                Decimal::zero(),
                Decimal::zero(),
            );
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender_owner.to_string(), &[]);
            create_poll_statking_contract_migration(deps.as_mut(), env.clone(), info.clone());

            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let msg = ExecuteMsg::Vote {
                poll_id: 1,
                approve: true,
            };

            let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg);

            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let poll_state = poll_storage(deps.as_mut().storage)
                .load(&1_u64.to_be_bytes())
                .unwrap();
            env.block.height = poll_state.end_height + 1;
            let state_before = read_config(&deps.storage).unwrap();

            let msg = ExecuteMsg::PresentPoll { poll_id: 1 };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
            println!("{:?}", res);
            assert_eq!(res.attributes.len(), 3);
            assert_eq!(res.messages.len(), 0);

            let poll_state = poll_storage(deps.as_mut().storage)
                .load(&1_u64.to_be_bytes())
                .unwrap();
            assert_eq!(poll_state.status, PollStatus::Passed);
            //let state = config(deps.as_mut());
            let state_after = read_config(&deps.storage).unwrap();
            assert_ne!(
                state_after.loterra_staking_contract_address,
                state_before.loterra_staking_contract_address
            );
            assert_eq!(
                deps.api
                    .addr_humanize(&state_after.loterra_staking_contract_address)
                    .unwrap(),
                Addr::unchecked("newAddress".to_string())
            );
        }
        #[test]
        fn success_security_migration() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            deps.querier.with_token_balances(Uint128::from(200_000u128));
            deps.querier.with_holder(
                before_all.default_sender.clone(),
                Uint128::from(150_000u128),
                Decimal::zero(),
                Decimal::zero(),
            );
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender_owner.to_string(), &[]);
            create_poll_security_migration(deps.as_mut(), env.clone(), info.clone());

            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let msg = ExecuteMsg::Vote {
                poll_id: 1,
                approve: true,
            };

            let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg);

            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let poll_state = poll_storage(deps.as_mut().storage)
                .load(&1_u64.to_be_bytes())
                .unwrap();
            env.block.height = poll_state.end_height + 1;
            read_config(&deps.storage).unwrap();

            let msg = ExecuteMsg::PresentPoll { poll_id: 1 };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
            println!("{:?}", res);
        }
        #[test]
        fn success_with_passed() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            deps.querier.with_token_balances(Uint128::from(200_000u128));
            deps.querier.with_holder(
                before_all.default_sender.clone(),
                Uint128::from(150_000u128),
                Decimal::zero(),
                Decimal::zero(),
            );
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            create_poll(deps.as_mut(), env.clone(), info.clone());

            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let msg = ExecuteMsg::Vote {
                poll_id: 1,
                approve: true,
            };

            let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg);

            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let poll_state = poll_storage(deps.as_mut().storage)
                .load(&1_u64.to_be_bytes())
                .unwrap();
            env.block.height = poll_state.end_height + 1;

            let msg = ExecuteMsg::PresentPoll { poll_id: 1 };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
            assert_eq!(res.attributes.len(), 3);
            assert_eq!(res.messages.len(), 0);

            let poll_state = poll_storage(deps.as_mut().storage)
                .load(&1_u64.to_be_bytes())
                .unwrap();
            assert_eq!(poll_state.status, PollStatus::Passed);

            let env = mock_env();
            let info = mock_info(&before_all.default_sender_owner.to_string(), &[]);
            create_poll_security_migration(deps.as_mut(), env.clone(), info.clone());
            let msg = ExecuteMsg::Vote {
                poll_id: 2,
                approve: true,
            };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
            println!("{:?}", res);
        }
        #[test]
        fn success_with_proposal_not_expired_yet_and_more_50_percent_weight_vote() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            deps.querier
                .with_token_balances(Uint128::from(1_200_000_000u128));
            deps.querier.with_holder(
                before_all.default_sender.clone(),
                Uint128::from(900_000_000u128),
                Decimal::zero(),
                Decimal::zero(),
            );
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            create_poll(deps.as_mut(), env.clone(), info.clone());

            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let msg = ExecuteMsg::Vote {
                poll_id: 1,
                approve: true,
            };

            let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg);

            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let poll_state = poll_storage(deps.as_mut().storage)
                .load(&1_u64.to_be_bytes())
                .unwrap();
            env.block.height = poll_state.end_height - 1000;

            let msg = ExecuteMsg::PresentPoll { poll_id: 1 };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
            assert_eq!(res.attributes.len(), 3);
            assert_eq!(res.messages.len(), 0);

            let poll_state = poll_storage(deps.as_mut().storage)
                .load(&1_u64.to_be_bytes())
                .unwrap();
            assert_eq!(poll_state.status, PollStatus::Passed);

            let env = mock_env();
            let info = mock_info(&before_all.default_sender_owner.to_string(), &[]);
            create_poll_security_migration(deps.as_mut(), env.clone(), info.clone());
            let msg = ExecuteMsg::Vote {
                poll_id: 2,
                approve: true,
            };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
            println!("{:?}", res);
        }
        #[test]
        fn error_with_proposal_not_expired_yet_and_less_50_percent_weight_vote() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128::from(9_000_000u128),
            }]);
            deps.querier.with_token_balances(Uint128::from(200_000u128));
            deps.querier.with_holder(
                before_all.default_sender.clone(),
                Uint128::from(1_000u128),
                Decimal::zero(),
                Decimal::zero(),
            );
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            create_poll(deps.as_mut(), env.clone(), info.clone());

            let msg = ExecuteMsg::Vote {
                poll_id: 1,
                approve: true,
            };

            let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg);

            let mut env = mock_env();
            let info = mock_info(&before_all.default_sender.to_string(), &[]);
            let poll_state = poll_storage(deps.as_mut().storage)
                .load(&1_u64.to_be_bytes())
                .unwrap();
            env.block.height = poll_state.end_height - 1000;

            let msg = ExecuteMsg::PresentPoll { poll_id: 1 };
            let res = execute(deps.as_mut(), env.clone(), info, msg);
            match res {
                Err(GenericErr { msg }) => assert_eq!(msg, "Proposal still in progress"),
                _ => panic!("Unexpected error"),
            }
        }
    }
    mod safe_lock {
        use super::*;
        // handle_switch

        #[test]
        fn only_admin() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender_two.to_string(), &[]);

            let res = execute_safe_lock(deps.as_mut(), env, info);
            match res {
                Err(StdError::GenericErr { .. }) => {}
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn success() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender_owner.to_string(), &[]);

            // Switch to Off
            let res = execute_safe_lock(deps.as_mut(), env.clone(), info.clone()).unwrap();
            assert_eq!(res.messages.len(), 0);
            let state = read_config(&deps.storage).unwrap();
            assert!(state.safe_lock);
            // Switch to On
            let res = execute_safe_lock(deps.as_mut(), env.clone(), info.clone()).unwrap();
            println!("{:?}", res);
            let state = read_config(&deps.storage).unwrap();
            assert!(!state.safe_lock);
        }
    }

    mod renounce {
        use super::*;
        // execute_renounce
        #[test]
        fn only_admin() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender_two.to_string(), &[]);

            let res = execute_renounce(deps.as_mut(), env.clone(), info.clone());
            match res {
                Err(StdError::GenericErr { .. }) => {}
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn safe_lock_on() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender_owner.to_string(), &[]);
            let mut state = read_config(&deps.storage).unwrap();
            state.safe_lock = true;
            store_config(deps.as_mut().storage, &state).unwrap();

            let res = execute_renounce(deps.as_mut(), env.clone(), info.clone());
            match res {
                Err(GenericErr { msg }) => {
                    assert_eq!(msg, "Contract is locked");
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn success() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let env = mock_env();
            let info = mock_info(&before_all.default_sender_owner.to_string(), &[]);

            // Transfer power to admin
            let res = execute_renounce(deps.as_mut(), env.clone(), info.clone()).unwrap();
            assert_eq!(res.messages.len(), 0);
            let state = read_config(&deps.storage).unwrap();
            assert_ne!(
                state.admin,
                deps.api
                    .addr_canonicalize(&before_all.default_sender_owner.to_string())
                    .unwrap()
            );
            assert_eq!(
                state.admin,
                deps.api
                    .addr_canonicalize(&env.contract.address.to_string())
                    .unwrap()
            );
        }
    }
}
