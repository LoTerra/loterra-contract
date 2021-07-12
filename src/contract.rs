use crate::helpers::{count_match, is_lower_hex};
use crate::msg::{AllCombinationResponse, AllWinnersResponse, ConfigResponse, ExecuteMsg, InstantiateMsg, QueryMsg, RoundResponse, WinnerResponse, DaoQueryMsg, GetPollResponse, Proposal, Migration};
use crate::state::{all_winners, combination_save, read_state, save_winner, store_state, State, ALL_USER_COMBINATION, COUNT_PLAYERS, COUNT_TICKETS, JACKPOT, PREFIXED_RANK, PREFIXED_USER_COMBINATION, PREFIXED_WINNER, STATE, WINNING_COMBINATION};
use crate::taxation::deduct_tax;
use cosmwasm_std::{
    attr, entry_point, to_binary, Addr, BankMsg, Binary, CanonicalAddr, Coin, Decimal, Deps,
    DepsMut, Env, MessageInfo, Response, StdError, StdResult, Timestamp, Uint128, WasmMsg,
    WasmQuery,
};
use cw20::{BalanceResponse, Cw20ExecuteMsg, Cw20QueryMsg};
use std::ops::{Mul};

const DRAND_GENESIS_TIME: u64 = 1595431050;
const DRAND_PERIOD: u64 = 30;
const DRAND_NEXT_ROUND_SECURITY: u64 = 10;
const DIV_BLOCK_TIME_BY_X: u64 = 2;
// Note, you can use StdResult in some functions where you do not
// make use of the custom errors
// #[serde(rename_all = "snake_case")]
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let state = State {
        dao_contract_address: deps.api.addr_canonicalize(info.sender.as_str())?,
        block_time_play: msg.block_time_play,
        every_block_time_play: msg.every_block_time_play,
        denom_stable: msg.denom_stable,
        poll_default_end_height: msg.poll_default_end_height,
        combination_len: 6,
        jackpot_percentage_reward: 20,
        token_holder_percentage_fee_reward: 20,
        fee_for_drand_worker_in_percentage: 1,
        prize_rank_winner_percentage: vec![87, 10, 2, 1],
        price_per_ticket_to_register: Uint128(1_000_000),
        terrand_contract_address: deps.api.addr_canonicalize(&msg.terrand_contract_address)?,
        loterra_cw20_contract_address: deps
            .api
            .addr_canonicalize(&msg.loterra_cw20_contract_address)?,
        loterra_staking_contract_address: deps
            .api
            .addr_canonicalize(&msg.loterra_staking_contract_address)?,
        lottery_counter: 1,
    };
    STATE.save(deps.storage, &state)?;

    Ok(Response::default())
}

// And declare a custom Error variant for the ones where you will want to make use of it
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::Register {
            address,
            combination,
        } => handle_register(deps, env, info, address, combination),
        ExecuteMsg::Play {} => handle_play(deps, env, info),
        ExecuteMsg::Claim { addresses } => handle_claim(deps, env, info, addresses),
        ExecuteMsg::Collect { address } => handle_collect(deps, env, info, address),
        ExecuteMsg::PresentPoll { poll_id } => handle_present_proposal(deps, env, info, poll_id),
    }
}

pub fn handle_register(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    address: Option<String>,
    combination: Vec<String>,
) -> StdResult<Response> {
    // Load the state
    let state = read_state(deps.storage)?;

    // Check if the lottery is about to play and cancel new ticket to enter until play
    if env.block.time > Timestamp::from_seconds(state.block_time_play) {
        return Err(StdError::generic_err("Lottery about to start"));
    }

    // Check if address filled as param
    let addr = match address {
        None => info.sender.clone(),
        Some(addr) => Addr::unchecked(addr),
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
            &state.price_per_ticket_to_register, &state.denom_stable
        ))),
        1 => {
            if info.funds[0].denom == state.denom_stable {
                Ok(info.funds[0].amount)
            } else {
                Err(StdError::generic_err(format!(
                    "you need to send {}{} per combination in order to register",
                    &state.price_per_ticket_to_register, &state.denom_stable
                )))
            }
        }
        _ => Err(StdError::generic_err(format!(
            "Only send {0} to register",
            &state.denom_stable
        ))),
    }?;

    if sent.is_zero() {
        return Err(StdError::generic_err(format!(
            "you need to send {}{} per combination in order to register",
            &state.price_per_ticket_to_register, &state.denom_stable
        )));
    }
    // Handle the player is not sending too much or too less
    if sent.u128() != state.price_per_ticket_to_register.u128() * combination.len() as u128 {
        return Err(StdError::generic_err(format!(
            "send {}{}",
            state.price_per_ticket_to_register.u128() * combination.len() as u128,
            state.denom_stable
        )));
    }

    // save combination
    let addr_raw = deps.api.addr_canonicalize(&addr.as_str())?;

    combination_save(
        deps.storage,
        state.lottery_counter,
        addr_raw,
        combination.clone(),
    )?;

    Ok(Response {
        submessages: vec![],
        messages: vec![],
        data: None,
        attributes: vec![
            attr("action", "register"),
            attr("price_per_ticket", state.price_per_ticket_to_register),
            attr("amount_ticket_purchased", combination.len()),
            attr("buyer", info.sender),
        ],
    })
}

pub fn handle_play(deps: DepsMut, env: Env, info: MessageInfo) -> StdResult<Response> {
    // Ensure the sender not sending funds accidentally
    if !info.funds.is_empty() {
        return Err(StdError::generic_err("Do not send funds with play"));
    }

    // Load the state
    let mut state = read_state(deps.storage)?;

    // calculate next round randomness
    let from_genesis = state
        .block_time_play
        .checked_sub(DRAND_GENESIS_TIME)
        .unwrap();
    let next_round = (from_genesis / DRAND_PERIOD)
        .checked_add(DRAND_NEXT_ROUND_SECURITY)
        .unwrap();

    // Make the contract callable for everyone every x blocks

    if env.block.time > Timestamp::from_seconds(state.block_time_play) {
        // Update the state
        state.block_time_play = env
            .block
            .time
            .plus_seconds(state.every_block_time_play)
            .nanos()
            / 1_000_000_000;
    } else {
        return Err(StdError::generic_err(format!(
            "Lottery registration is still in progress... Retry after block time {}",
            state.block_time_play
        )));
    }

    let msg = terrand::msg::QueryMsg::GetRandomness { round: next_round };
    let terrand_human = deps.api.addr_humanize(&state.terrand_contract_address)?;
    let wasm = WasmQuery::Smart {
        contract_addr: terrand_human.to_string(),
        msg: to_binary(&msg)?,
    };
    let res: terrand::msg::GetRandomResponse = deps.querier.query(&wasm.into())?;
    let randomness_hash = hex::encode(res.randomness.as_slice());

    let n = randomness_hash
        .char_indices()
        .rev()
        .nth(state.combination_len as usize - 1)
        .map(|(i, _)| i)
        .unwrap();
    let winning_combination = &randomness_hash[n..];

    // Save the combination for the current lottery count
    WINNING_COMBINATION.save(
        deps.storage,
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

    // Drand worker fee
    let fee_for_drand_worker = jackpot
        .mul(Decimal::percent(
            state.fee_for_drand_worker_in_percentage as u64,
        ))
        .mul(Decimal::percent(
            state.fee_for_drand_worker_in_percentage as u64,
        ));

    // The jackpot after worker fee applied
    let jackpot_after = jackpot.checked_sub(fee_for_drand_worker)?;

    let msg_fee_worker = BankMsg::Send {
        to_address: res.worker.clone(),
        amount: vec![deduct_tax(
            &deps.querier,
            Coin {
                denom: state.denom_stable.clone(),
                amount: fee_for_drand_worker,
            },
        )?],
    };

    // Save jackpot to storage
    JACKPOT.save(
        deps.storage,
        &state.lottery_counter.to_be_bytes(),
        &jackpot_after,
    )?;
    // Update the state
    state.lottery_counter += 1;

    // Save the new state
    store_state(deps.storage, &state)?;

    Ok(Response {
        submessages: vec![],
        messages: vec![msg_fee_worker.into()],
        data: None,
        attributes: vec![
            attr("action", "reward"),
            attr("by", info.sender.to_string()),
            attr("to", res.worker),
        ],
    })
}

pub fn handle_claim(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    addresses: Option<Vec<String>>,
) -> StdResult<Response> {
    let state = read_state(deps.storage)?;

    if env.block.time
        > Timestamp::from_seconds(
            state
                .block_time_play
                .checked_sub(state.every_block_time_play / DIV_BLOCK_TIME_BY_X)
                .unwrap(),
        )
    {
        return Err(StdError::generic_err("Claiming is closed"));
    }
    let last_lottery_counter_round = state.lottery_counter - 1;

    let lottery_winning_combination = match WINNING_COMBINATION
        .may_load(deps.storage, &last_lottery_counter_round.to_be_bytes())?
    {
        Some(combination) => Some(combination),
        None => {
            return Err(StdError::generic_err("No winning combination"));
        }
    }
    .unwrap();
    let addr = deps.api.addr_canonicalize(&info.sender.as_str())?;

    let mut combination: Vec<(CanonicalAddr, Vec<String>)> = vec![];

    match addresses {
        None => {
            match PREFIXED_USER_COMBINATION.may_load(
                deps.storage,
                (&last_lottery_counter_round.to_be_bytes(), addr.as_slice()),
            )? {
                None => {}
                Some(combo) => combination.push((addr, combo)),
            };
        }
        Some(addresses) => {
            for address in addresses {
                let addr = deps.api.addr_canonicalize(&address.as_str())?;
                match PREFIXED_USER_COMBINATION.may_load(
                    deps.storage,
                    (&last_lottery_counter_round.to_be_bytes(), addr.as_slice()),
                )? {
                    None => {}
                    Some(combo) => combination.push((addr, combo)),
                };
            }
        }
    }

    if combination.is_empty() {
        return Err(StdError::generic_err("No combination found"));
    }
    let mut some_winner = 0;
    for (addr, comb_raw) in combination {
        match PREFIXED_WINNER.may_load(
            deps.storage,
            (&last_lottery_counter_round.to_be_bytes(), addr.as_slice()),
        )? {
            None => {
                for combo in comb_raw {
                    let match_count = count_match(&combo, &lottery_winning_combination);
                    let rank = match match_count {
                        count if count == lottery_winning_combination.len() => 1,
                        count if count == lottery_winning_combination.len() - 1 => 2,
                        count if count == lottery_winning_combination.len() - 2 => 3,
                        count if count == lottery_winning_combination.len() - 3 => 4,
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
        return Err(StdError::generic_err(
            "No winning combination or already claimed",
        ));
    }

    Ok(Response {
        submessages: vec![],
        messages: vec![],
        data: None,
        attributes: vec![attr("action", "claim")],
    })
}
// Players claim the jackpot
pub fn handle_collect(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    address: Option<String>,
) -> StdResult<Response> {
    // Ensure the sender is not sending funds
    if !info.funds.is_empty() {
        return Err(StdError::generic_err("Do not send funds with jackpot"));
    }

    // Load state
    let state = read_state(deps.storage)?;
    let last_lottery_counter_round = state.lottery_counter - 1;
    let jackpot_reward = JACKPOT.load(deps.storage, &last_lottery_counter_round.to_be_bytes())?;

    if env.block.time
        < Timestamp::from_seconds(
            state
                .block_time_play
                .checked_sub(state.every_block_time_play / DIV_BLOCK_TIME_BY_X)
                .unwrap(),
        )
    {
        return Err(StdError::generic_err("Collecting jackpot is closed"));
    }
    // Ensure there is jackpot reward to claim
    if jackpot_reward.is_zero() {
        return Err(StdError::generic_err("No jackpot reward"));
    }
    let addr = match address {
        None => info.sender.clone(),
        Some(addr) => Addr::unchecked(addr),
    };

    // Get the contract balance
    let balance = deps
        .querier
        .query_balance(&env.contract.address, &state.denom_stable)?;
    // Ensure the contract have the balance
    if balance.amount.is_zero() {
        return Err(StdError::generic_err("Empty contract balance"));
    }

    let canonical_addr = deps.api.addr_canonicalize(&addr.as_str())?;
    // Load winner
    let mut rewards = match PREFIXED_WINNER.may_load(
        deps.storage,
        (
            &last_lottery_counter_round.to_be_bytes(),
            canonical_addr.as_slice(),
        ),
    )? {
        None => {
            return Err(StdError::generic_err("Address is not a winner"));
        }
        Some(rewards) => Some(rewards),
    }
    .unwrap();

    if rewards.claimed {
        return Err(StdError::generic_err("Already claimed"));
    }

    // Ensure the contract have sufficient balance to handle the transaction
    if balance.amount < jackpot_reward {
        return Err(StdError::generic_err("Not enough funds in the contract"));
    }

    let mut total_prize: u128 = 0;
    for rank in rewards.clone().ranks {
        let rank_count = PREFIXED_RANK.load(
            deps.storage,
            (
                &last_lottery_counter_round.to_be_bytes(),
                &rank.to_be_bytes(),
            ),
        )?;
        let prize = jackpot_reward
            .mul(Decimal::percent(
                state.prize_rank_winner_percentage[rank as usize - 1] as u64,
            ))
            .u128()
            / rank_count.u128() as u128;
        total_prize += prize
    }

    // update the winner to claimed true
    rewards.claimed = true;
    PREFIXED_WINNER.save(
        deps.storage,
        (
            &last_lottery_counter_round.to_be_bytes(),
            canonical_addr.as_slice(),
        ),
        &rewards,
    )?;

    let total_prize = Uint128::from(total_prize);
    // Amount token holders can claim of the reward as fee
    let token_holder_fee_reward = total_prize.mul(Decimal::percent(
        state.token_holder_percentage_fee_reward as u64,
    ));

    let total_prize_after = total_prize.checked_sub(token_holder_fee_reward)?;

    let loterra_human = deps
        .api
        .addr_humanize(&state.loterra_staking_contract_address)?;
    let msg_update_global_index = QueryMsg::UpdateGlobalIndex {};

    let res_update_global_index = WasmMsg::Execute {
        contract_addr: loterra_human.to_string(),
        msg: to_binary(&msg_update_global_index)?,
        send: vec![deduct_tax(
            &deps.querier,
            Coin {
                denom: state.denom_stable.clone(),
                amount: token_holder_fee_reward,
            },
        )?],
    }
    .into();

    // Build the amount transaction
    let msg = BankMsg::Send {
        to_address: addr.to_string(),
        amount: vec![deduct_tax(
            &deps.querier,
            Coin {
                denom: state.denom_stable,
                amount: total_prize_after,
            },
        )?],
    };

    // Send the jackpot
    Ok(Response {
        submessages: vec![],
        messages: vec![msg.into(), res_update_global_index],
        data: None,
        attributes: vec![
            attr("action", "handle_collect"),
            attr("by", info.sender),
            attr("to", addr),
            attr("prize_collect", "true"),
        ],
    })
}

pub fn handle_present_proposal(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    poll_id: u64,
) -> StdResult<Response> {
    // Load storage
    let mut state = read_state(deps.storage)?;
    // Only Dao contract can call this message
    if info.sender != deps.api.addr_humanize(&state.dao_contract_address)? {
        return Err(StdError::generic_err("Unauthorized"));
    }

    let msg = DaoQueryMsg::GetPoll { poll_id };
    let execute_query = WasmQuery::Smart { contract_addr: deps.api.addr_humanize( &state.dao_contract_address)?.to_string(), msg: to_binary(&msg)? };
    let poll: GetPollResponse = deps.querier.query(&execute_query.into())?;


    let mut msgs = vec![];
    // Valid the proposal
    match poll.proposal {
        Proposal::LotteryEveryBlockTime => {
            state.every_block_time_play = poll.amount.u128() as u64;
        }
        Proposal::DrandWorkerFeePercentage => {
            state.fee_for_drand_worker_in_percentage = poll.amount.u128() as u8;
        }
        Proposal::JackpotRewardPercentage => {
            state.jackpot_percentage_reward = poll.amount.u128() as u8;
        }
        Proposal::AmountToRegister => {
            state.price_per_ticket_to_register = poll.amount;
        }
        Proposal::PrizesPerRanks => {
            state.prize_rank_winner_percentage = poll.prizes_per_ranks;
        }
        Proposal::HolderFeePercentage => {
            state.token_holder_percentage_fee_reward = poll.amount.u128() as u8
        }
        Proposal::SecurityMigration => {
            let migration: Migration = poll.migration.unwrap();

            let migrate = WasmMsg::Migrate {
                contract_addr: migration.contract_addr,
                new_code_id: migration.new_code_id,
                msg: migration.msg
            };

            msgs.push(migrate.into())
        }
        Proposal::DaoFunding => {

            let recipient = match poll.recipient {
                None => poll.creator.to_string(),
                Some(address) => address,
            };

            // Get the contract balance prepare the tx
            let msg_balance = Cw20QueryMsg::Balance {
                address: env.contract.address.to_string(),
            };

            let loterra_human = deps
                .api
                .addr_humanize(&state.loterra_cw20_contract_address)?;

            let res_balance = WasmQuery::Smart {
                contract_addr: loterra_human.to_string(),
                msg: to_binary(&msg_balance)?,
            }
            .into();
            let loterra_balance: BalanceResponse = deps.querier.query(&res_balance)?;

            if loterra_balance.balance.u128() < poll.amount.u128() {
                // Reject the proposal on DAO contract ?
                return Err(StdError::generic_err("error not enough funds"))
                //return reject_proposal(deps.storage, poll_id);
            }
            let msg_transfer = Cw20ExecuteMsg::Transfer {
                recipient: recipient.to_string(),
                amount: poll.amount,
            };

            let loterra_human = deps
                .api
                .addr_humanize(&state.loterra_cw20_contract_address)?;
            let res_transfer = WasmMsg::Execute {
                contract_addr: loterra_human.to_string(),
                msg: to_binary(&msg_transfer)?,
                send: vec![],
            };

            msgs.push(res_transfer.into())
        }
        Proposal::StakingContractMigration => {
            state.loterra_staking_contract_address = deps
                .api
                .addr_canonicalize(&poll.recipient.unwrap())?;
        }
        Proposal::PollSurvey => {}
        _ =>
            // Give back a response to DAO contract
            return Ok(Response {
                submessages: vec![],
                messages: vec![],
                data: None,
                attributes: vec![
                    attr("action", "apply poll"),
                    attr("applied", false),
                    attr("poll_id", poll_id),
                ],
            }),

    }

    store_state(deps.storage, &state)?;

    // Give back a response to DAO contract
    Ok(Response {
        submessages: vec![],
        messages: msgs,
        data: None,
        attributes: vec![
            attr("action", "apply poll"),
            attr("applied", true),
            attr("poll_id", poll_id),
        ],
    })
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
        QueryMsg::Players { lottery_id } => to_binary(&query_all_players(deps, lottery_id)?)?,
        _ => to_binary(&())?,
    };
    Ok(response)
}

fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let state = read_state(deps.storage)?;
    Ok(state)
}
fn query_winner_rank(deps: Deps, lottery_id: u64, rank: u8) -> StdResult<Uint128> {
    let amount = match PREFIXED_RANK.may_load(
        deps.storage,
        (&lottery_id.to_be_bytes(), &rank.to_be_bytes()),
    )? {
        None => Uint128::zero(),
        Some(winners) => winners,
    };
    Ok(amount)
}

fn query_all_players(deps: Deps, lottery_id: u64) -> StdResult<Vec<String>> {
    let players = match ALL_USER_COMBINATION.may_load(deps.storage, &lottery_id.to_be_bytes())? {
        None => {
            return Err(StdError::generic_err("Not found"));
        }
        Some(players) => players
            .iter()
            .map(|e| deps.api.addr_humanize(&e).unwrap().to_string())
            .collect(),
    };

    Ok(players)
}
fn query_jackpot(deps: Deps, lottery_id: u64) -> StdResult<Uint128> {
    let amount = match JACKPOT.may_load(deps.storage, &lottery_id.to_be_bytes())? {
        None => Uint128::zero(),
        Some(jackpot) => jackpot,
    };
    Ok(amount)
}
fn query_count_ticket(deps: Deps, lottery_id: u64) -> StdResult<Uint128> {
    let amount = match COUNT_TICKETS.may_load(deps.storage, &lottery_id.to_be_bytes())? {
        None => Uint128::zero(),
        Some(ticket) => ticket,
    };
    Ok(amount)
}
fn query_count_player(deps: Deps, lottery_id: u64) -> StdResult<Uint128> {
    let amount = match COUNT_PLAYERS.may_load(deps.storage, &lottery_id.to_be_bytes())? {
        None => Uint128::zero(),
        Some(players) => players,
    };

    Ok(amount)
}
fn query_winning_combination(deps: Deps, lottery_id: u64) -> StdResult<String> {
    let combination = match WINNING_COMBINATION.may_load(deps.storage, &lottery_id.to_be_bytes())? {
        None => {
            return Err(StdError::generic_err("Not found"));
        }
        Some(combo) => combo,
    };

    Ok(combination)
}
fn query_all_combination(
    deps: Deps,
    lottery_id: u64,
    address: String,
) -> StdResult<AllCombinationResponse> {
    let addr = deps.api.addr_canonicalize(&address)?;
    let combo = match PREFIXED_USER_COMBINATION
        .may_load(deps.storage, (&lottery_id.to_be_bytes(), &addr.as_slice()))?
    {
        None => {
            return Err(StdError::generic_err("Not found"));
        }
        Some(combination) => combination,
    };

    Ok(AllCombinationResponse { combination: combo })
}

fn query_all_winner(deps: Deps, lottery_id: u64) -> StdResult<AllWinnersResponse> {
    let winners = all_winners(&deps, lottery_id)?;
    let res: StdResult<Vec<WinnerResponse>> = winners
        .into_iter()
        .map(|(can_addr, claims)| {
            Ok(WinnerResponse {
                address: deps.api.addr_humanize(&can_addr)?.to_string(),
                claims,
            })
        })
        .collect();

    Ok(AllWinnersResponse { winners: res? })
}

fn query_round(deps: Deps) -> StdResult<RoundResponse> {
    let state = read_state(deps.storage)?;
    let from_genesis = state
        .block_time_play
        .checked_sub(DRAND_GENESIS_TIME)
        .unwrap();
    let next_round = (from_genesis / DRAND_PERIOD) + DRAND_NEXT_ROUND_SECURITY;

    Ok(RoundResponse { next_round })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_querier::mock_dependencies_custom;
    use crate::msg::{ExecuteMsg, InstantiateMsg};
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{Api, Uint128, Uint64};

    struct BeforeAll {
        default_sender: String,
        default_sender_two: String,
        default_sender_owner: String,
    }
    fn before_all() -> BeforeAll {
        BeforeAll {
            default_sender: "addr0000".to_string(),
            default_sender_two: "addr0001".to_string(),
            default_sender_owner: "addr0002".to_string(),
        }
    }

    fn default_init(deps: DepsMut) {
        const DENOM_STABLE: &str = "ust";
        const BLOCK_TIME_PLAY: u64 = 1610566920;
        const EVERY_BLOCK_TIME_PLAY: u64 = 50000;
        const POLL_DEFAULT_END_HEIGHT: u64 = 40_000;

        let init_msg = InstantiateMsg {
            denom_stable: DENOM_STABLE.to_string(),
            block_time_play: BLOCK_TIME_PLAY,
            every_block_time_play: EVERY_BLOCK_TIME_PLAY,
            poll_default_end_height: POLL_DEFAULT_END_HEIGHT,
            terrand_contract_address: "terrand".to_string(),
            loterra_cw20_contract_address: "cw20".to_string(),
            loterra_staking_contract_address: "staking".to_string(),
        };
        instantiate(deps, mock_env(), mock_info("addr0002", &[]), init_msg).unwrap();
    }

    #[test]
    fn proper_init() {
        let before_all = before_all();
        let mut deps = mock_dependencies(&[]);

        default_init(deps.as_mut());
    }
    #[test]
    fn get_round_play() {
        let before_all = before_all();
        let mut deps = mock_dependencies(&[]);
        default_init(deps.as_mut());
        let res = query_round(deps.as_ref()).unwrap();
        println!("{:?}", res.next_round);
    }

    #[test]
    fn testing_saved_address_winner() {
        let before_all = before_all();
        let mut deps = mock_dependencies(&[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(100_000_000),
        }]);
        default_init(deps.as_mut());

        let winner_address = deps.api.addr_canonicalize(&"address".to_string()).unwrap();
        let winner_address2 = deps.api.addr_canonicalize(&"address2".to_string()).unwrap();
        save_winner(&mut deps.storage, 1u64, winner_address, 2).unwrap();
        save_winner(&mut deps.storage, 1u64, winner_address2, 2).unwrap();

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

            let mut state = read_state(deps.as_ref().storage).unwrap();
            let info = mock_info(before_all.default_sender.as_str(), &[]);
            let mut env = mock_env();
            env.block.time = Timestamp::from_seconds(state.block_time_play);
            let res = execute(deps.as_mut(), env, info, msg);
            match res {
                Err(StdError::GenericErr { msg, .. }) => assert_eq!(msg, "Claiming is closed"),
                _ => panic!("Unexpected error"),
            }
        }

        #[test]
        fn no_winning_combination() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());

            let msg = ExecuteMsg::Claim { addresses: None };
            let state = read_state(deps.as_ref().storage).unwrap();
            let mut env = mock_env();
            env.block.time = Timestamp::from_seconds(
                (state
                    .block_time_play
                    .checked_sub(state.every_block_time_play / DIV_BLOCK_TIME_BY_X)
                    .unwrap()),
            );
            println!("{:?}", env.block.time);
            println!("{:?}", state.block_time_play);
            let res = execute(
                deps.as_mut(),
                env,
                mock_info(before_all.default_sender.as_str(), &[]),
                msg,
            );
            match res {
                Err(StdError::GenericErr { msg, .. }) => assert_eq!(msg, "No winning combination"),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn no_combination() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let addr = deps
                .api
                .addr_canonicalize(&before_all.default_sender)
                .unwrap();
            let mut state = read_state(deps.as_ref().storage).unwrap();
            state.lottery_counter = 2;
            store_state(deps.as_mut().storage, &state).unwrap();
            let last_lottery_counter_round = state.lottery_counter - 1;
            // Save winning combination
            WINNING_COMBINATION
                .save(
                    deps.as_mut().storage,
                    &last_lottery_counter_round.to_be_bytes(),
                    &"123456".to_string(),
                )
                .unwrap();
            let msg = ExecuteMsg::Claim { addresses: None };

            let mut env = mock_env();
            env.block.time = Timestamp::from_seconds(
                state
                    .block_time_play
                    .checked_sub(state.every_block_time_play / DIV_BLOCK_TIME_BY_X)
                    .unwrap(),
            );
            let res = execute(
                deps.as_mut(),
                env,
                mock_info(before_all.default_sender.as_str(), &[]),
                msg,
            );
            match res {
                Err(StdError::GenericErr { msg, .. }) => assert_eq!(msg, "No combination found"),
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
                .addr_canonicalize(&before_all.default_sender)
                .unwrap();
            let mut state = read_state(deps.as_ref().storage).unwrap();
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
                ],
            )
            .unwrap();

            // Save winning combination
            WINNING_COMBINATION
                .save(
                    deps.as_mut().storage,
                    &state.lottery_counter.to_be_bytes(),
                    &"123456".to_string(),
                )
                .unwrap();
            state.lottery_counter = 2;
            store_state(deps.as_mut().storage, &state).unwrap();

            let msg = ExecuteMsg::Claim { addresses: None };
            let mut env = mock_env();
            env.block.time = Timestamp::from_seconds(
                state
                    .block_time_play
                    .checked_sub(state.every_block_time_play / DIV_BLOCK_TIME_BY_X)
                    .unwrap(),
            );
            let res = execute(
                deps.as_mut(),
                env.clone(),
                mock_info(before_all.default_sender.as_str().clone(), &[]),
                msg.clone(),
            )
            .unwrap();

            println!("{:?}", res);
            assert_eq!(
                res,
                Response {
                    submessages: vec![],
                    messages: vec![],
                    data: None,
                    attributes: vec![attr("action", "claim")]
                }
            );
            // Claim again is not possible
            let res = execute(
                deps.as_mut(),
                env,
                mock_info(before_all.default_sender.as_str().clone(), &[]),
                msg.clone(),
            );
            match res {
                Err(StdError::GenericErr { msg, .. }) => {
                    assert_eq!(msg, "No winning combination or already claimed")
                }
                _ => panic!("Unexpected error"),
            }

            let last_lottery_counter_round = state.lottery_counter - 1;
            let winners = PREFIXED_WINNER
                .load(
                    deps.as_ref().storage,
                    (&last_lottery_counter_round.to_be_bytes(), &addr.as_slice()),
                )
                .unwrap();

            println!("{:?}", winners);
            assert!(!winners.claimed);
            assert_eq!(winners.ranks.len(), 3);
            assert_eq!(winners.ranks[0], 1);
            assert_eq!(winners.ranks[1], 2);
            assert_eq!(winners.ranks[2], 2);
        }
    }

    mod register {
        // handle_register
        use super::*;
        use cosmwasm_std::from_binary;

        #[test]
        fn register_success() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let msg = ExecuteMsg::Register {
                address: None,
                combination: vec![
                    "1e3fab".to_string(),
                    "abcdef".to_string(),
                    "123456".to_string(),
                ],
            };
            let mut env = mock_env();
            let state = read_state(deps.as_ref().storage).unwrap();
            env.block.time = Timestamp::from_seconds(state.block_time_play.checked_sub(1).unwrap());
            let res = execute(
                deps.as_mut(),
                env.clone(),
                mock_info(
                    before_all.default_sender.as_str(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(3_000_000),
                    }],
                ),
                msg,
            )
            .unwrap();

            assert_eq!(
                res,
                Response {
                    submessages: vec![],
                    messages: vec![],
                    data: None,
                    attributes: vec![
                        attr("action", "register"),
                        attr("price_per_ticket", "1000000"),
                        attr("amount_ticket_purchased", "3"),
                        attr("buyer", "addr0000")
                    ]
                }
            );
            // Check combination added with success
            let addr = deps
                .api
                .addr_canonicalize(&before_all.default_sender)
                .unwrap();
            let store_two = PREFIXED_USER_COMBINATION
                .load(
                    deps.as_mut().storage,
                    (&1u64.to_be_bytes(), &addr.as_slice()),
                )
                .unwrap();
            assert_eq!(3, store_two.len());
            let msg_query = QueryMsg::Players { lottery_id: 1 };
            let res = query(deps.as_ref(), mock_env(), msg_query).unwrap();
            let formated_binary = String::from_utf8(res.into()).unwrap();
            println!("sdsds {:?}", formated_binary);

            // Play 2 more combination
            let msg = ExecuteMsg::Register {
                address: None,
                combination: vec!["affe3b".to_string(), "098765".to_string()],
            };

            let res = execute(
                deps.as_mut(),
                env.clone(),
                mock_info(
                    before_all.default_sender.as_str(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(2_000_000),
                    }],
                ),
                msg,
            )
            .unwrap();

            // Check combination added with success
            let addr = deps
                .api
                .addr_canonicalize(&before_all.default_sender)
                .unwrap();
            let store_two = PREFIXED_USER_COMBINATION
                .load(
                    deps.as_mut().storage,
                    (&1u64.to_be_bytes(), &addr.as_slice()),
                )
                .unwrap();

            assert_eq!(5, store_two.len());
            assert_eq!(store_two[3], "affe3b".to_string());
            assert_eq!(store_two[4], "098765".to_string());

            // Someone registering combination for other player
            let msg = ExecuteMsg::Register {
                address: Some(before_all.default_sender_two.clone()),
                combination: vec!["aaaaaa".to_string(), "bbbbbb".to_string()],
            };
            // default_sender_two sending combination for default_sender
            let res = execute(
                deps.as_mut(),
                env,
                mock_info(
                    before_all.default_sender.as_str(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(2_000_000),
                    }],
                ),
                msg,
            )
            .unwrap();

            // Check combination added with success
            let addr = deps
                .api
                .addr_canonicalize(&before_all.default_sender_two)
                .unwrap();
            let store_two = PREFIXED_USER_COMBINATION
                .load(
                    deps.as_mut().storage,
                    (&1u64.to_be_bytes(), &addr.as_slice()),
                )
                .unwrap();
            assert_eq!(2, store_two.len());
            assert_eq!(store_two[0], "aaaaaa".to_string());
            assert_eq!(store_two[1], "bbbbbb".to_string());

            let msg = QueryMsg::CountPlayer { lottery_id: 1 };
            let res = query(deps.as_ref(), mock_env(), msg).unwrap();
            let r: Uint128 = from_binary(&res).unwrap();
            //let r = String::from_utf8(res.into()).unwrap();
            assert_eq!(Uint128(2), r);
        }
        #[test]
        fn register_fail_if_sender_sent_empty_funds() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[]);
            default_init(deps.as_mut());
            let msg = ExecuteMsg::Register {
                address: None,
                combination: vec!["1e3fab".to_string()],
            };
            let mut env = mock_env();
            let state = read_state(deps.as_ref().storage).unwrap();
            env.block.time = Timestamp::from_seconds(state.block_time_play.checked_sub(1).unwrap());
            let res = execute(
                deps.as_mut(),
                env,
                mock_info(
                    before_all.default_sender.as_str(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128::zero(),
                    }],
                ),
                msg,
            );

            match res {
                Err(StdError::GenericErr { msg, .. }) => assert_eq!(
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
                combination: vec!["1e3fab".to_string()],
            };
            let mut env = mock_env();
            let state = read_state(deps.as_ref().storage).unwrap();
            env.block.time = Timestamp::from_seconds(state.block_time_play.checked_sub(1).unwrap());
            let res = execute(
                deps.as_mut(),
                env,
                mock_info(
                    before_all.default_sender.as_str(),
                    &[
                        Coin {
                            denom: "ust".to_string(),
                            amount: Uint128(1_000_000),
                        },
                        Coin {
                            denom: "wrong".to_string(),
                            amount: Uint128(10),
                        },
                    ],
                ),
                msg,
            );

            match res {
                Err(StdError::GenericErr { msg, .. }) => {
                    assert_eq!(msg, "Only send ust to register")
                }
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
                combination: vec!["1e3fab".to_string()],
            };

            let mut env = mock_env();
            let state = read_state(deps.as_ref().storage).unwrap();
            env.block.time = Timestamp::from_seconds(state.block_time_play.checked_sub(1).unwrap());
            let res = execute(
                deps.as_mut(),
                env,
                mock_info(
                    before_all.default_sender.as_str(),
                    &[Coin {
                        denom: "wrong".to_string(),
                        amount: Uint128(1_000_000),
                    }],
                ),
                msg,
            );

            match res {
                Err(StdError::GenericErr { msg, .. }) => assert_eq!(
                    msg,
                    "you need to send 1000000ust per combination in order to register"
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
                combination: vec!["1e3far".to_string()],
            };
            let mut env = mock_env();
            let state = read_state(deps.as_ref().storage).unwrap();
            env.block.time = Timestamp::from_seconds(state.block_time_play.checked_sub(1).unwrap());
            let res = execute(
                deps.as_mut(),
                env,
                mock_info(
                    before_all.default_sender.as_str(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(1_000_000),
                    }],
                ),
                msg,
            );

            match res {
                Err(StdError::GenericErr { msg, .. }) => assert_eq!(
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
                combination: vec!["1e3far".to_string(), "1e3fac".to_string()],
            };
            let mut env = mock_env();
            let state = read_state(deps.as_ref().storage).unwrap();
            env.block.time = Timestamp::from_seconds(state.block_time_play.checked_sub(1).unwrap());
            let res = execute(
                deps.as_mut(),
                env,
                mock_info(
                    before_all.default_sender.as_str(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(2_000_000),
                    }],
                ),
                msg,
            );

            match res {
                Err(StdError::GenericErr { msg, .. }) => assert_eq!(
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
                combination: vec!["1e3fae".to_string(), "1e3fa2".to_string()],
            };

            let mut env = mock_env();
            let state = read_state(deps.as_ref().storage).unwrap();
            env.block.time = Timestamp::from_seconds(state.block_time_play.checked_sub(1).unwrap());
            // Fail sending less than required (1_000_000)
            let res = execute(
                deps.as_mut(),
                env.clone(),
                mock_info(
                    before_all.default_sender.as_str(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(1_000_000),
                    }],
                ),
                msg.clone(),
            );
            match res {
                Err(StdError::GenericErr { msg, .. }) => assert_eq!(msg, "send 2000000ust"),
                _ => panic!("Unexpected error"),
            }
            // Fail sending more than required (2_000_000)
            let res = execute(
                deps.as_mut(),
                env,
                mock_info(
                    before_all.default_sender.as_str(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(3_000_000),
                    }],
                ),
                msg,
            );
            match res {
                Err(StdError::GenericErr { msg, .. }) => assert_eq!(msg, "send 2000000ust"),
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
                combination: vec!["1e3fae".to_string()],
            };
            let state = read_state(deps.as_ref().storage).unwrap();

            let mut env = mock_env();
            let state = read_state(deps.as_ref().storage).unwrap();
            // Block time is superior to block_time_play so the lottery is about to start
            env.block.time =
                Timestamp::from_seconds(state.block_time_play.checked_add(1000).unwrap());
            let res = execute(
                deps.as_mut(),
                env,
                mock_info(
                    before_all.default_sender.as_str(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(3_000_000),
                    }],
                ),
                msg,
            );
            match res {
                Err(StdError::GenericErr { msg, .. }) => assert_eq!(msg, "Lottery about to start"),
                _ => panic!("Unexpected error"),
            }
        }
    }

    mod play {
        use super::*;
        use cosmwasm_std::{CosmosMsg, Uint64};

        #[test]
        fn not_allowed_registration_in_progress() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128(9_000_000),
            }]);
            default_init(deps.as_mut());
            let mut state = read_state(deps.as_ref().storage).unwrap();
            let env = mock_env();
            state.block_time_play =
                env.block.time.plus_seconds(state.block_time_play).nanos() / 1_000_000_000;
            store_state(deps.as_mut().storage, &state).unwrap();
            let info = mock_info(before_all.default_sender.as_str(), &[]);
            let res = handle_play(deps.as_mut(), env, info);
            match res {
                Err(StdError::GenericErr { msg, .. }) => {
                    assert_eq!(msg, "Lottery registration is still in progress... Retry after block time 3182364339")
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn do_not_send_funds() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128(9_000_000),
            }]);
            default_init(deps.as_mut());
            let state = read_state(deps.as_ref().storage).unwrap();
            let mut env = mock_env();
            let info = mock_info(
                before_all.default_sender.as_str(),
                &[Coin {
                    denom: "ust".to_string(),
                    amount: Uint128(9),
                }],
            );
            env.block.time =
                Timestamp::from_seconds(state.block_time_play.checked_add(1000).unwrap());
            let res = handle_play(deps.as_mut(), env, info);
            println!("{:?}", res);
            match res {
                Err(StdError::GenericErr { msg, .. }) => {
                    assert_eq!(msg, "Do not send funds with play")
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn multi_contract_call_terrand() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128(9_000_000),
            }]);

            default_init(deps.as_mut());
            let state = read_state(deps.as_ref().storage).unwrap();
            let mut env = mock_env();
            env.block.time =
                Timestamp::from_seconds(state.block_time_play.checked_add(1000).unwrap());
            let info = mock_info(before_all.default_sender_owner.as_str(), &[]);
            let res = handle_play(deps.as_mut(), env, info).unwrap();
            assert_eq!(res.messages.len(), 1);
        }

        #[test]
        fn success() {
            let before_all = before_all();
            let contract_balance = Uint128(9_000_000);
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: contract_balance.clone(),
            }]);

            default_init(deps.as_mut());
            let state = read_state(deps.as_ref().storage).unwrap();
            let mut env = mock_env();
            env.block.time =
                Timestamp::from_seconds(state.block_time_play.checked_sub(1000).unwrap());
            // register some combination
            let msg = ExecuteMsg::Register {
                address: None,
                combination: vec!["1e3fab".to_string()],
            };
            execute(
                deps.as_mut(),
                env.clone(),
                mock_info(
                    before_all.default_sender.as_str(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(1_000_000),
                    }],
                ),
                msg.clone(),
            )
            .unwrap();

            let msg = ExecuteMsg::Register {
                address: None,
                combination: vec!["39493d".to_string()],
            };
            execute(
                deps.as_mut(),
                env,
                mock_info(
                    before_all.default_sender_two.as_str(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(1_000_000),
                    }],
                ),
                msg.clone(),
            )
            .unwrap();

            let state = read_state(deps.as_ref().storage).unwrap();
            JACKPOT
                .save(
                    deps.as_mut().storage,
                    &(state.lottery_counter - 1).to_be_bytes(),
                    &Uint128::zero(),
                )
                .unwrap();

            let jackpot_reward_before = JACKPOT
                .load(
                    deps.as_ref().storage,
                    &(state.lottery_counter - 1).to_be_bytes(),
                )
                .unwrap();

            let mut env = mock_env();
            env.block.time =
                Timestamp::from_seconds(state.block_time_play.checked_add(1000).unwrap());

            let info = mock_info(before_all.default_sender_owner.as_str(), &[]);
            let res = handle_play(deps.as_mut(), env, info).unwrap();
            println!("{:?}", res);
            assert_eq!(res.messages.len(), 1);
            assert_eq!(
                res.messages[0],
                CosmosMsg::Bank(BankMsg::Send {
                    to_address: "terra1q88h7ewu6h3am4mxxeqhu3srxterrandworker".to_string(),
                    amount: vec![Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(178)
                    }]
                })
            );

            let store = WINNING_COMBINATION
                .load(deps.as_ref().storage, &state.lottery_counter.to_be_bytes())
                .unwrap();
            assert_eq!(store, "39493d");
            let state_after = read_state(deps.as_ref().storage).unwrap();
            let jackpot_reward_after = JACKPOT
                .load(deps.as_ref().storage, &state.lottery_counter.to_be_bytes())
                .unwrap();

            // TODO add winner checks

            println!("{:?}", jackpot_reward_after);
            assert_eq!(20, state_after.token_holder_percentage_fee_reward);
            assert_eq!(jackpot_reward_before, Uint128::zero());
            assert_ne!(jackpot_reward_after, jackpot_reward_before);
            // 720720 total fees
            assert_eq!(jackpot_reward_after, Uint128(1_799_820));
            assert_eq!(state_after.lottery_counter, 2);
            assert_ne!(state_after.lottery_counter, state.lottery_counter);
        }

        #[test]
        fn success_no_big_winner() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128(9_000_000),
            }]);

            default_init(deps.as_mut());
            let state = read_state(deps.as_ref().storage).unwrap();
            let mut env = mock_env();
            env.block.time =
                Timestamp::from_seconds(state.block_time_play.checked_sub(1000).unwrap());
            // register some combination
            let msg = ExecuteMsg::Register {
                address: None,
                combination: vec!["39498d".to_string()],
            };
            execute(
                deps.as_mut(),
                env.clone(),
                mock_info(
                    before_all.default_sender_two.as_str().clone(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(1_000_000),
                    }],
                ),
                msg.clone(),
            )
            .unwrap();

            let state = read_state(deps.as_ref().storage).unwrap();
            JACKPOT
                .save(
                    deps.as_mut().storage,
                    &(state.lottery_counter - 1).to_be_bytes(),
                    &Uint128::zero(),
                )
                .unwrap();

            let jackpot_reward_before = JACKPOT
                .load(
                    deps.as_ref().storage,
                    &(state.lottery_counter - 1).to_be_bytes(),
                )
                .unwrap();
            let mut env = mock_env();
            env.block.time =
                Timestamp::from_seconds(state.block_time_play.checked_add(1000).unwrap());
            let info = mock_info(before_all.default_sender_owner.as_str().clone(), &[]);
            let res = handle_play(deps.as_mut(), env.clone(), info.clone()).unwrap();
            println!("{:?}", res);
            assert_eq!(res.messages.len(), 1);
            assert_eq!(
                res.messages[0],
                CosmosMsg::Bank(BankMsg::Send {
                    to_address: "terra1q88h7ewu6h3am4mxxeqhu3srxterrandworker".to_string(),
                    amount: vec![Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(178)
                    }]
                })
            );

            // TODO add winner check
            let state_after = read_state(deps.as_ref().storage).unwrap();
            let jackpot_reward_after = JACKPOT
                .load(deps.as_ref().storage, &state.lottery_counter.to_be_bytes())
                .unwrap();

            println!("{:?}", jackpot_reward_after);
            assert_eq!(20, state_after.token_holder_percentage_fee_reward);
            assert_eq!(jackpot_reward_before, Uint128::zero());
            assert_ne!(jackpot_reward_after, jackpot_reward_before);
            // 720720 total fees
            assert_eq!(jackpot_reward_after, Uint128(1_799_820));
            assert_eq!(state_after.lottery_counter, 2);
            assert_ne!(state_after.lottery_counter, state.lottery_counter);
        }
        #[test]
        fn success_bonus_holder_end_fee_superior_20_percent() {
            let before_all = before_all();
            let contract_balance = Uint128(9_000_000);
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: contract_balance.clone(),
            }]);

            default_init(deps.as_mut());
            let state = read_state(deps.as_ref().storage).unwrap();
            let mut env = mock_env();
            env.block.time =
                Timestamp::from_seconds(state.block_time_play.checked_sub(1000).unwrap());
            // register some combination
            let msg = ExecuteMsg::Register {
                address: None,
                combination: vec!["1e3fab".to_string()],
            };
            execute(
                deps.as_mut(),
                env.clone(),
                mock_info(
                    before_all.default_sender.as_str().clone(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(1_000_000),
                    }],
                ),
                msg.clone(),
            )
            .unwrap();

            let msg = ExecuteMsg::Register {
                address: None,
                combination: vec!["39493d".to_string()],
            };
            execute(
                deps.as_mut(),
                env,
                mock_info(
                    before_all.default_sender_two.as_str().clone(),
                    &[Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(1_000_000),
                    }],
                ),
                msg.clone(),
            )
            .unwrap();

            let state = read_state(deps.as_ref().storage).unwrap();
            assert_eq!(20, state.token_holder_percentage_fee_reward);
            JACKPOT
                .save(
                    deps.as_mut().storage,
                    &(state.lottery_counter - 1).to_be_bytes(),
                    &Uint128::zero(),
                )
                .unwrap();
            let jackpot_reward_before = JACKPOT
                .load(
                    deps.as_ref().storage,
                    &(state.lottery_counter - 1).to_be_bytes(),
                )
                .unwrap();

            let mut env = mock_env();
            env.block.time =
                Timestamp::from_seconds(state.block_time_play.checked_add(10_000).unwrap());
            let info = mock_info(before_all.default_sender_owner.as_str(), &[]);
            let res = handle_play(deps.as_mut(), env.clone(), info.clone()).unwrap();
            println!("{:?}", res);

            assert_eq!(res.messages.len(), 1);
            assert_eq!(
                res.messages[0],
                CosmosMsg::Bank(BankMsg::Send {
                    to_address: "terra1q88h7ewu6h3am4mxxeqhu3srxterrandworker".to_string(),
                    amount: vec![Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(178)
                    }]
                })
            );

            let store = WINNING_COMBINATION
                .load(deps.as_ref().storage, &state.lottery_counter.to_be_bytes())
                .unwrap();
            assert_eq!(store, "39493d");

            // TODO add winner checks
            let state_after = read_state(deps.as_ref().storage).unwrap();
            let jackpot_reward_after = JACKPOT
                .load(deps.as_ref().storage, &state.lottery_counter.to_be_bytes())
                .unwrap();

            println!("{:?}", jackpot_reward_after);
            assert_eq!(20, state_after.token_holder_percentage_fee_reward);
            assert_eq!(jackpot_reward_before, Uint128::zero());
            assert_ne!(jackpot_reward_after, jackpot_reward_before);
            // 720720 total fees
            assert_eq!(jackpot_reward_after, Uint128(1_799_820));
            assert_eq!(state_after.lottery_counter, 2);
            assert_ne!(state_after.lottery_counter, state.lottery_counter);
        }
    }

    mod collect {
        use super::*;
        use cosmwasm_std::CosmosMsg;

        #[test]
        fn do_not_send_funds() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128(9_000_000),
            }]);
            default_init(deps.as_mut());
            let info = mock_info(
                before_all.default_sender.as_str().clone(),
                &[Coin {
                    denom: "uluna".to_string(),
                    amount: Uint128(1_000),
                }],
            );
            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), mock_env(), info, msg);
            println!("{:?}", res);
            match res {
                Err(StdError::GenericErr { msg, .. }) => {
                    assert_eq!(msg, "Do not send funds with jackpot")
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn collect_jackpot_is_closed() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128(9_000_000),
            }]);
            default_init(deps.as_mut());
            let state = read_state(deps.as_ref().storage).unwrap();
            JACKPOT
                .save(
                    deps.as_mut().storage,
                    &(state.lottery_counter - 1).to_be_bytes(),
                    &Uint128::zero(),
                )
                .unwrap();
            let mut env = mock_env();
            env.block.time = Timestamp::from_seconds(
                state
                    .block_time_play
                    .checked_sub(state.every_block_time_play)
                    .unwrap(),
            );

            let info = mock_info(before_all.default_sender.as_str().clone(), &[]);
            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env, info, msg);
            match res {
                Err(StdError::GenericErr { msg, .. }) => {
                    assert_eq!(msg, "Collecting jackpot is closed")
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn no_jackpot_rewards() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128(9_000_000),
            }]);
            default_init(deps.as_mut());
            let state = read_state(deps.as_ref().storage).unwrap();
            JACKPOT
                .save(
                    deps.as_mut().storage,
                    &(state.lottery_counter - 1).to_be_bytes(),
                    &Uint128::zero(),
                )
                .unwrap();
            let mut env = mock_env();
            env.block.time = Timestamp::from_seconds(
                state
                    .block_time_play
                    .checked_sub(state.every_block_time_play / 2)
                    .unwrap(),
            );
            let info = mock_info(before_all.default_sender.as_str().clone(), &[]);
            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env, info, msg);

            match res {
                Err(StdError::GenericErr { msg, .. }) => assert_eq!(msg, "No jackpot reward"),
                _ => panic!("Unexpected error"),
            }
        }

        #[test]
        fn no_winners() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128(9_000_000),
            }]);
            default_init(deps.as_mut());
            let mut state = read_state(deps.as_ref().storage).unwrap();
            JACKPOT
                .save(
                    deps.as_mut().storage,
                    &(state.lottery_counter - 1).to_be_bytes(),
                    &Uint128(1_000_000),
                )
                .unwrap();
            let state = read_state(deps.as_ref().storage).unwrap();
            let mut env = mock_env();
            env.block.time = Timestamp::from_seconds(
                state
                    .block_time_play
                    .checked_sub(state.every_block_time_play / 2)
                    .unwrap(),
            );
            let info = mock_info(before_all.default_sender.as_str().clone(), &[]);
            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env, info, msg);
            match res {
                Err(StdError::GenericErr { msg, .. }) => assert_eq!(msg, "Address is not a winner"),
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn contract_balance_empty() {
            let before_all = before_all();
            let mut deps = mock_dependencies(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128(0),
            }]);

            default_init(deps.as_mut());
            let mut state_before = read_state(deps.as_ref().storage).unwrap();
            JACKPOT
                .save(
                    deps.as_mut().storage,
                    &(state_before.lottery_counter - 1).to_be_bytes(),
                    &Uint128(1_000_000),
                )
                .unwrap();

            let addr1 = deps.api.addr_canonicalize(&"address1".to_string()).unwrap();
            let addr2 = deps
                .api
                .addr_canonicalize(&before_all.default_sender)
                .unwrap();
            println!(
                "{:?}",
                deps.api.addr_canonicalize(&"address1".to_string()).unwrap()
            );

            save_winner(deps.as_mut().storage, 1u64, addr1.clone(), 1).unwrap();

            save_winner(deps.as_mut().storage, 1u64, addr2, 1).unwrap();
            let state = read_state(deps.as_ref().storage).unwrap();
            let mut env = mock_env();
            env.block.time = Timestamp::from_seconds(
                state
                    .block_time_play
                    .checked_sub(state.every_block_time_play / 2)
                    .unwrap(),
            );
            let info = mock_info("address1", &[]);
            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env, info, msg);

            println!("{:?}", res);
            match res {
                Err(StdError::GenericErr { msg, .. }) => assert_eq!(msg, "Empty contract balance"),
                _ => panic!("Unexpected error"),
            }
            /*
            let store = winner_storage(&mut deps.storage, 1u64)
                .load(&1_u8.to_be_bytes())
                .unwrap();
            let claimed_address = deps
                .api
                .canonical_address(&before_all.default_sender)
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
                amount: Uint128(9_000_000),
            }]);
            default_init(deps.as_mut());
            let mut state_before = read_state(deps.as_ref().storage).unwrap();
            JACKPOT
                .save(
                    deps.as_mut().storage,
                    &(state_before.lottery_counter - 1).to_be_bytes(),
                    &Uint128(1_000_000),
                )
                .unwrap();

            let addr = deps.api.addr_canonicalize(&"address".to_string()).unwrap();
            let addr_default = deps
                .api
                .addr_canonicalize(&before_all.default_sender)
                .unwrap();

            save_winner(deps.as_mut().storage, 1u64, addr.clone(), 1).unwrap();
            save_winner(deps.as_mut().storage, 1u64, addr_default.clone(), 1).unwrap();

            save_winner(deps.as_mut().storage, 1u64, addr.clone(), 4).unwrap();
            save_winner(deps.as_mut().storage, 1u64, addr_default.clone(), 4).unwrap();

            let mut env = mock_env();
            env.block.time = Timestamp::from_seconds(
                state_before
                    .block_time_play
                    .checked_sub(state_before.every_block_time_play / 2)
                    .unwrap(),
            );
            let msg = ExecuteMsg::Collect { address: None };
            let info = mock_info(before_all.default_sender_two.as_str().clone(), &[]);
            let res = execute(deps.as_mut(), env, info, msg);

            println!("{:?}", res);
            match res {
                Err(StdError::GenericErr { msg, .. }) => assert_eq!(msg, "Address is not a winner"),
                _ => panic!("Unexpected error"),
            }
        }

        #[test]
        fn success() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128(9_000_000),
            }]);
            default_init(deps.as_mut());

            let mut state_before = read_state(deps.as_ref().storage).unwrap();
            state_before.lottery_counter = 2;
            store_state(deps.as_mut().storage, &state_before).unwrap();
            JACKPOT
                .save(
                    deps.as_mut().storage,
                    &(state_before.lottery_counter - 1).to_be_bytes(),
                    &Uint128(1_000_000),
                )
                .unwrap();

            let addr2 = deps.api.addr_canonicalize(&"address2".to_string()).unwrap();
            let default_addr = deps
                .api
                .addr_canonicalize(&before_all.default_sender)
                .unwrap();

            save_winner(deps.as_mut().storage, 1u64, addr2.clone(), 1).unwrap();
            save_winner(deps.as_mut().storage, 1u64, default_addr.clone(), 1).unwrap();

            let mut env = mock_env();
            env.block.time = Timestamp::from_seconds(
                state_before
                    .block_time_play
                    .checked_sub(state_before.every_block_time_play / 2)
                    .unwrap(),
            );

            let msg = ExecuteMsg::Collect { address: None };
            let info = mock_info(before_all.default_sender.as_str().clone(), &[]);
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
            println!("{:?}", res);
            assert_eq!(res.messages.len(), 2);
            let amount_claimed = Uint128(344554);
            assert_eq!(
                res.messages[0],
                CosmosMsg::Bank(BankMsg::Send {
                    to_address: before_all.default_sender.clone(),
                    amount: vec![Coin {
                        denom: "ust".to_string(),
                        amount: amount_claimed.clone()
                    }]
                })
            );

            assert_eq!(
                res.messages[1],
                CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr: deps
                        .api
                        .addr_humanize(&state_before.loterra_staking_contract_address)
                        .unwrap()
                        .to_string(),
                    msg: Binary::from(r#"{"update_global_index":{}}"#.as_bytes()),
                    send: vec![Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(86138)
                    }]
                })
            );
            // Handle can't claim multiple times
            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env, info, msg);

            match res {
                Err(StdError::GenericErr { msg, .. }) => assert_eq!(msg, "Already claimed"),
                _ => panic!("Unexpected error"),
            }

            let claimed_address = deps
                .api
                .addr_canonicalize(&before_all.default_sender)
                .unwrap();
            let winner_claim = PREFIXED_WINNER
                .load(
                    deps.as_mut().storage,
                    (&1u64.to_be_bytes(), claimed_address.as_slice()),
                )
                .unwrap();
            assert_eq!(winner_claim.claimed, true);

            let not_claimed = PREFIXED_WINNER
                .load(
                    deps.as_mut().storage,
                    (&1u64.to_be_bytes(), addr2.as_slice()),
                )
                .unwrap();
            assert_eq!(not_claimed.claimed, false);

            let state_after = read_state(deps.as_ref().storage).unwrap();
            let jackpot_before = JACKPOT
                .load(
                    deps.as_ref().storage,
                    &(state_before.lottery_counter - 1).to_be_bytes(),
                )
                .unwrap();

            let jackpot_after = JACKPOT
                .load(
                    deps.as_ref().storage,
                    &(state_after.lottery_counter - 1).to_be_bytes(),
                )
                .unwrap();
            assert_eq!(state_after, state_before);
        }
        #[test]
        fn success_collecting_for_someone() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128(9_000_000),
            }]);
            default_init(deps.as_mut());

            let mut state_before = read_state(deps.as_ref().storage).unwrap();
            state_before.lottery_counter = 2;
            store_state(deps.as_mut().storage, &&state_before).unwrap();
            JACKPOT
                .save(
                    deps.as_mut().storage,
                    &(state_before.lottery_counter - 1).to_be_bytes(),
                    &Uint128(1_000_000),
                )
                .unwrap();

            let addr2 = deps.api.addr_canonicalize(&"address2".to_string()).unwrap();
            let default_addr = deps
                .api
                .addr_canonicalize(&before_all.default_sender)
                .unwrap();

            save_winner(&mut deps.storage, 1u64, addr2.clone(), 1).unwrap();
            save_winner(&mut deps.storage, 1u64, default_addr.clone(), 1).unwrap();

            let mut env = mock_env();
            env.block.time = Timestamp::from_seconds(
                state_before
                    .block_time_play
                    .checked_sub(state_before.every_block_time_play / 2)
                    .unwrap(),
            );
            let info = mock_info(before_all.default_sender_two.as_str().clone(), &[]);
            let msg = ExecuteMsg::Collect {
                address: Some(before_all.default_sender.clone()),
            };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
            println!("{:?}", res);

            assert_eq!(res.messages.len(), 2);
            let amount_claimed = Uint128(344554);
            assert_eq!(
                res.messages[0],
                CosmosMsg::Bank(BankMsg::Send {
                    to_address: before_all.default_sender.clone(),
                    amount: vec![Coin {
                        denom: "ust".to_string(),
                        amount: amount_claimed.clone()
                    }]
                })
            );
            assert_eq!(
                res.messages[1],
                CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr: deps
                        .api
                        .addr_humanize(&state_before.loterra_staking_contract_address)
                        .unwrap()
                        .to_string(),
                    msg: Binary::from(r#"{"update_global_index":{}}"#.as_bytes()),
                    send: vec![Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(86138)
                    }]
                })
            );
            // Handle can't claim multiple times
            let msg = ExecuteMsg::Collect {
                address: Some(before_all.default_sender.clone()),
            };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);

            match res {
                Err(StdError::GenericErr { msg, .. }) => assert_eq!(msg, "Already claimed"),
                _ => panic!("Unexpected error"),
            }

            let claimed_address = deps
                .api
                .addr_canonicalize(&before_all.default_sender)
                .unwrap();
            let winner_claim = PREFIXED_WINNER
                .load(
                    deps.as_ref().storage,
                    (&1u64.to_be_bytes(), claimed_address.as_slice()),
                )
                .unwrap();
            assert_eq!(winner_claim.claimed, true);

            let not_claimed = PREFIXED_WINNER
                .load(
                    deps.as_ref().storage,
                    (&1u64.to_be_bytes(), addr2.as_slice()),
                )
                .unwrap();
            assert_eq!(not_claimed.claimed, false);

            let state_after = read_state(deps.as_ref().storage).unwrap();
            let jackpot_before = JACKPOT
                .load(
                    deps.as_ref().storage,
                    &(state_before.lottery_counter - 1).to_be_bytes(),
                )
                .unwrap();
            let jackpot_after = JACKPOT
                .load(
                    deps.as_ref().storage,
                    &(state_after.lottery_counter - 1).to_be_bytes(),
                )
                .unwrap();
            assert_eq!(state_after, state_before);
        }
        #[test]
        fn success_multiple_win() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128(9_000_000),
            }]);
            default_init(deps.as_mut());

            let mut state_before = read_state(deps.as_ref().storage).unwrap();
            state_before.lottery_counter = 2;
            store_state(deps.as_mut().storage, &state_before).unwrap();
            JACKPOT
                .save(
                    deps.as_mut().storage,
                    &(state_before.lottery_counter - 1).to_be_bytes(),
                    &Uint128(1_000_000),
                )
                .unwrap();

            let addr2 = deps.api.addr_canonicalize(&"address2".to_string()).unwrap();
            let default_addr = deps
                .api
                .addr_canonicalize(&before_all.default_sender)
                .unwrap();

            // rank 1
            save_winner(&mut deps.storage, 1u64, addr2.clone(), 1).unwrap();
            save_winner(&mut deps.storage, 1u64, default_addr.clone(), 1).unwrap();

            // rank 5
            save_winner(&mut deps.storage, 1u64, addr2.clone(), 2).unwrap();
            save_winner(&mut deps.storage, 1u64, default_addr.clone(), 2).unwrap();
            save_winner(&mut deps.storage, 1u64, default_addr.clone(), 2).unwrap();

            let state = read_state(deps.as_ref().storage).unwrap();
            let mut env = mock_env();
            env.block.time = Timestamp::from_seconds(
                state_before
                    .block_time_play
                    .checked_sub(state_before.every_block_time_play / 2)
                    .unwrap(),
            );
            let info = mock_info(before_all.default_sender.as_str().clone(), &[]);
            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
            assert_eq!(res.messages.len(), 2);
            let amount_claimed = Uint128(397359);
            assert_eq!(
                res.messages[0],
                CosmosMsg::Bank(BankMsg::Send {
                    to_address: before_all.default_sender.clone(),
                    amount: vec![Coin {
                        denom: "ust".to_string(),
                        amount: amount_claimed.clone()
                    }]
                })
            );
            assert_eq!(
                res.messages[1],
                CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr: deps
                        .api
                        .addr_humanize(&state_before.loterra_staking_contract_address)
                        .unwrap()
                        .to_string(),
                    msg: Binary::from(r#"{"update_global_index":{}}"#.as_bytes()),
                    send: vec![Coin {
                        denom: "ust".to_string(),
                        amount: Uint128(99339)
                    }]
                })
            );
            // Handle can't claim multiple times
            let msg = ExecuteMsg::Collect { address: None };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);

            match res {
                Err(StdError::GenericErr { msg, .. }) => assert_eq!(msg, "Already claimed"),
                _ => panic!("Unexpected error"),
            }

            let claimed_address = deps
                .api
                .addr_canonicalize(&before_all.default_sender)
                .unwrap();

            let claimed = PREFIXED_WINNER
                .load(
                    deps.as_ref().storage,
                    (&1u64.to_be_bytes(), claimed_address.as_slice()),
                )
                .unwrap();
            assert_eq!(claimed.claimed, true);

            let not_claimed = PREFIXED_WINNER
                .load(
                    deps.as_ref().storage,
                    (&1u64.to_be_bytes(), addr2.as_slice()),
                )
                .unwrap();
            assert_eq!(not_claimed.claimed, false);

            let state_after = read_state(deps.as_ref().storage).unwrap();
            let jackpot_before = JACKPOT
                .load(
                    deps.as_ref().storage,
                    &(state_before.lottery_counter - 1).to_be_bytes(),
                )
                .unwrap();
            let jackpot_after = JACKPOT
                .load(
                    deps.as_ref().storage,
                    &(state_after.lottery_counter - 1).to_be_bytes(),
                )
                .unwrap();
            assert_eq!(state_after, state_before);
        }
    }

    mod present {
        use super::*;
        use cosmwasm_std::CosmosMsg;

        #[test]
        fn success_dao_funding() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128(9_000_000),
            }]);
            deps.querier.with_token_balances(Uint128(200_000));
            deps.querier.with_holder(
                before_all.default_sender.clone(),
                Uint128(150_000),
                Decimal::zero(),
                Decimal::zero(),
            );

            default_init(deps.as_mut());

            let mut env = mock_env();
            let info = mock_info("addr0002", &[]);
            let state_before = read_state(deps.as_ref().storage).unwrap();
            let msg = ExecuteMsg::PresentPoll { poll_id: 1 };
            let res = execute(deps.as_mut(), env, info, msg).unwrap();
            println!("{:?}", res);
            assert_eq!(res.attributes.len(), 3);
            assert_eq!(res.messages.len(), 1);
            assert_eq!(
                res.messages[0],
                CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr: deps
                        .api
                        .addr_humanize(&state_before.loterra_cw20_contract_address)
                        .unwrap()
                        .to_string(),
                    msg: Binary::from(
                        r#"{"transfer":{"recipient":"addr0002","amount":"22"}}"#.as_bytes()
                    ),
                    send: vec![]
                })
            );

        }
        #[test]
        fn success_staking_migration() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128(9_000_000),
            }]);
            deps.querier.with_token_balances(Uint128(200_000));
            deps.querier.with_holder(
                before_all.default_sender.clone(),
                Uint128(150_000),
                Decimal::zero(),
                Decimal::zero(),
            );
            default_init(deps.as_mut());

            let state_before = read_state(deps.as_ref().storage).unwrap();
            let mut env = mock_env();
            let info = mock_info("addr0002", &[]);
            let msg = ExecuteMsg::PresentPoll { poll_id: 1 };
            let res = execute(deps.as_mut(), env, info, msg).unwrap();
            println!("{:?}", res);
            assert_eq!(res.attributes.len(), 3);
            assert_eq!(res.messages.len(), 0);

            //let state = config(&mut deps);
            let state_after = read_state(deps.as_ref().storage).unwrap();
            assert_ne!(
                state_after.loterra_staking_contract_address,
                state_before.loterra_staking_contract_address
            );
            assert_eq!(
                deps.api
                    .addr_humanize(&state_after.loterra_staking_contract_address)
                    .unwrap()
                    .to_string(),
                "newAddress".to_string()
            );
        }
        #[test]
        fn success_security_migration() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128(9_000_000),
            }]);
            deps.querier.with_token_balances(Uint128(200_000));
            deps.querier.with_holder(
                before_all.default_sender.clone(),
                Uint128(150_000),
                Decimal::zero(),
                Decimal::zero(),
            );
            default_init(deps.as_mut());

            let mut env = mock_env();
            let info = mock_info("addr0002", &[]);
            let msg = ExecuteMsg::PresentPoll { poll_id: 1 };
            let res = execute(deps.as_mut(), env, info, msg).unwrap();
            println!("{:?}", res);
        }
        #[test]
        fn success_with_passed() {
            let before_all = before_all();
            let mut deps = mock_dependencies_custom(&[Coin {
                denom: "ust".to_string(),
                amount: Uint128(9_000_000),
            }]);
            deps.querier.with_token_balances(Uint128(200_000));
            deps.querier.with_holder(
                before_all.default_sender.clone(),
                Uint128(150_000),
                Decimal::zero(),
                Decimal::zero(),
            );
            default_init(deps.as_mut());
            let env = mock_env();
            // not the Dao address
            let info = mock_info("other", &[]);

            let msg = ExecuteMsg::PresentPoll { poll_id: 1 };
            let res = execute(deps.as_mut(), env.clone(), info, msg);
            match res {
                Err(StdError::GenericErr {msg, ..}) => {
                    assert_eq!(msg, "Unauthorized")
                },
                _ => panic!("Do not enter here")
            }

            // With Dao address
            let info = mock_info("addr0002", &[]);
            let msg = ExecuteMsg::PresentPoll { poll_id: 1 };
            let res = execute(deps.as_mut(), env, info, msg).unwrap();
            print!("{:?}", res);

        }

    }
}
