use crate::msg::{QueryMsg, StakingStateResponse};
use crate::query::{GetHolderResponse, LoterraBalanceResponse, TerrandResponse};
use crate::state::{Config, poll_storage, PollStatus};
use cosmwasm_std::{
    to_binary, Deps, CanonicalAddr, Coin, CosmosMsg, Empty, Addr,
    QueryRequest, StdResult, Uint128, WasmMsg, WasmQuery, Response, Storage, StdError,
};
pub fn count_match(x: &str, y: &str) -> usize {
    let mut count = 0;
    for i in 0..y.len() {
        if x.chars().nth(i).unwrap() == y.chars().nth(i).unwrap() {
            count += 1;
        } else {
            break;
        }
    }
    count
}
// There is probably some built-in function for this, but this is a simple way to do it
pub fn is_lower_hex(combination: &str, len: u8) -> bool {
    if combination.len() != (len as usize) {
        return false;
    }
    if !combination
        .chars()
        .all(|c| ('a'..='f').contains(&c) || ('0'..='9').contains(&c))
    {
        return false;
    }
    true
}

pub fn encode_msg_execute(
    msg: QueryMsg,
    address: Addr,
    coin: Vec<Coin>,
) -> StdResult<CosmosMsg> {
    Ok(CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: address.to_string(),
        msg: to_binary(&msg)?,
        funds: coin,
    }).into())
}
pub fn encode_msg_query(msg: QueryMsg, address: Addr) -> StdResult<QueryRequest<Empty>> {
    Ok(WasmQuery::Smart {
        contract_addr: address.to_string(),
        msg: to_binary(&msg)?,
    }
    .into())
}
pub fn wrapper_msg_terrand(
    deps: &Deps,
    query: QueryRequest<Empty>,
) -> StdResult<TerrandResponse> {
    let res: TerrandResponse = deps.querier.query(&query)?;
    Ok(res)
}

pub fn wrapper_msg_loterra_staking(
    deps: &Deps,
    query: QueryRequest<Empty>,
) -> StdResult<GetHolderResponse> {
    let res: GetHolderResponse = deps.querier.query(&query)?;

    Ok(res)
}

pub fn user_total_weight(
    deps: &Deps,
    state: &Config,
    address: &CanonicalAddr,
) -> Uint128 {
    let mut weight = Uint128::zero();
    let human_address = deps.api.addr_humanize(&address).unwrap();

    // Ensure sender have some reward tokens
    let msg = QueryMsg::Holder {
        address: human_address,
    };
    let loterra_human = deps
        .api
        .addr_humanize(&state.loterra_staking_contract_address.clone())
        .unwrap();
    let res = encode_msg_query(msg, loterra_human).unwrap();
    let loterra_balance = wrapper_msg_loterra_staking(&deps, res).unwrap();

    if !loterra_balance.balance.is_zero() {
        weight += loterra_balance.balance;
    }

    weight
}

pub fn total_weight(
    deps: &Deps,
    state: &Config,
) -> Uint128 {
    let msg = QueryMsg::State {};
    let loterra_human = deps
        .api
        .addr_humanize(&state.loterra_staking_contract_address.clone())
        .unwrap();
    let query = encode_msg_query(msg, loterra_human).unwrap();
    let loterra_balance: StakingStateResponse = deps.querier.query(&query).unwrap();
    loterra_balance.total_balance
}

pub fn wrapper_msg_loterra(
    deps: &Deps,
    query: QueryRequest<Empty>,
) -> StdResult<LoterraBalanceResponse> {
    let res: LoterraBalanceResponse = deps.querier.query(&query)?;

    Ok(res)
}

pub fn reject_proposal(
    storage: &mut dyn Storage,
    poll_id: u64,
) -> StdResult<Response> {
    poll_storage(storage).update::<_,StdError>(&poll_id.to_be_bytes(), |poll| {
        let mut poll_data = poll.unwrap();
        // Update the status to rejected
        poll_data.status = PollStatus::Rejected;
        Ok(poll_data)
    })?;
    Ok(Response::new()
        .add_attribute("action", "present the proposal")
        .add_attribute("proposal_id", &poll_id.to_string())
        .add_attribute("proposal_result", "rejected")
    )
}
