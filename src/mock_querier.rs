use crate::msg::StakingStateResponse;
use crate::query::{GetHoldersResponse, HoldersInfo};
use cosmwasm_std::testing::{MockApi, MockQuerier, MockStorage, MOCK_CONTRACT_ADDR};
use cosmwasm_std::{
    from_slice, to_binary, Addr, Binary, Coin, ContractResult, Decimal, OwnedDeps, Querier,
    QuerierResult, QueryRequest, SystemError, SystemResult, Uint128, WasmQuery,
};
use cw20::BalanceResponse;
use serde::Serialize;
use terra_cosmwasm::{TaxCapResponse, TaxRateResponse, TerraQuery, TerraQueryWrapper};

pub fn mock_dependencies_custom(
    contract_balance: &[Coin],
) -> OwnedDeps<MockStorage, MockApi, WasmMockQuerier> {
    let contract_addr = Addr::unchecked(MOCK_CONTRACT_ADDR);
    let custom_querier: WasmMockQuerier = WasmMockQuerier::new(MockQuerier::new(&[(
        &contract_addr.to_string(),
        contract_balance,
    )]));
    OwnedDeps {
        storage: MockStorage::default(),
        api: MockApi::default(),
        querier: custom_querier,
    }
}

pub struct WasmMockQuerier {
    base: MockQuerier<TerraQueryWrapper>,
    // terrand_response: TerrandResponse,
    lottery_balance_response: LotteraBalanceResponse,
    holder_response: GetHolderResponse,
}

#[derive(Clone, Serialize)]
pub struct TerrandResponse {
    pub randomness: Binary,
    pub worker: Addr,
}

// impl TerrandResponse {
//     // pub fn new(randomness: Binary, worker: Addr) -> Self {
//     //     TerrandResponse { randomness, worker }
//     // }
//     pub fn default() -> Self {
//         TerrandResponse {
//             randomness: Binary::default(),
//             worker: Addr::unchecked("")
//         }
//     }
// }

#[derive(Clone, Default, Serialize)]
pub struct LotteraBalanceResponse {
    pub balance: Uint128,
}

impl LotteraBalanceResponse {
    pub fn new(balance: Uint128) -> Self {
        LotteraBalanceResponse { balance }
    }
}
#[derive(Clone, Default, Serialize)]
pub struct GetAllBondedResponse {
    pub total_bonded: Uint128,
}

// impl GetAllBondedResponse {
//     pub fn new(total_bonded: Uint128) -> Self {
//         GetAllBondedResponse { total_bonded }
//     }
// }
#[derive(Clone, Serialize)]
pub struct GetHolderResponse {
    pub address: Addr,
    pub balance: Uint128,
    pub index: Decimal,
    pub pending_rewards: Decimal,
}

impl GetHolderResponse {
    pub fn new(address: Addr, balance: Uint128, index: Decimal, pending_rewards: Decimal) -> Self {
        GetHolderResponse {
            address,
            balance,
            index,
            pending_rewards,
        }
    }

    pub fn default() -> Self {
        GetHolderResponse {
            address: Addr::unchecked(""),
            balance: Uint128::from(0u128),
            index: Decimal::zero(),
            pending_rewards: Decimal::zero(),
        }
    }
}

impl Querier for WasmMockQuerier {
    fn raw_query(&self, bin_request: &[u8]) -> QuerierResult {
        // MockQuerier doesn't support Custom, so we ignore it completely here
        let request: QueryRequest<TerraQueryWrapper> = match from_slice(bin_request) {
            Ok(v) => v,
            Err(e) => {
                return SystemResult::Err(SystemError::InvalidRequest {
                    error: format!("Parsing query request: {}", e),
                    request: bin_request.into(),
                })
            }
        };
        self.handle_query(&request)
    }
}
impl WasmMockQuerier {
    pub fn handle_query(&self, request: &QueryRequest<TerraQueryWrapper>) -> QuerierResult {
        match &request {
            QueryRequest::Wasm(WasmQuery::Smart { contract_addr, msg }) => {
                println!("{:?} {}", request, msg);
                if contract_addr == &Addr::unchecked("terra1q88h7ewu6h3am4mxxeqhu3srt7zloterracw20")
                {
                    println!("{:?}", request);
                    let msg_balance = LotteraBalanceResponse {
                        balance: self.lottery_balance_response.balance,
                    };
                    return SystemResult::Ok(ContractResult::Ok(to_binary(&msg_balance).unwrap()));
                } else if contract_addr
                    == &Addr::unchecked("terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5terrand")
                {
                    let msg_terrand = TerrandResponse {
                        randomness: Binary::from(
                            "OdRl+j6PHnN84dy12n4Oq1BrGktD73FW4SKPihxfB9I=".as_bytes(),
                        ),
                        worker: Addr::unchecked("terra1q88h7ewu6h3am4mxxeqhu3srxterrandworker"),
                    };
                    return SystemResult::Ok(ContractResult::Ok(to_binary(&msg_terrand).unwrap()));
                } else if contract_addr == &Addr::unchecked("altered") {
                    let msg_balance = BalanceResponse {
                        balance: Uint128::from(1_000_000_000u128),
                    };
                    return SystemResult::Ok(ContractResult::Ok(to_binary(&msg_balance).unwrap()));
                } else if contract_addr
                    == &Addr::unchecked("terra1q88h7ewu6h3am4mxxeqhu3srloterrastaking")
                {
                    if msg == &Binary::from(r#"{"get_all_bonded":{}}"#.as_bytes()) {
                        let msg_balance = GetAllBondedResponse {
                            total_bonded: self.lottery_balance_response.balance.clone(),
                        };
                        return SystemResult::Ok(ContractResult::Ok(
                            to_binary(&msg_balance).unwrap(),
                        ));
                    } else if msg == &Binary::from(
                        r#"{"holder":{"address":"terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5s20q007"}}"#
                            .as_bytes(),
                    ) {
                        let msg_balance = GetHolderResponse {
                            address: Addr::unchecked(
                                "terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5s20q007",
                            ),
                            balance: self.holder_response.balance,
                            index: self.holder_response.index,
                            pending_rewards: self.holder_response.pending_rewards,
                        };
                        return SystemResult::Ok(ContractResult::Ok(
                            to_binary(&msg_balance).unwrap(),
                        ));
                    } else if msg == &Binary::from(r#"{"holders":{}}"#.as_bytes()) {
                        let msg_holders = GetHoldersResponse {
                            holders: vec![
                                HoldersInfo {
                                    address: Addr::unchecked(""),
                                    balance: Uint128::from(15_000u128),
                                    index: Decimal::zero(),
                                    pending_rewards: Decimal::zero(),
                                },
                                HoldersInfo {
                                    address: Addr::unchecked(""),
                                    balance: Uint128::from(10_000u128),
                                    index: Decimal::zero(),
                                    pending_rewards: Decimal::zero(),
                                },
                            ],
                        };
                        return SystemResult::Ok(ContractResult::Ok(
                            to_binary(&msg_holders).unwrap(),
                        ));
                    } else if msg == &Binary::from(
                        r#"{"holder":{"address":"terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5s20qu3k"}}"#
                            .as_bytes(),
                    ) {
                        let msg_balance = GetHolderResponse {
                            address: Addr::unchecked(
                                "terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5s20q007",
                            ),
                            balance: self.holder_response.balance,
                            index: self.holder_response.index,
                            pending_rewards: self.holder_response.pending_rewards,
                        };
                        return SystemResult::Ok(ContractResult::Ok(
                            to_binary(&msg_balance).unwrap(),
                        ));
                    } else if msg == &Binary::from(r#"{"state":{}}"#.as_bytes()) {
                        let msg_balance = StakingStateResponse {
                            global_index: Decimal::percent(2),
                            total_balance: Uint128::from(1_000_000_000u128),
                            prev_reward_balance: Uint128::from(1_000_000_000u128),
                        };
                        return SystemResult::Ok(ContractResult::Ok(
                            to_binary(&msg_balance).unwrap(),
                        ));
                    }
                }
                panic!("DO NOT ENTER HERE")
            }
            QueryRequest::Custom(TerraQueryWrapper {
                route: _,
                query_data,
            }) => match query_data {
                TerraQuery::TaxRate {} => {
                    let res = TaxRateResponse {
                        rate: Decimal::percent(1),
                    };
                    SystemResult::Ok(ContractResult::Ok(to_binary(&res).unwrap()))
                }
                TerraQuery::TaxCap { denom: _ } => {
                    let cap = Uint128::from(1u128);
                    let res = TaxCapResponse { cap };
                    SystemResult::Ok(ContractResult::Ok(to_binary(&res).unwrap()))
                }
                _ => panic!("DO NOT ENTER HERE"),
            },
            _ => self.base.handle_query(request),
        }
    }
}
impl WasmMockQuerier {
    pub fn new(base: MockQuerier<TerraQueryWrapper>) -> Self {
        WasmMockQuerier {
            base,
            // terrand_response: TerrandResponse::default(),
            lottery_balance_response: LotteraBalanceResponse::default(),
            holder_response: GetHolderResponse::default(),
        }
    }

    // configure the mint whitelist mock querier
    pub fn with_token_balances(&mut self, balances: Uint128) {
        self.lottery_balance_response = LotteraBalanceResponse::new(balances);
    }

    // configure the mint whitelist mock querier
    pub fn with_holder(
        &mut self,
        address: Addr,
        balance: Uint128,
        index: Decimal,
        pending_rewards: Decimal,
    ) {
        self.holder_response = GetHolderResponse::new(address, balance, index, pending_rewards)
    }
}
