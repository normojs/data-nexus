// Copyright 2022 SphereEx Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::sync::Arc;

use conn_pool::PoolConn;
use endpoint::endpoint::Endpoint;
use indexmap::IndexMap;
use mysql_parser::ast::SqlStmt;
use mysql_protocol::client::conn::ClientConn;
use pisa_error::error::{Error, ErrorKind};
use strategy::{
    rewrite::{DialectAst, ShardingRewriteInput, ShardingRewriter},
    route::{
        route_plan_single_endpoint, BoxError, Route, RouteInput, RouteInputTyp, RouteStrategy,
    },
    sharding_rewrite::{
        DataSource, DataSourceShardingIdx, ShardingColumn, ShardingIdx, ShardingRewriteOutput,
        ShardingRewriteResult,
    },
};
use tracing::debug;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TransState {
    TransDummyState,
    TransUseState,
    TransSetSessionState,
    TransStartState,
    TransPrepareState,
}

impl Default for TransState {
    fn default() -> Self {
        TransState::TransDummyState
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TransEventName {
    DummyEvent,
    UseEvent,
    SetSessionEvent,
    QueryEvent,
    StartEvent,
    PrepareEvent,
    SendLongDataEvent,
    ExecuteEvent,
    CloseEvent,
    ResetEvent,
    CommitRollBackEvent,
    DropEvent,
}

impl Default for TransEventName {
    fn default() -> Self {
        TransEventName::DummyEvent
    }
}

use strategy::sharding_rewrite::ShardingRewrite;
pub fn query_rewrite(
    rewriter: &mut ShardingRewrite,
    raw_sql: String,
    ast: SqlStmt,
    default_db: Option<String>,
    can_rewrite: bool,
) -> Result<ShardingRewriteOutput, BoxError> {
    if can_rewrite {
        let outputs = rewriter.rewrite(ShardingRewriteInput {
            raw_sql: raw_sql.clone(),
            ast: DialectAst::mysql(ast),
            default_db,
        })?;

        if !outputs.results.is_empty() {
            return Ok(outputs);
        }
    }

    let endpoints = rewriter.get_endpoints();
    let results = endpoints
        .iter()
        .map(|ep| ShardingRewriteResult {
            ds_idx: DataSourceShardingIdx {
                ds: DataSource::Endpoint(ep.clone()),
                idx: ShardingIdx::default(),
                column: ShardingColumn::default(),
            },
            changes: IndexMap::new(),
            target_sql: raw_sql.to_string(),
        })
        .collect::<Vec<_>>();

    Ok(ShardingRewriteOutput { results, agg_fields: IndexMap::new() })
}

pub fn route(
    input_typ: RouteInputTyp,
    raw_sql: &str,
    strategy: Arc<parking_lot::Mutex<RouteStrategy>>,
) -> Result<Endpoint, Error> {
    let mut strategy = strategy.lock();
    let input = match input_typ {
        RouteInputTyp::Statement => RouteInput::Statement(raw_sql),
        RouteInputTyp::Transaction => RouteInput::Transaction(raw_sql),
        _ => RouteInput::None,
    };

    let route_plan = strategy.dispatch(&input).map_err(route_runtime_error)?;
    debug!(
        "route_strategy rw + sharding to {:?} for input typ: {:?}, sql: {:?}",
        route_plan, input_typ, raw_sql
    );

    route_plan_single_endpoint(route_plan).map_err(route_runtime_error)
}

pub fn route_sharding(
    input_typ: RouteInputTyp,
    raw_sql: &str,
    strategy: Arc<parking_lot::Mutex<RouteStrategy>>,
    rewrite_outputs: &mut ShardingRewriteOutput,
) -> Result<(), Error> {
    let mut strategy = strategy.lock();
    for o in rewrite_outputs.results.iter_mut() {
        match &o.ds_idx.ds {
            // sharding only
            DataSource::Endpoint(ep) => {
                let _input = match input_typ {
                    RouteInputTyp::Statement => RouteInput::Sharding(ep.clone()),
                    RouteInputTyp::Transaction => RouteInput::Sharding(ep.clone()),
                    _ => RouteInput::None,
                };

                //let dispatch_res = strategy.dispatch(&input).unwrap();
                debug!(
                    "route_strategy sharding only to {:?} for input typ: {:?}, sql: {:?}",
                    ep, input_typ, raw_sql
                );
            }

            // rewritesplitting + sharding
            DataSource::NodeGroup(group) => {
                let input = match input_typ {
                    RouteInputTyp::Statement => {
                        RouteInput::ShardingStatement(raw_sql, group.clone())
                    }
                    RouteInputTyp::Transaction => {
                        RouteInput::ShardingTransaction(raw_sql, group.clone())
                    }
                    _ => RouteInput::None,
                };

                let route_plan = strategy.dispatch(&input).map_err(route_runtime_error)?;
                debug!(
                    "route_strategy rw + sharding to {:?} for input typ: {:?}, sql: {:?}",
                    route_plan, input_typ, raw_sql
                );
                // reassign data_source, type should is DataSource::Endpoint
                o.ds_idx.ds = DataSource::Endpoint(
                    route_plan_single_endpoint(route_plan).map_err(route_runtime_error)?,
                );
            }
            DataSource::None => return Err(missing_rewrite_data_source(input_typ, raw_sql)),
        }
    }
    Ok(())
}

fn route_runtime_error(error: BoxError) -> Error {
    Error::new(ErrorKind::Runtime(error))
}

fn missing_rewrite_data_source(input_typ: RouteInputTyp, raw_sql: &str) -> Error {
    Error::new(ErrorKind::Runtime(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("sharding rewrite returned no data source for {:?}: {}", input_typ, raw_sql),
    ))))
}

pub struct TransEvent {
    name: TransEventName,
    src_state: TransState,
    dst_state: TransState,
}

fn init_trans_events() -> Vec<TransEvent> {
    return vec![
        TransEvent {
            name: TransEventName::UseEvent,
            src_state: TransState::TransDummyState,
            dst_state: TransState::TransUseState,
            //driver: Some(Box::new(Driver)),
        },
        TransEvent {
            name: TransEventName::UseEvent,
            src_state: TransState::TransUseState,
            dst_state: TransState::TransUseState,
            //driver: Some(Box::new(Driver)),
        },
        TransEvent {
            name: TransEventName::SetSessionEvent,
            src_state: TransState::TransDummyState,
            dst_state: TransState::TransSetSessionState,
            //driver: Some(Box::new(Driver)),
        },
        TransEvent {
            name: TransEventName::SetSessionEvent,
            src_state: TransState::TransUseState,
            dst_state: TransState::TransSetSessionState,
            //driver: None,
        },
        TransEvent {
            name: TransEventName::SetSessionEvent,
            src_state: TransState::TransSetSessionState,
            dst_state: TransState::TransSetSessionState,
            //driver: None,
        },
        TransEvent {
            name: TransEventName::QueryEvent,
            src_state: TransState::TransSetSessionState,
            dst_state: TransState::TransSetSessionState,
            //driver: None,
        },
        TransEvent {
            name: TransEventName::QueryEvent,
            src_state: TransState::TransUseState,
            dst_state: TransState::TransUseState,
            //driver: None,
        },
        TransEvent {
            name: TransEventName::QueryEvent,
            src_state: TransState::TransDummyState,
            dst_state: TransState::TransDummyState,
            //driver: Some(Box::new(Driver)),
        },
        TransEvent {
            name: TransEventName::StartEvent,
            src_state: TransState::TransDummyState,
            dst_state: TransState::TransStartState,
            //driver: Some(Box::new(Driver)),
        },
        TransEvent {
            name: TransEventName::StartEvent,
            src_state: TransState::TransUseState,
            dst_state: TransState::TransStartState,
            //driver: None,
        },
        TransEvent {
            name: TransEventName::StartEvent,
            src_state: TransState::TransSetSessionState,
            dst_state: TransState::TransStartState,
            //driver: None,
        },
        TransEvent {
            name: TransEventName::PrepareEvent,
            src_state: TransState::TransDummyState,
            dst_state: TransState::TransPrepareState,
            //driver: Some(Box::new(Driver)),
        },
        TransEvent {
            name: TransEventName::PrepareEvent,
            src_state: TransState::TransUseState,
            dst_state: TransState::TransPrepareState,
            //driver: None,
        },
        TransEvent {
            name: TransEventName::PrepareEvent,
            src_state: TransState::TransStartState,
            dst_state: TransState::TransPrepareState,
            //driver: None,
        },
        TransEvent {
            name: TransEventName::SendLongDataEvent,
            src_state: TransState::TransPrepareState,
            dst_state: TransState::TransPrepareState,
            //driver: None,
        },
        TransEvent {
            name: TransEventName::ExecuteEvent,
            src_state: TransState::TransPrepareState,
            dst_state: TransState::TransPrepareState,
            //driver: None,
        },
        TransEvent {
            name: TransEventName::CloseEvent,
            src_state: TransState::TransPrepareState,
            dst_state: TransState::TransDummyState,
            //driver: None,
        },
        TransEvent {
            name: TransEventName::ResetEvent,
            src_state: TransState::TransPrepareState,
            dst_state: TransState::TransDummyState,
            //driver: None,
        },
        TransEvent {
            name: TransEventName::DropEvent,
            src_state: TransState::TransPrepareState,
            dst_state: TransState::TransDummyState,
            //driver: None,
        },
        TransEvent {
            name: TransEventName::CommitRollBackEvent,
            src_state: TransState::TransPrepareState,
            dst_state: TransState::TransDummyState,
            //driver: None,
        },
        TransEvent {
            name: TransEventName::CommitRollBackEvent,
            src_state: TransState::TransDummyState,
            dst_state: TransState::TransDummyState,
            //driver: Some(Box::new(Driver)),
        },
        TransEvent {
            name: TransEventName::CommitRollBackEvent,
            src_state: TransState::TransStartState,
            dst_state: TransState::TransDummyState,
            //driver: Some(Box::new(Driver)),
        },
        TransEvent {
            name: TransEventName::QueryEvent,
            src_state: TransState::TransSetSessionState,
            dst_state: TransState::TransDummyState,
            //driver: Some(Box::new(Driver)),
        },
    ];
}

pub struct TransFsm {
    pub events: Vec<TransEvent>,
    pub current_state: TransState,
    pub current_event: TransEventName,
    pub client_conn: Option<PoolConn<ClientConn>>,
    pub shard_cache_conn: Vec<PoolConn<ClientConn>>,
}

impl TransFsm {
    pub fn new() -> TransFsm {
        TransFsm {
            events: init_trans_events(),
            current_state: TransState::TransDummyState,
            current_event: TransEventName::DummyEvent,
            client_conn: None,
            shard_cache_conn: vec![],
        }
    }

    pub fn trigger(&mut self, state_name: TransEventName) -> bool {
        for event in &self.events {
            if event.name == state_name && event.src_state == self.current_state {
                self.current_state = event.dst_state;
                self.current_event = event.name;

                match event.src_state {
                    TransState::TransDummyState => return true,
                    _ => {}
                }

                return false;
            }
        }
        false
    }

    // when autocommit=0, should be reset fsm state
    pub fn reset_fsm_state(&mut self) {
        self.current_state = TransState::TransDummyState;
        self.current_event = TransEventName::DummyEvent;

        self.trigger(TransEventName::QueryEvent);
    }

    pub fn take_conn(&mut self) -> Result<PoolConn<ClientConn>, Error> {
        self.client_conn.take().ok_or_else(|| {
            Error::new(ErrorKind::Runtime(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "transaction FSM has no bound backend connection",
            ))))
        })
    }

    pub fn take_conn_if_bound(&mut self) -> Option<PoolConn<ClientConn>> {
        self.client_conn.take()
    }

    pub fn put_conn(&mut self, conn: PoolConn<ClientConn>) {
        self.client_conn = Some(conn)
    }

    pub fn get_shard_conns(&mut self) -> Vec<PoolConn<ClientConn>> {
        std::mem::replace(&mut self.shard_cache_conn, Vec::new())
    }

    pub fn put_shard_conns(&mut self, conns: Vec<PoolConn<ClientConn>>) {
        self.shard_cache_conn = conns;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_trigger() {
        let mut tsm = TransFsm::new();
        tsm.current_state = TransState::TransUseState;
        let _ = tsm.trigger(TransEventName::QueryEvent);
        assert_eq!(tsm.current_state, TransState::TransUseState);
        assert_eq!(tsm.current_event, TransEventName::QueryEvent);
        let _ = tsm.trigger(TransEventName::SetSessionEvent);
        assert_eq!(tsm.current_state, TransState::TransSetSessionState);
        assert_eq!(tsm.current_event, TransEventName::SetSessionEvent);
        let _ = tsm.trigger(TransEventName::StartEvent);
        assert_eq!(tsm.current_state, TransState::TransStartState);
        assert_eq!(tsm.current_event, TransEventName::StartEvent);
        let _ = tsm.trigger(TransEventName::PrepareEvent);
        assert_eq!(tsm.current_state, TransState::TransPrepareState);
        assert_eq!(tsm.current_event, TransEventName::PrepareEvent);
        let _ = tsm.trigger(TransEventName::SendLongDataEvent);
        assert_eq!(tsm.current_state, TransState::TransPrepareState);
        assert_eq!(tsm.current_event, TransEventName::SendLongDataEvent);
        let _ = tsm.trigger(TransEventName::ExecuteEvent);
        assert_eq!(tsm.current_state, TransState::TransPrepareState);
        assert_eq!(tsm.current_event, TransEventName::ExecuteEvent);
        let _ = tsm.trigger(TransEventName::CommitRollBackEvent);
        assert_eq!(tsm.current_state, TransState::TransDummyState);
        assert_eq!(tsm.current_event, TransEventName::CommitRollBackEvent);
    }
}
