//! JSON-RPC over a [`Transport`]: builds requests, unwraps the envelope, and turns every way a node can answer
//! badly into a [`DeployedError`].

use std::time::{Duration, Instant};

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::display::clean;
use super::error::DeployedError;
use super::transport::Transport;

/// Echoed back by the node; a response carrying another id is not an answer to our request.
const REQUEST_ID: &str = "preflight";

/// Response size caps. The protocol allows a 4 MiB contract (`max_contract_size` in the protocol config), which
/// is about 5.6 MB as base64, so 8 MiB holds any real `view_code` answer and nothing else needs more than 4.
pub(super) const MAX_CODE_RESPONSE: usize = 8 << 20;
pub(super) const MAX_RESPONSE: usize = 4 << 20;

pub(super) struct Rpc<'a> {
    transport: &'a dyn Transport,
    started: Instant,
    limit: Duration,
}

/// Which state a query reads.
#[derive(Clone, Copy)]
pub(super) enum At<'a> {
    /// The latest final block; the node picks it.
    Final,
    /// This exact block, so every read of one run sees one consistent state.
    Block(&'a str),
}

#[derive(Deserialize)]
struct Envelope {
    id: Option<Value>,
    result: Option<Value>,
    error: Option<NodeError>,
}

#[derive(Deserialize)]
struct NodeError {
    cause: Option<Cause>,
    message: Option<String>,
    data: Option<Value>,
}

#[derive(Deserialize)]
struct Cause {
    name: Option<String>,
}

impl<'a> Rpc<'a> {
    /// A run that has lasted `limit` sends no further request. The transport's own timeout bounds each request,
    /// so a run can overshoot `limit` by at most one request.
    pub(super) fn new(transport: &'a dyn Transport, limit: Duration) -> Self {
        Self { transport, started: Instant::now(), limit }
    }

    /// `method` with `params`; returns the envelope's `result`.
    pub(super) fn call(
        &self,
        call: &'static str,
        method: &str,
        params: Value,
        max_bytes: usize,
    ) -> Result<Value, DeployedError> {
        if self.started.elapsed() >= self.limit {
            return Err(DeployedError::Deadline { call, limit: self.limit });
        }
        let request = json!({ "jsonrpc": "2.0", "id": REQUEST_ID, "method": method, "params": params }).to_string();
        let body =
            self.transport.post(&request, max_bytes).map_err(|source| DeployedError::Transport { call, source })?;
        let envelope: Envelope = serde_json::from_slice(&body)
            .map_err(|e| DeployedError::malformed(call, format!("not a JSON-RPC response ({e})")))?;
        if envelope.id != Some(Value::String(REQUEST_ID.to_owned())) {
            return Err(DeployedError::malformed(call, "the response id does not match the request"));
        }
        if let Some(error) = envelope.error {
            let cause = error.cause.and_then(|cause| cause.name).map(|name| clean(&name, 64));
            let data = error.data.as_ref().and_then(Value::as_str).unwrap_or_default();
            let text =
                format!("{} {} {}", cause.as_deref().unwrap_or_default(), error.message.unwrap_or_default(), data);
            return Err(DeployedError::Node { call, cause, message: clean(text.trim(), 300) });
        }
        envelope.result.ok_or_else(|| DeployedError::malformed(call, "neither a result nor an error"))
    }

    /// A `query` request, `params` being everything but the block reference. When `at` names a block, the answer
    /// must say it was computed at that block.
    pub(super) fn query<T: DeserializeOwned>(
        &self,
        call: &'static str,
        at: At<'_>,
        mut params: Value,
        max_bytes: usize,
    ) -> Result<T, DeployedError> {
        let map = params.as_object_mut().expect("query params are an object");
        match at {
            At::Final => map.insert("finality".to_owned(), json!("final")),
            At::Block(hash) => map.insert("block_id".to_owned(), json!(hash)),
        };
        let result = self.call(call, "query", params, max_bytes)?;
        if let At::Block(hash) = at
            && result.get("block_hash").and_then(Value::as_str) != Some(hash)
        {
            return Err(DeployedError::malformed(call, format!("the node did not answer for block {hash}")));
        }
        serde_json::from_value(result).map_err(|e| DeployedError::malformed(call, e.to_string()))
    }
}
