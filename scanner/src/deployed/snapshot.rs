//! Everything the checks look at, read from one block over RPC. Reading is the only impure step; each check is
//! a pure function of a [`Snapshot`].

use std::collections::BTreeSet;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use wasmparser::{ExternalKind, Parser, Payload};

use super::AccountId;
use super::display::clean;
use super::error::DeployedError;
use super::rpc::{At, MAX_CODE_RESPONSE, MAX_RESPONSE, Rpc};
use super::transport::TransportError;

/// The code hash an account reports when it has no contract (base58 of 32 zero bytes).
const NO_CODE_HASH: &str = "11111111111111111111111111111111";
/// near-sdk stores a contract's state struct under this key.
const STATE_KEY_BASE64: &str = "U1RBVEU=";
/// Keys per page the node can return at most is 100 by default; the bound only stops a node that never ends.
const MAX_KEY_PAGES: usize = 100;
const METADATA_METHOD: &str = "contract_source_metadata";

pub(crate) struct Snapshot {
    pub account_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub amount: u128,
    pub locked: u128,
    pub storage_usage: u64,
    /// Base58 SHA-256 of the wasm, computed here and equal to the hash the node reported.
    pub code_hash: String,
    pub code_bytes: usize,
    /// Names of exported wasm functions, which are the contract's callable methods.
    pub exports: BTreeSet<String>,
    pub code_source: CodeSource,
    pub keys: Vec<AccessKey>,
    pub state: StateProbe,
    pub metadata: Metadata,
    pub storage_amount_per_byte: u128,
}

/// Where the account's code comes from. The two global kinds differ in who can change what the account runs.
pub(crate) enum CodeSource {
    /// Deployed to the account itself.
    Deployed,
    /// A global contract identified by its code hash, which has one fixed content. The hash is the one the node
    /// reported, and the code read was checked to hash to it.
    GlobalByHash(String),
    /// A global contract identified by the account that published it, which can replace it.
    GlobalByAccount(String),
}

pub(crate) struct AccessKey {
    pub public_key: String,
    pub permission: Permission,
}

pub(crate) enum Permission {
    /// Includes gas keys with full access: the node names the permission the same way.
    FullAccess,
    FunctionCall {
        receiver_id: String,
        method_names: Vec<String>,
    },
}

/// What `view_state` reads found in the account's storage.
pub(crate) enum StateProbe {
    /// The `STATE` key near-sdk stores a contract's state struct under exists.
    StateKey,
    /// Other keys exist but `STATE` does not: a contract with its own storage layout.
    OtherKeys,
    /// The account stores nothing at all.
    Empty,
    /// The node would not answer; the reason is shown, and it is never a finding.
    Unknown(String),
}

/// The result of calling `contract_source_metadata` (NEP-330).
pub(crate) enum Metadata {
    NotExported,
    Declared {
        version: Option<String>,
        link: Option<String>,
    },
    /// Exported, but calling it failed or returned something that is not NEP-330 JSON.
    Unusable(String),
}

pub(super) fn read(rpc: &Rpc<'_>, account: &AccountId) -> Result<Snapshot, DeployedError> {
    let account_id = account.to_string();
    let view: AccountView = rpc
        .query(
            "view_account",
            At::Final,
            json!({"request_type": "view_account", "account_id": account_id}),
            MAX_RESPONSE,
        )
        .map_err(|error| match error {
            DeployedError::Node { cause: Some(cause), .. } if cause == "UNKNOWN_ACCOUNT" => {
                DeployedError::UnknownAccount { account: account_id.clone() }
            }
            other => other,
        })?;
    let global_hash = view.global_contract_hash.as_deref();
    let code_source = match (global_hash, view.global_contract_account_id.as_deref()) {
        (None, None) => CodeSource::Deployed,
        (Some(hash), None) => CodeSource::GlobalByHash(hash.to_owned()),
        (None, Some(publisher)) => CodeSource::GlobalByAccount(clean(publisher, 64)),
        (Some(_), Some(_)) => {
            return Err(DeployedError::malformed("view_account", "the account names two kinds of global contract"));
        }
    };
    if view.code_hash == NO_CODE_HASH && matches!(code_source, CodeSource::Deployed) {
        return Err(DeployedError::NoContract { account: account_id });
    }
    let at = At::Block(&view.block_hash);
    let amount = parse_amount("view_account", &view.amount)?;
    let locked = parse_amount("view_account", &view.locked)?;

    let code: CodeView =
        rpc.query("view_code", at, json!({"request_type": "view_code", "account_id": account_id}), MAX_CODE_RESPONSE)?;
    let wasm = STANDARD
        .decode(&code.code_base64)
        .map_err(|e| DeployedError::malformed("view_code", format!("code_base64 is not base64 ({e})")))?;
    let code_hash = bs58::encode(Sha256::digest(&wasm)).into_string();
    if code_hash != code.hash || (view.code_hash != NO_CODE_HASH && view.code_hash != code_hash) {
        return Err(DeployedError::malformed("view_code", "the code does not match the hash the node reports for it"));
    }
    if matches!(&code_source, CodeSource::GlobalByHash(hash) if *hash != code_hash) {
        return Err(DeployedError::malformed(
            "view_code",
            "the code does not match the global contract hash the node reports for the account",
        ));
    }
    let exports = function_exports(&wasm).map_err(|e| DeployedError::malformed("view_code", e))?;

    let keys = read_keys(rpc, at, &account_id)?;
    let state = read_state(rpc, at, &account_id)?;
    let metadata =
        if exports.contains(METADATA_METHOD) { read_metadata(rpc, at, &account_id)? } else { Metadata::NotExported };
    let config: ProtocolConfig = serde_json::from_value(rpc.call(
        "protocol_config",
        "EXPERIMENTAL_protocol_config",
        json!({"block_id": view.block_hash}),
        MAX_RESPONSE,
    )?)
    .map_err(|e| DeployedError::malformed("protocol_config", e.to_string()))?;
    let storage_amount_per_byte = parse_amount("protocol_config", &config.runtime_config.storage_amount_per_byte)?;

    Ok(Snapshot {
        account_id,
        block_height: view.block_height,
        block_hash: view.block_hash,
        amount,
        locked,
        storage_usage: view.storage_usage,
        code_hash,
        code_bytes: wasm.len(),
        exports,
        code_source,
        keys,
        state,
        metadata,
        storage_amount_per_byte,
    })
}

#[derive(Deserialize)]
struct AccountView {
    amount: String,
    locked: String,
    code_hash: String,
    storage_usage: u64,
    block_height: u64,
    block_hash: String,
    global_contract_hash: Option<String>,
    global_contract_account_id: Option<String>,
}

#[derive(Deserialize)]
struct CodeView {
    code_base64: String,
    hash: String,
}

#[derive(Deserialize)]
struct ProtocolConfig {
    runtime_config: RuntimeConfig,
}

#[derive(Deserialize)]
struct RuntimeConfig {
    storage_amount_per_byte: String,
}

fn parse_amount(call: &'static str, text: &str) -> Result<u128, DeployedError> {
    text.parse().map_err(|_| DeployedError::malformed(call, "an amount is not a decimal integer"))
}

/// Exported function names, read from the export section only: the code itself is never decoded.
fn function_exports(wasm: &[u8]) -> Result<BTreeSet<String>, String> {
    let mut names = BTreeSet::new();
    for payload in Parser::new(0).parse_all(wasm) {
        if let Payload::ExportSection(section) = payload.map_err(|e| format!("not a readable wasm module ({e})"))? {
            for export in section {
                let export = export.map_err(|e| format!("not a readable wasm module ({e})"))?;
                if export.kind == ExternalKind::Func {
                    names.insert(export.name.to_owned());
                }
            }
        }
    }
    Ok(names)
}

#[derive(Deserialize)]
struct KeyPage {
    keys: Vec<KeyEntry>,
    last_key: Option<String>,
}

#[derive(Deserialize)]
struct KeyEntry {
    public_key: String,
    access_key: AccessKeyView,
}

#[derive(Deserialize)]
struct AccessKeyView {
    permission: PermissionView,
}

/// The node's wire format, matching nearcore's `AccessKeyPermissionView`. An unknown variant fails the read
/// rather than being skipped: a key the scanner cannot classify must not make the account look cleaner.
#[derive(Deserialize)]
enum PermissionView {
    FullAccess,
    GasKeyFullAccess(serde::de::IgnoredAny),
    FunctionCall(FunctionCallView),
    GasKeyFunctionCall(FunctionCallView),
}

#[derive(Deserialize)]
struct FunctionCallView {
    receiver_id: String,
    method_names: Vec<String>,
}

fn read_keys(rpc: &Rpc<'_>, at: At<'_>, account_id: &str) -> Result<Vec<AccessKey>, DeployedError> {
    let mut keys = Vec::new();
    let mut after_key: Option<String> = None;
    for _ in 0..MAX_KEY_PAGES {
        let mut params = json!({"request_type": "view_access_key_list", "account_id": account_id, "limit": 100});
        if let Some(after) = &after_key {
            params["after_key"] = json!(after);
        }
        let page: KeyPage = rpc.query("view_access_key_list", at, params, MAX_RESPONSE)?;
        keys.extend(page.keys.into_iter().map(|entry| AccessKey {
            public_key: clean(&entry.public_key, 120),
            permission: match entry.access_key.permission {
                PermissionView::FullAccess | PermissionView::GasKeyFullAccess(_) => Permission::FullAccess,
                PermissionView::FunctionCall(call) | PermissionView::GasKeyFunctionCall(call) => {
                    Permission::FunctionCall { receiver_id: call.receiver_id, method_names: call.method_names }
                }
            },
        }));
        match page.last_key {
            None => return Ok(keys),
            // A node that ignores `after_key` would send the same page forever.
            Some(last) if after_key.as_ref() == Some(&last) => {
                return Err(DeployedError::malformed("view_access_key_list", "the node's key pages do not advance"));
            }
            Some(last) => after_key = Some(last),
        }
    }
    Err(DeployedError::malformed("view_access_key_list", "more key pages than Preflight will read"))
}

#[derive(Deserialize)]
struct StatePage {
    values: Vec<StateItem>,
}

#[derive(Deserialize)]
struct StateItem {
    key: String,
}

enum FirstKey {
    Key(String),
    NoKey,
    /// The node would not say, and why.
    Unknown(String),
}

/// The first key under `prefix_base64`. A paginated request skips the node's whole-account size check, so large
/// contracts answer too; a node that does not support pagination refuses them with `TOO_LARGE_CONTRACT_STATE`,
/// which means "unknown" here, as does an entry over the response cap. Any other failure stays an error.
fn first_key(rpc: &Rpc<'_>, at: At<'_>, account_id: &str, prefix_base64: &str) -> Result<FirstKey, DeployedError> {
    let params =
        json!({"request_type": "view_state", "account_id": account_id, "prefix_base64": prefix_base64, "limit": 1});
    match rpc.query::<StatePage>("view_state", at, params, MAX_RESPONSE) {
        // Keys sort byte-wise, so if the exact key exists it is the first one under its own prefix.
        Ok(page) => Ok(page.values.into_iter().next().map_or(FirstKey::NoKey, |item| FirstKey::Key(item.key))),
        Err(DeployedError::Node { cause: Some(cause), .. }) if cause == "TOO_LARGE_CONTRACT_STATE" => {
            Ok(FirstKey::Unknown("the node refused to read the state: TOO_LARGE_CONTRACT_STATE".to_owned()))
        }
        Err(DeployedError::Transport { source: TransportError::TooLarge { limit }, .. }) => {
            Ok(FirstKey::Unknown(format!("the state entry is larger than the {limit} byte response limit")))
        }
        Err(other) => Err(other),
    }
}

/// Looks for the `STATE` key first; only if it is missing, asks whether the account stores anything at all.
fn read_state(rpc: &Rpc<'_>, at: At<'_>, account_id: &str) -> Result<StateProbe, DeployedError> {
    Ok(match first_key(rpc, at, account_id, STATE_KEY_BASE64)? {
        FirstKey::Unknown(why) => StateProbe::Unknown(why),
        FirstKey::Key(key) if key == STATE_KEY_BASE64 => StateProbe::StateKey,
        FirstKey::Key(_) => StateProbe::OtherKeys,
        FirstKey::NoKey => match first_key(rpc, at, account_id, "")? {
            FirstKey::Unknown(why) => StateProbe::Unknown(why),
            FirstKey::Key(_) => StateProbe::OtherKeys,
            FirstKey::NoKey => StateProbe::Empty,
        },
    })
}

#[derive(Deserialize)]
struct CallResult {
    result: Option<Vec<u8>>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct MetadataJson {
    version: Option<String>,
    link: Option<String>,
}

fn read_metadata(rpc: &Rpc<'_>, at: At<'_>, account_id: &str) -> Result<Metadata, DeployedError> {
    let params = json!({"request_type": "call_function", "account_id": account_id, "method_name": METADATA_METHOD, "args_base64": ""});
    let call: CallResult = rpc.query("call_function", at, params, MAX_RESPONSE)?;
    let bytes = match (call.result, call.error) {
        (Some(bytes), None) => bytes,
        (_, Some(error)) => return Ok(Metadata::Unusable(format!("the call failed: {}", clean(&error, 200)))),
        (None, None) => return Err(DeployedError::malformed("call_function", "neither a result nor an error")),
    };
    Ok(match serde_json::from_slice::<MetadataJson>(&bytes) {
        Ok(json) => Metadata::Declared {
            version: json.version.map(|v| clean(&v, 200)),
            link: json.link.map(|l| clean(&l, 300)),
        },
        Err(_) => Metadata::Unusable("the call returned something that is not NEP-330 JSON".to_owned()),
    })
}

#[cfg(test)]
impl Snapshot {
    /// A deployed token-like contract with nothing to report: the base the check tests change one field of.
    pub(crate) fn sample() -> Self {
        Self {
            account_id: "token.example.near".to_owned(),
            block_height: 100,
            block_hash: "BLOCKHASH".to_owned(),
            amount: 100 * 10u128.pow(24),
            locked: 0,
            storage_usage: 1_000_000,
            code_hash: "CODEHASH".to_owned(),
            code_bytes: 500_000,
            exports: [
                "new",
                "ft_transfer",
                "ft_transfer_call",
                "ft_resolve_transfer",
                "storage_deposit",
                "contract_source_metadata",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            code_source: CodeSource::Deployed,
            keys: Vec::new(),
            state: StateProbe::StateKey,
            metadata: Metadata::Declared {
                version: Some("1.0.0".to_owned()),
                link: Some("https://github.com/example/token/tree/abc123".to_owned()),
            },
            storage_amount_per_byte: 10u128.pow(19),
        }
    }
}
