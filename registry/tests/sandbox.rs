//! Sandbox tests: the real registry wasm running in a local NEAR node.

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use near_workspaces::network::Sandbox;
use near_workspaces::types::NearToken;
use near_workspaces::{Account, Contract, Worker};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Starts the local NEAR node, retrying with a growing delay (0.5 s, 1 s, 2 s).
///
/// near-workspaces picks its ports itself and can lose the race for them to another sandbox starting at the same
/// time. Nothing is deployed yet, so starting again is safe. Duplicated in `exploits/src/lib.rs`: this crate
/// cannot depend on that one.
async fn sandbox() -> Result<Worker<Sandbox>> {
    const ATTEMPTS: u32 = 4;
    let mut delay = Duration::from_millis(500);
    for attempt in 1..ATTEMPTS {
        match near_workspaces::sandbox().await {
            Ok(worker) => return Ok(worker),
            Err(err) => eprintln!("sandbox start attempt {attempt}/{ATTEMPTS} failed: {err:#}"),
        }
        tokio::time::sleep(delay).await;
        delay *= 2;
    }
    near_workspaces::sandbox().await.with_context(|| format!("sandbox failed to start after {ATTEMPTS} attempts"))
}

const REPORT_URL: &str = "https://example.com/report.json";
/// Protocol price of one byte of contract storage, in yoctoNEAR.
const STORAGE_BYTE_COST_YOCTO: u128 = 10_000_000_000_000_000_000;

/// The registry wasm, built once for the whole test binary.
static REGISTRY_WASM: LazyLock<Vec<u8>> = LazyLock::new(|| build_registry().expect("build the registry wasm"));

/// Builds this crate for wasm32 with the release profile and returns the wasm bytes.
///
/// Runs the same `cargo` (and pinned toolchain) that runs the tests. The artifact path comes from cargo's JSON
/// messages, so it follows `CARGO_TARGET_DIR`. Ambient `RUSTFLAGS` are dropped so the wasm flags in
/// `.cargo/config.toml` (`--cfg near`) always apply, as they do under `cargo near build`.
fn build_registry() -> Result<Vec<u8>> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    // Read at run time, not with `env!`: a checkout moved on disk reuses the cached test binary, and a path baked
    // in at compile time would point at the old location.
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR").context("cargo sets CARGO_MANIFEST_DIR for tests")?;
    let output = Command::new(cargo)
        .args(["build", "--locked", "--target", "wasm32-unknown-unknown", "--release"])
        .args(["--message-format", "json-render-diagnostics", "--manifest-path"])
        .arg(Path::new(&manifest_dir).join("Cargo.toml"))
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .stderr(Stdio::inherit())
        .output()
        .context("failed to start cargo")?;
    ensure!(output.status.success(), "cargo build failed for the registry");
    let wasm = String::from_utf8(output.stdout)?
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|message| message["reason"] == "compiler-artifact" && message["target"]["name"] == "registry")
        .filter_map(|message| message["filenames"].as_array().cloned())
        .flatten()
        .filter_map(|name| name.as_str().map(str::to_owned))
        .find(|name| name.ends_with(".wasm"));
    let Some(wasm) = wasm else { bail!("cargo reported no registry .wasm artifact") };
    Ok(std::fs::read(wasm)?)
}

struct Scene {
    registry: Contract,
    auditor: Account,
    other_auditor: Account,
    outsider: Account,
}

impl Scene {
    /// Deploys the registry with `auditor` and `other_auditor` on the allowlist.
    async fn new(worker: &Worker<Sandbox>) -> Result<Self> {
        let registry = worker.dev_deploy(&REGISTRY_WASM).await?;
        let auditor = worker.dev_create_account().await?;
        let other_auditor = worker.dev_create_account().await?;
        let outsider = worker.dev_create_account().await?;
        registry
            .call("new")
            .args_json(json!({ "auditors": [auditor.id(), other_auditor.id()] }))
            .transact()
            .await?
            .into_result()?;
        Ok(Self { registry, auditor, other_auditor, outsider })
    }

    fn publish(
        &self,
        who: &Account,
        code_hash: &str,
        status: &str,
        rule_ids: &[&str],
    ) -> near_workspaces::operations::CallTransaction {
        who.call(self.registry.id(), "publish_verdict")
            .args_json(json!({
                "code_hash": code_hash,
                "status": status,
                "rule_ids": rule_ids,
                "report_url": REPORT_URL,
                "report_sha256": "ab".repeat(32),
            }))
            .deposit(NearToken::from_millinear(100))
    }

    async fn verdict(&self, reader: &Account, code_hash: &str) -> Result<Value> {
        let view = reader.view(self.registry.id(), "get_verdict").args_json(json!({ "code_hash": code_hash }));
        Ok(view.await?.json()?)
    }
}

fn some_hash(seed: u8) -> String {
    bs58_of(&Sha256::digest([seed]))
}

fn bs58_of(bytes: &[u8]) -> String {
    near_workspaces::CryptoHash::try_from(bytes).expect("32 bytes").to_string()
}

#[tokio::test]
async fn an_allowlisted_auditor_publishes_and_anyone_reads_it_back() -> Result<()> {
    let worker = sandbox().await?;
    let scene = Scene::new(&worker).await?;
    let hash = some_hash(1);

    let outcome =
        scene.publish(&scene.auditor, &hash, "Unsafe", &["PF001", "PF007"]).transact().await?.into_result()?;
    let event =
        outcome.logs().into_iter().find(|log| log.starts_with("EVENT_JSON:")).context("no event logged")?.to_owned();
    let event: Value = serde_json::from_str(&event["EVENT_JSON:".len()..])?;
    assert_eq!(
        event,
        json!({
            "standard": "preflight", "version": "1.0.0", "event": "verdict_published",
            "data": { "code_hash": hash, "status": "Unsafe", "auditor": scene.auditor.id() },
        })
    );

    for reader in [&scene.outsider, &scene.other_auditor] {
        let verdict = scene.verdict(reader, &hash).await?;
        assert_eq!(verdict["code_hash"], hash);
        assert_eq!(verdict["status"], "Unsafe");
        assert_eq!(verdict["rule_ids"], json!(["PF001", "PF007"]));
        assert_eq!(verdict["report_url"], REPORT_URL);
        assert_eq!(verdict["report_sha256"], "ab".repeat(32));
        assert_eq!(verdict["auditor"], scene.auditor.id().as_str());
        let published_at_ms: u64 = verdict["published_at_ms"].as_str().context("U64 is a JSON string")?.parse()?;
        assert!(published_at_ms > 1_700_000_000_000, "block timestamp in ms, got {published_at_ms}");
    }
    let auditors: Vec<String> = scene.registry.view("get_auditors").await?.json()?;
    assert_eq!(auditors, [scene.auditor.id().to_string(), scene.other_auditor.id().to_string()]);
    Ok(())
}

#[tokio::test]
async fn an_account_outside_the_allowlist_is_rejected_and_nothing_is_stored() -> Result<()> {
    let worker = sandbox().await?;
    let scene = Scene::new(&worker).await?;
    let hash = some_hash(1);

    let failure =
        scene.publish(&scene.outsider, &hash, "Safe", &[]).transact().await?.into_result().unwrap_err().to_string();
    assert!(
        failure.contains(&format!("{} is not an allowlisted auditor", scene.outsider.id())),
        "unexpected failure: {failure}"
    );
    assert_eq!(scene.verdict(&scene.outsider, &hash).await?, Value::Null);

    // The contract's own account is not an auditor either.
    let failure = scene
        .publish(scene.registry.as_account(), &hash, "Safe", &[])
        .transact()
        .await?
        .into_result()
        .unwrap_err()
        .to_string();
    assert!(failure.contains("is not an allowlisted auditor"), "unexpected failure: {failure}");
    Ok(())
}

#[tokio::test]
async fn a_second_publish_replaces_the_first() -> Result<()> {
    let worker = sandbox().await?;
    let scene = Scene::new(&worker).await?;
    let hash = some_hash(1);

    scene.publish(&scene.auditor, &hash, "Safe", &[]).transact().await?.into_result()?;
    let first = scene.verdict(&scene.outsider, &hash).await?;
    scene.publish(&scene.other_auditor, &hash, "Warn", &["PF008"]).transact().await?.into_result()?;
    let second = scene.verdict(&scene.outsider, &hash).await?;

    assert_eq!(first["status"], "Safe");
    assert_eq!(second["status"], "Warn");
    assert_eq!(second["rule_ids"], json!(["PF008"]));
    assert_eq!(second["auditor"], scene.other_auditor.id().as_str());
    let (before, after): (u64, u64) =
        (first["published_at_ms"].as_str().unwrap().parse()?, second["published_at_ms"].as_str().unwrap().parse()?);
    assert!(after > before, "the replacement carries a later timestamp");
    Ok(())
}

#[tokio::test]
async fn get_verdict_for_an_unknown_hash_is_null() -> Result<()> {
    let worker = sandbox().await?;
    let scene = Scene::new(&worker).await?;
    scene.publish(&scene.auditor, &some_hash(1), "Safe", &[]).transact().await?.into_result()?;
    assert_eq!(scene.verdict(&scene.outsider, &some_hash(2)).await?, Value::Null);
    Ok(())
}

/// The guard hashes the wasm it reads with RPC `view_code` and looks that up. This proves the key the registry
/// stores is the very string the node reports as the account's `code_hash`.
#[tokio::test]
async fn the_published_code_hash_equals_what_the_rpc_reports_for_a_deployed_contract() -> Result<()> {
    let worker = sandbox().await?;
    let scene = Scene::new(&worker).await?;
    let wasm: &[u8] = &REGISTRY_WASM;
    let deployed = worker.dev_deploy(wasm).await?;

    let rpc_code_hash = match deployed.view_account().await?.contract_state {
        near_workspaces::ContractState::LocalHash(hash) => hash.to_string(),
        other => bail!("expected a locally deployed contract, got {other:?}"),
    };
    let code_via_rpc = deployed.view_code().await?;
    assert_eq!(
        bs58_of(&Sha256::digest(&code_via_rpc)),
        rpc_code_hash,
        "the guard's computation matches the RPC's code_hash"
    );
    assert_eq!(bs58_of(&Sha256::digest(wasm)), rpc_code_hash, "so does hashing the wasm that was deployed");

    scene.publish(&scene.auditor, &rpc_code_hash, "Safe", &[]).transact().await?.into_result()?;
    let verdict = scene.verdict(&scene.outsider, &rpc_code_hash).await?;
    assert_eq!(verdict["code_hash"], rpc_code_hash);
    assert_eq!(verdict["status"], "Safe");
    Ok(())
}

#[tokio::test]
async fn the_auditor_pays_for_storage_and_gets_the_excess_back() -> Result<()> {
    let worker = sandbox().await?;
    let scene = Scene::new(&worker).await?;
    let registry_before = scene.registry.view_account().await?;
    let auditor_before = scene.auditor.view_account().await?.balance;

    let without_deposit =
        scene.publish(&scene.auditor, &some_hash(1), "Safe", &[]).deposit(NearToken::from_yoctonear(0));
    let failure = without_deposit.transact().await?.into_result().unwrap_err().to_string();
    assert!(failure.contains("attach at least"), "unexpected failure: {failure}");

    let attached = NearToken::from_near(1);
    scene.publish(&scene.auditor, &some_hash(1), "Safe", &[]).deposit(attached).transact().await?.into_result()?;
    let registry_after = scene.registry.view_account().await?;

    let storage_cost = NearToken::from_yoctonear(
        u128::from(registry_after.storage_usage - registry_before.storage_usage) * STORAGE_BYTE_COST_YOCTO,
    );
    let gained = registry_after.balance.saturating_sub(registry_before.balance);
    assert!(
        gained >= storage_cost,
        "the registry keeps at least the cost of the bytes it stores: {gained} vs {storage_cost}"
    );
    let paid = auditor_before.saturating_sub(scene.auditor.view_account().await?.balance);
    assert!(
        paid < NearToken::from_millinear(50),
        "of {attached} attached the auditor pays storage and gas only; paid {paid}"
    );
    Ok(())
}

#[tokio::test]
async fn the_allowlist_is_fixed_at_init_and_the_contract_cannot_be_re_initialised() -> Result<()> {
    let worker = sandbox().await?;
    let scene = Scene::new(&worker).await?;

    let takeover = scene
        .outsider
        .call(scene.registry.id(), "new")
        .args_json(json!({ "auditors": [scene.outsider.id()] }))
        .transact()
        .await?
        .into_result()
        .unwrap_err()
        .to_string();
    assert!(takeover.contains("The contract has already been initialized"), "unexpected failure: {takeover}");
    let auditors: Vec<String> = scene.registry.view("get_auditors").await?.json()?;
    assert!(!auditors.contains(&scene.outsider.id().to_string()));
    Ok(())
}

#[tokio::test]
async fn init_rejects_an_empty_allowlist() -> Result<()> {
    let worker = sandbox().await?;
    let registry = worker.dev_deploy(&REGISTRY_WASM).await?;
    let failure = registry
        .call("new")
        .args_json(json!({ "auditors": [] }))
        .transact()
        .await?
        .into_result()
        .unwrap_err()
        .to_string();
    assert!(failure.contains("the auditor allowlist must not be empty"), "unexpected failure: {failure}");
    Ok(())
}

#[tokio::test]
async fn invalid_publications_are_rejected_with_a_clear_message() -> Result<()> {
    let worker = sandbox().await?;
    let scene = Scene::new(&worker).await?;
    let good_hash = some_hash(1);
    let cases = [
        (scene.publish(&scene.auditor, "short", "Safe", &[]), "code_hash must be the base58 form of a 32-byte SHA-256"),
        (scene.publish(&scene.auditor, &good_hash, "Safe", &["PF001"]), "a Safe verdict must not list rule ids"),
        (
            scene.publish(&scene.auditor, &good_hash, "Unsafe", &[]),
            "a Warn or Unsafe verdict must list at least one rule id",
        ),
        (scene.publish(&scene.auditor, &good_hash, "Unsafe", &["nope"]), "must be PF followed by three digits"),
    ];
    for (call, expected) in cases {
        let failure = call.transact().await?.into_result().unwrap_err().to_string();
        assert!(failure.contains(expected), "expected {expected:?}, got: {failure}");
    }
    assert_eq!(scene.verdict(&scene.outsider, &good_hash).await?, Value::Null);
    Ok(())
}

/// No owner, no upgrade path: the wasm exports exactly the four SPEC methods and nothing that could change the
/// allowlist or the code.
#[test]
fn the_wasm_exports_only_the_spec_methods() -> Result<()> {
    let mut exported = Vec::new();
    for payload in wasmparser::Parser::new(0).parse_all(&REGISTRY_WASM) {
        if let wasmparser::Payload::ExportSection(section) = payload? {
            for export in section {
                let export = export?;
                if export.kind == wasmparser::ExternalKind::Func {
                    exported.push(export.name.to_owned());
                }
            }
        }
    }
    exported.sort();
    assert_eq!(exported, ["contract_source_metadata", "get_auditors", "get_verdict", "new", "publish_verdict"]);
    Ok(())
}
