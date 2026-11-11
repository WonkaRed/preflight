//! Sandbox tests of The Swap: the real chameleon and switch wasm running in a local NEAR node.

use std::collections::HashMap;
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
/// time. Nothing is deployed yet, so starting again is safe. Duplicated in `registry/tests/sandbox.rs` and
/// `exploits/src/lib.rs`: these crates cannot depend on each other.
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

/// The wasm of every contract crate of the workspace, built once for the whole test binary, by library name.
static WASM: LazyLock<HashMap<String, Vec<u8>>> = LazyLock::new(|| build_all().expect("build the contract wasm"));

/// Builds the three contract crates for wasm32 with the release profile.
///
/// Runs the same `cargo` (and pinned toolchain) that runs the tests. The artifact paths come from cargo's JSON
/// messages, so they follow `CARGO_TARGET_DIR`. Ambient `RUSTFLAGS` are dropped so the wasm flags in
/// `.cargo/config.toml` (`--cfg near`) always apply, as they do under `cargo near build`.
fn build_all() -> Result<HashMap<String, Vec<u8>>> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR").context("cargo sets CARGO_MANIFEST_DIR for tests")?;
    let output = Command::new(cargo)
        .args(["build", "--locked", "--target", "wasm32-unknown-unknown", "--release"])
        .args(["-p", "chameleon-vulnerable", "-p", "chameleon-patched", "-p", "swap-switch"])
        .args(["--message-format", "json-render-diagnostics", "--manifest-path"])
        .arg(Path::new(&manifest_dir).join("../Cargo.toml"))
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .stderr(Stdio::inherit())
        .output()
        .context("failed to start cargo")?;
    ensure!(output.status.success(), "cargo build failed for the contracts");
    let mut wasm = HashMap::new();
    for message in String::from_utf8(output.stdout)?.lines().filter_map(|line| serde_json::from_str::<Value>(line).ok()) {
        if message["reason"] != "compiler-artifact" {
            continue;
        }
        let Some(name) = message["target"]["name"].as_str() else { continue };
        let file = message["filenames"].as_array().into_iter().flatten().filter_map(Value::as_str).find(|f| f.ends_with(".wasm"));
        if let Some(file) = file {
            wasm.insert(name.to_owned(), std::fs::read(file)?);
        }
    }
    for name in ["chameleon_vulnerable", "chameleon_patched", "swap_switch"] {
        if !wasm.contains_key(name) {
            bail!("cargo reported no .wasm artifact for {name}");
        }
    }
    Ok(wasm)
}

fn wasm(package: &str) -> &'static [u8] {
    &WASM[&package.replace('-', "_")]
}

fn sha256(bytes: &[u8]) -> near_workspaces::CryptoHash {
    near_workspaces::CryptoHash::try_from(Sha256::digest(bytes).as_slice()).expect("32 bytes")
}

/// The interval the switch enforces in these tests: long enough to catch an immediate second flip, short enough
/// to wait out.
const INTERVAL_MS: u64 = 3_000;
const BUILD_VULNERABLE: u8 = 0;

struct Scene {
    chameleon: Contract,
    switch: Contract,
    treasury: Account,
    /// An account with no role: it calls `flip`, as any visitor of the page would.
    visitor: Account,
    victim: Account,
    mallory: Account,
}

impl Scene {
    /// The chameleon runs the vulnerable build and the switch holds both builds.
    async fn new(worker: &Worker<Sandbox>) -> Result<Self> {
        Self::with_chameleon(worker, None).await
    }

    /// As `new`, with the switch pointed at `chameleon` when given: an account the switch cannot upgrade.
    async fn with_chameleon(worker: &Worker<Sandbox>, chameleon_override: Option<&Account>) -> Result<Self> {
        let root = worker.root_account()?;
        let account = |name: &'static str, near: u128| {
            let root = root.clone();
            async move { Ok::<_, anyhow::Error>(root.create_subaccount(name).initial_balance(NearToken::from_near(near)).transact().await?.into_result()?) }
        };
        let chameleon = account("chameleon", 20).await?;
        let switch = account("switch", 20).await?;
        let treasury = account("treasury", 1).await?;
        let visitor = account("visitor", 20).await?;
        let victim = account("victim", 50).await?;
        let mallory = account("mallory", 20).await?;

        let chameleon = chameleon.deploy(wasm("chameleon-vulnerable")).await?.into_result()?;
        chameleon
            .call("new")
            .args_json(json!({ "switch": switch.id(), "treasury": treasury.id() }))
            .transact()
            .await?
            .into_result()?;
        let target = chameleon_override.map_or(chameleon.id(), |account| account.id());
        let switch = switch.deploy(wasm("swap-switch")).await?.into_result()?;
        switch
            .call("new")
            .args_borsh((
                target.to_string(),
                BUILD_VULNERABLE,
                INTERVAL_MS,
                wasm("chameleon-vulnerable").to_vec(),
                wasm("chameleon-patched").to_vec(),
            ))
            .max_gas()
            .transact()
            .await?
            .into_result()?;
        Ok(Self { chameleon, switch, treasury, visitor, victim, mallory })
    }

    async fn status(&self) -> Result<Value> {
        Ok(self.switch.view("status").await?.json()?)
    }

    async fn code_hash(&self) -> Result<near_workspaces::CryptoHash> {
        match self.chameleon.view_account().await?.contract_state {
            near_workspaces::ContractState::LocalHash(hash) => Ok(hash),
            other => bail!("the chameleon has no local code: {other:?}"),
        }
    }

    /// A visitor signs `flip` with the gas a page would attach.
    async fn flip(&self) -> Result<near_workspaces::result::ExecutionFinalResult> {
        Ok(self.visitor.call(self.switch.id(), "flip").max_gas().transact().await?)
    }

    async fn deposit(&self, who: &Account, near: u128) -> Result<()> {
        who.call(self.chameleon.id(), "deposit").deposit(NearToken::from_near(near)).max_gas().transact().await?.into_result()?;
        Ok(())
    }

    async fn balance_of(&self, who: &Account) -> Result<NearToken> {
        let yocto: String = self.chameleon.view("balance_of").args_json(json!({ "account_id": who.id() })).await?.json()?;
        Ok(NearToken::from_yoctonear(yocto.parse()?))
    }

    /// Mallory calls the settlement callback directly, naming herself and a credit of `near` NEAR.
    async fn forge_credit(&self, near: u128) -> Result<near_workspaces::result::ExecutionFinalResult> {
        let credit = NearToken::from_near(near).as_yoctonear().to_string();
        Ok(self
            .mallory
            .call(self.chameleon.id(), "on_deposit")
            .args_json(json!({ "depositor": self.mallory.id(), "gross": credit, "net": credit }))
            .max_gas()
            .transact()
            .await?)
    }

    async fn withdraw(&self, who: &Account, near: u128) -> Result<near_workspaces::result::ExecutionFinalResult> {
        Ok(who
            .call(self.chameleon.id(), "withdraw")
            .args_json(json!({ "amount": NearToken::from_near(near).as_yoctonear().to_string() }))
            .deposit(NearToken::from_yoctonear(1))
            .max_gas()
            .transact()
            .await?)
    }
}

async fn wait_out_the_interval() {
    tokio::time::sleep(Duration::from_millis(INTERVAL_MS + 1_500)).await;
}

fn failure_of(result: near_workspaces::result::ExecutionFinalResult) -> String {
    result.into_result().expect_err("the call must fail").to_string()
}

#[tokio::test]
async fn the_vulnerable_chameleon_lets_an_outsider_credit_itself_and_drain_a_depositor() -> Result<()> {
    let worker = sandbox().await?;
    let scene = Scene::new(&worker).await?;
    scene.deposit(&scene.victim, 10).await?;
    // Mallory pays the 1 yocto minimum, so the vault has a balance entry for her; then she names her own credit.
    scene.mallory.call(scene.chameleon.id(), "deposit").deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;

    scene.forge_credit(10).await?.into_result()?;
    assert_eq!(scene.balance_of(&scene.mallory).await?, NearToken::from_near(10).saturating_add(NearToken::from_yoctonear(1)), "a credit she never paid for");

    let (mallory_before, vault_before) = (scene.mallory.view_account().await?.balance, scene.chameleon.view_account().await?.balance);
    scene.withdraw(&scene.mallory, 10).await?.into_result()?;
    let gained = scene.mallory.view_account().await?.balance.as_yoctonear().saturating_sub(mallory_before.as_yoctonear());
    let paid_out = vault_before.as_yoctonear().saturating_sub(scene.chameleon.view_account().await?.balance.as_yoctonear());
    assert!(gained > NearToken::from_millinear(9_900).as_yoctonear(), "mallory walked away with 10 NEAR she never paid: gained {gained}");
    assert!(paid_out > NearToken::from_millinear(9_999).as_yoctonear(), "the vault paid it out of what others deposited: {paid_out}");
    Ok(())
}

#[tokio::test]
async fn the_patched_chameleon_rejects_the_forged_callback_and_still_settles_a_real_deposit() -> Result<()> {
    let worker = sandbox().await?;
    let scene = Scene::new(&worker).await?;
    scene.flip().await?.into_result()?;
    assert_eq!(scene.status().await?["live"], "patched");
    let treasury_before = scene.treasury.view_account().await?.balance;

    scene.deposit(&scene.victim, 10).await?;
    scene.mallory.call(scene.chameleon.id(), "deposit").deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
    let failure = failure_of(scene.forge_credit(10).await?);
    assert!(failure.contains("Method on_deposit is private"), "unexpected failure: {failure}");
    assert_eq!(scene.balance_of(&scene.mallory).await?, NearToken::from_yoctonear(1), "the rejected call changed nothing");
    let failure = failure_of(scene.withdraw(&scene.mallory, 10).await?);
    assert!(failure.contains("insufficient balance"), "unexpected failure: {failure}");

    // The contract's own callback still works: 99% credited, 1% to the treasury.
    assert_eq!(scene.balance_of(&scene.victim).await?, NearToken::from_millinear(9_900));
    let fee = scene.treasury.view_account().await?.balance.as_yoctonear() - treasury_before.as_yoctonear();
    assert_eq!(fee, NearToken::from_millinear(100).as_yoctonear(), "the 1% fee reached the treasury");
    scene.withdraw(&scene.victim, 9).await?.into_result()?;
    assert_eq!(scene.balance_of(&scene.victim).await?, NearToken::from_millinear(900));
    Ok(())
}

#[tokio::test]
async fn flip_swaps_the_code_back_and_forth_and_keeps_the_state() -> Result<()> {
    let worker = sandbox().await?;
    let scene = Scene::new(&worker).await?;
    let (vulnerable, patched) = (sha256(wasm("chameleon-vulnerable")), sha256(wasm("chameleon-patched")));

    let status = scene.status().await?;
    assert_eq!(status["live"], "vulnerable");
    assert_eq!(status["chameleon"], scene.chameleon.id().as_str());
    assert_eq!(status["flips"], 0);
    assert_eq!(status["min_interval_ms"], INTERVAL_MS);
    assert_eq!(status["vulnerable"]["code_hash"], vulnerable.to_string());
    assert_eq!(status["vulnerable"]["code_hash_hex"], hex(&Sha256::digest(wasm("chameleon-vulnerable"))));
    assert_eq!(status["vulnerable"]["size_bytes"], wasm("chameleon-vulnerable").len());
    assert_eq!(status["patched"]["code_hash"], patched.to_string());
    assert_eq!(scene.code_hash().await?, vulnerable, "the chameleon starts on the vulnerable build");

    scene.deposit(&scene.victim, 5).await?;
    let balance = scene.balance_of(&scene.victim).await?;

    let first = scene.flip().await?;
    eprintln!("flip gas burnt, vulnerable to patched: {}", first.total_gas_burnt);
    let outcome = first.into_result()?;
    let event = outcome.logs().into_iter().find(|log| log.starts_with("EVENT_JSON:")).context("no event logged")?.to_owned();
    let event: Value = serde_json::from_str(&event["EVENT_JSON:".len()..])?;
    assert_eq!(
        event,
        json!({
            "standard": "swap", "version": "1.0.0", "event": "flipped",
            "data": { "chameleon": scene.chameleon.id(), "from": "vulnerable", "to": "patched", "flips": 1, "code_hash": patched.to_string() },
        })
    );
    assert_eq!(scene.code_hash().await?, patched);
    let status = scene.status().await?;
    assert_eq!((status["live"].as_str(), status["flips"].as_u64()), (Some("patched"), Some(1)));
    let last = status["last_flip_ms"].as_u64().context("last_flip_ms")?;
    assert_eq!(status["next_flip_ms"], last + INTERVAL_MS);
    assert_eq!(scene.balance_of(&scene.victim).await?, balance, "the state survives the swap");

    wait_out_the_interval().await;
    let second = scene.flip().await?;
    eprintln!("flip gas burnt, patched to vulnerable: {}", second.total_gas_burnt);
    second.into_result()?;
    assert_eq!(scene.code_hash().await?, vulnerable);
    assert_eq!(scene.status().await?["flips"], 2);
    assert_eq!(scene.balance_of(&scene.victim).await?, balance);
    // Back on the vulnerable build the forged callback works again.
    scene.mallory.call(scene.chameleon.id(), "deposit").deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
    scene.forge_credit(1).await?.into_result()?;
    Ok(())
}

#[tokio::test]
async fn flip_enforces_the_interval_and_a_minimum_of_gas() -> Result<()> {
    let worker = sandbox().await?;
    let scene = Scene::new(&worker).await?;
    scene.flip().await?.into_result()?;
    let status = scene.status().await?;

    let failure = failure_of(scene.flip().await?);
    assert!(failure.contains("too soon"), "unexpected failure: {failure}");
    assert_eq!(scene.status().await?, status, "a refused flip changes nothing");
    wait_out_the_interval().await;

    let starved = scene.visitor.call(scene.switch.id(), "flip").gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?;
    assert!(failure_of(starved).contains("attach at least"), "a flip started with too little gas is refused");
    assert_eq!(scene.status().await?["flips"], 1);
    scene.flip().await?.into_result()?;
    assert_eq!(scene.status().await?["flips"], 2);
    Ok(())
}

#[tokio::test]
async fn only_the_switch_may_upgrade_the_chameleon_and_only_the_switch_itself_may_record_a_flip() -> Result<()> {
    let worker = sandbox().await?;
    let scene = Scene::new(&worker).await?;
    let before = scene.code_hash().await?;
    let patched = wasm("chameleon-patched").to_vec();

    // No account but the switch may swap the code; the call dies before it reads the wasm.
    for caller in [&scene.mallory, &scene.visitor, &scene.victim] {
        let result = caller.call(scene.chameleon.id(), "upgrade").args_borsh(patched.clone()).max_gas().transact().await?;
        let failure = failure_of(result);
        assert!(failure.contains("only the switch may upgrade this contract"), "unexpected failure: {failure}");
    }
    assert_eq!(scene.code_hash().await?, before);

    let failure = failure_of(scene.mallory.call(scene.switch.id(), "on_flipped").args_json(json!({ "to": "patched" })).max_gas().transact().await?);
    assert!(failure.contains("Method on_flipped is private"), "unexpected failure: {failure}");
    let status = scene.status().await?;
    assert_eq!((status["live"].as_str(), status["flips"].as_u64()), (Some("vulnerable"), Some(0)));
    Ok(())
}

#[tokio::test]
async fn a_flip_whose_upgrade_fails_is_not_recorded() -> Result<()> {
    let worker = sandbox().await?;
    // The switch points at an account with no contract, so its `upgrade` call cannot succeed.
    let bare = worker.root_account()?.create_subaccount("bare").initial_balance(NearToken::from_near(1)).transact().await?.into_result()?;
    let scene = Scene::with_chameleon(&worker, Some(&bare)).await?;

    let outcome = scene.flip().await?.into_result()?;
    assert!(outcome.logs().iter().any(|log| log.contains("upgrade failed")), "logs: {:?}", outcome.logs());
    let status = scene.status().await?;
    assert_eq!((status["live"].as_str(), status["flips"].as_u64()), (Some("vulnerable"), Some(0)));
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The patched build is the vulnerable one plus a `#[private]`: no state, method or signature differs, so the
/// switch can swap one for the other without a migration.
#[test]
fn the_two_chameleon_sources_differ_only_in_the_callback_guard() -> Result<()> {
    let read = |build: &str| std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../chameleon/{build}/src/lib.rs")));
    let (vulnerable, patched) = (read("vulnerable")?, read("patched")?);
    let code = |source: &str| source.lines().filter(|line| !line.trim_start().starts_with("//")).map(str::to_owned).collect::<Vec<_>>();
    let (vulnerable, patched) = (code(&vulnerable), code(&patched));
    assert_eq!(vulnerable.len() + 1, patched.len(), "only the `#[private]` line is added");
    let mut patched_rest = patched.clone();
    let private = patched_rest.iter().position(|line| line.trim() == "#[private]").context("no #[private] in the patched build")?;
    patched_rest.remove(private);
    assert_eq!(vulnerable, patched_rest);
    Ok(())
}
