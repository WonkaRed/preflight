//! The Swap, switch: holds both chameleon builds and flips the chameleon account between them.
//!
//! `flip` sends the build that is not live to the chameleon's `upgrade`, and records the flip once that upgrade has
//! gone through. Anyone may call it (the web page signs it with a function-call key limited to this method), so it
//! enforces a minimum interval between flips. The two builds are stored when the switch is initialised and never
//! change: there is no method that writes or replaces them.

use near_sdk::json_types::Base58CryptoHash;
use near_sdk::store::LookupMap;
use near_sdk::{
    AccountId, BorshStorageKey, CryptoHash, Gas, GasWeight, PanicOnDefault, Promise, env, is_promise_success, near,
    require,
};

/// The least gas `flip` must start with: the upgrade carries a 130 KB wasm and the chameleon compiles it on deploy.
const MIN_FLIP_GAS: Gas = Gas::from_tgas(100);
/// Gas kept for `on_flipped`; the upgrade gets every other unspent gas.
const CALLBACK_GAS: Gas = Gas::from_tgas(10);
/// The gas the upgrade call is guaranteed, on top of its share of the unspent gas.
const UPGRADE_GAS: Gas = Gas::from_tgas(30);

#[near(serializers = [borsh, json])]
#[serde(rename_all = "lowercase")]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Build {
    Vulnerable,
    Patched,
}

impl Build {
    fn other(self) -> Self {
        match self {
            Self::Vulnerable => Self::Patched,
            Self::Patched => Self::Vulnerable,
        }
    }
}

#[near(serializers = [borsh])]
#[derive(BorshStorageKey)]
enum StorageKey {
    Code,
}

/// What the switch remembers of a stored build, so a read of the status never loads the wasm.
#[near(serializers = [borsh])]
#[derive(Clone, Copy)]
struct Blob {
    hash: CryptoHash,
    size_bytes: u32,
}

impl Blob {
    fn of(code: &[u8]) -> Self {
        let size_bytes = u32::try_from(code.len()).unwrap_or_else(|_| env::panic_str("wasm too long"));
        Self { hash: env::sha256_array(code), size_bytes }
    }
}

/// What a reader needs to recognise a build on chain: its code hash in both spellings.
#[near(serializers = [json])]
pub struct BuildInfo {
    /// Base58 SHA-256 of the wasm, as NEAR RPC shows an account's `code_hash` and as the registry keys verdicts.
    pub code_hash: Base58CryptoHash,
    /// The same hash as lowercase hex.
    pub code_hash_hex: String,
    /// Length of the wasm in bytes.
    pub size_bytes: u32,
}

#[near(serializers = [json])]
pub struct Status {
    pub chameleon: AccountId,
    /// The build the chameleon runs, as of the last flip that went through.
    pub live: Build,
    pub vulnerable: BuildInfo,
    pub patched: BuildInfo,
    /// Flips that went through.
    pub flips: u64,
    /// Block time of the last accepted `flip`, in milliseconds since the Unix epoch; 0 before the first.
    pub last_flip_ms: u64,
    pub min_interval_ms: u64,
    /// Block time from which `flip` is accepted again.
    pub next_flip_ms: u64,
}

/// NEP-297 event logged when a flip has gone through.
#[near(event_json(standard = "swap"))]
pub enum Event<'a> {
    #[event_version("1.0.0")]
    Flipped { chameleon: &'a AccountId, from: Build, to: Build, flips: u64, code_hash: &'a Base58CryptoHash },
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Switch {
    chameleon: AccountId,
    live: Build,
    flips: u64,
    last_flip_ms: u64,
    min_interval_ms: u64,
    vulnerable: Blob,
    patched: Blob,
    /// The wasm of each build, read one at a time so a call never loads both.
    code: LookupMap<Build, Vec<u8>>,
}

#[near]
impl Switch {
    /// Stores both builds for good. `live` names the one the chameleon runs now. Deploy and call this in one
    /// transaction so nobody can initialise the contract in between. All arguments are Borsh.
    #[init]
    pub fn new(
        #[serializer(borsh)] chameleon: AccountId,
        #[serializer(borsh)] live: Build,
        #[serializer(borsh)] min_interval_ms: u64,
        #[serializer(borsh)] vulnerable: Vec<u8>,
        #[serializer(borsh)] patched: Vec<u8>,
    ) -> Self {
        let (stored_vulnerable, stored_patched) = (Blob::of(&vulnerable), Blob::of(&patched));
        require!(stored_vulnerable.hash != stored_patched.hash, "the two builds are the same wasm");
        let mut code = LookupMap::new(StorageKey::Code);
        code.insert(Build::Vulnerable, vulnerable);
        code.insert(Build::Patched, patched);
        code.flush();
        Self {
            chameleon,
            live,
            flips: 0,
            last_flip_ms: 0,
            min_interval_ms,
            vulnerable: stored_vulnerable,
            patched: stored_patched,
            code,
        }
    }

    /// Upgrades the chameleon to the build that is not live. Panics before `next_flip_ms`.
    pub fn flip(&mut self) -> Promise {
        let now = env::block_timestamp_ms();
        require!(now >= self.next_flip_ms(), format!("too soon: the next flip is allowed from {}", self.next_flip_ms()));
        require!(env::prepaid_gas() >= MIN_FLIP_GAS, format!("attach at least {MIN_FLIP_GAS} of gas"));
        let to = self.live.other();
        let code = self.code.get(&to).unwrap_or_else(|| env::panic_str("the build is not stored"));
        // The chameleon's `upgrade` takes its argument as Borsh: a 4-byte little-endian length, then the wasm.
        let mut args = Vec::with_capacity(code.len() + 4);
        args.extend_from_slice(&self.blob(to).size_bytes.to_le_bytes());
        args.extend_from_slice(code);
        self.last_flip_ms = now;
        Promise::new(self.chameleon.clone())
            .function_call_weight("upgrade".to_owned(), args, near_sdk::NearToken::default(), UPGRADE_GAS, GasWeight(1))
            .then(Self::ext(env::current_account_id()).with_static_gas(CALLBACK_GAS).on_flipped(to))
    }

    /// Records the flip once the chameleon's upgrade has gone through; a failed upgrade leaves everything as it was.
    #[private]
    pub fn on_flipped(&mut self, to: Build) {
        if !is_promise_success() {
            env::log_str("the chameleon's upgrade failed; it still runs the previous build");
            return;
        }
        let from = self.live;
        self.live = to;
        self.flips += 1;
        let code_hash = Base58CryptoHash::from(self.blob(to).hash);
        Event::Flipped { chameleon: &self.chameleon, from, to, flips: self.flips, code_hash: &code_hash }.emit();
    }

    pub fn status(&self) -> Status {
        Status {
            chameleon: self.chameleon.clone(),
            live: self.live,
            vulnerable: self.info(Build::Vulnerable),
            patched: self.info(Build::Patched),
            flips: self.flips,
            last_flip_ms: self.last_flip_ms,
            min_interval_ms: self.min_interval_ms,
            next_flip_ms: self.next_flip_ms(),
        }
    }

    fn next_flip_ms(&self) -> u64 {
        self.last_flip_ms.saturating_add(self.min_interval_ms)
    }

    fn blob(&self, build: Build) -> Blob {
        match build {
            Build::Vulnerable => self.vulnerable,
            Build::Patched => self.patched,
        }
    }

    fn info(&self, build: Build) -> BuildInfo {
        let Blob { hash, size_bytes } = self.blob(build);
        BuildInfo { code_hash: hash.into(), code_hash_hex: hash.iter().map(|byte| format!("{byte:02x}")).collect(), size_bytes }
    }
}
