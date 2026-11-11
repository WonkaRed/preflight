use std::ffi::OsStr;
use std::io::{self, ErrorKind, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::builder::TypedValueParser;
use clap::error::ErrorKind as ClapErrorKind;
use clap::{Arg, Args, Command as ClapCommand, Parser, Subcommand};
use preflight::deployed::{self, AccountId, HttpTransport, RpcUrl};
use preflight::rules;

/// Free public mainnet endpoint, listed at docs.near.org/api/rpc/providers; needs no key.
const DEFAULT_RPC: &str = "https://free.rpc.fastnear.com";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Scan NEAR smart contract source for known vulnerability patterns, or check a deployed contract.
///
/// Exit status: 0 no findings, 1 findings, 2 the scan could not run. `preflight account` adds 3: the chain could
/// not be read (network, timeout, rate limit, node error, malformed answer).
#[derive(Parser)]
#[command(version, args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// A `.rs` file or a directory to scan. A directory named `account` is given as `./account`.
    #[arg(required = true)]
    path: Option<PathBuf>,
    /// Print the report as JSON (schema in SPEC.md) instead of text.
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Check a contract that is already deployed, by account id, using read-only JSON-RPC requests.
    ///
    /// Runs checks PFW01 to PFW06 on what the chain shows: access keys, upgrade-style exports, NEP-330 source
    /// metadata, initialization, storage balance and fungible-token shape. Nothing is signed, sent or spent.
    /// Findings of severity info are printed but do not change the exit status.
    Account(AccountArgs),
}

#[derive(Args)]
struct AccountArgs {
    /// Account id of the contract, such as `contract.example`.
    account_id: AccountId,
    /// JSON-RPC endpoint to read from.
    #[arg(long, default_value = DEFAULT_RPC, value_parser = RpcUrlParser)]
    rpc: RpcUrl,
    /// Print the report as JSON (schema in SPEC.md) instead of text.
    #[arg(long)]
    json: bool,
}

/// Parses `--rpc`. Unlike clap's built-in error, its message never repeats the value: the path of an endpoint URL
/// can carry an API key.
#[derive(Clone)]
struct RpcUrlParser;

impl TypedValueParser for RpcUrlParser {
    type Value = RpcUrl;

    fn parse_ref(&self, cmd: &ClapCommand, _arg: Option<&Arg>, value: &OsStr) -> Result<RpcUrl, clap::Error> {
        let parsed = value.to_str().ok_or_else(|| "not valid UTF-8".to_owned()).and_then(str::parse::<RpcUrl>);
        parsed.map_err(|reason: String| {
            cmd.clone().error(ClapErrorKind::ValueValidation, format!("invalid value for '--rpc <RPC>': {reason}"))
        })
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match (cli.command, cli.path) {
        (Some(Command::Account(args)), _) => account(args),
        (None, Some(path)) => source(&path, cli.json),
        (None, None) => unreachable!("clap requires a path unless a subcommand is given"),
    }
}

fn source(path: &std::path::Path, json: bool) -> ExitCode {
    let rules: Vec<_> = rules::all().collect();
    let report = match preflight::scan(path, &rules) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("preflight: {error}");
            return ExitCode::from(2);
        }
    };
    let output = if json { to_json(&report) } else { report.to_string() };
    print_report(&output, u8::from(!report.is_clean()))
}

fn account(args: AccountArgs) -> ExitCode {
    let transport = HttpTransport::new(args.rpc, REQUEST_TIMEOUT);
    let report = match deployed::check_account(&transport, &args.account_id) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("preflight: {error}");
            return ExitCode::from(if error.is_read_failure() { 3 } else { 2 });
        }
    };
    let output = if args.json { to_json(&report) } else { report.to_string() };
    print_report(&output, u8::from(!report.is_clean()))
}

fn to_json(report: &impl serde::Serialize) -> String {
    serde_json::to_string_pretty(report).expect("a report always serializes") + "\n"
}

fn print_report(output: &str, status: u8) -> ExitCode {
    match io::stdout().write_all(output.as_bytes()) {
        // `preflight ... | head` closes the pipe early; that is the reader's choice, not an error.
        Err(error) if error.kind() != ErrorKind::BrokenPipe => {
            eprintln!("preflight: cannot write the report: {error}");
            ExitCode::from(2)
        }
        _ => ExitCode::from(status),
    }
}
