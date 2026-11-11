//! The real HTTP client against a loopback server, and the real `preflight account` binary, still offline: the
//! server replays recorded responses or misbehaves on purpose. Proves what the in-process tests cannot: that
//! timeouts, HTTP errors, oversize bodies and garbage become errors, and what exit code the binary gives.

mod support;

use std::process::{Command, Output};
use std::str::FromStr;
use std::time::{Duration, Instant};

use preflight::deployed::{
    AccountId, DeployedError, HttpTransport, RpcUrl, TransportError, check_account, check_account_within,
};
use serde_json::Value;
use support::{Fixture, Reply, Server};

fn run_against(server: &Server) -> Result<preflight::deployed::AccountReport, DeployedError> {
    let transport = HttpTransport::new(RpcUrl::from_str(&server.url).unwrap(), Duration::from_secs(10));
    check_account(&transport, &AccountId::from_str("no-keys.example").unwrap())
}

fn transport_error(server: &Server, timeout: Duration) -> TransportError {
    let transport = HttpTransport::new(RpcUrl::from_str(&server.url).unwrap(), timeout);
    match check_account(&transport, &AccountId::from_str("no-keys.example").unwrap()) {
        Err(DeployedError::Transport { source, .. }) => source,
        other => panic!("expected a transport error, got {other:?}"),
    }
}

// --- HttpTransport -------------------------------------------------------------------------------------------

#[test]
fn a_recorded_run_replayed_over_http_gives_the_same_report() {
    let server = Server::replaying(Fixture::account("three-keys.example"));
    let transport = HttpTransport::new(RpcUrl::from_str(&server.url).unwrap(), Duration::from_secs(10));
    let report = check_account(&transport, &AccountId::from_str("three-keys.example").unwrap()).unwrap();
    assert_eq!(report.findings.len(), 3);
    assert_eq!(report.rpc, server.url, "the endpoint is reported as scheme://host:port");
    assert_eq!(server.request_count(), 6);
}

#[test]
fn a_slow_node_times_out_with_a_clear_error() {
    let server = Server::start(|_| Reply::Slow(Duration::from_secs(5), String::new()));
    let started = Instant::now();
    let error = transport_error(&server, Duration::from_millis(300));
    assert!(matches!(error, TransportError::Timeout(_)), "{error}");
    assert!(started.elapsed() < Duration::from_secs(4), "the timeout must cut the wait short");
    assert_eq!(error.to_string(), "no answer within 300ms");
}

#[test]
fn http_errors_carry_the_status_and_a_cleaned_snippet() {
    let server = Server::start(|_| Reply::Status(503, "overloaded\u{1b}[31m\nretry".to_owned()));
    let error = transport_error(&server, Duration::from_secs(5));
    assert!(
        matches!(&error, TransportError::Status { status: 503, body } if body == "overloaded?[31m?retry"),
        "{error}"
    );
}

#[test]
fn http_429_is_reported_as_rate_limiting() {
    let server = Server::start(|_| Reply::Status(429, "slow down".to_owned()));
    assert!(matches!(transport_error(&server, Duration::from_secs(5)), TransportError::RateLimited));
}

#[test]
fn a_redirect_is_an_error_not_a_hop_to_another_host() {
    let server = Server::start(|_| Reply::Status(302, String::new()));
    assert!(matches!(transport_error(&server, Duration::from_secs(5)), TransportError::Status { status: 302, .. }));
}

#[test]
fn a_connection_that_closes_without_an_answer_is_a_network_error() {
    let server = Server::start(|_| Reply::Hangup);
    assert!(matches!(transport_error(&server, Duration::from_secs(5)), TransportError::Network(_)));
}

#[test]
fn nothing_listening_is_a_network_error() {
    let url = {
        let server = Server::start(|_| Reply::Hangup);
        server.url.clone()
    };
    std::thread::sleep(Duration::from_millis(100));
    let transport = HttpTransport::new(RpcUrl::from_str(&url).unwrap(), Duration::from_secs(5));
    let error = check_account(&transport, &AccountId::from_str("no-keys.example").unwrap()).unwrap_err();
    assert!(error.is_read_failure(), "{error}");
}

#[test]
fn a_body_over_the_limit_is_refused_while_it_streams() {
    let server = Server::start(|_| Reply::Huge(64 << 20));
    let started = Instant::now();
    let error = transport_error(&server, Duration::from_secs(20));
    assert!(matches!(error, TransportError::TooLarge { limit } if limit == 4 << 20), "{error}");
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_body_that_is_not_json_is_a_malformed_response() {
    let server = Server::start(|_| Reply::Body("<html>captive portal</html>".to_owned()));
    let error = run_against(&server).unwrap_err();
    assert!(matches!(error, DeployedError::Malformed { call: "view_account", .. }), "{error}");
    assert!(error.is_read_failure());
}

#[test]
fn a_json_body_of_the_wrong_shape_is_a_malformed_response() {
    let server = Server::start(|_| Reply::Body("[1,2,3]".to_owned()));
    assert!(matches!(run_against(&server).unwrap_err(), DeployedError::Malformed { .. }));
}

// --- the binary ----------------------------------------------------------------------------------------------

fn preflight(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_preflight")).args(args).output().unwrap()
}

fn account(args: &[&str], server: &Server) -> Output {
    let mut all = vec!["account"];
    all.extend(args);
    all.extend(["--rpc", &server.url]);
    preflight(&all)
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn findings_of_low_or_more_exit_1_and_print_the_report() {
    let server = Server::replaying(Fixture::account("three-keys.example"));
    let output = account(&["three-keys.example"], &server);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.starts_with("three-keys.example at block "), "{text}");
    assert!(text.contains("PFW01 [medium] Access keys that can change the contract"));
    assert!(text.ends_with("3 findings (1 medium, 2 info)\n"), "{text}");
}

#[test]
fn information_alone_exits_0() {
    for (name, summary) in
        [("restricted-keys.example", "2 findings (2 info)"), ("no-keys.example", "1 finding (1 info)")]
    {
        let server = Server::replaying(Fixture::account(name));
        let output = account(&[name], &server);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert!(stdout(&output).ends_with(&format!("{summary}\n")), "{}", stdout(&output));
    }
}

#[test]
fn json_prints_the_documented_report_and_hides_the_endpoint_path() {
    let server = Server::replaying(Fixture::account("three-keys.example"));
    let secret = format!("{}/v1/SECRET-API-KEY", server.url);
    let output = preflight(&["account", "three-keys.example", "--rpc", &secret, "--json"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(!text.contains("SECRET-API-KEY"));
    let report: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["kind"], "deployed");
    assert_eq!(report["rpc"], server.url);
    assert_eq!(report["findings"][0]["rule_id"], "PFW01");
    assert_eq!(report["summary"]["by_severity"]["medium"], 1);
}

#[test]
fn an_unknown_account_exits_2() {
    let fixture = Fixture::account("no-keys.example").with("view_account", support::recorded_error("unknown_account"));
    let output = account(&["no-keys.example"], &Server::replaying(fixture));
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stderr(&output), "preflight: no-keys.example does not exist on this network\n");
    assert_eq!(stdout(&output), "");
}

#[test]
fn an_account_without_a_contract_exits_2_and_never_prints_a_clean_report() {
    let fixture = Fixture::account("no-keys.example").with("view_account", support::recorded_error("no_code_account"));
    let output = account(&["no-keys.example"], &Server::replaying(fixture));
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("has no contract code deployed"));
    assert_eq!(stdout(&output), "");
}

#[test]
fn a_chain_that_cannot_be_read_exits_3_with_nothing_on_stdout() {
    for reply in [
        Box::new(|| Reply::Status(500, "boom".to_owned())) as Box<dyn Fn() -> Reply + Send + Sync>,
        Box::new(|| Reply::Status(429, String::new())),
        Box::new(|| Reply::Body("not json".to_owned())),
        Box::new(|| Reply::Hangup),
    ] {
        let server = Server::start(move |_| reply());
        let output = account(&["no-keys.example"], &server);
        assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
        assert_eq!(stdout(&output), "");
        assert!(stderr(&output).starts_with("preflight: view_account: "), "{}", stderr(&output));
    }
}

#[test]
fn a_node_error_exits_3_and_names_the_cause() {
    let fixture = Fixture::account("no-keys.example").with("view_code", support::recorded_error("unknown_block"));
    let output = account(&["no-keys.example"], &Server::replaying(fixture));
    assert_eq!(output.status.code(), Some(3));
    assert!(stderr(&output).contains("view_code: the node returned an error: UNKNOWN_BLOCK"), "{}", stderr(&output));
}

#[test]
fn an_invalid_account_id_exits_2_before_any_request() {
    let server = Server::start(|_| Reply::Hangup);
    for bad in ["Wrap.NEAR", "wrap..near", "x", "no-keys.example\"},{\"id", "../etc/passwd"] {
        let output = account(&[bad], &server);
        assert_eq!(output.status.code(), Some(2), "{bad}");
        assert_eq!(stdout(&output), "");
    }
    assert_eq!(server.request_count(), 0);
}

#[test]
fn an_invalid_rpc_url_exits_2_before_any_request_and_is_never_echoed() {
    for bad in ["not a url", "ftp://rpc.example", "file:///etc/passwd", ""] {
        let output = preflight(&["account", "no-keys.example", "--rpc", bad]);
        assert_eq!(output.status.code(), Some(2), "{bad:?}");
        assert!(stderr(&output).contains("--rpc"), "{}", stderr(&output));
    }
    // A key in the path of a rejected URL must not reach the terminal or a CI log.
    let output = preflight(&["account", "no-keys.example", "--rpc", "ftp://rpc.example/v1/SECRET-API-KEY"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!stderr(&output).contains("SECRET-API-KEY"), "{}", stderr(&output));
    assert!(!stdout(&output).contains("SECRET-API-KEY"));
}

#[test]
fn proxy_environment_variables_are_ignored() {
    // Nothing listens on port 9, so a proxy that was honoured would make the run fail.
    let server = Server::replaying(Fixture::account("restricted-keys.example"));
    let output = Command::new(env!("CARGO_BIN_EXE_preflight"))
        .args(["account", "restricted-keys.example", "--rpc", &server.url])
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("http_proxy", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env("all_proxy", "http://127.0.0.1:9")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(server.request_count() > 0);
}

#[test]
fn a_node_that_answers_too_slowly_for_the_whole_run_is_stopped() {
    let server = Server::replaying_slowly(Fixture::account("restricted-keys.example"), Duration::from_millis(150));
    let transport = HttpTransport::new(server.url.parse().unwrap(), Duration::from_secs(5));
    let account = AccountId::from_str("restricted-keys.example").unwrap();
    let error = check_account_within(&transport, &account, Duration::from_millis(400)).unwrap_err();
    assert!(matches!(error, DeployedError::Deadline { .. }), "{error}");
    assert!(error.is_read_failure());
    assert!(error.to_string().contains("longer than 400ms in total"), "{error}");
    let requests = server.request_count();
    assert!((2..6).contains(&requests), "the run stopped after {requests} of 6 requests");
}

#[test]
fn the_source_scan_still_takes_a_path_and_a_missing_one_still_exits_2() {
    let output = preflight(&["no/such/path"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("cannot read no/such/path"));
    let output = preflight(&[]);
    assert_eq!(output.status.code(), Some(2), "a path is still required");
}

#[test]
fn the_default_endpoint_is_documented_in_help() {
    let output = preflight(&["account", "--help"]);
    assert!(stdout(&output).contains("https://free.rpc.fastnear.com"), "{}", stdout(&output));
}
