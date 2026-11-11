//! Checks a deployed contract by account id, offline: the RPC answers come from real responses recorded from
//! mainnet (`tests/data/`) and are replayed through the library's `Transport` seam. Tests that need a response
//! the chain does not hold edit a recorded one and say how.

mod support;

use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use preflight::Severity;
use preflight::deployed::{AccountId, AccountReport, DeployedError, TransportError, check_account};
use serde_json::json;
use sha2::{Digest, Sha256};
use support::{Fixture, Replay, recorded_error};

fn check(fixture: Fixture, account: &str) -> Result<AccountReport, DeployedError> {
    check_account(&Replay::new(fixture), &AccountId::from_str(account).unwrap())
}

fn report(account: &str) -> AccountReport {
    check(Fixture::account(account), account).unwrap()
}

fn ids(report: &AccountReport) -> Vec<(&'static str, Severity)> {
    report.findings.iter().map(|finding| (finding.rule_id, finding.severity)).collect()
}

/// A minimal wasm module whose export section lists `exports` as functions: all the scanner reads.
fn wasm_exporting(exports: &[&str]) -> Vec<u8> {
    let mut section = vec![exports.len() as u8];
    for name in exports {
        section.push(name.len() as u8);
        section.extend(name.as_bytes());
        section.extend([0x00, 0x00]); // kind: function, index 0
    }
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.push(7); // export section
    wasm.push(section.len() as u8);
    wasm.extend(section);
    wasm
}

/// `no-keys.example`'s recorded run with the contract replaced by one that exports `exports`.
fn contract_exporting(exports: &[&str]) -> Fixture {
    contract_with_wasm(&wasm_exporting(exports))
}

fn contract_with_wasm(wasm: &[u8]) -> Fixture {
    let hash = bs58::encode(Sha256::digest(wasm)).into_string();
    Fixture::account("no-keys.example").edit("view_account", |v| v["result"]["code_hash"] = json!(hash)).edit(
        "view_code",
        |v| {
            v["result"]["code_base64"] = json!(STANDARD.encode(wasm));
            v["result"]["hash"] = json!(hash);
        },
    )
}

fn finding_ids(fixture: Fixture) -> Vec<(&'static str, Severity)> {
    ids(&check(fixture, "no-keys.example").unwrap())
}

// --- the three recorded mainnet accounts ---------------------------------------------------------------------

#[test]
fn an_account_with_no_keys_and_no_standard_metadata_is_only_information() {
    let report = report("no-keys.example");
    assert_eq!(ids(&report), [("PFW03", Severity::Info)]);
    assert!(report.findings[0].message.contains("does not export contract_source_metadata"));
    assert!(report.not_evaluated.is_empty());
    assert!(report.is_clean(), "NEP-330 is optional, so its absence alone is not unclean");
    assert_eq!(report.target, "no-keys.example");
    assert_eq!(report.account.exported_functions, 15);
    assert_eq!(
        report.account.code_hash,
        Fixture::account("no-keys.example").response("view_account")["result"]["code_hash"]
    );
    assert_eq!(report.rpc, "replay://recorded");
}

#[test]
fn an_account_with_only_restricted_keys_reports_only_information() {
    let report = report("restricted-keys.example");
    assert_eq!(ids(&report), [("PFW02", Severity::Info), ("PFW03", Severity::Info)]);
    assert!(report.findings[0].message.contains("state_migrate, upgrade"), "{}", report.findings[0].message);
    assert!(report.findings[1].message.contains("version 0.4.5 and link https://github.com/near/intents/tree/"));
    assert!(report.findings[1].message.contains("self-declared"));
    assert!(report.is_clean(), "information alone does not make a report unclean");
}

#[test]
fn an_account_with_three_full_access_keys_is_medium() {
    let report = report("three-keys.example");
    assert_eq!(ids(&report), [("PFW01", Severity::Medium), ("PFW02", Severity::Info), ("PFW03", Severity::Info)]);
    assert!(report.findings[0].message.starts_with("this account has 3 full-access keys: ed25519:"));
    assert!(report.findings[0].message.contains("Whoever holds one can replace the contract's code"));
    assert!(report.findings[1].message.contains("set_owner"));
    assert!(!report.is_clean());
}

#[test]
fn every_request_is_a_read_pinned_to_one_block() {
    let replay = Replay::new(Fixture::account("restricted-keys.example"));
    check_account(&replay, &AccountId::from_str("restricted-keys.example").unwrap()).unwrap();
    let requests = replay.requests();
    let kinds: Vec<String> = requests.iter().map(support::kind_of).collect();
    assert_eq!(
        kinds,
        [
            "view_account",
            "view_code",
            "view_access_key_list",
            "view_state",
            "call_function",
            "EXPERIMENTAL_protocol_config"
        ]
    );
    let block = Fixture::account("restricted-keys.example").response("view_account")["result"]["block_hash"].clone();
    for request in &requests {
        let params = &request["params"];
        match request["method"].as_str().unwrap() {
            "query" => assert!(
                ["view_account", "view_code", "view_access_key_list", "view_state", "call_function"]
                    .contains(&params["request_type"].as_str().unwrap()),
                "{request}"
            ),
            "EXPERIMENTAL_protocol_config" => {}
            other => panic!("not a read-only method: {other}"),
        }
        if support::kind_of(request) == "view_account" {
            assert_eq!(params["finality"], "final");
        } else {
            assert_eq!(params["block_id"], block, "{request}");
            assert!(params.get("finality").is_none());
        }
        assert!(request.get("signature").is_none() && params.get("signed_tx_base64").is_none());
    }
}

#[test]
fn the_json_report_has_the_documented_shape() {
    let value = serde_json::to_value(report("three-keys.example")).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["kind"], "deployed");
    assert_eq!(value["tool"]["name"], "preflight");
    assert_eq!(value["target"], "three-keys.example");
    assert_eq!(value["summary"]["findings"], 3);
    assert_eq!(value["summary"]["by_severity"], json!({"info": 2, "low": 0, "medium": 1, "high": 0, "critical": 0}));
    assert_eq!(value["not_evaluated"], json!([]));
    assert!(value["block"]["height"].as_u64().unwrap() > 0);
    assert!(value["account"]["amount"].is_string(), "amounts are strings: they do not fit a JSON number");
    let finding = &value["findings"][0];
    for field in ["rule_id", "title", "severity", "item", "message", "read", "limits", "help"] {
        assert!(finding[field].is_string(), "{field}");
    }
}

#[test]
fn the_text_report_names_what_was_read_and_what_it_does_not_prove() {
    let text = report("three-keys.example").to_string();
    assert!(text.starts_with("three-keys.example at block "), "{text}");
    assert!(text.contains("PFW01 [medium] Access keys that can change the contract"));
    assert!(text.contains("    read: RPC query view_access_key_list"));
    assert!(text.contains("    limits: It shows that a key exists, not who holds it or how it is guarded: a multisig, a DAO or a timelock may sit behind it. A contract can be upgradable through such a key or through its own methods (see PFW02), and it reads no code."));
    assert!(text.ends_with("3 findings (1 medium, 2 info)\n"), "{text}");
}

#[test]
fn a_report_with_no_findings_says_it_is_not_an_audit() {
    let metadata = r#"{"version":"1.0.0","link":"https://example.org/src/tree/abc"}"#;
    let fixture = Fixture::account("restricted-keys.example")
        .edit("call_function", |v| v["result"]["result"] = json!(metadata.bytes().collect::<Vec<u8>>()));
    let mut report = check(fixture, "restricted-keys.example").unwrap();
    report.findings.clear();
    assert!(report.to_string().ends_with("No findings from checks PFW01-PFW06. That is not a safety audit\n"));
}

// --- each check, end to end, with a finding and without --------------------------------------------------------

#[test]
fn pfw01_function_call_key_on_the_contract_with_no_method_list() {
    let key = json!({"public_key": "ed25519:SELFKEY", "access_key": {"nonce": 1, "permission":
        {"FunctionCall": {"allowance": null, "method_names": [], "receiver_id": "no-keys.example"}}}});
    let fixture =
        Fixture::account("no-keys.example").edit("view_access_key_list", |v| v["result"]["keys"] = json!([key]));
    let found = check(fixture, "no-keys.example").unwrap();
    assert!(found.findings.iter().any(|f| f.rule_id == "PFW01" && f.message.contains("ed25519:SELFKEY")));
    let message = &found.findings.iter().find(|f| f.rule_id == "PFW01").unwrap().message;
    assert!(
        message.ends_with(
            "Such a key can call, with no attached deposit, any method on the contract, including methods guarded \
             only by checking that the caller is the contract itself (`#[private]`)"
        ),
        "{message}"
    );
}

#[test]
fn pfw01_gas_key_permissions_are_classified_and_unknown_ones_fail_the_read() {
    let gas = json!({"public_key": "ed25519:GAS", "access_key": {"nonce": 1, "permission":
        {"GasKeyFullAccess": {"balance": "0", "num_nonces": 3}}}});
    let fixture =
        Fixture::account("no-keys.example").edit("view_access_key_list", |v| v["result"]["keys"] = json!([gas]));
    assert!(check(fixture, "no-keys.example").unwrap().findings.iter().any(|f| f.rule_id == "PFW01"));

    let unknown = json!({"public_key": "ed25519:NEW", "access_key": {"nonce": 1, "permission": "SomethingNew"}});
    let fixture =
        Fixture::account("no-keys.example").edit("view_access_key_list", |v| v["result"]["keys"] = json!([unknown]));
    let error = check(fixture, "no-keys.example").unwrap_err();
    assert!(matches!(error, DeployedError::Malformed { call: "view_access_key_list", .. }), "{error}");
}

#[test]
fn pfw01_pages_are_followed_and_a_node_that_ignores_after_key_is_an_error() {
    let page = |last: Option<&str>| {
        let mut result =
            json!({"keys": [{"public_key": "ed25519:K", "access_key": {"nonce": 1, "permission": "FullAccess"}}]});
        if let Some(last) = last {
            result["last_key"] = json!(last);
        }
        result
    };
    let stuck = Fixture::account("no-keys.example").edit("view_access_key_list", |v| {
        v["result"]["keys"] = page(Some("ed25519:K"))["keys"].clone();
        v["result"]["last_key"] = json!("ed25519:K");
    });
    let error = check(stuck, "no-keys.example").unwrap_err();
    assert!(error.to_string().contains("do not advance"), "{error}");
}

#[test]
fn pfw02_matches_only_upgrade_style_names() {
    assert_eq!(finding_ids(contract_exporting(&["get_greeting", "set_greeting"])), [("PFW03", Severity::Info)]);
    let found = finding_ids(contract_exporting(&["upgrade", "get_greeting"]));
    assert!(found.contains(&("PFW02", Severity::Info)), "{found:?}");
}

#[test]
fn pfw03_exported_metadata_that_fails_or_is_not_json_is_reported_not_trusted() {
    let method_not_found = recorded_error("method_not_found")["result"]["error"].clone();
    let fixture = Fixture::account("restricted-keys.example").edit("call_function", |v| {
        v["result"].as_object_mut().unwrap().remove("result");
        v["result"]["error"] = method_not_found;
    });
    let report = check(fixture, "restricted-keys.example").unwrap();
    let finding = report.findings.iter().find(|f| f.rule_id == "PFW03").unwrap();
    assert_eq!(finding.severity, Severity::Low);
    assert!(finding.message.contains("MethodNotFound"), "{}", finding.message);

    let fixture = Fixture::account("restricted-keys.example")
        .edit("call_function", |v| v["result"]["result"] = json!(b"<html>".to_vec()));
    let report = check(fixture, "restricted-keys.example").unwrap();
    assert!(report.findings.iter().any(|f| f.rule_id == "PFW03" && f.message.contains("not NEP-330 JSON")));
}

#[test]
fn pfw03_hostile_metadata_cannot_inject_terminal_escapes() {
    let hostile = "{\"version\":\"1\\u001b[2J\",\"link\":\"https://x\\r\\nFAKE LINE\"}";
    let fixture = Fixture::account("restricted-keys.example")
        .edit("call_function", |v| v["result"]["result"] = json!(hostile.bytes().collect::<Vec<u8>>()));
    let text = check(fixture, "restricted-keys.example").unwrap().to_string();
    assert!(!text.contains('\u{1b}') && !text.contains('\r'), "{text:?}");
    assert!(text.contains("https://x??FAKE LINE"));
}

/// `no-keys.example`'s recorded run whose `STATE` probe found nothing, and whose any-key probe answers `values`.
fn without_state_key(values: serde_json::Value) -> Fixture {
    let block = Fixture::account("no-keys.example").response("view_state")["result"]["block_hash"].clone();
    let page = |values: serde_json::Value| json!({"jsonrpc": "2.0", "id": "preflight", "result": {"block_hash": block, "block_height": 1, "values": values}});
    Fixture::account("no-keys.example").with("view_state", page(json!([]))).with("view_state_any", page(values))
}

#[test]
fn pfw04_an_init_export_and_no_state_at_all() {
    let found = check(without_state_key(json!([])), "no-keys.example").unwrap();
    let finding = found.findings.iter().find(|f| f.rule_id == "PFW04").unwrap();
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.title, "Initialization method exported and no contract state");
    assert!(finding.message.contains("exports `new` and the account stores no state at all"));
    assert!(found.not_evaluated.is_empty());
}

#[test]
fn pfw04_state_under_other_keys_is_not_evaluated_never_a_finding() {
    // The real first key of restricted-keys.example's state, which has no key called STATE in this position.
    let real = Fixture::account("restricted-keys.example").response("view_state_any")["result"]["values"].clone();
    for fixture in [
        without_state_key(real),
        // Or another key under the STATE prefix, so the second read is never made.
        Fixture::account("no-keys.example")
            .edit("view_state", |v| v["result"]["values"] = json!([{"key": "U1RBVEVfT1RIRVI=", "value": ""}])),
    ] {
        let report = check(fixture, "no-keys.example").unwrap();
        assert!(report.findings.iter().all(|f| f.rule_id != "PFW04"));
        assert_eq!(report.not_evaluated.len(), 1);
        assert_eq!(report.not_evaluated[0].rule_id, "PFW04");
        assert!(report.not_evaluated[0].reason.contains("own storage layout"));
    }
}

#[test]
fn pfw04_the_second_read_is_made_only_when_the_state_key_is_missing() {
    let kinds = |fixture: Fixture| {
        let replay = Replay::new(fixture);
        check_account(&replay, &AccountId::from_str("no-keys.example").unwrap()).unwrap();
        replay.requests().iter().map(support::kind_of).collect::<Vec<_>>()
    };
    assert!(!kinds(Fixture::account("no-keys.example")).contains(&"view_state_any".to_owned()));
    assert!(kinds(without_state_key(json!([]))).contains(&"view_state_any".to_owned()));
}

#[test]
fn pfw04_a_second_read_that_is_too_large_is_not_evaluated() {
    let fixture = without_state_key(json!([])).with("view_state_any", recorded_error("too_large_state"));
    let report = check(fixture, "no-keys.example").unwrap();
    assert!(report.findings.iter().all(|f| f.rule_id != "PFW04"));
    assert!(report.not_evaluated[0].reason.contains("TOO_LARGE_CONTRACT_STATE"));
}

#[test]
fn pfw04_a_state_read_that_fails_for_any_other_reason_fails_the_run() {
    let fixture = Fixture::account("no-keys.example").with("view_state", recorded_error("unknown_block"));
    let error = check(fixture, "no-keys.example").unwrap_err();
    assert!(
        matches!(error, DeployedError::Node { call: "view_state", cause: Some(ref c), .. } if c == "UNKNOWN_BLOCK"),
        "{error}"
    );
    let fixture = without_state_key(json!([])).with("view_state_any", recorded_error("unknown_block"));
    let error = check(fixture, "no-keys.example").unwrap_err();
    assert!(matches!(error, DeployedError::Node { call: "view_state", .. }), "{error}");
}

#[test]
fn pfw03_a_failed_metadata_call_fails_the_run_and_never_reads_as_not_exported() {
    let fixture = Fixture::account("restricted-keys.example").with("call_function", recorded_error("unknown_block"));
    let error = check(fixture, "restricted-keys.example").unwrap_err();
    assert!(matches!(error, DeployedError::Node { call: "call_function", .. }), "{error}");
    let fixture =
        Fixture::account("restricted-keys.example").with("call_function", json!({"jsonrpc": "2.0", "id": "preflight"}));
    assert!(check(fixture, "restricted-keys.example").is_err());
}

#[test]
fn pfw04_a_too_large_state_is_not_evaluated_and_never_a_finding() {
    let fixture = Fixture::account("no-keys.example").with("view_state", recorded_error("too_large_state"));
    let report = check(fixture, "no-keys.example").unwrap();
    assert!(report.findings.iter().all(|f| f.rule_id != "PFW04"));
    assert_eq!(report.not_evaluated.len(), 1);
    assert_eq!(report.not_evaluated[0].rule_id, "PFW04");
    assert!(report.not_evaluated[0].reason.contains("TOO_LARGE_CONTRACT_STATE"));
    assert!(report.to_string().contains("PFW04 not evaluated: the node refused to read the state"));
    assert!(report.to_string().trim_end().ends_with("; 1 not evaluated"));
}

#[test]
fn pfw04_a_state_entry_beyond_the_size_cap_is_not_evaluated() {
    let huge = json!({"jsonrpc": "2.0", "id": "preflight", "result": {"block_hash": Fixture::account("no-keys.example").response("view_state")["result"]["block_hash"],
        "values": [{"key": "U1RBVEU=", "value": "A".repeat(5 << 20)}]}});
    let report = check(Fixture::account("no-keys.example").with("view_state", huge), "no-keys.example").unwrap();
    assert_eq!(report.not_evaluated.len(), 1);
    assert!(report.not_evaluated[0].reason.contains("response limit"), "{}", report.not_evaluated[0].reason);
}

#[test]
fn pfw05_a_balance_below_the_storage_cost() {
    let fixture = Fixture::account("no-keys.example").edit("view_account", |v| v["result"]["amount"] = json!("1000"));
    let report = check(fixture, "no-keys.example").unwrap();
    let finding = report.findings.iter().find(|f| f.rule_id == "PFW05").unwrap();
    assert_eq!(finding.severity, Severity::Low);
    assert!(finding.message.contains("at 10000000000000000000 yoctoNEAR per byte"), "{}", finding.message);
    assert!(finding.message.starts_with("the account holds 0.0000 NEAR (1000 yoctoNEAR"), "{}", finding.message);
}

#[test]
fn pfw05_a_zero_balance_account_is_exempt_up_to_770_bytes() {
    let with = |storage_usage: u64| {
        let fixture = Fixture::account("no-keys.example").edit("view_account", |v| {
            v["result"]["amount"] = json!("0");
            v["result"]["storage_usage"] = json!(storage_usage);
        });
        check(fixture, "no-keys.example").unwrap().findings.iter().any(|f| f.rule_id == "PFW05")
    };
    assert!(!with(300));
    assert!(!with(770));
    assert!(with(771));
}

#[test]
fn pfw05_locked_stake_counts() {
    let fixture = Fixture::account("no-keys.example").edit("view_account", |v| {
        v["result"]["amount"] = json!("0");
        v["result"]["locked"] = json!("36677996000000000000000000000000");
    });
    assert!(check(fixture, "no-keys.example").unwrap().findings.iter().all(|f| f.rule_id != "PFW05"));
}

#[test]
fn pfw06_a_token_with_transfer_call_and_no_resolver() {
    let found = finding_ids(contract_exporting(&["ft_transfer", "ft_transfer_call", "storage_deposit", "new"]));
    assert!(found.contains(&("PFW06", Severity::Low)), "{found:?}");
}

#[test]
fn pfw06_a_token_with_a_resolver_and_registration_has_no_pfw06_finding() {
    let found =
        finding_ids(contract_exporting(&["ft_transfer", "ft_transfer_call", "ft_resolve_transfer", "storage_deposit"]));
    assert!(found.iter().all(|(id, _)| *id != "PFW06"), "{found:?}");
}

#[test]
fn pfw06_transfer_without_storage_deposit_is_information() {
    let found = finding_ids(contract_exporting(&["ft_transfer"]));
    assert!(found.contains(&("PFW06", Severity::Info)), "{found:?}");
}

// --- the account cannot be checked -----------------------------------------------------------------------------

#[test]
fn an_unknown_account_is_an_error_naming_it() {
    let fixture = Fixture::account("no-keys.example").with("view_account", recorded_error("unknown_account"));
    let error = check(fixture, "no-keys.example").unwrap_err();
    assert!(matches!(error, DeployedError::UnknownAccount { ref account } if account == "no-keys.example"), "{error}");
    assert!(!error.is_read_failure());
}

#[test]
fn an_account_with_no_contract_is_an_error_not_a_clean_report() {
    let fixture = Fixture::account("no-keys.example").with("view_account", recorded_error("no_code_account"));
    let error = check(fixture, "no-keys.example").unwrap_err();
    assert!(matches!(error, DeployedError::NoContract { .. }), "{error}");
    assert!(error.to_string().contains("nothing to check"));
    assert!(!error.is_read_failure());
}

#[test]
fn view_code_saying_there_is_no_code_is_an_error() {
    let fixture = Fixture::account("no-keys.example").with("view_code", recorded_error("no_contract_code"));
    let error = check(fixture, "no-keys.example").unwrap_err();
    assert!(
        matches!(error, DeployedError::Node { call: "view_code", cause: Some(ref c), .. } if c == "NO_CONTRACT_CODE"),
        "{error}"
    );
}

#[test]
fn a_node_error_object_is_surfaced_with_its_cause() {
    let fixture = Fixture::account("no-keys.example").with("view_code", recorded_error("unknown_block"));
    let error = check(fixture, "no-keys.example").unwrap_err();
    assert!(
        matches!(error, DeployedError::Node { call: "view_code", cause: Some(ref c), .. } if c == "UNKNOWN_BLOCK"),
        "{error}"
    );
    assert!(error.is_read_failure());
    assert!(error.to_string().starts_with("view_code: the node returned an error: UNKNOWN_BLOCK"), "{error}");
}

#[test]
fn a_response_with_neither_result_nor_error_is_unusable() {
    let fixture =
        Fixture::account("no-keys.example").with("view_account", json!({"jsonrpc": "2.0", "id": "preflight"}));
    let error = check(fixture, "no-keys.example").unwrap_err();
    assert!(matches!(error, DeployedError::Malformed { call: "view_account", .. }), "{error}");
}

#[test]
fn a_response_to_a_different_request_is_unusable() {
    let fixture = Fixture::account("no-keys.example").edit("view_account", |v| v["id"] = json!("someone-else"));
    let error = check(fixture, "no-keys.example").unwrap_err();
    assert!(error.to_string().contains("id does not match"), "{error}");
}

#[test]
fn a_result_missing_a_field_is_unusable() {
    let fixture = Fixture::account("no-keys.example").edit("view_account", |v| {
        v["result"].as_object_mut().unwrap().remove("storage_usage");
    });
    let error = check(fixture, "no-keys.example").unwrap_err();
    assert!(error.to_string().contains("storage_usage"), "{error}");
}

#[test]
fn an_amount_that_is_not_a_number_is_unusable() {
    let fixture = Fixture::account("no-keys.example").edit("view_account", |v| v["result"]["amount"] = json!("lots"));
    assert!(matches!(
        check(fixture, "no-keys.example").unwrap_err(),
        DeployedError::Malformed { call: "view_account", .. }
    ));
}

#[test]
fn a_node_that_answers_for_another_block_is_unusable() {
    let fixture =
        Fixture::account("no-keys.example").edit("view_code", |v| v["result"]["block_hash"] = json!("SomeOtherBlock"));
    let error = check(fixture, "no-keys.example").unwrap_err();
    assert!(error.to_string().contains("did not answer for block"), "{error}");
}

#[test]
fn code_that_does_not_match_its_hash_is_unusable() {
    let fixture = Fixture::account("no-keys.example").edit("view_code", |v| {
        let mut wasm = STANDARD.decode(v["result"]["code_base64"].as_str().unwrap()).unwrap();
        *wasm.last_mut().unwrap() ^= 1;
        v["result"]["code_base64"] = json!(STANDARD.encode(wasm));
    });
    let error = check(fixture, "no-keys.example").unwrap_err();
    assert!(error.to_string().contains("does not match the hash"), "{error}");
}

#[test]
fn code_that_does_not_match_its_hash_is_unusable_for_a_global_contract_too() {
    let fixture = Fixture::account("no-keys.example")
        .edit("view_account", |v| {
            v["result"]["code_hash"] = json!("11111111111111111111111111111111");
            v["result"]["global_contract_hash"] = json!("SomeGlobalHash");
        })
        .edit("view_code", |v| v["result"]["hash"] = json!("11111111111111111111111111111112"));
    assert!(check(fixture, "no-keys.example").unwrap_err().to_string().contains("does not match the hash"));
}

#[test]
fn code_whose_hash_differs_from_the_account_hash_is_unusable() {
    let fixture = Fixture::account("no-keys.example")
        .edit("view_account", |v| v["result"]["code_hash"] = json!("11111111111111111111111111111112"));
    assert!(check(fixture, "no-keys.example").unwrap_err().to_string().contains("does not match the hash"));
}

#[test]
fn code_that_is_not_base64_or_not_wasm_is_unusable() {
    let fixture = Fixture::account("no-keys.example").edit("view_code", |v| v["result"]["code_base64"] = json!("***"));
    assert!(check(fixture, "no-keys.example").unwrap_err().to_string().contains("not base64"));
    let error = check(contract_with_wasm(b"this is not a wasm module"), "no-keys.example").unwrap_err();
    assert!(error.to_string().contains("not a readable wasm module"), "{error}");
}

#[test]
fn an_oversized_code_response_is_refused_not_truncated() {
    let fixture = Fixture::account("no-keys.example")
        .edit("view_code", |v| v["result"]["code_base64"] = json!("A".repeat(9 << 20)));
    let error = check(fixture, "no-keys.example").unwrap_err();
    assert!(
        matches!(error, DeployedError::Transport { call: "view_code", source: TransportError::TooLarge { .. } }),
        "{error}"
    );
}

/// `no-keys.example`'s recorded run as an account that holds no code of its own but uses a global contract.
fn global_contract_account(edit: impl FnOnce(&mut serde_json::Value)) -> Fixture {
    Fixture::account("no-keys.example").edit("view_account", |v| {
        v["result"]["code_hash"] = json!("11111111111111111111111111111111");
        edit(&mut v["result"]);
    })
}

fn recorded_code_hash() -> String {
    Fixture::account("no-keys.example").response("view_code")["result"]["hash"].as_str().unwrap().to_owned()
}

#[test]
fn a_global_contract_named_by_account_is_checked_and_can_be_replaced_by_its_publisher() {
    let fixture = global_contract_account(|v| v["global_contract_account_id"] = json!("publisher.near"));
    let report = check(fixture, "no-keys.example").unwrap();
    assert_eq!(report.account.global_contract_account_id.as_deref(), Some("publisher.near"));
    assert_eq!(report.account.global_contract_hash, None);
    assert!(
        report.to_string().contains(
            "  code follows the global contract published by publisher.near; publisher.near can replace it (not checked)\n"
        ),
        "{report}"
    );
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["account"]["global_contract_account_id"], "publisher.near");
    assert_eq!(json["account"]["global_contract_hash"], json!(null));
}

#[test]
fn a_global_contract_named_by_hash_is_checked_against_that_hash_and_cannot_change() {
    let hash = recorded_code_hash();
    let report =
        check(global_contract_account(|v| v["global_contract_hash"] = json!(hash)), "no-keys.example").unwrap();
    assert_eq!(report.account.global_contract_hash.as_deref(), Some(hash.as_str()));
    assert_eq!(report.account.global_contract_account_id, None);
    assert!(
        report.to_string().contains(&format!("  code is the global contract with hash {hash}, which cannot change\n")),
        "{report}"
    );
}

#[test]
fn code_that_is_not_the_global_contract_the_account_names_by_hash_is_unusable() {
    let other = bs58::encode(Sha256::digest(b"another contract")).into_string();
    let error =
        check(global_contract_account(|v| v["global_contract_hash"] = json!(other)), "no-keys.example").unwrap_err();
    assert!(matches!(error, DeployedError::Malformed { call: "view_code", .. }), "{error}");
    assert!(error.to_string().contains("does not match the global contract hash"), "{error}");
}

#[test]
fn an_account_naming_both_kinds_of_global_contract_is_unusable() {
    let hash = recorded_code_hash();
    let fixture = global_contract_account(|v| {
        v["global_contract_hash"] = json!(hash);
        v["global_contract_account_id"] = json!("publisher.near");
    });
    let error = check(fixture, "no-keys.example").unwrap_err();
    assert!(matches!(error, DeployedError::Malformed { call: "view_account", .. }), "{error}");
}

// --- account ids ----------------------------------------------------------------------------------------------

#[test]
fn hostile_or_malformed_account_ids_are_rejected_before_any_request() {
    for good in ["no-keys.example", "a1.b-c_d.near", "ab", &"a".repeat(64), &"0".repeat(64)] {
        assert!(AccountId::from_str(good).is_ok(), "{good}");
    }
    let long = "a".repeat(65);
    for bad in [
        "",
        "a",
        &long,
        "Wrap.near",
        "wrap..near",
        ".no-keys.example",
        "no-keys.example.",
        "-no-keys.example",
        "wrap-.near",
        "wra__p.near",
        "wrap near",
        "no-keys.example\n",
        "no-keys.example/../x",
        "no-keys.example\",\"id\":\"x",
        "no-keys.example;DROP",
        "wrap\u{0}.near",
        "wräp.near",
        "https://no-keys.example",
        "no-keys.example?x=1",
    ] {
        assert!(AccountId::from_str(bad).is_err(), "{bad:?}");
    }
}
