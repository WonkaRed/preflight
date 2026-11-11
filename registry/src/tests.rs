//! Contract-level unit tests: access control, the stored verdict, the event and the storage deposit.

use near_sdk::test_utils::{VMContextBuilder, accounts, get_created_receipts, get_logs};
use near_sdk::{AccountId, NearToken, bs58, testing_env};

use super::*;

const REPORT_URL: &str = "https://example.com/report.json";

fn hash(seed: u8) -> String {
    bs58::encode([seed; 32]).into_string()
}

fn sha() -> String {
    "ab".repeat(32)
}

fn rules(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|id| id.to_string()).collect()
}

/// Runs the next contract call as `caller` at `timestamp_ms` with `deposit` attached.
fn call_as(caller: AccountId, timestamp_ms: u64, deposit: NearToken) {
    testing_env!(
        VMContextBuilder::new()
            .predecessor_account_id(caller)
            .block_timestamp(timestamp_ms * 1_000_000)
            .attached_deposit(deposit)
            .build()
    );
}

/// A registry whose allowlist is `accounts(1)` and `accounts(2)`.
fn registry() -> Registry {
    call_as(accounts(0), 0, NearToken::from_yoctonear(0));
    Registry::new(vec![accounts(1), accounts(2)])
}

fn publish(registry: &mut Registry, code_hash: String, status: VerdictStatus, rule_ids: &[&str]) {
    registry.publish_verdict(code_hash, status, rules(rule_ids), REPORT_URL.into(), sha());
}

const ONE_NEAR: NearToken = NearToken::from_near(1);

#[test]
fn new_stores_the_allowlist_and_get_auditors_returns_it() {
    assert_eq!(registry().get_auditors(), vec![accounts(1), accounts(2)]);
}

#[test]
#[should_panic(expected = "the auditor allowlist must not be empty")]
fn new_rejects_an_empty_allowlist() {
    call_as(accounts(0), 0, NearToken::from_yoctonear(0));
    Registry::new(vec![]);
}

#[test]
#[should_panic(expected = "is listed twice")]
fn new_rejects_a_repeated_auditor() {
    call_as(accounts(0), 0, NearToken::from_yoctonear(0));
    Registry::new(vec![accounts(1), accounts(1)]);
}

#[test]
fn an_allowlisted_auditor_publishes_and_the_contract_sets_auditor_and_time() {
    let mut registry = registry();
    call_as(accounts(2), 1_700_000_000_123, ONE_NEAR);
    registry.publish_verdict(hash(1), VerdictStatus::Unsafe, rules(&["PF001", "PF007"]), REPORT_URL.into(), sha());

    call_as(accounts(4), 1_800_000_000_000, NearToken::from_yoctonear(0));
    let verdict = registry.get_verdict(hash(1)).expect("published verdict is readable by anyone");
    assert_eq!(
        verdict,
        Verdict {
            code_hash: hash(1),
            status: VerdictStatus::Unsafe,
            rule_ids: rules(&["PF001", "PF007"]),
            report_url: REPORT_URL.into(),
            report_sha256: sha(),
            auditor: accounts(2),
            published_at_ms: U64(1_700_000_000_123),
        }
    );
}

#[test]
fn get_verdict_for_an_unknown_hash_is_none() {
    let mut registry = registry();
    call_as(accounts(1), 1, ONE_NEAR);
    publish(&mut registry, hash(1), VerdictStatus::Safe, &[]);
    assert_eq!(registry.get_verdict(hash(2)), None);
    assert_eq!(registry.get_verdict("not even base58".into()), None);
}

#[test]
#[should_panic(expected = "danny is not an allowlisted auditor")]
fn a_caller_outside_the_allowlist_is_rejected() {
    let mut registry = registry();
    call_as(accounts(3), 1, ONE_NEAR);
    publish(&mut registry, hash(1), VerdictStatus::Safe, &[]);
}

#[test]
fn a_rejected_outsider_leaves_no_verdict_behind() {
    let mut registry = registry();
    call_as(accounts(3), 1, ONE_NEAR);
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        publish(&mut registry, hash(1), VerdictStatus::Safe, &[]);
    }));
    assert!(attempt.is_err());
    assert_eq!(registry.get_verdict(hash(1)), None);
}

#[test]
fn the_contract_account_itself_is_not_an_auditor() {
    let mut registry = registry();
    call_as(accounts(0), 1, ONE_NEAR);
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        publish(&mut registry, hash(1), VerdictStatus::Safe, &[]);
    }));
    assert!(attempt.is_err());
}

#[test]
fn a_later_verdict_for_the_same_hash_replaces_the_earlier_one() {
    let mut registry = registry();
    call_as(accounts(1), 1_000, ONE_NEAR);
    publish(&mut registry, hash(1), VerdictStatus::Safe, &[]);
    call_as(accounts(2), 2_000, ONE_NEAR);
    publish(&mut registry, hash(1), VerdictStatus::Warn, &["PF008"]);

    let verdict = registry.get_verdict(hash(1)).unwrap();
    assert_eq!(verdict.status, VerdictStatus::Warn);
    assert_eq!(verdict.rule_ids, rules(&["PF008"]));
    assert_eq!(verdict.auditor, accounts(2));
    assert_eq!(verdict.published_at_ms, U64(2_000));
}

#[test]
fn verdicts_for_different_hashes_do_not_interfere() {
    let mut registry = registry();
    call_as(accounts(1), 1, ONE_NEAR);
    publish(&mut registry, hash(1), VerdictStatus::Safe, &[]);
    publish(&mut registry, hash(2), VerdictStatus::Unsafe, &["PF001"]);
    assert_eq!(registry.get_verdict(hash(1)).unwrap().status, VerdictStatus::Safe);
    assert_eq!(registry.get_verdict(hash(2)).unwrap().status, VerdictStatus::Unsafe);
}

#[test]
fn publishing_logs_a_nep297_event() {
    let mut registry = registry();
    call_as(accounts(1), 1, ONE_NEAR);
    publish(&mut registry, hash(1), VerdictStatus::Warn, &["PF008"]);
    let expected = format!(
        r#"EVENT_JSON:{{"standard":"preflight","version":"1.0.0","event":"verdict_published","data":{{"code_hash":"{}","status":"Warn","auditor":"{}"}}}}"#,
        hash(1),
        accounts(1)
    );
    assert_eq!(get_logs(), vec![expected]);
}

#[test]
#[should_panic(expected = "code_hash must be the base58 form of a 32-byte SHA-256")]
fn publish_rejects_a_malformed_code_hash() {
    let mut registry = registry();
    call_as(accounts(1), 1, ONE_NEAR);
    publish(&mut registry, "short".into(), VerdictStatus::Safe, &[]);
}

#[test]
#[should_panic(expected = "a Safe verdict must not list rule ids")]
fn publish_rejects_a_safe_verdict_with_rule_ids() {
    let mut registry = registry();
    call_as(accounts(1), 1, ONE_NEAR);
    publish(&mut registry, hash(1), VerdictStatus::Safe, &["PF001"]);
}

#[test]
#[should_panic(expected = "must be PF followed by three digits")]
fn publish_rejects_a_malformed_rule_id() {
    let mut registry = registry();
    call_as(accounts(1), 1, ONE_NEAR);
    publish(&mut registry, hash(1), VerdictStatus::Unsafe, &["PF1"]);
}

#[test]
#[should_panic(expected = "report_url must start with https:// or http://")]
fn publish_rejects_a_report_url_that_is_not_http() {
    let mut registry = registry();
    call_as(accounts(1), 1, ONE_NEAR);
    registry.publish_verdict(hash(1), VerdictStatus::Safe, vec![], "javascript:alert(1)".into(), sha());
}

#[test]
#[should_panic(expected = "report_sha256 must be 64 lowercase hex characters")]
fn publish_rejects_a_malformed_report_digest() {
    let mut registry = registry();
    call_as(accounts(1), 1, ONE_NEAR);
    registry.publish_verdict(hash(1), VerdictStatus::Safe, vec![], REPORT_URL.into(), "ABC".into());
}

#[test]
#[should_panic(expected = "attach at least")]
fn a_new_verdict_without_a_storage_deposit_is_rejected() {
    let mut registry = registry();
    call_as(accounts(1), 1, NearToken::from_yoctonear(0));
    publish(&mut registry, hash(1), VerdictStatus::Safe, &[]);
}

#[test]
fn the_storage_deposit_is_charged_and_the_excess_refunded_to_the_auditor() {
    let mut registry = registry();
    call_as(accounts(1), 1, ONE_NEAR);
    publish(&mut registry, hash(1), VerdictStatus::Safe, &[]);
    let receipts = get_created_receipts();
    assert_eq!(receipts.len(), 1, "one refund receipt");
    assert_eq!(receipts[0].receiver_id, accounts(1));
}

#[test]
fn replacing_a_verdict_with_one_of_the_same_size_needs_no_deposit() {
    let mut registry = registry();
    call_as(accounts(1), 1, ONE_NEAR);
    publish(&mut registry, hash(1), VerdictStatus::Warn, &["PF001"]);
    call_as(accounts(1), 2, NearToken::from_yoctonear(0));
    publish(&mut registry, hash(1), VerdictStatus::Unsafe, &["PF002"]);
    assert_eq!(registry.get_verdict(hash(1)).unwrap().status, VerdictStatus::Unsafe);
    assert!(get_created_receipts().is_empty(), "nothing attached, nothing to refund");
}

#[test]
#[should_panic(expected = "attach at least")]
fn replacing_a_verdict_with_a_larger_one_pays_for_the_growth() {
    let mut registry = registry();
    call_as(accounts(1), 1, ONE_NEAR);
    publish(&mut registry, hash(1), VerdictStatus::Safe, &[]);
    call_as(accounts(1), 2, NearToken::from_yoctonear(0));
    publish(&mut registry, hash(1), VerdictStatus::Unsafe, &["PF001", "PF002", "PF003"]);
}

#[test]
fn the_largest_verdict_the_bounds_allow_costs_under_ten_milli_near() {
    call_as(accounts(0), 0, NearToken::from_yoctonear(0));
    let longest_account: AccountId = format!("{}.near", "a".repeat(59)).parse().unwrap();
    assert_eq!(longest_account.as_str().len(), 64);
    let mut registry = Registry::new(vec![longest_account.clone()]);
    call_as(longest_account, 1, NearToken::from_millinear(10));

    let rule_ids: Vec<String> = (0..validate::MAX_RULE_IDS).map(|i| format!("PF{i:03}")).collect();
    let url = format!("https://{}", "a".repeat(validate::REPORT_URL_MAX_BYTES - "https://".len()));
    let longest_hash = bs58::encode([0xff; 32]).into_string();
    assert_eq!(longest_hash.len(), validate::CODE_HASH_MAX_CHARS);
    registry.publish_verdict(longest_hash, VerdictStatus::Unsafe, rule_ids, url, sha());
}
