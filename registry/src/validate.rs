//! Boundary checks for everything an auditor sends. Each returns the panic message on failure, so every branch is
//! testable without a VM and the contract has one place that turns a message into a panic.

use near_sdk::AccountId;
use near_sdk::bs58;

use crate::VerdictStatus;

/// A SHA-256 digest is 32 bytes and base58 spends at most 44 characters on 32 bytes.
pub const CODE_HASH_BYTES: usize = 32;
pub const CODE_HASH_MAX_CHARS: usize = 44;
/// Lowercase hex SHA-256.
pub const REPORT_SHA256_CHARS: usize = 64;
pub const REPORT_URL_MAX_BYTES: usize = 256;
/// `PF` and three digits.
pub const RULE_ID_CHARS: usize = 5;
pub const MAX_RULE_IDS: usize = 32;
pub const MAX_AUDITORS: usize = 16;

pub fn auditors(auditors: &[AccountId]) -> Result<(), String> {
    if auditors.is_empty() {
        return Err("the auditor allowlist must not be empty".into());
    }
    if auditors.len() > MAX_AUDITORS {
        return Err(format!("at most {MAX_AUDITORS} auditors, got {}", auditors.len()));
    }
    if let Some(duplicate) = first_duplicate(auditors) {
        return Err(format!("auditor {duplicate} is listed twice"));
    }
    Ok(())
}

pub fn publication(
    code_hash: &str,
    status: &VerdictStatus,
    rule_ids: &[String],
    report_url: &str,
    report_sha256: &str,
) -> Result<(), String> {
    self::code_hash(code_hash)?;
    self::rule_ids(status, rule_ids)?;
    self::report_url(report_url)?;
    self::report_sha256(report_sha256)
}

fn code_hash(code_hash: &str) -> Result<(), String> {
    let invalid =
        || format!("code_hash must be the base58 form of a {CODE_HASH_BYTES}-byte SHA-256, got {code_hash:?}");
    if code_hash.len() > CODE_HASH_MAX_CHARS {
        return Err(format!("code_hash is longer than {CODE_HASH_MAX_CHARS} characters"));
    }
    let mut decoded = [0u8; CODE_HASH_BYTES];
    match bs58::decode(code_hash).onto(&mut decoded) {
        Ok(CODE_HASH_BYTES) => Ok(()),
        _ => Err(invalid()),
    }
}

fn rule_ids(status: &VerdictStatus, rule_ids: &[String]) -> Result<(), String> {
    match status {
        VerdictStatus::Safe if !rule_ids.is_empty() => return Err("a Safe verdict must not list rule ids".into()),
        VerdictStatus::Warn | VerdictStatus::Unsafe if rule_ids.is_empty() => {
            return Err("a Warn or Unsafe verdict must list at least one rule id, so the reader knows why".into());
        }
        _ => {}
    }
    if rule_ids.len() > MAX_RULE_IDS {
        return Err(format!("at most {MAX_RULE_IDS} rule ids, got {}", rule_ids.len()));
    }
    if let Some(bad) = rule_ids.iter().find(|id| !is_rule_id(id)) {
        return Err(format!("rule id {bad:?} must be PF followed by three digits"));
    }
    if let Some(duplicate) = first_duplicate(rule_ids) {
        return Err(format!("rule id {duplicate} is listed twice"));
    }
    Ok(())
}

fn is_rule_id(id: &str) -> bool {
    id.len() == RULE_ID_CHARS && id.starts_with("PF") && id[2..].bytes().all(|b| b.is_ascii_digit())
}

fn report_url(url: &str) -> Result<(), String> {
    if url.len() > REPORT_URL_MAX_BYTES {
        return Err(format!("report_url is longer than {REPORT_URL_MAX_BYTES} bytes"));
    }
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("report_url must start with https:// or http://".into());
    }
    Ok(())
}

fn report_sha256(digest: &str) -> Result<(), String> {
    let lowercase_hex = digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if digest.len() != REPORT_SHA256_CHARS || !lowercase_hex {
        return Err(format!("report_sha256 must be {REPORT_SHA256_CHARS} lowercase hex characters"));
    }
    Ok(())
}

fn first_duplicate<T: PartialEq>(items: &[T]) -> Option<&T> {
    items.iter().enumerate().find(|(i, item)| items[..*i].contains(item)).map(|(_, item)| item)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(id: &str) -> AccountId {
        id.parse().unwrap()
    }

    fn rules(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|id| id.to_string()).collect()
    }

    #[test]
    fn auditors_accepts_one_to_the_maximum_distinct_accounts() {
        assert_eq!(auditors(&[account("a.near")]), Ok(()));
        let full: Vec<_> = (0..MAX_AUDITORS).map(|i| account(&format!("auditor{i}.near"))).collect();
        assert_eq!(auditors(&full), Ok(()));
    }

    #[test]
    fn auditors_rejects_empty_oversized_and_repeated_lists() {
        assert_eq!(auditors(&[]), Err("the auditor allowlist must not be empty".into()));
        let too_many: Vec<_> = (0..=MAX_AUDITORS).map(|i| account(&format!("auditor{i}.near"))).collect();
        assert_eq!(auditors(&too_many), Err("at most 16 auditors, got 17".into()));
        assert_eq!(
            auditors(&[account("a.near"), account("b.near"), account("a.near")]),
            Err("auditor a.near is listed twice".into())
        );
    }

    #[test]
    fn code_hash_accepts_a_base58_sha256() {
        let real = bs58::encode([0xab; CODE_HASH_BYTES]).into_string();
        assert_eq!(code_hash(&real), Ok(()));
        let with_leading_zero_byte = bs58::encode([0u8; CODE_HASH_BYTES]).into_string();
        assert_eq!(with_leading_zero_byte.len(), CODE_HASH_BYTES);
        assert_eq!(code_hash(&with_leading_zero_byte), Ok(()));
    }

    #[test]
    fn code_hash_rejects_everything_that_is_not_exactly_32_base58_bytes() {
        let too_short = bs58::encode([0xab; 31]).into_string();
        let too_long = bs58::encode([0u8; 33]).into_string();
        for bad in [too_short.as_str(), too_long.as_str(), "", "not base58 0OIl", "é", "0".repeat(44).as_str()] {
            let reason = code_hash(bad).unwrap_err();
            assert!(reason.starts_with("code_hash must be the base58 form of a 32-byte SHA-256"), "{bad:?}: {reason}");
        }
        let hex_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(code_hash(hex_digest).is_err(), "hex is not base58");
    }

    #[test]
    fn code_hash_rejects_a_string_longer_than_any_32_byte_encoding_before_decoding_it() {
        let reason = code_hash(&"1".repeat(CODE_HASH_MAX_CHARS + 1)).unwrap_err();
        assert_eq!(reason, "code_hash is longer than 44 characters");
    }

    #[test]
    fn rule_ids_follow_the_status() {
        assert_eq!(rule_ids(&VerdictStatus::Safe, &[]), Ok(()));
        assert_eq!(rule_ids(&VerdictStatus::Warn, &rules(&["PF008"])), Ok(()));
        assert_eq!(rule_ids(&VerdictStatus::Unsafe, &rules(&["PF001", "PF007"])), Ok(()));
        assert_eq!(
            rule_ids(&VerdictStatus::Safe, &rules(&["PF001"])),
            Err("a Safe verdict must not list rule ids".into())
        );
    }

    const MUST_SAY_WHY: &str = "a Warn or Unsafe verdict must list at least one rule id, so the reader knows why";

    #[test]
    fn a_warn_verdict_without_rule_ids_is_rejected() {
        assert_eq!(rule_ids(&VerdictStatus::Warn, &[]), Err(MUST_SAY_WHY.into()));
    }

    #[test]
    fn an_unsafe_verdict_without_rule_ids_is_rejected() {
        assert_eq!(rule_ids(&VerdictStatus::Unsafe, &[]), Err(MUST_SAY_WHY.into()));
    }

    #[test]
    fn rule_ids_must_be_pf_and_three_digits() {
        for bad in ["", "PF1", "PF0001", "pf001", "XX001", "PF00a", "PF 01", "PF+01", "PF-01", "PF００１", "PFé01"]
        {
            let reason = rule_ids(&VerdictStatus::Unsafe, &rules(&[bad])).unwrap_err();
            assert_eq!(reason, format!("rule id {bad:?} must be PF followed by three digits"));
        }
    }

    #[test]
    fn rule_ids_are_counted_and_unique() {
        let all: Vec<String> = (0..MAX_RULE_IDS).map(|i| format!("PF{i:03}")).collect();
        assert_eq!(rule_ids(&VerdictStatus::Unsafe, &all), Ok(()));
        let one_more: Vec<String> = (0..=MAX_RULE_IDS).map(|i| format!("PF{i:03}")).collect();
        assert_eq!(rule_ids(&VerdictStatus::Unsafe, &one_more), Err("at most 32 rule ids, got 33".into()));
        assert_eq!(
            rule_ids(&VerdictStatus::Unsafe, &rules(&["PF001", "PF002", "PF001"])),
            Err("rule id PF001 is listed twice".into())
        );
    }

    #[test]
    fn report_url_must_be_a_bounded_http_url() {
        assert_eq!(report_url("https://example.com/report.json"), Ok(()));
        assert_eq!(report_url("http://localhost:8080/report.json"), Ok(()));
        let longest = format!("https://{}", "a".repeat(REPORT_URL_MAX_BYTES - "https://".len()));
        assert_eq!(report_url(&longest), Ok(()));
        assert_eq!(report_url(&format!("{longest}a")), Err("report_url is longer than 256 bytes".into()));
        for bad in ["", "ftp://example.com/r.json", "javascript:alert(1)", "example.com/r.json", "HTTPS://example.com"]
        {
            assert_eq!(report_url(bad), Err("report_url must start with https:// or http://".into()), "{bad:?}");
        }
    }

    #[test]
    fn report_sha256_must_be_64_lowercase_hex_characters() {
        assert_eq!(report_sha256(&"0123456789abcdef".repeat(4)), Ok(()));
        let message = "report_sha256 must be 64 lowercase hex characters";
        for bad in [
            "".to_string(),
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
            format!("{}é", "a".repeat(62)),
        ] {
            assert_eq!(report_sha256(&bad), Err(message.into()), "{bad:?}");
        }
    }

    #[test]
    fn publication_reports_the_first_failing_field() {
        let hash = bs58::encode([1u8; CODE_HASH_BYTES]).into_string();
        let sha = "a".repeat(64);
        assert_eq!(publication(&hash, &VerdictStatus::Safe, &[], "https://x.io/r.json", &sha), Ok(()));
        assert!(
            publication("bad", &VerdictStatus::Safe, &[], "https://x.io/r.json", &sha)
                .unwrap_err()
                .starts_with("code_hash")
        );
        assert!(
            publication(&hash, &VerdictStatus::Safe, &rules(&["PF001"]), "https://x.io/r.json", &sha)
                .unwrap_err()
                .starts_with("a Safe")
        );
        assert!(publication(&hash, &VerdictStatus::Safe, &[], "nope", &sha).unwrap_err().starts_with("report_url"));
        assert!(
            publication(&hash, &VerdictStatus::Safe, &[], "https://x.io/r.json", "nope")
                .unwrap_err()
                .starts_with("report_sha256")
        );
    }
}
