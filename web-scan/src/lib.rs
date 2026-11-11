//! Preflight as a WebAssembly module: source files in, the JSON `preflight --json` prints out.
//!
//! The module has no imports and no pointer in its interface that JavaScript has to free. A call is four steps:
//! write the request into the buffer [`preflight_input`] sizes, call [`preflight_scan`] (or
//! [`preflight_rules`]), read [`preflight_output_len`] bytes at [`preflight_output_ptr`], and discard the
//! instance. The status the call returns says what the output is: [`OK`] or [`FAILED`].
//!
//! A scan request is JSON: `{"target": "<label>", "files": [{"path": "src/lib.rs", "text": "..."}], "above": []}`
//! (`above` is optional), with the same meaning as the arguments of [`preflight::scan_files`]. [`OK`] output is the
//! report, byte for byte what the command line prints for the same files; [`FAILED`] output is a message for the
//! person (a file that does not parse, a malformed request).

#![deny(unsafe_code)]

use std::cell::RefCell;

use preflight::{ScanError, rules, scan_files};
use serde::Deserialize;

/// The output is the requested JSON.
pub const OK: u32 = 0;
/// The output is a plain-text message saying why there is no result.
pub const FAILED: u32 = 1;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    target: String,
    files: Vec<File>,
    /// `Cargo.toml` text of each directory above the scanned one, nearest first; `null` where there is none.
    #[serde(default)]
    above: Vec<Option<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    path: String,
    text: String,
}

/// The report for a scan request, formatted as `preflight --json` formats it.
pub fn scan_json(request: &[u8]) -> Result<String, String> {
    let Request { target, files, above } =
        serde_json::from_slice(request).map_err(|error| format!("malformed scan request: {error}"))?;
    let files: Vec<(&str, &str)> = files.iter().map(|file| (file.path.as_str(), file.text.as_str())).collect();
    let above: Vec<Option<&str>> = above.iter().map(Option::as_deref).collect();
    let rules: Vec<_> = rules::all().collect();
    let report = scan_files(&target, &files, &above, &rules).map_err(|error| describe(&error))?;
    let json = serde_json::to_string_pretty(&report).expect("a report always serializes");
    Ok(json + "\n")
}

/// A scan error as a sentence. A file that does not parse also gets the line and column the parser stopped at, which
/// the command line's message leaves out; the page shows pasted code, where the position is what you look for.
fn describe(error: &ScanError) -> String {
    match error {
        ScanError::Parse { path, source } => {
            let at = source.span().start();
            format!("cannot parse {path}:{}:{}: {source}", at.line, at.column + 1)
        }
        other => other.to_string(),
    }
}

/// Every rule the scanner runs, as `[{"id", "title", "severity"}]` in rule-id order.
pub fn rules_json() -> String {
    let rules: Vec<_> = rules::all()
        .map(|rule| serde_json::json!({ "id": rule.id(), "title": rule.title(), "severity": rule.severity() }))
        .collect();
    serde_json::to_string(&rules).expect("rule metadata always serializes")
}

thread_local! {
    static INPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn finish(result: Result<String, String>) -> u32 {
    let (status, text) = match result {
        Ok(text) => (OK, text),
        Err(message) => (FAILED, message),
    };
    OUTPUT.with_borrow_mut(|output| *output = text.into_bytes());
    status
}

// The exports are the one place the crate needs an unsafe attribute; they dereference nothing, so every line
// of their bodies is safe code.
#[allow(unsafe_code)]
mod exports {
    use super::*;

    /// Makes the request buffer `len` bytes long and returns its address, for JavaScript to fill.
    #[unsafe(no_mangle)]
    pub extern "C" fn preflight_input(len: usize) -> *mut u8 {
        INPUT.with_borrow_mut(|input| {
            input.clear();
            input.resize(len, 0);
            input.as_mut_ptr()
        })
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn preflight_scan() -> u32 {
        finish(INPUT.with_borrow(|input| scan_json(input)))
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn preflight_rules() -> u32 {
        finish(Ok(rules_json()))
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn preflight_output_ptr() -> *const u8 {
        OUTPUT.with_borrow(|output| output.as_ptr())
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn preflight_output_len() -> usize {
        OUTPUT.with_borrow(Vec::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_gets_the_report_json_the_command_line_prints() {
        let request = br#"{"target":"pasted","files":[{"path":"src/lib.rs","text":"pub fn f() {}"}]}"#;
        let json = scan_json(request).unwrap();
        assert!(json.ends_with("}\n"), "{json}");
        let report: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(report["target"], "pasted");
        assert_eq!(report["summary"]["files_scanned"], 1);
        assert_eq!(report["findings"], serde_json::json!([]));
    }

    #[test]
    fn a_bad_request_or_unparseable_file_is_a_message_not_a_panic() {
        assert!(scan_json(b"not json").unwrap_err().starts_with("malformed scan request: "));
        assert!(scan_json(br#"{"target":"t","files":[],"extra":1}"#).unwrap_err().contains("unknown field `extra`"));
        let request = br#"{"target":"t","files":[{"path":"src/a.rs","text":"fn broken( {"}]}"#;
        assert!(scan_json(request).unwrap_err().starts_with("cannot parse src/a.rs:"));
    }

    #[test]
    fn manifests_above_the_scanned_directory_set_the_build_profile() {
        let source = "pub fn f() {}";
        let request = |above: &str| {
            let files = serde_json::json!([{ "path": "Cargo.toml", "text": "[package]\nname = \"a\"\n" }, { "path": "src/lib.rs", "text": source }]);
            format!(r#"{{"target":"t","files":{files},"above":{above}}}"#)
        };
        assert!(scan_json(request("[]").as_bytes()).is_ok());
        assert!(scan_json(request(r#"[null,"[workspace]"]"#).as_bytes()).is_ok());
        let error = scan_json(request(r#"[null,"[workspace"]"#).as_bytes()).unwrap_err();
        assert!(error.starts_with("cannot parse ../../Cargo.toml: "), "{error}");
    }

    #[test]
    fn a_parse_error_says_where_the_parser_stopped() {
        let request = br#"{"target":"t","files":[{"path":"src/a.rs","text":"fn a() {}\nfn broken( {"}]}"#;
        let message = scan_json(request).unwrap_err();
        assert!(message.starts_with("cannot parse src/a.rs:2:"), "{message}");
        let column: usize = message["cannot parse src/a.rs:2:".len()..].split(':').next().unwrap().parse().unwrap();
        assert!((11..=13).contains(&column), "{message}");
    }

    #[test]
    fn the_rule_list_has_every_rule() {
        let list: Vec<serde_json::Value> = serde_json::from_str(&rules_json()).unwrap();
        assert_eq!(list.len(), rules::all().count());
        assert_eq!(list[0]["id"], "PF001");
        assert!(["info", "low", "medium", "high", "critical"].contains(&list[0]["severity"].as_str().unwrap()));
    }
}
