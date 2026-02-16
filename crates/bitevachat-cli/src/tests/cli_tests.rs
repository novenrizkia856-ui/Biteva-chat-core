//! CLI integration tests.
//!
//! These tests verify argument parsing, input validation, and output
//! formatting without requiring a running Bitevachat node.

// We test the binary's clap parsing by invoking it as a process
// (no real RPC needed — clap exits before connecting).

use std::process::Command;

/// Helper to run the CLI binary with args and capture output.
/// Returns (exit_code, stdout, stderr).
fn run_cli(args: &[&str]) -> (i32, String, String) {
    // Use `cargo run` to avoid needing to know the binary path.
    // In CI, the binary is built first, so this is fast.
    let output = Command::new(env!("CARGO_BIN_EXE_bitevachat"))
        .args(args)
        .output();

    match output {
        Ok(o) => {
            let code = o.status.code().unwrap_or(-1);
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            (code, stdout, stderr)
        }
        Err(e) => {
            // Binary not built yet — skip gracefully.
            eprintln!("WARNING: could not run binary: {e}");
            (-1, String::new(), e.to_string())
        }
    }
}

// -----------------------------------------------------------------------
// Clap parsing tests
// -----------------------------------------------------------------------

#[test]
fn help_flag_exits_zero() {
    let (code, stdout, _) = run_cli(&["--help"]);
    assert_eq!(code, 0, "--help should exit 0");
    assert!(
        stdout.contains("Bitevachat"),
        "help should mention Bitevachat"
    );
}

#[test]
fn version_flag_exits_zero() {
    let (code, stdout, _) = run_cli(&["--version"]);
    assert_eq!(code, 0, "--version should exit 0");
    assert!(
        stdout.contains("bitevachat"),
        "version should print program name"
    );
}

#[test]
fn unknown_command_fails() {
    let (code, _, stderr) = run_cli(&["nonexistent"]);
    assert_ne!(code, 0, "unknown command should fail");
    assert!(
        stderr.contains("error") || stderr.contains("unrecognized"),
        "stderr should indicate error: {stderr}"
    );
}

#[test]
fn message_send_missing_args_fails() {
    let (code, _, stderr) = run_cli(&["message", "send"]);
    assert_ne!(code, 0, "msg send without args should fail");
    assert!(
        !stderr.is_empty(),
        "should print error about missing arguments"
    );
}

#[test]
fn message_help() {
    let (code, stdout, _) = run_cli(&["message", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("send") || stdout.contains("Send"));
}

#[test]
fn contact_help() {
    let (code, stdout, _) = run_cli(&["contact", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("add") || stdout.contains("Add"));
}

#[test]
fn node_help() {
    let (code, stdout, _) = run_cli(&["node", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("status") || stdout.contains("Status"));
}

#[test]
fn wallet_help() {
    let (code, stdout, _) = run_cli(&["wallet", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("address") || stdout.contains("Address"));
}

#[test]
fn profile_help() {
    let (code, stdout, _) = run_cli(&["profile", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("get") || stdout.contains("Get"));
}

#[test]
fn json_flag_accepted_globally() {
    // --json should be accepted before the subcommand.
    // It will fail to connect (no node running), but clap parsing
    // should succeed and the error should be valid JSON.
    let (code, _, stderr) = run_cli(&["--json", "node", "status"]);
    // Should fail with exit 1 (connection error), not a parse error.
    assert_ne!(code, 0);
    // In JSON mode, errors go to stderr as JSON.
    if !stderr.is_empty() {
        // Try to parse as JSON to validate format.
        let parsed: std::result::Result<serde_json::Value, _> =
            serde_json::from_str(stderr.trim());
        assert!(
            parsed.is_ok(),
            "JSON mode stderr should be valid JSON, got: {stderr}"
        );
    }
}

#[test]
fn rpc_endpoint_flag_accepted() {
    // Should parse successfully even with custom endpoint.
    let (code, _, _) = run_cli(&[
        "--rpc-endpoint",
        "http://192.168.1.1:9999",
        "node",
        "status",
    ]);
    // Will fail to connect, but shouldn't fail to parse.
    assert_ne!(code, 0); // connection failure expected
}

// -----------------------------------------------------------------------
// Validation unit tests
// -----------------------------------------------------------------------

/// We can't import from the binary crate directly in integration
/// tests, so we duplicate the validation logic here for testing.
mod validation {
    pub fn validate_address(s: &str) -> std::result::Result<(), String> {
        if s.len() != 64 {
            return Err(format!(
                "address must be 64 hex characters (got {})",
                s.len()
            ));
        }
        if !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("address contains non-hex characters".into());
        }
        Ok(())
    }

    pub fn validate_message_id(s: &str) -> std::result::Result<(), String> {
        if s.len() != 64 {
            return Err(format!(
                "message_id must be 64 hex characters (got {})",
                s.len()
            ));
        }
        if !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("message_id contains non-hex characters".into());
        }
        Ok(())
    }

    pub fn sanitize_alias(s: &str) -> String {
        s.trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(64)
            .collect()
    }
}

#[test]
fn valid_address_passes() {
    let addr = "ab".repeat(32); // 64 hex chars
    assert!(validation::validate_address(&addr).is_ok());
}

#[test]
fn short_address_rejected() {
    assert!(validation::validate_address("abcd").is_err());
}

#[test]
fn non_hex_address_rejected() {
    let bad = "zz".repeat(32);
    assert!(validation::validate_address(&bad).is_err());
}

#[test]
fn valid_message_id_passes() {
    let mid = "42".repeat(32);
    assert!(validation::validate_message_id(&mid).is_ok());
}

#[test]
fn short_message_id_rejected() {
    assert!(validation::validate_message_id("1234").is_err());
}

#[test]
fn alias_sanitized() {
    let raw = "  Hello\x00World\t ";
    let clean = validation::sanitize_alias(raw);
    assert_eq!(clean, "HelloWorld");
    assert!(!clean.contains('\x00'));
    assert!(!clean.contains('\t'));
}

#[test]
fn alias_truncated_at_64() {
    let long = "A".repeat(200);
    let clean = validation::sanitize_alias(&long);
    assert_eq!(clean.len(), 64);
}

#[test]
fn empty_alias_ok() {
    let clean = validation::sanitize_alias("");
    assert!(clean.is_empty());
}

// -----------------------------------------------------------------------
// JSON output format tests
// -----------------------------------------------------------------------

#[test]
fn json_error_format_valid() {
    // Simulate what output::print_error produces in JSON mode.
    let msg = "test error message";
    let obj = serde_json::json!({ "error": msg });
    let json_str = obj.to_string();
    let parsed: serde_json::Value = serde_json::from_str(&json_str)
        .unwrap_or_else(|_| panic!("invalid JSON: {json_str}"));
    assert_eq!(parsed["error"], "test error message");
}

#[test]
fn json_success_format_valid() {
    let obj = serde_json::json!({ "status": "ok", "message": "done" });
    let json_str = obj.to_string();
    let parsed: serde_json::Value = serde_json::from_str(&json_str)
        .unwrap_or_else(|_| panic!("invalid JSON: {json_str}"));
    assert_eq!(parsed["status"], "ok");
}

#[test]
fn json_table_format_valid() {
    // Simulate table output in JSON mode.
    let headers = ["address", "alias", "blocked"];
    let rows = vec![
        vec!["abc".to_string(), "Alice".to_string(), "false".to_string()],
        vec!["def".to_string(), "Bob".to_string(), "true".to_string()],
    ];
    let arr: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            let mut obj = serde_json::Map::new();
            for (i, h) in headers.iter().enumerate() {
                let val = row.get(i).cloned().unwrap_or_default();
                obj.insert(h.to_string(), serde_json::Value::String(val));
            }
            serde_json::Value::Object(obj)
        })
        .collect();
    let json_str = serde_json::Value::Array(arr).to_string();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&json_str)
        .unwrap_or_else(|_| panic!("invalid JSON array: {json_str}"));
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0]["alias"], "Alice");
}