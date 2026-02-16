//! Output formatting for human-readable and JSON modes.
//!
//! Human mode uses colored terminal output.
//! JSON mode outputs pure JSON with no ANSI escapes.

use colored::Colorize;
use serde::Serialize;

/// Prints a success message with an optional value.
pub fn print_success(msg: &str, json_mode: bool) {
    if json_mode {
        let obj = serde_json::json!({ "status": "ok", "message": msg });
        println!("{}", obj);
    } else {
        println!("{} {}", "✓".green().bold(), msg);
    }
}

/// Prints a single key-value pair.
pub fn print_kv(key: &str, value: &str, json_mode: bool) {
    if json_mode {
        let obj = serde_json::json!({ key: value });
        println!("{}", obj);
    } else {
        println!("{}: {}", key.bold(), value);
    }
}

/// Prints a serializable value as JSON or a human-readable debug form.
pub fn print_value<T: Serialize>(value: &T, json_mode: bool) {
    if json_mode {
        match serde_json::to_string(value) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("{{\"error\":\"json serialization failed: {e}\"}}"),
        }
    } else {
        match serde_json::to_string_pretty(value) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("Error formatting output: {e}"),
        }
    }
}

/// Prints a JSON value directly (already constructed).
pub fn print_json_value(value: &serde_json::Value, json_mode: bool) {
    if json_mode {
        println!("{value}");
    } else {
        match serde_json::to_string_pretty(value) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("Error formatting output: {e}"),
        }
    }
}

/// Prints an error message.
pub fn print_error(msg: &str, json_mode: bool) {
    if json_mode {
        let obj = serde_json::json!({ "error": msg });
        eprintln!("{}", obj);
    } else {
        eprintln!("{} {}", "error:".red().bold(), msg);
    }
}

/// Prints a table of rows in human mode, JSON array in JSON mode.
pub fn print_table(
    headers: &[&str],
    rows: &[Vec<String>],
    json_mode: bool,
) {
    if json_mode {
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
        println!("{}", serde_json::Value::Array(arr));
        return;
    }

    // Human-readable table.
    if rows.is_empty() {
        println!("{}", "(no results)".dimmed());
        return;
    }

    // Calculate column widths.
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() && cell.len() > widths[i] {
                widths[i] = cell.len();
            }
        }
    }

    // Print header.
    let header_line: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:<w$}", h.to_uppercase(), w = widths[i]))
        .collect();
    println!("{}", header_line.join("  ").bold());

    // Print separator.
    let sep: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    println!("{}", sep.join("  ").dimmed());

    // Print rows.
    for row in rows {
        let line: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let w = widths.get(i).copied().unwrap_or(0);
                format!("{:<w$}", cell, w = w)
            })
            .collect();
        println!("{}", line.join("  "));
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validates a hex-encoded address string (64 hex chars = 32 bytes).
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

/// Validates a hex-encoded message ID (64 hex chars = 32 bytes).
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

/// Sanitizes an alias string: trim, limit length, strip control chars.
pub fn sanitize_alias(s: &str) -> String {
    s.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect()
}