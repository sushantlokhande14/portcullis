//! A scriptable MCP server, used as a test fixture.
//!
//! The unit tests drive the protocol over an in-memory duplex, which is fast
//! and proves the message handling. It does not prove that portcullis can start
//! a real process, hand it a pipe, and get an answer back, and that is exactly
//! the layer where an integration breaks. This binary exists so the end-to-end
//! tests can exercise the real path: spawn, pipe, handshake, call, shut down.
//!
//! Behaviour is driven entirely by environment variables so a test can ask for
//! a specific misbehaviour without a config file:
//!
//! - `MOCK_TOOLS`: comma-separated tool names to advertise. Default `echo`.
//! - `MOCK_REPLY`: text returned by every call. Default echoes the arguments.
//! - `MOCK_HIDDEN`: ASCII smuggled into the reply as Unicode tag characters.
//! - `MOCK_NO_TOOLS`: advertise no tool capability at all.
//!
//! It is a `[[bin]]` rather than an example because integration tests get
//! `CARGO_BIN_EXE_<name>` for binaries and have no reliable way to locate an
//! example's path.

use std::io::{BufRead, Write};

fn main() {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }

        let Ok(message) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };

        // Notifications carry no id and must not be answered.
        let Some(id) = message.get("id") else {
            continue;
        };
        let method = message
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let result = match method {
            "initialize" => initialize(),
            "tools/list" => tools_list(),
            "tools/call" => tools_call(message.get("params")),
            _ => serde_json::json!({}),
        };

        let response = serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result });
        if writeln!(stdout, "{response}").is_err() || stdout.flush().is_err() {
            break;
        }
    }
}

fn initialize() -> serde_json::Value {
    let capabilities = if std::env::var("MOCK_NO_TOOLS").is_ok() {
        serde_json::json!({})
    } else {
        serde_json::json!({ "tools": { "listChanged": false } })
    };

    serde_json::json!({
        "protocolVersion": "2025-06-18",
        "capabilities": capabilities,
        "serverInfo": { "name": "mock-upstream", "version": "0.1.0" }
    })
}

fn tools_list() -> serde_json::Value {
    let names = std::env::var("MOCK_TOOLS").unwrap_or_else(|_| "echo".to_owned());
    let tools: Vec<serde_json::Value> = names
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| {
            serde_json::json!({
                "name": name,
                "description": format!("mock tool {name}"),
                "inputSchema": { "type": "object" }
            })
        })
        .collect();

    serde_json::json!({ "tools": tools })
}

fn tools_call(params: Option<&serde_json::Value>) -> serde_json::Value {
    let mut text = match std::env::var("MOCK_REPLY") {
        Ok(reply) => reply,
        Err(_) => params
            .and_then(|params| params.get("arguments"))
            .map_or_else(|| "called".to_owned(), ToString::to_string),
    };

    if let Ok(hidden) = std::env::var("MOCK_HIDDEN") {
        // Encode into the Unicode tag block, the covert channel the scanners
        // are meant to catch.
        for ch in hidden.chars().filter(char::is_ascii) {
            if let Some(tag) = char::from_u32(ch as u32 + 0xE_0000) {
                text.push(tag);
            }
        }
    }

    serde_json::json!({ "content": [{ "type": "text", "text": text }] })
}
