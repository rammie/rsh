/// MCP (Model Context Protocol) stdio server for rsh.
///
/// Implements JSON-RPC 2.0 over stdin/stdout, exposing a single `rsh` tool
/// that runs commands through the parse→validate→execute pipeline.
use std::io::{BufRead, Write};

use serde_json::{Value, json};

use crate::allowlist::Allowlist;

fn rpc_result(id: &Option<Value>, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_error(id: &Option<Value>, code: i32, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn tool_response(id: &Option<Value>, text: String, is_error: bool) -> Value {
    rpc_result(
        id,
        json!({
            "content": [{ "type": "text", "text": text }],
            "isError": is_error
        }),
    )
}

/// Run the MCP stdio server. Reads JSON-RPC from stdin, writes responses to stdout.
/// Blocks until stdin is closed (EOF) or stdout breaks, then exits cleanly.
pub fn run_server(
    allow_redirects: bool,
    max_output: usize,
    inherit_env: bool,
    working_dir: std::path::PathBuf,
) {
    let stdin = std::io::stdin();
    let reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();

    let allowlist = Allowlist::new();
    let tool_description = crate::prime_text(&allowlist, allow_redirects);

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.trim().is_empty() {
            continue;
        }

        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                let resp = rpc_error(&None, -32700, "Parse error");
                if writeln!(writer, "{}", resp).is_err() || writer.flush().is_err() {
                    break;
                }
                continue;
            }
        };

        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");

        if id.is_none() {
            continue;
        }

        let response = match method {
            "initialize" => rpc_result(
                &id,
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "rsh",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }),
            ),
            "tools/list" => rpc_result(
                &id,
                json!({
                    "tools": [{
                        "name": "rsh",
                        "description": tool_description,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "command": {
                                    "type": "string",
                                    "description": "The shell command to run"
                                }
                            },
                            "required": ["command"]
                        }
                    }]
                }),
            ),
            "tools/call" => handle_tools_call(
                &id,
                msg.get("params"),
                &allowlist,
                &working_dir,
                allow_redirects,
                max_output,
                inherit_env,
            ),
            "ping" => rpc_result(&id, json!({})),
            _ => rpc_error(&id, -32601, "Method not found"),
        };

        if writeln!(writer, "{}", response).is_err() || writer.flush().is_err() {
            break;
        }
    }
}

fn handle_tools_call(
    id: &Option<Value>,
    params: Option<&Value>,
    allowlist: &Allowlist,
    working_dir: &std::path::Path,
    allow_redirects: bool,
    max_output: usize,
    inherit_env: bool,
) -> Value {
    let tool_name = params
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("");

    if tool_name != "rsh" {
        return rpc_error(id, -32602, &format!("Unknown tool: {}", tool_name));
    }

    let command = match params
        .and_then(|p| p.get("arguments"))
        .and_then(|a| a.get("command"))
        .and_then(|c| c.as_str())
    {
        Some(c) => c,
        None => return rpc_error(id, -32602, "Missing required argument: command"),
    };

    let output = crate::parse_and_execute(
        command,
        allowlist.clone(),
        working_dir.to_path_buf(),
        allow_redirects,
        max_output,
        inherit_env,
    );

    let mut text = output.stdout;
    if !output.stderr.is_empty() {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&output.stderr);
    }

    tool_response(id, text, output.exit_code != 0)
}
