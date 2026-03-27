use std::io::Write;
use std::process::{Command, Stdio};

fn rsh_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rsh"))
}

/// Send JSON-RPC messages to an rsh --mcp process, return all response lines.
fn mcp_session(messages: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut child = rsh_bin()
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start rsh --mcp");

    let mut stdin = child.stdin.take().unwrap();
    for msg in messages {
        writeln!(stdin, "{}", msg).unwrap();
    }
    drop(stdin); // close stdin to signal EOF

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("invalid JSON in MCP response"))
        .collect()
}

fn initialize_msg() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test", "version": "1.0" }
        }
    })
}

fn initialized_notification() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    })
}

fn tools_list_msg(id: u64) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/list"
    })
}

fn tools_call_msg(id: u64, command: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "rsh",
            "arguments": { "command": command }
        }
    })
}

// --- Protocol tests ---

#[test]
fn test_mcp_initialize_handshake() {
    let responses = mcp_session(&[initialize_msg(), initialized_notification()]);
    assert_eq!(
        responses.len(),
        1,
        "notification should not produce a response"
    );

    let resp = &responses[0];
    assert_eq!(resp["id"], 1);
    assert_eq!(resp["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(resp["result"]["serverInfo"]["name"], "rsh");
    assert!(resp["result"]["capabilities"]["tools"].is_object());
}

#[test]
fn test_mcp_tools_list() {
    let responses = mcp_session(&[
        initialize_msg(),
        initialized_notification(),
        tools_list_msg(2),
    ]);
    assert_eq!(responses.len(), 2);

    let resp = &responses[1];
    assert_eq!(resp["id"], 2);
    let tools = resp["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "rsh");

    let desc = tools[0]["description"].as_str().unwrap();
    assert!(desc.contains("Allowed commands:"));
    assert!(desc.contains("grep"));

    let schema = &tools[0]["inputSchema"];
    assert_eq!(schema["type"], "object");
    assert!(schema["properties"]["command"].is_object());
    assert_eq!(schema["required"][0], "command");
}

#[test]
fn test_mcp_tool_execution_success() {
    let responses = mcp_session(&[
        initialize_msg(),
        initialized_notification(),
        tools_call_msg(2, "echo hello from mcp"),
    ]);
    assert_eq!(responses.len(), 2);

    let resp = &responses[1];
    assert_eq!(resp["id"], 2);
    let content = &resp["result"]["content"][0];
    assert_eq!(content["type"], "text");
    assert!(content["text"].as_str().unwrap().contains("hello from mcp"));
    assert_eq!(resp["result"]["isError"], false);
}

#[test]
fn test_mcp_tool_execution_rejected_command() {
    let responses = mcp_session(&[
        initialize_msg(),
        initialized_notification(),
        tools_call_msg(2, "curl http://example.com"),
    ]);
    assert_eq!(responses.len(), 2);

    let resp = &responses[1];
    assert_eq!(resp["id"], 2);
    assert_eq!(resp["result"]["isError"], true);
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("not in allowlist"),
        "expected rejection, got: {}",
        text
    );
}

#[test]
fn test_mcp_tool_execution_pipeline() {
    let responses = mcp_session(&[
        initialize_msg(),
        initialized_notification(),
        tools_call_msg(2, "printf 'a\\nb\\nc\\n' | wc -l"),
    ]);
    assert_eq!(responses.len(), 2);

    let resp = &responses[1];
    assert_eq!(resp["result"]["isError"], false);
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.trim().contains("3"), "expected 3 lines, got: {}", text);
}

#[test]
fn test_mcp_multiple_calls() {
    let responses = mcp_session(&[
        initialize_msg(),
        initialized_notification(),
        tools_call_msg(2, "echo first"),
        tools_call_msg(3, "echo second"),
        tools_call_msg(4, "echo third"),
    ]);
    assert_eq!(responses.len(), 4); // 1 init + 3 calls

    assert!(
        responses[1]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("first")
    );
    assert!(
        responses[2]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("second")
    );
    assert!(
        responses[3]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("third")
    );
}

#[test]
fn test_mcp_ping() {
    let responses = mcp_session(&[
        initialize_msg(),
        initialized_notification(),
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
    ]);
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[1]["id"], 2);
    assert!(responses[1]["result"].is_object());
}

#[test]
fn test_mcp_unknown_method() {
    let responses =
        mcp_session(&[serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "unknown/method"})]);
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["error"]["code"], -32601);
    assert!(
        responses[0]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not found")
    );
}

#[test]
fn test_mcp_missing_command_argument() {
    let responses = mcp_session(&[serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "rsh", "arguments": {} }
    })]);
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["error"]["code"], -32602);
}

#[test]
fn test_mcp_unknown_tool_name() {
    let responses = mcp_session(&[serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "not_rsh", "arguments": { "command": "echo hi" } }
    })]);
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["error"]["code"], -32602);
}

#[test]
fn test_mcp_server_exits_on_eof() {
    let mut child = rsh_bin()
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start rsh --mcp");

    // Close stdin immediately
    drop(child.stdin.take());

    let status = child.wait().unwrap();
    assert!(status.success(), "server should exit 0 on EOF");
}

#[test]
fn test_mcp_notification_ignored() {
    // Notifications (no id) should produce no response
    let responses = mcp_session(&[
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/cancelled"}),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
    ]);
    // Only the ping should produce a response
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["id"], 1);
}

// --- Install tests (unique to mcp_tests; see executor_tests for create/idempotent/preserve/subdir) ---

#[test]
fn test_install_claude_merges_existing_mcp_servers() {
    let tmpdir = std::env::temp_dir().join(format!("rsh_test_merge_{}", std::process::id()));
    std::fs::create_dir_all(tmpdir.join(".git")).unwrap();

    let existing = serde_json::json!({
        "mcpServers": {
            "other-tool": { "command": "other", "args": ["--serve"] }
        }
    });
    std::fs::write(
        tmpdir.join(".mcp.json"),
        serde_json::to_string_pretty(&existing).unwrap(),
    )
    .unwrap();

    let output = rsh_bin()
        .args(["--install", "claude", "--dir"])
        .arg(&tmpdir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(tmpdir.join(".mcp.json")).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(config["mcpServers"]["other-tool"]["command"], "other");
    assert_eq!(config["mcpServers"]["rsh"]["command"], "rsh");

    std::fs::remove_dir_all(&tmpdir).unwrap();
}

#[test]
fn test_install_claude_with_flags() {
    let tmpdir = std::env::temp_dir().join(format!("rsh_test_flags_{}", std::process::id()));
    std::fs::create_dir_all(tmpdir.join(".git")).unwrap();

    let output = rsh_bin()
        .args([
            "--install",
            "claude",
            "--allow-redirects",
            "--inherit-env",
            "--dir",
        ])
        .arg(&tmpdir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(tmpdir.join(".mcp.json")).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();
    let args = config["mcpServers"]["rsh"]["args"].as_array().unwrap();
    let args_strs: Vec<&str> = args.iter().map(|a| a.as_str().unwrap()).collect();
    assert!(args_strs.contains(&"--mcp"));
    assert!(args_strs.contains(&"--allow-redirects"));
    assert!(args_strs.contains(&"--inherit-env"));

    std::fs::remove_dir_all(&tmpdir).unwrap();
}

#[test]
fn test_install_unknown_target() {
    let output = rsh_bin().args(["--install", "unknown"]).output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown install target"));
}
