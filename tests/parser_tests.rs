use std::process::Command;

fn rsh_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rsh"))
}

#[test]
fn test_parse_error_and_or() {
    let output = rsh_bin()
        .arg("ls && echo hi")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"].as_str().unwrap().contains("&&"));
}

#[test]
fn test_parse_error_backticks() {
    let output = rsh_bin()
        .arg("echo `whoami`")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"].as_str().unwrap().contains("backtick"));
}

#[test]
fn test_parse_error_command_substitution() {
    let output = rsh_bin()
        .arg("echo $(whoami)")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"].as_str().unwrap().contains("substitution"));
}

#[test]
fn test_parse_error_eval() {
    let output = rsh_bin()
        .arg("eval echo hi")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    // eval is now rejected at the allowlist level
    assert!(err.contains("eval"), "error was: {}", err);
    assert!(err.contains("not in allowlist"), "error was: {}", err);
}

#[test]
fn test_keywords_in_quotes_allowed() {
    // 'if' inside quotes should not be rejected
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("grep 'if' src/main.rs")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"].is_null(), "error: {:?}", json["error"]);
    assert_eq!(json["exit_code"], 0);
}

#[test]
fn test_and_in_quotes_allowed() {
    // '&&' inside quotes should not be rejected
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("grep '&&' src/parser.rs")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"].is_null(), "error: {:?}", json["error"]);
}

#[test]
fn test_parse_error_if() {
    let output = rsh_bin()
        .arg("if true; then echo hi; fi")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    // Keywords are now rejected at the allowlist level, not the parser
    assert!(err.contains("not in allowlist") || err.contains("not supported"), "error was: {}", err);
}

#[test]
fn test_allowlist_rejection() {
    let output = rsh_bin()
        .arg("curl http://example.com")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"].as_str().unwrap().contains("not in allowlist"));
}

#[test]
fn test_empty_input() {
    let output = rsh_bin()
        .arg("")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"].is_string());
}
