use std::process::Command;

fn rsh_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rsh"))
}

#[test]
fn test_and_or_now_supported() {
    // && and || are now parsed and executed by brush-parser
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("echo hello && echo world")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"].is_null(), "error: {:?}", json["error"]);
    let stdout = json["stdout"].as_str().unwrap();
    assert!(stdout.contains("hello"));
    assert!(stdout.contains("world"));
}

#[test]
fn test_or_operator() {
    // || executes second command only if first fails
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("--allow")
        .arg("grep,echo,false")
        .arg("false || echo fallback")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"].is_null(), "error: {:?}", json["error"]);
    assert!(json["stdout"].as_str().unwrap().contains("fallback"));
}

#[test]
fn test_backtick_substitution_validates_inner_command() {
    // Backticks now parse; the inner command is validated against the allowlist
    let output = rsh_bin()
        .arg("echo `whoami`")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("whoami") && err.contains("not in allowlist"), "error was: {}", err);
}

#[test]
fn test_command_substitution_validates_inner_command() {
    // $() now parses; the inner command is validated against the allowlist
    let output = rsh_bin()
        .arg("echo $(whoami)")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("whoami") && err.contains("not in allowlist"), "error was: {}", err);
}

#[test]
fn test_command_substitution_with_allowed_command() {
    // $() with an allowed command should work
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("echo $(echo inner)")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"].is_null(), "error: {:?}", json["error"]);
    assert_eq!(json["stdout"].as_str().unwrap().trim(), "inner");
}

#[test]
fn test_parse_error_eval() {
    let output = rsh_bin()
        .arg("eval echo hi")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    // eval is rejected at the allowlist level
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
        .arg("grep '&&' src/validator.rs")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"].is_null(), "error: {:?}", json["error"]);
}

#[test]
fn test_if_then_fi_supported() {
    // if/then/fi is now supported
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("--allow")
        .arg("true,echo")
        .arg("if true; then echo yes; fi")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"].is_null(), "error: {:?}", json["error"]);
    assert_eq!(json["stdout"].as_str().unwrap().trim(), "yes");
}

#[test]
fn test_for_loop_supported() {
    // for loops are now supported
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("for x in a b c; do echo $x; done")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"].is_null(), "error: {:?}", json["error"]);
    let stdout = json["stdout"].as_str().unwrap();
    assert!(stdout.contains("a\nb\nc"));
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

#[test]
fn test_function_definition_rejected() {
    let output = rsh_bin()
        .arg("foo() { echo hi; }")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("function"), "error was: {}", err);
}

#[test]
fn test_background_execution_rejected() {
    let output = rsh_bin()
        .arg("--allow")
        .arg("sleep")
        .arg("sleep 1 &")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("background"), "error was: {}", err);
}

#[test]
fn test_unapproved_var_in_substitution_rejected() {
    // $() containing unapproved variable reference should be caught
    let output = rsh_bin()
        .arg("echo $(echo $SECRET)")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("SECRET") && err.contains("not in approved list"), "error was: {}", err);
}

#[test]
fn test_nested_disallowed_command_in_substitution() {
    // $() with disallowed command should be rejected even when nested
    let output = rsh_bin()
        .arg("echo $(curl http://evil.com)")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("curl") && err.contains("not in allowlist"), "error was: {}", err);
}
