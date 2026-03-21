use std::process::Command;

fn rsh_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rsh"))
}

#[test]
fn test_simple_echo() {
    let output = rsh_bin()
        .arg("echo hello world")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["exit_code"], 0);
    assert_eq!(json["stdout"].as_str().unwrap().trim(), "hello world");
    assert!(json["error"].is_null());
    let cmds = json["commands"].as_array().unwrap();
    assert_eq!(cmds, &[serde_json::json!("echo")]);
}

#[test]
fn test_pipeline() {
    let output = rsh_bin()
        .arg("echo -e 'line1\nline2\nline3' | head -n 1")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["exit_code"], 0);
    let cmds = json["commands"].as_array().unwrap();
    assert_eq!(cmds.len(), 2);
    assert_eq!(cmds[0], "echo");
    assert_eq!(cmds[1], "head");
}

#[test]
fn test_pwd() {
    let output = rsh_bin()
        .arg("--dir")
        .arg("/tmp")
        .arg("pwd")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["exit_code"], 0);
    // On macOS, /tmp is a symlink to /private/tmp
    let stdout = json["stdout"].as_str().unwrap().trim();
    assert!(
        stdout == "/tmp" || stdout == "/private/tmp",
        "unexpected pwd output: {}",
        stdout
    );
}

#[test]
fn test_custom_allowlist() {
    // With a custom allowlist that only allows 'echo', 'ls' should be rejected
    let output = rsh_bin()
        .arg("--allow")
        .arg("echo")
        .arg("ls")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"].as_str().unwrap().contains("not in allowlist"));
}

#[test]
fn test_json_output_structure() {
    let output = rsh_bin()
        .arg("echo test")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    // All required fields present
    assert!(json["stdout"].is_string());
    assert!(json["stderr"].is_string());
    assert!(json["exit_code"].is_number());
    assert!(json["commands"].is_array());
    // error is null on success
    assert!(json["error"].is_null());
}

#[test]
fn test_semicolons_multiple_pipelines() {
    let output = rsh_bin()
        .arg("echo hello; echo world")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["exit_code"], 0);
    let stdout = json["stdout"].as_str().unwrap();
    assert!(stdout.contains("hello"));
    assert!(stdout.contains("world"));
    let cmds = json["commands"].as_array().unwrap();
    assert_eq!(cmds.len(), 2);
}

#[test]
fn test_grep_with_quoted_pattern() {
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("grep -r 'fn main' src/main.rs")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["exit_code"], 0);
    assert!(json["stdout"].as_str().unwrap().contains("fn main"));
}

#[test]
fn test_variable_expansion() {
    let output = rsh_bin()
        .arg("echo $HOME")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["exit_code"], 0);
    let stdout = json["stdout"].as_str().unwrap().trim();
    assert!(!stdout.is_empty(), "HOME should expand to something");
    assert!(!stdout.contains('$'), "variable should be expanded");
}

#[test]
fn test_unapproved_variable() {
    let output = rsh_bin()
        .arg("echo $SECRET_KEY")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"].as_str().unwrap().contains("not in approved list"));
}

#[test]
fn test_glob_expansion() {
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("ls *.toml")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["exit_code"], 0);
    let stdout = json["stdout"].as_str().unwrap();
    assert!(stdout.contains("Cargo.toml"), "stdout was: {}", stdout);
}

#[test]
fn test_double_quoted_variable() {
    let output = rsh_bin()
        .arg(r#"echo "hello $HOME""#)
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["exit_code"], 0);
    let stdout = json["stdout"].as_str().unwrap();
    assert!(stdout.starts_with("hello /"), "stdout was: {}", stdout);
}

#[test]
fn test_three_stage_pipeline() {
    let output = rsh_bin()
        .arg("echo -e 'aaa\nbbb\nccc' | grep -c ''")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["exit_code"], 0);
}

#[test]
fn test_path_in_command_rejected() {
    let output = rsh_bin()
        .arg("/usr/bin/grep foo")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"].as_str().unwrap().contains("not in allowlist"));
}

#[test]
fn test_redirects_blocked_by_default() {
    let output = rsh_bin()
        .arg("echo hi > out.txt")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("redirects are not allowed"), "error was: {}", err);
}

#[test]
fn test_redirect_path_traversal_blocked() {
    let tmp = std::env::temp_dir();
    let workdir = tmp.join("rsh_test_traversal");
    std::fs::create_dir_all(&workdir).unwrap();

    let output = rsh_bin()
        .arg("--allow-redirects")
        .arg("--dir")
        .arg(workdir.to_str().unwrap())
        .arg("echo pwned > ../../etc/passwd")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("escapes working directory"), "error was: {}", err);

    let _ = std::fs::remove_dir_all(&workdir);
}

#[test]
fn test_append_redirect() {
    let tmp = std::env::temp_dir();
    let workdir = tmp.join("rsh_test_append");
    std::fs::create_dir_all(&workdir).unwrap();

    let output = rsh_bin()
        .arg("--allow-redirects")
        .arg("--dir")
        .arg(workdir.to_str().unwrap())
        .arg("echo hello >> out.txt")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["exit_code"], 0, "error: {:?}", json["error"]);

    // Run again to append
    let output2 = rsh_bin()
        .arg("--allow-redirects")
        .arg("--dir")
        .arg(workdir.to_str().unwrap())
        .arg("echo world >> out.txt")
        .output()
        .unwrap();
    let json2: serde_json::Value = serde_json::from_slice(&output2.stdout).unwrap();
    assert_eq!(json2["exit_code"], 0);

    let content = std::fs::read_to_string(workdir.join("out.txt")).unwrap();
    assert!(content.contains("hello"), "content was: {}", content);
    assert!(content.contains("world"), "content was: {}", content);

    let _ = std::fs::remove_dir_all(&workdir);
}
