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

// --- S1: truncate on multi-byte chars ---
#[test]
fn test_max_output_multibyte_no_panic() {
    // Use a very small --max-output to trigger truncation on multi-byte output
    let output = rsh_bin()
        .arg("--max-output")
        .arg("5")
        .arg("--inherit-env")
        .arg(r#"echo "héllo wörld""#)
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    // Should not panic; output should be valid JSON with truncated: true
    assert_eq!(json["truncated"], true);
    // stdout should be valid UTF-8 (serde parsed it fine)
    assert!(json["stdout"].is_string());
}

// --- S2: argument path traversal ---
#[test]
fn test_arg_path_traversal_rejected() {
    let output = rsh_bin()
        .arg("cat ../../etc/passwd")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("path traversal"), "error was: {}", err);
}

#[test]
fn test_arg_absolute_path_rejected() {
    let output = rsh_bin()
        .arg("cat /etc/passwd")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("absolute path"), "error was: {}", err);
}

#[test]
fn test_arg_relative_path_ok() {
    // Accessing files within the working dir should work
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("--inherit-env")
        .arg("cat src/main.rs")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["exit_code"], 0, "error: {:?}", json["error"]);
    assert!(json["stdout"].as_str().unwrap().contains("fn main"));
}

#[test]
fn test_flags_not_rejected_as_paths() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("ls -la")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["exit_code"], 0, "error: {:?}", json["error"]);
}

// --- S3: glob traversal ---
#[test]
fn test_glob_traversal_rejected() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("ls ../../*")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("path traversal"), "error was: {}", err);
}

// --- S4: double-quoted variable validation ---
#[test]
fn test_double_quoted_unapproved_var_rejected_at_validate() {
    // This should fail BEFORE any command executes
    let output = rsh_bin()
        .arg(r#"echo "hello $SECRET_KEY""#)
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("not in approved list"), "error was: {}", err);
    assert!(err.contains("SECRET_KEY"), "error was: {}", err);
}

// --- S5: execution timeout ---
#[test]
fn test_timeout() {
    // Use a 1-second timeout with a command that would hang
    let start = std::time::Instant::now();
    let output = rsh_bin()
        .arg("--timeout")
        .arg("1")
        .arg("--allow")
        .arg("sleep")
        .arg("--inherit-env")
        .arg("sleep 60")
        .output()
        .unwrap();
    let elapsed = start.elapsed();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("timed out"), "error was: {}", err);
    assert!(elapsed.as_secs() < 10, "took too long: {:?}", elapsed);
}

// --- S6: environment sanitization ---
#[test]
fn test_env_sanitized_by_default() {
    // Set a custom env var and verify the child can't see it
    let output = rsh_bin()
        .env("RSH_TEST_SECRET", "supersecret")
        .arg("--allow")
        .arg("env")
        .arg("env")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["exit_code"], 0, "error: {:?}", json["error"]);
    let stdout = json["stdout"].as_str().unwrap();
    assert!(!stdout.contains("RSH_TEST_SECRET"), "env leaked: {}", stdout);
    assert!(!stdout.contains("supersecret"), "secret leaked: {}", stdout);
}

#[test]
fn test_env_inherited_with_flag() {
    let output = rsh_bin()
        .env("RSH_TEST_VISIBLE", "yes")
        .arg("--inherit-env")
        .arg("--allow")
        .arg("env")
        .arg("env")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["exit_code"], 0, "error: {:?}", json["error"]);
    let stdout = json["stdout"].as_str().unwrap();
    assert!(stdout.contains("RSH_TEST_VISIBLE"), "env not inherited: {}", stdout);
}

// --- S7: non-final pipeline redirect ---
#[test]
fn test_redirect_on_non_final_pipeline_rejected() {
    let output = rsh_bin()
        .arg("--allow-redirects")
        .arg("echo hi > out.txt | head")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("non-final pipeline command"), "error was: {}", err);
}

// --- Dangerous sub-command arguments ---

#[test]
fn test_find_exec_blocked() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("find . -name '*.rs' -exec wc -l {} ';'")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("-exec"), "error was: {}", err);
    assert!(err.contains("not allowed"), "error was: {}", err);
}

#[test]
fn test_find_execdir_blocked() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("find . -execdir echo {} ';'")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("-execdir"), "error was: {}", err);
}

#[test]
fn test_find_delete_blocked() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("find . -name '*.tmp' -delete")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("-delete"), "error was: {}", err);
}

#[test]
fn test_find_without_exec_allowed() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("find src -name '*.rs' -type f")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"].is_null(), "error: {}", json["error"]);
    assert_eq!(json["exit_code"], 0);
}

#[test]
fn test_xargs_always_blocked() {
    let output = rsh_bin()
        .arg("--allow")
        .arg("echo,xargs")
        .arg("--inherit-env")
        .arg("echo hello | xargs echo")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("xargs"), "error was: {}", err);
    assert!(err.contains("not allowed"), "error was: {}", err);
}
