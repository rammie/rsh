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
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello world");
}

#[test]
fn test_pipeline() {
    let output = rsh_bin()
        .arg("echo -e 'line1\nline2\nline3' | head -n 1")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn test_pwd() {
    let output = rsh_bin()
        .arg("--dir")
        .arg("/tmp")
        .arg("pwd")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim();
    // On macOS, /tmp is a symlink to /private/tmp
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
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not in allowlist"));
}

#[test]
fn test_output_structure() {
    let output = rsh_bin()
        .arg("echo test")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty());
}

#[test]
fn test_semicolons_multiple_pipelines() {
    let output = rsh_bin()
        .arg("echo hello; echo world")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hello"));
    assert!(stdout.contains("world"));
}

#[test]
fn test_grep_with_quoted_pattern() {
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("grep -r 'fn main' src/main.rs")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("fn main"));
}

#[test]
fn test_variable_expansion() {
    let output = rsh_bin()
        .arg("echo $HOME")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim();
    assert!(!stdout.is_empty(), "HOME should expand to something");
    assert!(!stdout.contains('$'), "variable should be expanded");
}

#[test]
fn test_unapproved_variable() {
    let output = rsh_bin()
        .arg("echo $SECRET_KEY")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not in approved list"));
}

#[test]
fn test_glob_expansion() {
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("ls *.toml")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Cargo.toml"), "stdout was: {}", stdout);
}

#[test]
fn test_double_quoted_variable() {
    let output = rsh_bin()
        .arg(r#"echo "hello $HOME""#)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("hello /"), "stdout was: {}", stdout);
}

#[test]
fn test_three_stage_pipeline() {
    let output = rsh_bin()
        .arg("echo -e 'aaa\nbbb\nccc' | grep -c ''")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn test_path_in_command_rejected() {
    let output = rsh_bin()
        .arg("/usr/bin/grep foo")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not in allowlist"));
}

#[test]
fn test_redirects_blocked_by_default() {
    let output = rsh_bin()
        .arg("echo hi > out.txt")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("redirects are not allowed"), "stderr was: {}", stderr);
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
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("escapes working directory"), "stderr was: {}", stderr);

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
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    // Run again to append
    let output2 = rsh_bin()
        .arg("--allow-redirects")
        .arg("--dir")
        .arg(workdir.to_str().unwrap())
        .arg("echo world >> out.txt")
        .output()
        .unwrap();
    assert!(output2.status.success(), "stderr: {}", String::from_utf8_lossy(&output2.stderr));

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
    // Should not panic; stderr should indicate truncation
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("output truncated"), "stderr was: {}", stderr);
    // stdout should be bounded and valid UTF-8
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.len() <= 10, "stdout too long: {}", stdout.len());
}

// --- S2: argument path traversal ---
#[test]
fn test_arg_path_traversal_rejected() {
    let output = rsh_bin()
        .arg("cat ../../etc/passwd")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("path traversal"), "stderr was: {}", stderr);
}

#[test]
fn test_arg_absolute_path_rejected() {
    let output = rsh_bin()
        .arg("cat /etc/passwd")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("absolute path"), "stderr was: {}", stderr);
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
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("fn main"));
}

#[test]
fn test_flags_not_rejected_as_paths() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("ls -la")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
}

// --- S3: glob traversal ---
#[test]
fn test_glob_traversal_rejected() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("ls ../../*")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("path traversal"), "stderr was: {}", stderr);
}

// --- S4: double-quoted variable validation ---
#[test]
fn test_double_quoted_unapproved_var_rejected_at_validate() {
    // This should fail BEFORE any command executes
    let output = rsh_bin()
        .arg(r#"echo "hello $SECRET_KEY""#)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not in approved list"), "stderr was: {}", stderr);
    assert!(stderr.contains("SECRET_KEY"), "stderr was: {}", stderr);
}

// --- S5: environment sanitization ---
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
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
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
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
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
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("non-final pipeline command"), "stderr was: {}", stderr);
}

// --- Dangerous sub-command arguments / -exec validation ---

#[test]
fn test_find_exec_with_allowlisted_command() {
    // find -exec grep is safe — grep is in the allowlist
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("find src -name '*.rs' -exec grep -l 'fn main' {} ';'")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("main.rs"));
}

#[test]
fn test_find_exec_with_plus_terminator() {
    // find -exec cmd {} + (batch mode) should also work
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("find src -name '*.rs' -exec wc -l {} +")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("total"));
}

#[test]
fn test_find_exec_with_non_allowlisted_command_blocked() {
    // find -exec rm should be rejected — rm is not in the allowlist
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("find . -name '*.rs' -exec rm {} ';'")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("rm"), "stderr was: {}", stderr);
    assert!(stderr.contains("not in allowlist"), "stderr was: {}", stderr);
}

#[test]
fn test_find_exec_with_path_command_blocked() {
    // find -exec /usr/bin/grep — sub-command must be a bare name
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("find . -exec /usr/bin/grep foo {} ';'")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("bare command name"), "stderr was: {}", stderr);
}

#[test]
fn test_find_execdir_with_allowlisted_command() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("find src -name '*.rs' -execdir echo {} ';'")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn test_find_execdir_with_non_allowlisted_command_blocked() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("find . -execdir bash -c 'echo pwned' ';'")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("bash"), "stderr was: {}", stderr);
    assert!(stderr.contains("not in allowlist"), "stderr was: {}", stderr);
}

#[test]
fn test_find_delete_blocked() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("find . -name '*.tmp' -delete")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("-delete"), "stderr was: {}", stderr);
}

#[test]
fn test_find_ok_blocked() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("find . -ok rm {} ';'")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("-ok"), "stderr was: {}", stderr);
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
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn test_xargs_with_allowlisted_subcmd() {
    // xargs echo is safe — echo is in the allowlist
    let output = rsh_bin()
        .arg("--allow")
        .arg("echo,xargs")
        .arg("--inherit-env")
        .arg("echo hello | xargs echo")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hello"));
}

#[test]
fn test_xargs_with_non_allowlisted_subcmd() {
    // xargs rm should be rejected
    let output = rsh_bin()
        .arg("--allow")
        .arg("echo,xargs")
        .arg("--inherit-env")
        .arg("echo foo | xargs rm")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("rm"), "stderr was: {}", stderr);
    assert!(stderr.contains("not in allowlist"), "stderr was: {}", stderr);
}

#[test]
fn test_xargs_with_path_subcmd_blocked() {
    let output = rsh_bin()
        .arg("--allow")
        .arg("echo,xargs,grep")
        .arg("--inherit-env")
        .arg("echo foo | xargs /usr/bin/grep foo")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("bare command name"), "stderr was: {}", stderr);
}

#[test]
fn test_xargs_interactive_flag_blocked() {
    let output = rsh_bin()
        .arg("--allow")
        .arg("echo,xargs")
        .arg("--inherit-env")
        .arg("echo foo | xargs -p echo")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("-p"), "stderr was: {}", stderr);
    assert!(stderr.contains("not allowed"), "stderr was: {}", stderr);
}

#[test]
fn test_xargs_with_flags_and_allowlisted_subcmd() {
    // xargs -I {} grep -l {} should work with flags parsed correctly
    let output = rsh_bin()
        .arg("--allow")
        .arg("echo,xargs,grep")
        .arg("--inherit-env")
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("echo Cargo.toml | xargs -I {} grep -l 'rsh' {}")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn test_xargs_no_subcmd_defaults_to_echo() {
    // xargs with no command defaults to echo
    let output = rsh_bin()
        .arg("--allow")
        .arg("echo,xargs")
        .arg("--inherit-env")
        .arg("echo hello | xargs")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hello"));
}

#[test]
fn test_xargs_subcmd_path_traversal_blocked() {
    let output = rsh_bin()
        .arg("--allow")
        .arg("echo,xargs,grep")
        .arg("--inherit-env")
        .arg("echo foo | xargs grep foo ../../etc/passwd")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("path traversal"), "stderr was: {}", stderr);
}

#[test]
fn test_find_exec_subcmd_path_traversal_blocked() {
    // The sub-command args should also be checked for path traversal
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("find . -exec grep foo ../../etc/passwd {} ';'")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("path traversal"), "stderr was: {}", stderr);
}
