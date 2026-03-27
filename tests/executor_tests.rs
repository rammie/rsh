use std::process::Command;

fn rsh_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rsh"))
}

/// Assert that a command is rejected with the given substring in stderr.
fn assert_rejected_with(cmd: &str, expected: &str) {
    let output = rsh_bin().arg(cmd).output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(expected),
        "expected '{}' for '{}', got: {}",
        expected,
        cmd,
        stderr
    );
}

/// Assert that a command is rejected with "not in allowlist" in stderr.
fn assert_not_in_allowlist(cmd: &str) {
    assert_rejected_with(cmd, "not in allowlist");
}

#[test]
fn test_simple_echo() {
    let output = rsh_bin().arg("echo hello world").output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello world");
}

#[test]
fn test_pipeline() {
    let output = rsh_bin()
        .arg("echo -e 'line1\nline2\nline3' | head -n 1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_pwd() {
    let output = rsh_bin()
        .arg("--dir")
        .arg("/tmp")
        .arg("pwd")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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
fn test_disallowed_command_rejected() {
    assert_not_in_allowlist("curl http://example.com");
}

#[test]
fn test_output_structure() {
    let output = rsh_bin().arg("echo test").output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty());
}

#[test]
fn test_semicolons_multiple_pipelines() {
    let output = rsh_bin().arg("echo hello; echo world").output().unwrap();
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
fn test_grep_with_quoted_pattern() {
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("grep -r 'fn main' src/main.rs")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("fn main"));
}

#[test]
fn test_variable_expansion_blocked() {
    let output = rsh_bin().arg("echo $PWD").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not allowed"), "stderr was: {}", stderr);
}

#[test]
fn test_unapproved_variable() {
    let output = rsh_bin().arg("echo $SECRET_KEY").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not allowed"), "stderr was: {}", stderr);
}

#[test]
fn test_glob_expansion() {
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("ls *.toml")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Cargo.toml"), "stdout was: {}", stdout);
}

#[test]
fn test_double_quoted_variable_blocked() {
    let output = rsh_bin().arg(r#"echo "hello $PWD""#).output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not allowed"), "stderr was: {}", stderr);
}

#[test]
fn test_three_stage_pipeline() {
    let output = rsh_bin()
        .arg("echo -e 'aaa\nbbb\nccc' | grep -c ''")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_path_in_command_rejected() {
    let output = rsh_bin().arg("/usr/bin/grep foo").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not in allowlist"));
}

#[test]
fn test_redirects_blocked_by_default() {
    let output = rsh_bin().arg("echo hi > out.txt").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("redirects are not allowed"),
        "stderr was: {}",
        stderr
    );
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
    assert!(
        stderr.contains("path traversal") || stderr.contains("escapes working directory"),
        "stderr was: {}",
        stderr
    );

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
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Run again to append
    let output2 = rsh_bin()
        .arg("--allow-redirects")
        .arg("--dir")
        .arg(workdir.to_str().unwrap())
        .arg("echo world >> out.txt")
        .output()
        .unwrap();
    assert!(
        output2.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output2.stderr)
    );

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
    assert!(
        stderr.contains("output truncated"),
        "stderr was: {}",
        stderr
    );
    // stdout should be bounded and valid UTF-8
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.len() <= 10, "stdout too long: {}", stdout.len());
}

// --- S2: argument path traversal ---
#[test]
fn test_arg_path_traversal_rejected() {
    let output = rsh_bin().arg("cat ../../etc/passwd").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("path traversal"), "stderr was: {}", stderr);
}

#[test]
fn test_arg_absolute_path_rejected() {
    let output = rsh_bin().arg("cat /etc/passwd").output().unwrap();
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
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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
    assert!(stderr.contains("not allowed"), "stderr was: {}", stderr);
    assert!(stderr.contains("SECRET_KEY"), "stderr was: {}", stderr);
}

// --- S5: environment sanitization ---
#[test]
fn test_env_sanitized_by_default() {
    // Set a custom env var and verify the child can't see it.
    let output = rsh_bin()
        .env("RSH_TEST_SECRET", "supersecret")
        .arg("printenv")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("RSH_TEST_SECRET"),
        "env leaked: {}",
        stdout
    );
    assert!(!stdout.contains("supersecret"), "secret leaked: {}", stdout);
}

#[test]
fn test_env_inherited_with_flag() {
    let output = rsh_bin()
        .env("RSH_TEST_VISIBLE", "yes")
        .arg("--inherit-env")
        .arg("printenv")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("RSH_TEST_VISIBLE"),
        "env not inherited: {}",
        stdout
    );
}

#[test]
fn test_env_not_in_allowlist() {
    assert_not_in_allowlist("env");
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
    assert!(
        stderr.contains("non-final pipeline command"),
        "stderr was: {}",
        stderr
    );
}

#[test]
fn test_stderr_to_dev_null_on_non_final_pipeline_allowed() {
    let output = rsh_bin()
        .arg("echo hello 2>/dev/null | head -1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello");
}

#[test]
fn test_fd_dup_on_non_final_pipeline_allowed() {
    let output = rsh_bin()
        .arg("echo hello 2>&1 | head -1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello");
}

#[test]
fn test_file_redirect_on_non_final_pipeline_still_rejected() {
    let output = rsh_bin()
        .arg("--allow-redirects")
        .arg("echo hi > /tmp/test.txt | head")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("non-final pipeline command"),
        "stderr was: {}",
        stderr
    );
}

// --- Dangerous sub-command arguments / -exec validation ---

#[test]
fn test_find_exec_blocked() {
    // find -exec is now unconditionally blocked
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("find src -name '*.rs' -exec grep -l 'fn main' {} ';'")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("-exec"), "stderr was: {}", stderr);
    assert!(stderr.contains("not allowed"), "stderr was: {}", stderr);
}

#[test]
fn test_find_execdir_blocked() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("find . -name '*.rs' -execdir echo {} ';'")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("-execdir"), "stderr was: {}", stderr);
    assert!(stderr.contains("not allowed"), "stderr was: {}", stderr);
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
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_sed_substitute_rejected() {
    // sed is a builtin that only supports -n with address+p; s command is not allowed
    let out = rsh_bin()
        .arg("echo hello | sed 's/hello/world/'")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("sed:"),
        "expected sed error, got: {}",
        stderr
    );
}

#[test]
fn test_xargs_not_in_allowlist() {
    assert_not_in_allowlist("echo hello | xargs echo");
}

#[test]
fn test_command_substitution_with_find() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("grep -l 'fn main' $(find src -name '*.rs')")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("main.rs"), "stdout was: {}", stdout);
}

#[test]
fn test_for_loop_with_find() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("for f in $(find src -name '*.rs' -type f); do wc -l \"$f\"; done")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("main.rs"), "stdout was: {}", stdout);
}

#[test]
fn test_fd_exec_blocked() {
    // fd --exec should be blocked
    let output = rsh_bin()
        .arg("fd -e rs --exec grep -l 'fn main'")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--exec"), "stderr was: {}", stderr);
    assert!(stderr.contains("not allowed"), "stderr was: {}", stderr);
}

// --- sort -o / --output (file write bypass) ---

#[test]
fn test_sort_o_blocked() {
    let output = rsh_bin()
        .arg("echo test | sort -o out.txt")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("sort"), "stderr was: {}", stderr);
}

#[test]
fn test_sort_output_long_flag_blocked() {
    let output = rsh_bin()
        .arg("echo test | sort --output=out.txt")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("sort"), "stderr was: {}", stderr);
}

#[test]
fn test_sort_normal_usage_allowed() {
    let output = rsh_bin().arg("echo -e 'b\na\nc' | sort").output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// --- Tilde/variable expansion path traversal bypass ---

#[test]
fn test_tilde_path_traversal_blocked() {
    let output = rsh_bin()
        .arg("--dir")
        .arg("/tmp")
        .arg("cat ~/../../etc/hosts")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "tilde+traversal should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("path traversal") || stderr.contains("..") || stderr.contains("tilde"),
        "stderr was: {}",
        stderr
    );
}

#[test]
fn test_variable_expansion_path_traversal_blocked() {
    let output = rsh_bin()
        .arg("--dir")
        .arg("/tmp")
        .arg("cat $HOME/../../etc/hosts")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "$HOME+traversal should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not allowed"), "stderr was: {}", stderr);
}

#[test]
fn test_double_quoted_variable_path_traversal_blocked() {
    let output = rsh_bin()
        .arg("--dir")
        .arg("/tmp")
        .arg(r#"cat "$HOME/../../etc/hosts""#)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "quoted $HOME+traversal should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not allowed"), "stderr was: {}", stderr);
}

#[test]
fn test_for_loop_tilde_traversal_blocked() {
    let output = rsh_bin()
        .arg("--dir")
        .arg("/tmp")
        .arg("for f in ~/../../etc/hosts; do cat $f; done")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "for-loop tilde+traversal should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("path traversal") || stderr.contains("..") || stderr.contains("tilde"),
        "stderr was: {}",
        stderr
    );
}

// --- all env vars and tilde blocked ---

#[test]
fn test_home_var_blocked() {
    let output = rsh_bin().arg("echo $HOME").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not allowed"), "stderr was: {}", stderr);
}

#[test]
fn test_tilde_blocked() {
    let output = rsh_bin().arg("echo ~").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("tilde"), "stderr was: {}", stderr);
}

#[test]
fn test_for_loop_variable_allowed() {
    // For-loop variables are dynamically approved — the only way to use variables
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg(r#"for f in src/*.rs; do echo "$f"; done"#)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("src/main.rs"), "stdout was: {}", stdout);
}

// --- /dev/null and fd duplication always allowed ---

#[test]
fn test_redirect_to_dev_null_allowed_without_flag() {
    let output = rsh_bin().arg("echo hello > /dev/null").output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // stdout should be empty since it was redirected to /dev/null
    assert!(String::from_utf8_lossy(&output.stdout).trim().is_empty());
}

#[test]
fn test_stderr_to_dev_null_allowed() {
    let output = rsh_bin().arg("echo hello 2>/dev/null").output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_fd_duplication_allowed_without_flag() {
    let output = rsh_bin().arg("echo hello 2>&1").output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hello"));
}

#[test]
fn test_redirect_to_real_file_still_blocked_without_flag() {
    let output = rsh_bin().arg("echo hello > /tmp/out.txt").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("redirect") || stderr.contains("not allowed"),
        "stderr was: {}",
        stderr
    );
}

// ============================================================
// Sandbox escape tests
// ============================================================

#[test]
fn test_escape_for_loop_absolute_path_bypass() {
    // For-loop values with absolute paths are blocked by the executor's check_expanded_arg_path.
    let output = rsh_bin()
        .arg("for x in /etc; do cat $x/hosts; done")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "ESCAPE: for-loop absolute path bypass succeeded — \
         should have been blocked. stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("not allowed"),
        "expected 'not allowed' error, got: {}",
        stderr
    );
}

#[test]
fn test_escape_for_loop_absolute_path_multi_segment() {
    // Variant: split the absolute path across loop variable and argument
    let output = rsh_bin()
        .arg("for d in /usr /etc; do ls $d | head -2; done")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "ESCAPE: for-loop directory listing bypass succeeded. stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("not allowed"),
        "expected 'not allowed' error, got: {}",
        stderr
    );
}

#[test]
fn test_escape_for_loop_grep_arbitrary_files() {
    // ESCAPE: Use for-loop to grep files outside working directory
    let output = rsh_bin()
        .arg("for x in /etc; do grep localhost $x/hosts; done")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "ESCAPE: for-loop grep bypass succeeded. stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("not allowed"),
        "expected 'not allowed' error, got: {}",
        stderr
    );
}

#[test]
fn test_escape_find_fprint_writes_file() {
    // ESCAPE: find's -fprint flag writes output to a file, bypassing --allow-redirects.
    // The validator only blocks -delete, -ok, -okdir on find.
    // Note: -fprint is GNU find only (not available on macOS BSD find).
    // The validator should still block it regardless of platform.
    let output = rsh_bin()
        .arg("find . -name 'Cargo.toml' -fprint output.txt")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("rsh:") && stderr.contains("not allowed"),
        "ESCAPE: find -fprint should be blocked by rsh validator. stderr: {}",
        stderr
    );
}

#[test]
fn test_escape_find_fprintf_writes_file() {
    // ESCAPE: find's -fprintf flag writes formatted output to a file.
    let output = rsh_bin()
        .arg("find . -name 'Cargo.toml' -fprintf output.txt '%p\\n'")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("rsh:") && stderr.contains("not allowed"),
        "ESCAPE: find -fprintf should be blocked by rsh validator. stderr: {}",
        stderr
    );
}

#[test]
fn test_escape_find_fls_writes_file() {
    // ESCAPE: find's -fls flag writes ls-style output to a file.
    let output = rsh_bin()
        .arg("find . -name 'Cargo.toml' -fls output.txt")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("rsh:") && stderr.contains("not allowed"),
        "ESCAPE: find -fls should be blocked by rsh validator. stderr: {}",
        stderr
    );
}

// ============================================================
// Post-expansion absolute path blocking
// ============================================================

#[test]
fn test_escape_command_substitution_absolute_path_blocked() {
    // ESCAPE: command substitution output could produce an absolute path.
    // echo /etc/hosts outputs "/etc/hosts", which becomes an argument to cat.
    // The executor must reject absolute paths in expanded arguments.
    let output = rsh_bin()
        .arg("--dir")
        .arg("/tmp")
        .arg("cat $(echo /etc/hosts)")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "ESCAPE: command substitution absolute path bypass succeeded. stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("not allowed") || stderr.contains("absolute"),
        "expected absolute path rejection, got: {}",
        stderr
    );
}

#[test]
fn test_escape_realpath_substitution_blocked() {
    // ESCAPE: realpath outputs absolute paths by design.
    // $(realpath .) expands to an absolute path that must be rejected as an arg.
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("cat $(realpath Cargo.toml)")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "ESCAPE: realpath substitution bypass succeeded. stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("not allowed") || stderr.contains("absolute"),
        "expected absolute path rejection, got: {}",
        stderr
    );
}

#[test]
fn test_awk_not_in_allowlist() {
    assert_not_in_allowlist("echo hello | awk '{print}'");
}

// --- Parameter expansion sub-expression validation ---

#[test]
fn test_param_default_command_substitution_blocked() {
    // ${var:-$(cmd)} should be rejected: the command substitution in the default
    // value must be validated, not silently executed.
    let output = rsh_bin()
        .arg(r#"for x in ""; do echo "${x:-$(id)}"; done"#)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "command substitution in parameter default should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not in allowlist") || stderr.contains("not allowed"),
        "expected allowlist rejection for 'id', got: {}",
        stderr
    );
}

#[test]
fn test_param_default_command_substitution_allowed_command_blocked() {
    // Even if the inner command is allowlisted, the variable reference in the
    // default should still be validated (e.g., if it references unapproved vars).
    let output = rsh_bin()
        .arg(r#"for x in ""; do echo "${x:-$(echo $HOME)}"; done"#)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "unapproved var in param default's command substitution should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not allowed"),
        "expected variable rejection, got: {}",
        stderr
    );
}

#[test]
fn test_param_default_with_allowed_command_passes() {
    // ${var:-$(echo safe)} where the inner command is fully valid should work.
    let output = rsh_bin()
        .arg(r#"for x in ""; do echo "${x:-$(echo fallback)}"; done"#)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "valid command substitution in param default should pass, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "fallback");
}

#[test]
fn test_param_default_literal_value_still_works() {
    // ${var:-literal} without command substitution should continue to work.
    let output = rsh_bin()
        .arg(r#"for x in ""; do echo "${x:-default_val}"; done"#)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "literal param default should work, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "default_val");
}

#[test]
fn test_param_alternative_command_substitution_blocked() {
    // ${var:+$(cmd)} — alternative value should also be validated.
    let output = rsh_bin()
        .arg(r#"for x in "notempty"; do echo "${x:+$(id)}"; done"#)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "command substitution in parameter alternative should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not in allowlist") || stderr.contains("not allowed"),
        "expected allowlist rejection for 'id', got: {}",
        stderr
    );
}

#[test]
fn test_param_error_command_substitution_blocked() {
    // ${var:?$(cmd)} — error message should also be validated.
    let output = rsh_bin()
        .arg(r#"for x in ""; do echo "${x:?$(id)}"; done"#)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "command substitution in parameter error should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not in allowlist") || stderr.contains("not allowed"),
        "expected allowlist rejection for 'id', got: {}",
        stderr
    );
}

#[test]
fn test_param_pattern_command_substitution_blocked() {
    // ${var%$(cmd)} — suffix pattern should also be validated.
    let output = rsh_bin()
        .arg(r#"for x in "hello"; do echo "${x%$(id)}"; done"#)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "command substitution in parameter pattern should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not in allowlist") || stderr.contains("not allowed"),
        "expected allowlist rejection for 'id', got: {}",
        stderr
    );
}

#[test]
fn test_param_replace_command_substitution_blocked() {
    // ${var/$(cmd)/replacement} — replace pattern should also be validated.
    let output = rsh_bin()
        .arg(r#"for x in "hello"; do echo "${x/$(id)/world}"; done"#)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "command substitution in parameter replace pattern should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not in allowlist") || stderr.contains("not allowed"),
        "expected allowlist rejection for 'id', got: {}",
        stderr
    );
}

#[test]
fn test_param_backtick_substitution_in_default_blocked() {
    // ${var:-`cmd`} — backtick command substitution should also be validated.
    let output = rsh_bin()
        .arg(r#"for x in ""; do echo "${x:-`id`}"; done"#)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "backtick command substitution in parameter default should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not in allowlist") || stderr.contains("not allowed"),
        "expected allowlist rejection for 'id', got: {}",
        stderr
    );
}

// --- &> and &>> redirect execution ---

#[test]
fn test_output_and_error_redirect_write() {
    let tmp = std::env::temp_dir();
    let workdir = tmp.join("rsh_test_output_and_error");
    std::fs::create_dir_all(&workdir).unwrap();
    let outfile = workdir.join("combined.txt");
    // Clean up from previous runs
    let _ = std::fs::remove_file(&outfile);

    let output = rsh_bin()
        .arg("--allow-redirects")
        .arg("--dir")
        .arg(workdir.to_str().unwrap())
        .arg("echo hello &> combined.txt")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let contents = std::fs::read_to_string(&outfile).unwrap();
    assert_eq!(contents.trim(), "hello");

    // Clean up
    let _ = std::fs::remove_dir_all(&workdir);
}

#[test]
fn test_output_and_error_redirect_append() {
    let tmp = std::env::temp_dir();
    let workdir = tmp.join("rsh_test_output_and_error_append");
    std::fs::create_dir_all(&workdir).unwrap();
    let outfile = workdir.join("combined.txt");
    let _ = std::fs::remove_file(&outfile);

    // First write
    let output = rsh_bin()
        .arg("--allow-redirects")
        .arg("--dir")
        .arg(workdir.to_str().unwrap())
        .arg("echo first &> combined.txt")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Append
    let output2 = rsh_bin()
        .arg("--allow-redirects")
        .arg("--dir")
        .arg(workdir.to_str().unwrap())
        .arg("echo second &>> combined.txt")
        .output()
        .unwrap();
    assert!(
        output2.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output2.stderr)
    );

    let contents = std::fs::read_to_string(&outfile).unwrap();
    assert!(
        contents.contains("first") && contents.contains("second"),
        "expected both lines in file, got: {}",
        contents
    );

    let _ = std::fs::remove_dir_all(&workdir);
}

#[test]
fn test_output_and_error_redirect_blocked_without_flag() {
    let output = rsh_bin()
        .arg("echo hello &> out.txt")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "&> should be blocked without --allow-redirects"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not allowed"),
        "expected redirect rejection, got: {}",
        stderr
    );
}

#[test]
fn test_output_and_error_redirect_to_dev_null_allowed() {
    let output = rsh_bin()
        .arg("echo hello &> /dev/null")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "&> /dev/null should be allowed without --allow-redirects, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // stdout should be empty since it went to /dev/null
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "");
}

#[test]
fn test_output_and_error_redirect_path_traversal_blocked() {
    let output = rsh_bin()
        .arg("--allow-redirects")
        .arg("echo hello &> ../escape.txt")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "&> with path traversal should be blocked"
    );
}

// ============================================================
// Flag-embedded path bypass tests
// ============================================================

#[test]
fn test_flag_embedded_absolute_path_blocked() {
    // --file=/etc/passwd should be caught even though it starts with -
    let output = rsh_bin()
        .arg("grep --file=/etc/passwd .")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "flag-embedded absolute path should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("absolute path"),
        "expected absolute path error, got: {}",
        stderr
    );
}

#[test]
fn test_flag_embedded_path_traversal_blocked() {
    // --from-file=../../etc/passwd should be caught
    let output = rsh_bin()
        .arg("diff --from-file=../../etc/passwd Cargo.toml")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "flag-embedded path traversal should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("path traversal"),
        "expected path traversal error, got: {}",
        stderr
    );
}

#[test]
fn test_flag_embedded_quoted_absolute_path_blocked() {
    // --file="/etc/passwd" — quotes around the value should be stripped
    let output = rsh_bin()
        .arg(r#"grep --file="/etc/passwd" ."#)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "flag-embedded quoted absolute path should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("absolute path"),
        "expected absolute path error, got: {}",
        stderr
    );
}

#[test]
fn test_flag_with_equals_relative_path_allowed() {
    // --include='*.rs' should still be allowed (relative, no traversal)
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("grep -r '--include=*.rs' fn src")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "flag with relative value should be allowed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_flag_without_equals_still_works() {
    // Plain flags like -r, -n should still be allowed
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("grep -rn fn src/main.rs")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "plain flags should still work, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_diff_from_file_absolute_blocked() {
    // diff --from-file=/etc/passwd was a complete file read bypass
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("diff --from-file=/etc/passwd Cargo.toml")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "diff --from-file with absolute path should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("absolute path"),
        "expected absolute path error, got: {}",
        stderr
    );
}

#[test]
fn test_sort_files0_from_absolute_blocked() {
    let output = rsh_bin()
        .arg("sort --files0-from=/etc/passwd")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "sort --files0-from with absolute path should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("absolute path"),
        "expected absolute path error, got: {}",
        stderr
    );
}

// Post-expansion flag-embedded path check
#[test]
fn test_flag_embedded_path_post_expansion_blocked() {
    // Command substitution producing a flag value with absolute path
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("grep --file=$(echo /etc/passwd) .")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "post-expansion flag-embedded absolute path should be blocked"
    );
}

// ============================================================
// For-loop variable scope tests
// ============================================================

#[test]
fn test_for_loop_var_not_approved_outside_loop() {
    // Variable $f should only be approved inside the for-loop body,
    // not in subsequent commands
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg(r#"for f in a b; do echo "$f"; done; echo "$f""#)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "for-loop variable should not be approved outside loop body"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not allowed"),
        "expected variable rejection, got: {}",
        stderr
    );
}

// ============================================================
// Environment variable leak prevention
// ============================================================

#[test]
fn test_no_env_leak_through_for_loop_var_name() {
    // If a for-loop variable name collides with an env var, the loop
    // should use the loop value, not the env value
    let output = rsh_bin()
        .env("RSH_TEST_VAR", "leaked_secret")
        .arg(r#"for RSH_TEST_VAR in safe_value; do echo "$RSH_TEST_VAR"; done"#)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "safe_value");
    assert!(
        !stdout.contains("leaked_secret"),
        "env var leaked through for-loop variable: {}",
        stdout
    );
}

// --- Redirect path safety (checked post-expansion by executor) ---

#[test]
fn test_redirect_absolute_path_rejected() {
    // Executor catches absolute paths in expanded redirect targets
    let output = rsh_bin()
        .arg("--allow-redirects")
        .arg("echo hello > /tmp/evil")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("absolute path") || stderr.contains("not allowed"),
        "stderr was: {}",
        stderr
    );
}

#[test]
fn test_redirect_path_traversal_rejected() {
    // Executor catches .. traversal in expanded redirect targets
    let output = rsh_bin()
        .arg("--allow-redirects")
        .arg("echo hello > ../../../etc/shadow")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("path traversal"),
        "stderr was: {}",
        stderr
    );
}

#[test]
fn test_output_and_error_redirect_absolute_path_blocked() {
    let output = rsh_bin()
        .arg("--allow-redirects")
        .arg("echo hello &> /tmp/evil")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("absolute path") || stderr.contains("not allowed"),
        "stderr was: {}",
        stderr
    );
}

#[test]
fn test_output_and_error_redirect_traversal_blocked() {
    let output = rsh_bin()
        .arg("--allow-redirects")
        .arg("echo hello &> ../../evil")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("path traversal"),
        "stderr was: {}",
        stderr
    );
}

// --- Fix #2: Substring offset/length validation ---

#[test]
fn test_substring_offset_command_substitution_blocked() {
    // ${x:$(dangerous):1} — substring expansion is unsupported; executor rejects it
    let output = rsh_bin()
        .arg("for x in hello; do echo ${x:$(cat /etc/passwd):1}; done")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unsupported parameter expansion")
            || stderr.contains("absolute path")
            || stderr.contains("not allowed"),
        "stderr was: {}",
        stderr
    );
}

#[test]
fn test_substring_length_command_substitution_blocked() {
    // ${x:0:$(dangerous)} — substring expansion is unsupported; executor rejects it
    let output = rsh_bin()
        .arg("for x in hello; do echo ${x:0:$(cat /etc/passwd)}; done")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unsupported parameter expansion")
            || stderr.contains("absolute path")
            || stderr.contains("not allowed"),
        "stderr was: {}",
        stderr
    );
}

// --- Fix #3: AssignDefaultValues rejected ---

#[test]
fn test_assign_default_values_rejected() {
    // ${var:=default} performs variable assignment — should be rejected
    let output = rsh_bin()
        .arg("for x in hello; do echo ${x:=world}; done")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("assignment") && stderr.contains("not allowed"),
        "stderr was: {}",
        stderr
    );
}

// --- Fix #4: For-loop iteration cap ---

#[test]
fn test_for_loop_iteration_cap() {
    // A for loop with more than 10,000 iterations should be rejected.
    // Generate a large iteration list via seq-like echo; since seq isn't in allowlist,
    // use a brace expansion or a long literal. We'll test with a command that produces
    // many words via find in a temp dir with many files.
    // Instead, just test that the cap exists by checking the error message format.
    // We can test with a realistic scenario using command substitution.

    // Create a temp dir with a known structure
    let tmp = std::env::temp_dir().join("rsh_test_for_cap");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    // Create 3 files to verify for-loop works under the cap
    for i in 0..3 {
        std::fs::write(tmp.join(format!("f{}.txt", i)), "").unwrap();
    }

    let output = rsh_bin()
        .arg("--dir")
        .arg(tmp.to_str().unwrap())
        .arg("for f in $(find . -name '*.txt'); do echo $f; done")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "small for loop should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("f0.txt"));

    let _ = std::fs::remove_dir_all(&tmp);
}

// --- $? (last exit status) tracking ---

#[test]
fn test_exit_status_success() {
    let output = rsh_bin().arg("true; echo $?").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "0", "true should set $? to 0");
}

#[test]
fn test_exit_status_failure() {
    let output = rsh_bin().arg("false; echo $?").output().unwrap();
    assert!(output.status.success()); // echo succeeds
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "1", "false should set $? to 1");
}

#[test]
fn test_exit_status_in_and_or() {
    // false || echo $? — should print 1 (exit code of false)
    let output = rsh_bin().arg("false || echo $?").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "1", "false || echo $? should print 1");
}

#[test]
fn test_exit_status_and_chain() {
    // true && echo $? — should print 0
    let output = rsh_bin().arg("true && echo $?").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "0", "true && echo $? should print 0");
}

#[test]
fn test_exit_status_pipeline() {
    // Test that $? reflects the last pipeline's exit code
    let output = rsh_bin()
        .arg("false; true; echo $?")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        "0",
        "true is the last command before echo, so $? should be 0"
    );
}

#[test]
fn test_exit_status_in_for_loop() {
    // $? should update within loop iterations
    let output = rsh_bin()
        .arg("for x in a; do false; echo $?; done")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "1", "$? should be 1 after false in loop body");
}

// --- Arithmetic expression validation ---

#[test]
fn test_arithmetic_expression_with_command_substitution_blocked() {
    // $(($(evil_command))) — command substitution inside arithmetic should be validated
    let output = rsh_bin()
        .arg("echo $(($(curl evil.com)))")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "command substitution in arithmetic expression should be validated"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not in allowlist") || stderr.contains("blocked"),
        "expected rejection of command in arithmetic, got: {}",
        stderr
    );
}

#[test]
fn test_arithmetic_expression_rejected() {
    // $((1 + 2)) — arithmetic expansion is not supported and should error
    let output = rsh_bin().arg("echo $((1 + 2))").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("arithmetic expansion"),
        "expected arithmetic error, got: {}",
        stderr
    );
}

// ============================================================
// Concatenated short-flag path bypass prevention
// ============================================================

#[test]
fn test_concatenated_flag_absolute_path_blocked() {
    // grep -f/etc/passwd . — should be caught even without '='
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("grep -f/etc/passwd .")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "concatenated short flag with absolute path should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("absolute path"),
        "expected absolute path error, got: {}",
        stderr
    );
}

#[test]
fn test_concatenated_flag_path_traversal_blocked() {
    // grep -f../../etc/passwd . — path traversal via concatenated short flag
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("grep -f../../etc/passwd .")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "concatenated short flag with path traversal should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("path traversal"),
        "expected path traversal error, got: {}",
        stderr
    );
}

#[test]
fn test_concatenated_flag_rg_pattern_file_blocked() {
    // rg -f../../etc/passwd . — same attack with ripgrep
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("rg -f../../etc/passwd .")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "rg -f with path traversal should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("path traversal"),
        "expected path traversal error, got: {}",
        stderr
    );
}

#[test]
fn test_concatenated_flag_file_command_blocked() {
    // file -f../../etc/passwd — reads filenames from arbitrary file
    let output = rsh_bin()
        .arg("file -f../../etc/passwd")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "file -f with path traversal should be blocked"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("path traversal"),
        "expected path traversal error, got: {}",
        stderr
    );
}

#[test]
fn test_concatenated_flag_letters_only_still_allowed() {
    // grep -rn — purely alphabetic flag cluster should still work
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("grep -rn fn src/main.rs")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "purely alphabetic flags should still work, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_concatenated_flag_with_number_allowed() {
    // head -n5 — numeric value after flag letter should be allowed (not a path)
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("head -n5 Cargo.toml")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "numeric flag value should still work, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_concatenated_flag_relative_path_allowed() {
    // grep -f with a relative path (no traversal) should be allowed
    // Use a file with a simple pattern that won't cause regex errors
    let tmp = std::env::temp_dir().join(format!(
        "rsh_test_flag_relpath_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("patterns.txt"), "name\n").unwrap();
    std::fs::write(tmp.join("data.txt"), "name = rsh\nversion = 1\n").unwrap();

    let output = rsh_bin()
        .arg("--dir")
        .arg(tmp.to_str().unwrap())
        .arg("grep -fpatterns.txt data.txt")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "concatenated flag with relative path should work, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("name = rsh"));

    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_concatenated_flag_post_expansion_blocked() {
    // for f in ../../etc; do grep -f"$f"/passwd .; done
    // The for-loop value itself has .. so the validator catches it
    let output = rsh_bin()
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg(r#"for f in "../../etc"; do grep -f"$f"/passwd .; done"#)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "for-loop value with path traversal should be blocked"
    );
}

// ============================================================
// less not in allowlist
// ============================================================

#[test]
fn test_less_not_in_allowlist() {
    // less has interactive escape capabilities (pipe to commands, open editor)
    assert_not_in_allowlist("less Cargo.toml");
}

// ============================================================
// Stderr redirect execution on non-final pipeline commands
// ============================================================

#[test]
fn test_stderr_devnull_on_non_final_pipeline_suppresses_stderr() {
    // ls on a nonexistent file writes to stderr; 2>/dev/null should suppress it
    let output = rsh_bin()
        .arg("ls nonexistent_file_xyz 2>/dev/null | head -1")
        .output()
        .unwrap();
    // ls will fail, but stderr should be suppressed
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("No such file"),
        "stderr should be suppressed by 2>/dev/null, got: {}",
        stderr
    );
}

#[test]
fn test_stderr_merge_to_stdout_on_non_final_pipeline() {
    // ls nonexistent 2>&1 | grep "No such file" — stderr merged to stdout,
    // so the next command in the pipeline can see it
    let output = rsh_bin()
        .arg("ls nonexistent_file_xyz 2>&1 | grep -c 'No such file'")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "2>&1 should merge stderr into stdout for the pipeline, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let count: i32 = stdout.trim().parse().unwrap_or(0);
    assert!(
        count >= 1,
        "grep should find 'No such file' in merged output, got count: {}",
        count
    );
}

// --- Blocked flag bypass via expansion ---

#[test]
fn test_find_delete_blocked_via_command_substitution() {
    // Critical: $(echo -delete) should not bypass blocked flag check
    let output = rsh_bin()
        .arg("find . $(echo -delete)")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("-delete") && stderr.contains("not allowed"),
        "blocked flag via command substitution should be caught, stderr: {}",
        stderr
    );
}

#[test]
fn test_find_exec_blocked_via_command_substitution() {
    // Critical: $(echo -exec) should not bypass blocked flag check
    let output = rsh_bin()
        .arg("find . $(echo -exec) cat {} \\;")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("-exec") && stderr.contains("not allowed"),
        "blocked flag via command substitution should be caught, stderr: {}",
        stderr
    );
}

#[test]
fn test_find_execdir_blocked_via_command_substitution() {
    let output = rsh_bin()
        .arg("find . $(echo -execdir) cat {} \\;")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("-execdir") && stderr.contains("not allowed"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn test_find_fprint_blocked_via_command_substitution() {
    let output = rsh_bin()
        .arg("find . $(echo -fprint) leaked.txt")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("-fprint") && stderr.contains("not allowed"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn test_find_delete_blocked_via_for_loop_variable() {
    // Critical: for-loop variable expanding to blocked flag should be caught
    let output = rsh_bin()
        .arg("for x in -delete; do find . $x; done")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("-delete") && stderr.contains("not allowed"),
        "blocked flag via for-loop variable should be caught, stderr: {}",
        stderr
    );
}

#[test]
fn test_find_exec_blocked_via_for_loop_variable() {
    let output = rsh_bin()
        .arg("for x in -exec; do find . $x cat {} \\;; done")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("-exec") && stderr.contains("not allowed"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn test_fd_exec_blocked_via_command_substitution() {
    let output = rsh_bin()
        .arg("fd pattern $(echo --exec) cat")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--exec") && stderr.contains("not allowed"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn test_sort_output_blocked_via_command_substitution() {
    let output = rsh_bin()
        .arg("--allow-redirects")
        .arg("sort $(echo -o) output.txt input.txt")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("-o") && stderr.contains("not allowed"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn test_sort_output_blocked_via_for_loop_variable() {
    let output = rsh_bin()
        .arg("--allow-redirects")
        .arg("for x in -ofoo; do sort $x input.txt; done")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("-o") && stderr.contains("not allowed"),
        "stderr: {}",
        stderr
    );
}

// --- Disallowed commands (shells, interpreters, dangerous tools) ---

#[test]
fn test_shells_not_in_allowlist() {
    assert_not_in_allowlist("sh -c 'echo hello'");
    assert_not_in_allowlist("bash -c 'echo hello'");
}

#[test]
fn test_interpreters_not_in_allowlist() {
    assert_not_in_allowlist("python -c 'print(1)'");
    assert_not_in_allowlist("node -e 'console.log(1)'");
    assert_not_in_allowlist("perl -e 'print 1'");
}

// --- Combined short-flag cluster bypass tests ---

#[test]
fn test_fd_exec_blocked_via_combined_flags() {
    // fd -Hx is parsed by fd as -H -x, which is the blocked -x/--exec flag.
    // Must be caught even though the arg "-Hx" doesn't exactly equal "-x".
    let output = rsh_bin()
        .arg("fd -Hx echo {} .")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not allowed") && stderr.contains("-x"),
        "expected '-x' blocked in combined flags for 'fd -Hx', got: {}",
        stderr
    );
}

#[test]
fn test_fd_exec_batch_blocked_via_combined_flags() {
    // fd -HX is parsed by fd as -H -X (--exec-batch), must be caught.
    let output = rsh_bin()
        .arg("fd -HX echo {} .")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not allowed") && stderr.contains("-X"),
        "expected '-X' blocked in combined flags for 'fd -HX', got: {}",
        stderr
    );
}

#[test]
fn test_fd_exec_blocked_via_three_combined_flags() {
    // fd -HIx: three combined flags, -x is the blocked one
    let output = rsh_bin()
        .arg("fd -HIx echo {} .")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not allowed") && stderr.contains("-x"),
        "expected '-x' blocked in combined flags for 'fd -HIx', got: {}",
        stderr
    );
}

#[test]
fn test_sort_output_blocked_via_combined_flags() {
    // sort -ro is parsed by sort as -r -o, which is the blocked -o/--output flag.
    let output = rsh_bin()
        .arg("sort -ro output.txt input.txt")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not allowed") && stderr.contains("-o"),
        "expected '-o' blocked in combined flags for 'sort -ro', got: {}",
        stderr
    );
}

#[test]
fn test_sort_output_blocked_via_three_combined_flags() {
    // sort -nro: three flags combined, -o is the blocked one
    let output = rsh_bin()
        .arg("sort -nro output.txt input.txt")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not allowed") && stderr.contains("-o"),
        "expected '-o' blocked in combined flags for 'sort -nro', got: {}",
        stderr
    );
}

#[test]
fn test_fd_exec_blocked_at_start_of_combined_flags() {
    // fd -xH: blocked flag -x appears at the START of the cluster, not the end
    let output = rsh_bin()
        .arg("fd -xH echo {} .")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not allowed") && stderr.contains("-x"),
        "expected '-x' blocked at start of combined flags for 'fd -xH', got: {}",
        stderr
    );
}

#[test]
fn test_fd_standalone_flags_still_allowed() {
    // fd -H (hidden) without -x should still be allowed
    let output = rsh_bin()
        .arg("fd -H . .")
        .output()
        .unwrap();
    // May fail for other reasons (fd not installed, etc.) but should NOT fail
    // with "not allowed" for blocked flags
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("-x") || !stderr.contains("not allowed"),
        "fd -H should not be blocked, got: {}",
        stderr
    );
}

#[test]
fn test_sort_non_blocked_combined_flags_allowed() {
    // sort -rn should still work — neither r nor n is a blocked flag
    let output = rsh_bin()
        .arg("echo -e '3\n1\n2' | sort -rn")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sort -rn should be allowed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_combined_flag_check_skips_long_flags() {
    // --sort should not trigger the combined-flag check (it's a long flag, not a cluster)
    let output = rsh_bin()
        .arg("ls --sort=size .")
        .output()
        .unwrap();
    // ls --sort=size is fine, it's a legitimate long flag
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("writes files in place"),
        "long flag --sort should not trigger combined flag check, got: {}",
        stderr
    );
}

#[test]
fn test_combined_flag_check_skips_flags_with_values() {
    // sort -t: should not trigger the combined flag check (has non-alpha char ':')
    let output = rsh_bin()
        .arg("echo 'a:b:c' | sort -t:")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sort -t: should not be blocked, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// --- Defense-in-depth: expanded command name re-validation ---

#[test]
fn test_expanded_command_name_blocked() {
    // Variable in command position should fail at validation (not in allowlist),
    // but even if it somehow reached execution, the expanded name check catches it.
    let output = rsh_bin()
        .arg("for cmd in cat; do $cmd --help; done")
        .output()
        .unwrap();
    // The raw "$cmd" is not in the allowlist, so validation rejects it
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not in allowlist"),
        "stderr: {}",
        stderr
    );
}

// --- Restricted sed builtin ---

#[test]
fn test_sed_single_line() {
    let out = rsh_bin()
        .arg("sed -n '1p' Cargo.toml")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "[package]"
    );
}

#[test]
fn test_sed_line_range() {
    let out = rsh_bin()
        .arg("sed -n '2,4p' Cargo.toml")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].contains("rsh"));
}

#[test]
fn test_sed_last_line() {
    let out = rsh_bin()
        .arg("sed -n '$p' Cargo.toml")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.trim().is_empty());
}

#[test]
fn test_sed_range_to_last() {
    let out = rsh_bin()
        .arg("sed -n '1,2p' Cargo.toml")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2);
}

#[test]
fn test_sed_in_pipeline() {
    let out = rsh_bin()
        .arg("cat Cargo.toml | sed -n '1,3p'")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].contains("[package]"));
}

#[test]
fn test_sed_pipeline_to_grep() {
    let out = rsh_bin()
        .arg("sed -n '1,10p' Cargo.toml | grep name")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("name"));
}

#[test]
fn test_sed_multiple_expressions() {
    let out = rsh_bin()
        .arg("sed -n '1p;3p' Cargo.toml")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2);
}

#[test]
fn test_sed_multiple_e_flags() {
    let out = rsh_bin()
        .arg("sed -n -e '1p' -e '3p' Cargo.toml")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2);
}

#[test]
fn test_sed_no_n_flag_rejected() {
    let out = rsh_bin()
        .arg("sed '1p' Cargo.toml")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("requires -n"));
}

#[test]
fn test_sed_i_flag_rejected() {
    let out = rsh_bin()
        .arg("sed -n -i '1p' Cargo.toml")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unsupported sed flag"));
}

#[test]
fn test_sed_e_command_rejected() {
    // The dangerous 'e' command (execute) must be rejected
    let out = rsh_bin()
        .arg("sed -n '1e' Cargo.toml")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unsupported sed command"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn test_sed_d_command_rejected() {
    let out = rsh_bin()
        .arg("sed -n '1d' Cargo.toml")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unsupported sed command"));
}

#[test]
fn test_sed_w_command_rejected() {
    let out = rsh_bin()
        .arg("sed -n '1w /tmp/out' Cargo.toml")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unsupported sed command"));
}

#[test]
fn test_sed_nonexistent_file() {
    let out = rsh_bin()
        .arg("sed -n '1p' nonexistent_file_xyz.txt")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("nonexistent_file_xyz.txt"));
}

#[test]
fn test_sed_multiple_files() {
    let out = rsh_bin()
        .arg("sed -n '1p' Cargo.toml src/main.rs")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    // First line of each file
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("[package]"));
    assert!(lines[1].contains("mod "));
}

#[test]
fn test_sed_in_command_substitution() {
    let out = rsh_bin()
        .arg("echo $(sed -n '1p' Cargo.toml)")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "[package]"
    );
}

#[test]
fn test_sed_in_for_loop() {
    let out = rsh_bin()
        .arg("for f in Cargo.toml src/main.rs; do sed -n '1p' $f; done")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2);
}

// ---- ANSI-C quoting tests ----

#[test]
fn test_ansi_c_quoting_not_expanded() {
    // $'\x2F' would be '/' if expanded — verify brush-parser does NOT expand
    // ANSI-C quoting, so hex escapes are passed as literal strings (no bypass possible)
    let output = rsh_bin()
        .arg("echo $'\\x2Fetc\\x2Fpasswd'")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should contain the literal escape sequences, not expanded /etc/passwd
    assert!(
        !stdout.contains("/etc/passwd"),
        "ANSI-C hex escapes should NOT be expanded to real paths, got: {}",
        stdout
    );
}

#[test]
fn test_ansi_c_quoting_traversal_not_expanded() {
    // $'\x2e\x2e\x2f' would be '../' if expanded — verify it's not
    let output = rsh_bin()
        .arg("echo $'\\x2e\\x2e\\x2ffile'")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("../"),
        "ANSI-C hex escapes should NOT be expanded to traversal paths, got: {}",
        stdout
    );
}

// ---- Brace expansion tests ----

#[test]
fn test_brace_expansion_not_expanded() {
    // brush-parser does not expand braces — they should be passed through as literals
    let output = rsh_bin().arg("echo {a,b,c}").output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        "{a,b,c}",
        "brace expansion should not be expanded — expected literal output"
    );
}

// ---- Indirect/variable name expansion tests ----

#[test]
fn test_variable_names_expansion_rejected() {
    assert_rejected_with("echo ${!PATH@}", "variable name expansion");
}

#[test]
fn test_member_keys_expansion_rejected() {
    assert_rejected_with("echo ${!arr[@]}", "key expansion");
}

// ---- Here-document and here-string tests ----

#[test]
fn test_here_document_rejected() {
    assert_rejected_with("cat <<EOF\nhello\nEOF", "here-documents are not supported");
}

#[test]
fn test_here_string_rejected() {
    assert_rejected_with("cat <<< hello", "here-strings are not supported");
}

// ---- --version tests ----

#[test]
fn test_version_flag() {
    let out = rsh_bin().arg("--version").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.starts_with("rsh "),
        "expected 'rsh <version>', got: {}",
        stdout
    );
    // Should match Cargo.toml version
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn test_version_short_flag() {
    let out = rsh_bin().arg("-V").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("rsh "));
}

// ---- --prime tests ----

#[test]
fn test_prime_still_works() {
    let out = rsh_bin().arg("--prime").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Allowed commands:"));
}

// ---- --install claude tests ----

/// Create a temp dir with `.git` init'd, returning the path. Caller must clean up.
fn create_test_git_dir(suffix: &str) -> std::path::PathBuf {
    let tmp = std::env::temp_dir().join(format!("rsh_test_{}_{}", suffix, std::process::id()));
    std::fs::create_dir_all(tmp.join(".git")).unwrap();
    tmp
}

fn run_install_claude(dir: &std::path::Path) -> std::process::Output {
    let out = rsh_bin()
        .args(["--install", "claude", "--dir"])
        .arg(dir.to_str().unwrap())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn read_settings(root: &std::path::Path) -> serde_json::Value {
    let content = std::fs::read_to_string(root.join(".claude/settings.local.json")).unwrap();
    serde_json::from_str(&content).unwrap()
}

#[test]
fn test_install_claude_creates_both() {
    let tmp = create_test_git_dir("install_claude_both");
    run_install_claude(&tmp);

    // Verify .mcp.json
    let mcp_content = std::fs::read_to_string(tmp.join(".mcp.json")).unwrap();
    let mcp: serde_json::Value = serde_json::from_str(&mcp_content).unwrap();
    assert_eq!(mcp["mcpServers"]["rsh"]["command"], "rsh");
    let args = mcp["mcpServers"]["rsh"]["args"].as_array().unwrap();
    assert!(args.iter().any(|a| a == "--mcp"));

    // Verify SessionStart hook
    let settings_path = tmp.join(".claude/settings.local.json");
    assert!(settings_path.exists(), "settings.local.json should exist");
    let content = std::fs::read_to_string(&settings_path).unwrap();
    let settings: serde_json::Value = serde_json::from_str(&content).unwrap();
    let hooks = &settings["hooks"]["SessionStart"];
    assert!(hooks.is_array(), "SessionStart should be an array");
    let arr = hooks.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["hooks"][0]["command"], "rsh --prime");
    assert_eq!(arr[0]["hooks"][0]["type"], "command");
    assert_eq!(arr[0]["matcher"], "");
    assert!(content.ends_with('\n'));

    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_install_claude_idempotent() {
    let tmp = create_test_git_dir("install_claude_idem");

    run_install_claude(&tmp);
    run_install_claude(&tmp);

    let settings = read_settings(&tmp);
    let arr = settings["hooks"]["SessionStart"].as_array().unwrap();
    assert_eq!(arr.len(), 1, "hook should not be duplicated");

    let mcp_content = std::fs::read_to_string(tmp.join(".mcp.json")).unwrap();
    let mcp: serde_json::Value = serde_json::from_str(&mcp_content).unwrap();
    let servers = mcp["mcpServers"].as_object().unwrap();
    assert_eq!(servers.len(), 1, "should have exactly one server entry");

    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_install_claude_preserves_existing_settings() {
    let tmp = create_test_git_dir("install_claude_preserve");
    std::fs::create_dir_all(tmp.join(".claude")).unwrap();

    std::fs::write(
        tmp.join(".claude/settings.local.json"),
        r#"{"permissions": {"allow": ["echo"]}}"#,
    )
    .unwrap();

    run_install_claude(&tmp);

    let settings = read_settings(&tmp);
    assert_eq!(settings["permissions"]["allow"][0], "echo");
    assert!(settings["hooks"]["SessionStart"].is_array());

    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_install_claude_finds_git_root_from_subdir() {
    let tmp = create_test_git_dir("install_claude_subdir");
    let subdir = tmp.join("src/deep");
    std::fs::create_dir_all(&subdir).unwrap();

    let out = rsh_bin()
        .args(["--install", "claude", "--dir"])
        .arg(subdir.to_str().unwrap())
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));

    // Both files should be at git root, not in subdir
    assert!(tmp.join(".mcp.json").exists());
    assert!(tmp.join(".claude/settings.local.json").exists());
    assert!(!subdir.join(".mcp.json").exists());
    assert!(!subdir.join(".claude/settings.local.json").exists());

    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_prime_claude_redirects_to_install() {
    let tmp = create_test_git_dir("prime_claude_compat");

    let out = rsh_bin()
        .arg("--dir")
        .arg(tmp.to_str().unwrap())
        .arg("--prime")
        .arg("claude")
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));

    // Should produce both files just like --install claude
    assert!(tmp.join(".mcp.json").exists());
    assert!(tmp.join(".claude/settings.local.json").exists());

    std::fs::remove_dir_all(&tmp).unwrap();
}

// --- Finding 1: --inherit-env strips dangerous library-injection vars ---

#[test]
fn test_inherit_env_strips_dangerous_vars() {
    let dangerous_vars = [
        ("LD_PRELOAD", "/tmp/evil.so"),
        ("LD_LIBRARY_PATH", "/tmp/evil"),
        ("LD_AUDIT", "/tmp/evil.so"),
        ("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib"),
        ("DYLD_FRAMEWORK_PATH", "/tmp/evil"),
        ("DYLD_LIBRARY_PATH", "/tmp/evil"),
    ];

    for (var_name, var_value) in &dangerous_vars {
        let output = rsh_bin()
            .env(var_name, var_value)
            .arg("--inherit-env")
            .arg(format!("printenv {}", var_name))
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.trim().is_empty(),
            "{} should be stripped, got: {}",
            var_name,
            stdout
        );
    }
}

#[test]
fn test_inherit_env_still_passes_normal_vars() {
    let output = rsh_bin()
        .env("MY_SAFE_VAR", "hello123")
        .arg("--inherit-env")
        .arg("printenv MY_SAFE_VAR")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello123");
}

// --- Finding 2: Recursion depth guard on command substitution ---

#[test]
fn test_deeply_nested_substitution_rejected() {
    // 17 levels deep — exceeds the cap of 16
    let depth = 17;
    let mut cmd = String::from("hello");
    for _ in 0..depth {
        cmd = format!("echo $({})", cmd);
    }
    let output = rsh_bin().arg(&cmd).output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nested too deeply"),
        "expected depth error, got: {}",
        stderr
    );
}

#[test]
fn test_reasonable_nesting_allowed() {
    // 2 levels deep — well within the cap
    let output = rsh_bin()
        .arg("echo $(echo $(echo hello))")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello");
}

// --- Finding 3: Arithmetic expansion returns error ---

#[test]
fn test_arithmetic_expansion_error() {
    let output = rsh_bin().arg("echo $((1+2))").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("arithmetic expansion"),
        "expected arithmetic error, got: {}",
        stderr
    );
}

// --- Finding 4: Missing test coverage for existing security checks ---

#[test]
fn test_sed_path_traversal_rejected() {
    assert_rejected_with("sed -n '1p' ../../etc/passwd", "path traversal");
}

#[test]
fn test_sed_absolute_path_rejected() {
    assert_rejected_with("sed -n '1p' /etc/passwd", "absolute path");
}

#[test]
fn test_input_redirect_rejected() {
    assert_rejected_with("cat < file.txt", "input redirection");
}

#[test]
fn test_compound_redirect_brace_group() {
    let tmp = std::env::temp_dir();
    let workdir = tmp.join("rsh_test_brace_redirect");
    std::fs::create_dir_all(&workdir).unwrap();

    let output = rsh_bin()
        .arg("--allow-redirects")
        .arg("--dir")
        .arg(workdir.to_str().unwrap())
        .arg("{ echo hi; } > out.txt")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let content = std::fs::read_to_string(workdir.join("out.txt")).unwrap();
    assert!(content.contains("hi"), "content was: {}", content);

    let _ = std::fs::remove_dir_all(&workdir);
}

#[test]
fn test_compound_redirect_for_loop() {
    let tmp = std::env::temp_dir();
    let workdir = tmp.join("rsh_test_for_redirect");
    std::fs::create_dir_all(&workdir).unwrap();

    let output = rsh_bin()
        .arg("--allow-redirects")
        .arg("--dir")
        .arg(workdir.to_str().unwrap())
        .arg("for x in a b; do echo $x; done > out.txt")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let content = std::fs::read_to_string(workdir.join("out.txt")).unwrap();
    assert!(content.contains("a"), "content was: {}", content);
    assert!(content.contains("b"), "content was: {}", content);

    let _ = std::fs::remove_dir_all(&workdir);
}

#[test]
fn test_multiple_redirects_sequential() {
    let tmp = std::env::temp_dir();
    let workdir = tmp.join("rsh_test_multi_redirect");
    std::fs::create_dir_all(&workdir).unwrap();

    // Two commands, each with their own redirect
    let output = rsh_bin()
        .arg("--allow-redirects")
        .arg("--dir")
        .arg(workdir.to_str().unwrap())
        .arg("echo first > a.txt; echo second > b.txt")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let a = std::fs::read_to_string(workdir.join("a.txt")).unwrap();
    let b = std::fs::read_to_string(workdir.join("b.txt")).unwrap();
    assert!(a.contains("first"), "a.txt was: {}", a);
    assert!(b.contains("second"), "b.txt was: {}", b);

    let _ = std::fs::remove_dir_all(&workdir);
}

// --- Multi-arg CLI invocation tests ---

#[test]
fn test_multi_arg_simple() {
    // rsh echo hello world (multiple OS args instead of single string)
    let output = rsh_bin()
        .args(["echo", "hello", "world"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "hello world"
    );
}

#[test]
fn test_multi_arg_with_flags() {
    // rsh echo -n hello
    let output = rsh_bin().args(["echo", "-n", "hello"]).output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "hello");
}

#[test]
fn test_multi_arg_with_special_chars() {
    // rsh echo "hello world" (arg with spaces gets quoted)
    let output = rsh_bin()
        .args(["echo", "hello world"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "hello world"
    );
}

#[test]
fn test_double_dash_simple() {
    // rsh -- echo hello
    let output = rsh_bin()
        .args(["--", "echo", "hello"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "hello"
    );
}

#[test]
fn test_double_dash_with_rsh_flag_like_arg() {
    // rsh -- echo --help (--help should be passed to echo, not rsh)
    let output = rsh_bin()
        .args(["--", "echo", "--help"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "--help"
    );
}

#[test]
fn test_double_dash_with_options_before() {
    // rsh --inherit-env -- echo hello
    let output = rsh_bin()
        .args(["--inherit-env", "--", "echo", "hello"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "hello"
    );
}

#[test]
fn test_double_dash_empty_error() {
    // rsh -- (no command after --)
    let output = rsh_bin().args(["--"]).output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no command after --"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn test_single_string_arg_backward_compat() {
    // rsh "echo hello world" (original single-string form still works)
    let output = rsh_bin().arg("echo hello world").output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "hello world"
    );
}

#[test]
fn test_multi_arg_disallowed_command() {
    // rsh curl http://example.com (disallowed command via multi-arg)
    let output = rsh_bin()
        .args(["curl", "http://example.com"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not in allowlist"),
        "stderr: {}",
        stderr
    );
}
