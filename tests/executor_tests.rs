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
    // xargs echo is safe — echo is in the allowlist (xargs is now in default allowlist)
    let output = rsh_bin()
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

// --- Sub-command flag validation bypass ---

#[test]
fn test_find_exec_sed_inplace_blocked() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("find . -name '*.txt' -exec sed -i 's/foo/bar/' {} ';'")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("-i"), "stderr was: {}", stderr);
    assert!(stderr.contains("sed"), "stderr was: {}", stderr);
    assert!(stderr.contains("in place"), "stderr was: {}", stderr);
}

#[test]
fn test_xargs_sed_inplace_blocked() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("echo file.txt | xargs sed -i 's/foo/bar/'")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("-i"), "stderr was: {}", stderr);
    assert!(stderr.contains("sed"), "stderr was: {}", stderr);
    assert!(stderr.contains("in place"), "stderr was: {}", stderr);
}

#[test]
fn test_find_exec_find_delete_blocked() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("find . -exec find /tmp -delete ';'")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("-delete"), "stderr was: {}", stderr);
}

#[test]
fn test_find_exec_grep_still_works() {
    // grep with no blocked flags should still be allowed in -exec
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("find src -name '*.rs' -exec grep -l 'validate' {} ';'")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn test_nested_find_exec_sed_inplace_blocked() {
    // find -exec find -exec sed -i — nested chain must be caught
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("--allow-absolute")
        .arg("find . -exec find /tmp -exec sed -i 's/x/y/' {} ';' ';'")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("-i"), "stderr was: {}", stderr);
    assert!(stderr.contains("sed"), "stderr was: {}", stderr);
}

#[test]
fn test_xargs_find_exec_sed_inplace_blocked() {
    // xargs find -exec sed -i — cross-tool nested chain
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("echo dir | xargs find -exec sed -i 's/x/y/' {} ';'")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("-i"), "stderr was: {}", stderr);
    assert!(stderr.contains("sed"), "stderr was: {}", stderr);
}

// ─── Sandbox escape regression tests ───

// --- sed w (file write bypass) ---

#[test]
fn test_sed_w_command_blocked() {
    let output = rsh_bin()
        .arg(r#"echo test | sed "w /tmp/out""#)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("writes to a file"), "stderr was: {}", stderr);
}

#[test]
fn test_sed_w_single_quoted_blocked() {
    let output = rsh_bin()
        .arg("echo test | sed 'w /tmp/out'")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("writes to a file"), "stderr was: {}", stderr);
}

#[test]
fn test_sed_address_w_blocked() {
    let output = rsh_bin()
        .arg(r#"echo test | sed "1w /tmp/out""#)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("writes to a file"), "stderr was: {}", stderr);
}

#[test]
fn test_sed_e_w_blocked() {
    let output = rsh_bin()
        .arg(r#"echo test | sed -e "w /tmp/out""#)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("writes to a file"), "stderr was: {}", stderr);
}

#[test]
fn test_sed_s_w_flag_blocked() {
    // sed s/pattern/replacement/w writes matches to a file
    let output = rsh_bin()
        .arg(r#"echo hello | sed "s/hello/world/w /tmp/out""#)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("writes to a file"), "stderr was: {}", stderr);
}

#[test]
fn test_sed_normal_substitution_allowed() {
    let output = rsh_bin()
        .arg(r#"echo hello | sed "s/hello/world/""#)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "world");
}

#[test]
fn test_sed_word_containing_w_allowed() {
    // 's/www/xxx/' should not be flagged — the w is inside the pattern, not a command
    let output = rsh_bin()
        .arg(r#"echo www | sed "s/www/xxx/""#)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "xxx");
}

#[test]
fn test_find_exec_sed_w_blocked() {
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg(r#"find . -exec sed "w /tmp/out" {} ;"#)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("writes to a file"), "stderr was: {}", stderr);
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
    let output = rsh_bin()
        .arg("echo -e 'b\na\nc' | sort")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
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
    assert!(!output.status.success(), "tilde+traversal should be blocked");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("path traversal") || stderr.contains(".."),
        "stderr was: {}", stderr);
}

#[test]
fn test_variable_expansion_path_traversal_blocked() {
    let output = rsh_bin()
        .arg("--dir")
        .arg("/tmp")
        .arg("cat $HOME/../../etc/hosts")
        .output()
        .unwrap();
    assert!(!output.status.success(), "$HOME+traversal should be blocked");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("path traversal") || stderr.contains(".."),
        "stderr was: {}", stderr);
}

#[test]
fn test_double_quoted_variable_path_traversal_blocked() {
    let output = rsh_bin()
        .arg("--dir")
        .arg("/tmp")
        .arg(r#"cat "$HOME/../../etc/hosts""#)
        .output()
        .unwrap();
    assert!(!output.status.success(), "quoted $HOME+traversal should be blocked");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("path traversal") || stderr.contains(".."),
        "stderr was: {}", stderr);
}

#[test]
fn test_for_loop_tilde_traversal_blocked() {
    let output = rsh_bin()
        .arg("--dir")
        .arg("/tmp")
        .arg("for f in ~/../../etc/hosts; do cat $f; done")
        .output()
        .unwrap();
    assert!(!output.status.success(), "for-loop tilde+traversal should be blocked");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("path traversal") || stderr.contains(".."),
        "stderr was: {}", stderr);
}

// --- /dev/null and fd duplication always allowed ---

#[test]
fn test_redirect_to_dev_null_allowed_without_flag() {
    let output = rsh_bin()
        .arg("echo hello > /dev/null")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    // stdout should be empty since it was redirected to /dev/null
    assert!(String::from_utf8_lossy(&output.stdout).trim().is_empty());
}

#[test]
fn test_stderr_to_dev_null_allowed() {
    let output = rsh_bin()
        .arg("echo hello 2>/dev/null")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn test_fd_duplication_allowed_without_flag() {
    let output = rsh_bin()
        .arg("echo hello 2>&1")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hello"));
}

#[test]
fn test_redirect_to_real_file_still_blocked_without_flag() {
    let output = rsh_bin()
        .arg("echo hello > /tmp/out.txt")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("redirect") || stderr.contains("not allowed"),
        "stderr was: {}", stderr);
}

// --- Sandbox escape helpers & tests ---

/// Run a command in a tempdir seeded with the given files and assert it is rejected.
/// Returns the tempdir (for further assertions) and the process output.
fn assert_rejected_in_dir(
    files: &[(&str, &str)],
    cmd: &str,
) -> (tempfile::TempDir, std::process::Output) {
    let dir = tempfile::tempdir().unwrap();
    for (name, content) in files {
        std::fs::write(dir.path().join(name), content).unwrap();
    }
    let output = rsh_bin()
        .arg("--dir")
        .arg(dir.path())
        .arg(cmd)
        .output()
        .unwrap();
    assert!(!output.status.success(),
        "expected rejection for `{cmd}`, stderr: {}",
        String::from_utf8_lossy(&output.stderr));
    (dir, output)
}

// --- xargs stdin argument injection ---
//
// xargs constructs command lines from stdin at runtime.  With --exec rewriting,
// every command xargs spawns goes through a child rsh that validates the full argv.

#[test]
fn test_xargs_stdin_injects_sed_i_flag() {
    // The child rsh rejects sed -ibak (prefix-blocked flag)
    let (dir, _) = assert_rejected_in_dir(
        &[("target.txt", "original\n")],
        "echo '-ibak' | xargs -I{} sed {} 's/original/HACKED/' target.txt",
    );
    let content = std::fs::read_to_string(dir.path().join("target.txt")).unwrap();
    assert_eq!(content, "original\n", "file was modified: {content}");
}

#[test]
fn test_xargs_stdin_injects_sed_i_flag_simple() {
    let (dir, _) = assert_rejected_in_dir(
        &[("target.txt", "original\n")],
        "echo '-ibak s/original/HACKED/ target.txt' | xargs sed",
    );
    let content = std::fs::read_to_string(dir.path().join("target.txt")).unwrap();
    assert_eq!(content, "original\n", "file was modified: {content}");
}

#[test]
fn test_xargs_stdin_injects_find_delete() {
    let (dir, _) = assert_rejected_in_dir(
        &[("target.txt", "keep me\n")],
        "echo '-delete' | xargs -I{} find . -name target.txt {}",
    );
    assert!(dir.path().join("target.txt").exists(), "file was deleted");
}

#[test]
fn test_xargs_stdin_injects_sort_output() {
    let (dir, _) = assert_rejected_in_dir(
        &[("input.txt", "banana\napple\n")],
        "echo '--output=stolen.txt input.txt' | xargs sort",
    );
    assert!(!dir.path().join("stolen.txt").exists(), "file was created");
}

// --- sed brace-group write command bypass ---
//
// check_sed_expr_for_write must detect `w`/`W` commands even when wrapped in
// `{`/`}` brace groups or preceded by `!` negation.

#[test]
fn test_sed_brace_group_w_bypass() {
    let (dir, _) = assert_rejected_in_dir(
        &[("input.txt", "secret data\n")],
        "sed -n '{ w output.txt\n}' input.txt",
    );
    assert!(!dir.path().join("output.txt").exists(), "output.txt was created");
}

#[test]
fn test_sed_brace_group_w_with_address_bypass() {
    let (dir, _) = assert_rejected_in_dir(
        &[("input.txt", "secret data\n")],
        "sed -n '1{ w output.txt\n}' input.txt",
    );
    assert!(!dir.path().join("output.txt").exists(), "output.txt was created");
}

// --- --exec mode tests ---

#[test]
fn test_exec_flag_basic() {
    let output = rsh_bin()
        .arg("--exec")
        .arg("echo")
        .arg("hello")
        .arg("world")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello world");
}

#[test]
fn test_exec_flag_validates() {
    // --exec should still validate: sed -i should be rejected
    let output = rsh_bin()
        .arg("--exec")
        .arg("sed")
        .arg("-i")
        .arg("s/foo/bar/")
        .arg("file.txt")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("-i"), "stderr was: {}", stderr);
}

#[test]
fn test_exec_flag_rejects_non_allowlisted() {
    let output = rsh_bin()
        .arg("--exec")
        .arg("rm")
        .arg("file.txt")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not in allowlist"), "stderr was: {}", stderr);
}

// --- xargs/find --exec rewrite integration tests ---

#[test]
fn test_xargs_exec_rewrite_works() {
    // A safe xargs pipeline should work end-to-end via the rsh child rewrite
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("echo Cargo.toml | xargs grep -l rsh")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Cargo.toml"), "stdout was: {}", stdout);
}

#[test]
fn test_find_exec_rewrite_works() {
    // find -exec through the rewrite should still work for safe commands
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("find src -name '*.rs' -exec grep -l 'fn main' {} ';'")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("main.rs"), "stdout was: {}", stdout);
}
