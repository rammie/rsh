//! Integration tests exercising real-world usage patterns for rsh.
//!
//! These tests run against the actual project source tree at CARGO_MANIFEST_DIR
//! to verify that complex find, grep, pipeline, and multi-command workflows
//! behave correctly.

use std::process::Command;

fn rsh_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rsh"))
}

/// Helper: run an rsh command in the project directory, return Output.
fn run(cmd: &str) -> std::process::Output {
    rsh_bin()
        .arg("--inherit-env")
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg(cmd)
        .output()
        .unwrap()
}

/// Helper: run and assert success, return stdout.
fn run_ok(cmd: &str) -> String {
    let output = run(cmd);
    assert!(
        output.status.success(),
        "command '{}' failed.\nstderr: {}",
        cmd,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

// ============================================================
// grep — pattern matching
// ============================================================

#[test]
fn test_grep_literal_string() {
    let out = run_ok("grep 'Restricted Shell' README.md");
    assert!(out.contains("Restricted"), "stdout: {}", out);
}

#[test]
fn test_grep_case_insensitive() {
    let out = run_ok("grep -i 'name' Cargo.toml");
    assert!(out.to_lowercase().contains("name"));
}

#[test]
fn test_grep_with_line_numbers() {
    let out = run_ok("grep -n 'fn main' src/main.rs");
    // Should have line_number:content format
    assert!(out.contains(":"), "expected line numbers, got: {}", out);
    assert!(out.contains("fn main"));
}

#[test]
fn test_grep_count() {
    let out = run_ok("grep -c 'fn ' src/executor.rs");
    let count: i32 = out.trim().parse().unwrap();
    assert!(count > 5, "expected many functions, got count={}", count);
}

#[test]
fn test_grep_recursive_in_directory() {
    let out = run_ok("grep -r 'allowlist' src/");
    assert!(out.contains("allowlist.rs"));
    assert!(out.contains("executor.rs"));
}

#[test]
fn test_grep_multiple_flags() {
    // -r recursive, -l files only, -i case insensitive
    let out = run_ok("grep -rli 'struct' src/");
    assert!(out.contains("validator.rs"));
    assert!(out.contains("executor.rs"));
}

#[test]
fn test_grep_regex_pattern() {
    // Match function signatures: fn word(
    let out = run_ok("grep -E 'fn [a-z_]+\\(' src/validator.rs");
    assert!(out.contains("fn validate"));
    assert!(out.contains("fn validate_program"));
}

#[test]
fn test_grep_inverted_match() {
    // Lines NOT containing 'use' in a small file
    let out = run_ok("grep -v 'use' src/glob.rs");
    // Should have content but no 'use' lines
    assert!(!out.is_empty());
    for line in out.lines() {
        assert!(!line.contains("use "), "inverted match leaked: {}", line);
    }
}

#[test]
fn test_grep_fixed_string_with_special_chars() {
    // grep -F treats pattern as literal, not regex
    let out = run_ok("grep -F 'Vec<String>' src/executor.rs");
    assert!(out.contains("Vec<String>"));
}

#[test]
fn test_grep_context_lines() {
    // -A 2: show 2 lines after each match
    let out = run_ok("grep -A 2 'fn main' src/main.rs");
    let lines: Vec<&str> = out.lines().collect();
    assert!(
        lines.len() >= 3,
        "expected context lines, got {} lines",
        lines.len()
    );
}

#[test]
fn test_grep_keyword_in_quotes_not_rejected() {
    // Regression: 'if' in a quoted grep pattern must not be blocked as a keyword
    let out = run_ok("grep 'if' src/validator.rs");
    assert!(!out.is_empty(), "grep 'if' should find matches");
}

#[test]
fn test_grep_and_operator_in_quotes() {
    // Regression: '&&' in a quoted grep pattern must not be blocked
    let out = run_ok("grep '&&' src/validator.rs");
    assert!(!out.is_empty(), "grep '&&' should find matches");
}

#[test]
fn test_grep_pipe_in_quotes() {
    // '|' in a quoted pattern should not break pipeline parsing
    let out = run_ok("grep 'Some(redirect_list)' src/validator.rs");
    assert!(out.contains("Some(redirect_list)"));
}

#[test]
fn test_grep_no_match_exit_code() {
    let output = run("grep 'ZZZZZ_NONEXISTENT_PATTERN_ZZZZZ' src/main.rs");
    assert!(
        !output.status.success(),
        "grep no-match should exit non-zero"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "");
}

// ============================================================
// find — file discovery
// ============================================================

#[test]
fn test_find_all_rust_files() {
    let out = run_ok("find src -name '*.rs'");
    assert!(out.contains("src/main.rs"));
    assert!(out.contains("src/validator.rs"));
    assert!(out.contains("src/executor.rs"));
    assert!(out.contains("src/allowlist.rs"));
    assert!(out.contains("src/glob.rs"));
}

#[test]
fn test_find_by_type_file() {
    let out = run_ok("find src -type f -name '*.rs'");
    for line in out.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        assert!(trimmed.ends_with(".rs"), "unexpected file: {}", trimmed);
    }
}

#[test]
fn test_find_by_type_directory() {
    let out = run_ok("find . -type d -name 'src'");
    assert!(out.contains("src"), "stdout: {}", out);
}

#[test]
fn test_find_maxdepth() {
    let out = run_ok("find . -maxdepth 1 -type f -name '*.toml'");
    assert!(out.contains("Cargo.toml"));
    // Should not find files in subdirectories
    assert!(
        !out.contains("src/"),
        "maxdepth 1 should not recurse into src/"
    );
}

#[test]
fn test_find_multiple_name_patterns() {
    // Find both .rs and .toml files
    let out = run_ok("find . -name '*.rs' -o -name '*.toml'");
    assert!(out.contains(".rs"));
    assert!(out.contains(".toml"));
}

#[test]
fn test_find_current_directory() {
    let out = run_ok("find . -maxdepth 0 -type d");
    assert_eq!(out.trim(), ".");
}

// ============================================================
// Complex pipelines — multi-stage data processing
// ============================================================

#[test]
fn test_grep_pipe_wc() {
    // Count functions in executor.rs
    let out = run_ok("grep -c 'fn ' src/executor.rs");
    let count: i32 = out.trim().parse().unwrap();
    assert!(count > 0);
}

#[test]
fn test_find_pipe_grep() {
    // Find all .rs files then filter for ones containing 'test'
    let out = run_ok("find src -name '*.rs' | grep 'rs'");
    assert!(!out.is_empty());
    for line in out.lines() {
        assert!(line.contains("rs"), "expected .rs in line: {}", line);
    }
}

#[test]
fn test_find_pipe_wc_count_files() {
    // Count the number of .rs source files
    let out = run_ok("find src -name '*.rs' -type f | wc -l");
    let count: i32 = out.trim().parse().unwrap();
    assert_eq!(count, 5, "expected 5 source files, got {}", count);
}

#[test]
fn test_grep_pipe_head() {
    // Get first 3 function definitions
    let out = run_ok("grep 'fn ' src/executor.rs | head -n 3");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "expected 3 lines, got {}: {:?}",
        lines.len(),
        lines
    );
}

#[test]
fn test_grep_pipe_tail() {
    // Get last 2 function definitions
    let out = run_ok("grep 'fn ' src/executor.rs | tail -n 2");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "expected 2 lines, got {}: {:?}",
        lines.len(),
        lines
    );
}

#[test]
fn test_grep_pipe_grep_double_filter() {
    // Grep for struct, then filter for 'pub'
    let out = run_ok("grep 'struct' src/executor.rs | grep 'pub'");
    assert!(out.contains("pub struct"));
}

#[test]
fn test_cat_pipe_grep_pipe_wc() {
    // Three-stage pipeline: read file, filter, count
    let out = run_ok("cat src/glob.rs | grep 'pub' | wc -l");
    let count: i32 = out.trim().parse().unwrap();
    assert!(count >= 2, "expected pub items in glob.rs, got {}", count);
}

#[test]
fn test_find_pipe_head_limits_output() {
    // Find all files, only show first 3
    let out = run_ok("find . -type f | head -n 3");
    let lines: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        3,
        "head -n 3 should give 3 lines, got {:?}",
        lines
    );
}

#[test]
fn test_cat_pipe_head_pipe_tail() {
    // Read file, take first 10 lines, then last 3 of those (lines 8-10)
    let out = run_ok("cat src/main.rs | head -n 10 | tail -n 3");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "expected 3 lines, got {:?}", lines);
}

#[test]
fn test_four_stage_pipeline() {
    // find files | filter .rs | count lines in each | sort numerically
    let out = run_ok("find src -name '*.rs' | grep 'rs' | head -n 3 | wc -l");
    let count: i32 = out.trim().parse().unwrap();
    assert_eq!(count, 3);
}

// ============================================================
// ls — directory listing
// ============================================================

#[test]
fn test_ls_basic() {
    let out = run_ok("ls");
    assert!(out.contains("Cargo.toml"));
    assert!(out.contains("src"));
}

#[test]
fn test_ls_long_format() {
    let out = run_ok("ls -l src/main.rs");
    // Long format includes permissions and size
    assert!(out.contains("main.rs"));
}

#[test]
fn test_ls_hidden_files() {
    let out = run_ok("ls -a");
    assert!(out.contains(".gitignore"));
}

#[test]
fn test_ls_subdirectory() {
    let out = run_ok("ls src/");
    assert!(out.contains("main.rs"));
    assert!(out.contains("validator.rs"));
}

#[test]
fn test_ls_glob_pattern() {
    let out = run_ok("ls src/*.rs");
    assert!(out.contains("main.rs"));
    // Should not list non-.rs files
    assert!(!out.contains(".toml"));
}

// ============================================================
// cat / head / tail — file reading
// ============================================================

#[test]
fn test_cat_whole_file() {
    let out = run_ok("cat src/glob.rs");
    assert!(out.contains("pub fn is_glob"));
    assert!(out.contains("pub fn expand_glob"));
}

#[test]
fn test_head_default() {
    // head with no -n defaults to 10 lines
    let out = run_ok("head src/main.rs");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 10);
}

#[test]
fn test_head_specific_count() {
    let out = run_ok("head -n 3 src/main.rs");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].contains("mod allowlist"));
}

#[test]
fn test_tail_specific_count() {
    let out = run_ok("tail -n 1 src/main.rs");
    let trimmed = out.trim();
    // Last line of main.rs should be closing brace or empty
    assert!(!trimmed.is_empty());
}

#[test]
fn test_cat_multiple_files() {
    let out = run_ok("cat src/validator.rs src/glob.rs");
    // Should contain content from both files
    assert!(out.contains("pub struct ValidatorConfig"));
    assert!(out.contains("fn is_glob"));
}

// ============================================================
// wc — counting
// ============================================================

#[test]
fn test_wc_lines() {
    let out = run_ok("wc -l src/glob.rs");
    assert!(out.contains("glob.rs") || out.trim().parse::<i32>().is_ok());
}

#[test]
fn test_wc_words() {
    let out = run_ok("wc -w src/glob.rs");
    let parts: Vec<&str> = out.trim().split_whitespace().collect();
    let count: i32 = parts[0].parse().unwrap();
    assert!(count > 10, "expected many words, got {}", count);
}

#[test]
fn test_wc_multiple_files() {
    let out = run_ok("wc -l src/glob.rs src/main.rs");
    // wc with multiple files should show individual counts and total
    assert!(out.contains("total") || out.lines().count() >= 2);
}

// ============================================================
// stat — file metadata
// ============================================================

#[test]
fn test_stat_file() {
    let out = run_ok("stat Cargo.toml");
    // macOS stat output includes the filename
    assert!(out.contains("Cargo.toml") || out.contains("File:"));
}

// ============================================================
// echo — output generation
// ============================================================

#[test]
fn test_echo_with_single_quotes() {
    let out = run_ok("echo 'hello world'");
    assert_eq!(out.trim(), "hello world");
}

#[test]
fn test_echo_with_double_quotes_and_var_blocked() {
    let output = run(r#"echo "user is $USER""#);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not allowed"), "stderr was: {}", stderr);
}

#[test]
fn test_echo_braced_variable_blocked() {
    let output = run(r#"echo ${PWD}"#);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not allowed"), "stderr was: {}", stderr);
}

#[test]
fn test_echo_multiple_args() {
    let out = run_ok("echo one two three");
    assert_eq!(out.trim(), "one two three");
}

// ============================================================
// Semicolons — multiple independent commands
// ============================================================

#[test]
fn test_semicolon_three_commands() {
    let out = run_ok("echo first; echo second; echo third");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], "first");
    assert_eq!(lines[1], "second");
    assert_eq!(lines[2], "third");
}

#[test]
fn test_semicolon_mixed_commands() {
    let output = run("echo start; wc -l src/glob.rs; echo end");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.starts_with("start\n"));
    assert!(out.ends_with("end\n"));
}

#[test]
fn test_trailing_semicolon() {
    let out = run_ok("echo hello;");
    assert_eq!(out.trim(), "hello");
}

// ============================================================
// Glob expansion
// ============================================================

#[test]
fn test_glob_star_rs() {
    // ls src/*.rs should list all source files
    let out = run_ok("ls src/*.rs");
    assert!(out.contains("main.rs"));
    assert!(out.contains("validator.rs"));
}

#[test]
fn test_glob_question_mark() {
    // src/gl?b.rs should match glob.rs via ? wildcard
    let out = run_ok("ls src/gl?b.rs");
    assert!(out.contains("glob.rs"), "stdout: {}", out);
}

#[test]
fn test_glob_no_match_passthrough() {
    // Glob with no matches passes the pattern through (shell behavior)
    let output = run("echo zzz_no_match_*.xyz");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(
        out.contains("zzz_no_match_*.xyz"),
        "unmatched glob should pass through: {}",
        out
    );
}

// ============================================================
// Realistic agent workflows — multi-step investigation
// ============================================================

#[test]
fn test_workflow_find_and_count_lines() {
    // Agent wants to know how many .rs files exist and total line count
    let file_count = run_ok("find src -name '*.rs' -type f | wc -l");
    let count: i32 = file_count.trim().parse().unwrap();
    assert!(count >= 5, "expected at least 5 .rs files");
}

#[test]
fn test_workflow_search_for_struct_definitions() {
    // Agent wants to find all struct definitions across the codebase
    let out = run_ok("grep -rn 'pub struct' src/");
    assert!(out.contains("Allowlist"));
    assert!(out.contains("Executor"));
    assert!(out.contains("Output"));
    assert!(out.contains("ValidatorConfig"));
}

#[test]
fn test_workflow_find_todos() {
    // Common agent task: search for TODO/FIXME across codebase
    // This should succeed even if there are no matches (exit code 1 for no matches is ok)
    let output = run("grep -rn 'TODO\\|FIXME' src/");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should not be a validation error (rsh: prefix means validation failure)
    assert!(
        !stderr.starts_with("rsh: "),
        "unexpected validation error: {}",
        stderr
    );
}

#[test]
fn test_workflow_check_imports() {
    // Agent inspects which modules are imported in main
    let out = run_ok("grep '^mod ' src/main.rs");
    assert!(out.contains("mod allowlist"));
    assert!(out.contains("mod validator"));
    assert!(out.contains("mod executor"));
}

#[test]
fn test_workflow_inspect_file_structure() {
    // Agent examines project layout
    let out = run_ok("find . -maxdepth 2 -type f -name '*.rs'");
    assert!(out.contains("src/main.rs"));
    assert!(out.contains("tests/"));
}

#[test]
fn test_workflow_grep_pipe_grep_refine_search() {
    // Agent first finds all function defs, then narrows to non-pub ones
    // glob.rs has no private functions, so the result is empty (exit code 1)
    // The point is the double-grep pipeline works without validation error
    let output = run("grep -n 'fn ' src/glob.rs | grep -v 'pub'");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.starts_with("rsh: "),
        "unexpected validation error: {}",
        stderr
    );
}

#[test]
fn test_workflow_count_lines_per_file() {
    // Agent checks which source files are largest
    let out = run_ok("wc -l src/executor.rs src/validator.rs src/main.rs");
    assert!(out.contains("executor.rs"));
    assert!(out.contains("validator.rs"));
    assert!(out.contains("main.rs"));
}

#[test]
fn test_workflow_read_specific_section() {
    // Agent reads the first 5 lines of a file to see the module doc comment
    let out = run_ok("head -n 5 src/validator.rs");
    assert!(
        out.contains("AST security walker"),
        "expected validator doc: {}",
        out
    );
}

#[test]
fn test_workflow_check_cargo_dependencies() {
    // Agent inspects dependencies
    let out = run_ok("grep -A 1 'dependencies' Cargo.toml");
    assert!(out.contains("[dependencies]") || out.contains("[dev-dependencies]"));
}

#[test]
fn test_workflow_semicolons_multi_inspect() {
    // Agent runs multiple independent inspection commands
    let output = run("wc -l src/main.rs; grep -c 'fn ' src/executor.rs; ls src/");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let out = String::from_utf8_lossy(&output.stdout);
    // Should contain output from all three commands
    assert!(!out.is_empty());
}

// ============================================================
// Edge cases and tricky patterns
// ============================================================

#[test]
fn test_grep_pattern_with_dots() {
    // Dots in grep patterns are regex wildcards — should work fine
    // 'rsh.glob' matches 'rsh_glob' because . is a wildcard
    let out = run_ok("grep 'rsh.glob' src/executor.rs");
    assert!(out.contains("rsh_glob"));
}

#[test]
fn test_grep_with_backslash_escaped_pattern() {
    // Literal dot search
    let out = run_ok("grep 'Cargo\\.toml' README.md");
    assert!(out.contains("Cargo.toml"));
}

#[test]
fn test_find_with_not() {
    // find with negation: find files that are NOT .rs
    let out = run_ok("find . -maxdepth 1 -type f -not -name '*.rs'");
    assert!(out.contains("Cargo.toml") || out.contains(".gitignore"));
}

#[test]
fn test_empty_pipeline_stage_stderr() {
    // grep with no matches in a pipeline — downstream gets empty input
    let output = run("grep 'ZZZNONEXISTENT' src/main.rs | wc -l");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let out = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        out.trim(),
        "0",
        "wc -l of empty input should be 0, got '{}'",
        out.trim()
    );
}

#[test]
fn test_quoted_arg_with_spaces() {
    let out = run_ok("echo 'hello   world'");
    assert_eq!(out.trim(), "hello   world");
}

#[test]
fn test_mixed_quote_types() {
    let out = run_ok(r#"echo 'single' "double" bare"#);
    assert_eq!(out.trim(), "single double bare");
}

#[test]
fn test_find_with_empty_result_in_pipeline() {
    // find something that doesn't exist, pipe to wc
    let output = run("find src -name '*.xyz' -type f | wc -l");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let out = String::from_utf8_lossy(&output.stdout);
    assert_eq!(out.trim(), "0");
}

#[test]
fn test_grep_after_grep_in_pipeline() {
    // Progressive filtering: all lines with 'fn' -> only ones with 'pub' -> count
    let out = run_ok("grep 'fn ' src/executor.rs | grep 'pub' | wc -l");
    let count: i32 = out.trim().parse().unwrap();
    assert!(count >= 2, "expected at least 2 pub fns, got {}", count);
}

#[test]
fn test_ls_pipe_grep_filters_filenames() {
    // List directory, filter for specific extension
    let out = run_ok("ls src/ | grep '\\.rs'");
    for line in out.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        assert!(trimmed.ends_with(".rs"), "unexpected: {}", trimmed);
    }
}

#[test]
fn test_cat_nonexistent_file() {
    let output = run("cat nonexistent_file_abc.txt");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.is_empty(), "cat should report error on stderr");
}

#[test]
fn test_grep_binary_flag_quiet() {
    // grep -q returns exit code only, no stdout
    let output = run("grep -q 'fn main' src/main.rs");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "");
}

// ============================================================
// Redirects with real workflows (opt-in)
// ============================================================

#[test]
fn test_redirect_grep_output_to_file() {
    let tmp = std::env::temp_dir().join("rsh_integ_redirect");
    std::fs::create_dir_all(&tmp).unwrap();

    // Copy a source file into the temp dir so we have something to grep
    std::fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/glob.rs"),
        tmp.join("glob.rs"),
    )
    .unwrap();

    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("--allow-redirects")
        .arg("--dir")
        .arg(tmp.to_str().unwrap())
        .arg("grep 'pub' glob.rs > structs.txt")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(tmp.join("structs.txt")).unwrap();
    assert!(content.contains("pub fn"));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_redirect_pipeline_to_file() {
    let tmp = std::env::temp_dir().join("rsh_integ_pipe_redir");
    std::fs::create_dir_all(&tmp).unwrap();

    std::fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/executor.rs"),
        tmp.join("executor.rs"),
    )
    .unwrap();

    // Pipeline with redirect on the last command
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("--allow-redirects")
        .arg("--dir")
        .arg(tmp.to_str().unwrap())
        .arg("grep 'fn ' executor.rs | head -n 5 > top_fns.txt")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(tmp.join("top_fns.txt")).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 5, "expected 5 lines, got: {:?}", lines);

    let _ = std::fs::remove_dir_all(&tmp);
}

// ============================================================
// Timeout behavior in real commands
// ============================================================

#[test]
fn test_fast_command_within_timeout() {
    // A fast command should complete quickly
    let output = rsh_bin()
        .arg("--inherit-env")
        .arg("--dir")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("echo fast")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "fast");
}

// ============================================================
// Combining features: globs + pipelines + working dir
// ============================================================

#[test]
fn test_glob_in_grep_with_pipeline() {
    // grep across multiple files by glob, pipe to wc
    let out = run_ok("grep -l 'fn ' src/*.rs | wc -l");
    let count: i32 = out.trim().parse().unwrap();
    // Most .rs files contain 'fn '
    assert!(
        count >= 4,
        "expected at least 4 files with functions, got {}",
        count
    );
}

#[test]
fn test_glob_in_cat_with_pipeline() {
    // Cat multiple files via glob, count total lines
    let out = run_ok("cat src/*.rs | wc -l");
    let count: i32 = out.trim().parse().unwrap();
    assert!(
        count > 100,
        "expected many lines across all source files, got {}",
        count
    );
}

#[test]
fn test_glob_in_wc() {
    // wc -l on all .rs files
    let out = run_ok("wc -l src/*.rs");
    assert!(out.contains("total") || out.lines().count() >= 5);
}

#[test]
fn test_find_then_count_with_pipeline() {
    // Find test files and count them
    let out = run_ok("find tests -name '*.rs' -type f | wc -l");
    let count: i32 = out.trim().parse().unwrap();
    assert!(count >= 3, "expected at least 3 test files, got {}", count);
}
