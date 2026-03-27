mod allowlist;
mod executor;
mod glob;
mod install;
mod mcp;
mod sed;
mod validator;

use allowlist::Allowlist;
use executor::{Executor, Output};

/// Join args into a single shell command string, quoting as needed.
fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|arg| {
            if arg.is_empty() {
                "''".to_string()
            } else if arg
                .chars()
                .all(|c| c.is_alphanumeric() || "._-/=@:,+%".contains(c))
            {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn has_command(name: &str) -> bool {
    std::process::Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn prime_text(al: &Allowlist, allow_redirects: bool) -> String {
    let cmds = al.allowed_commands().join(", ");
    let has_rg = has_command("rg");
    let has_fd = has_command("fd");

    let redirect_note = if allow_redirects {
        ""
    } else {
        "\n- File output redirects (> and >>)"
    };

    let mut s = format!(
        "\
Use rsh for read-only shell operations. rsh works like bash but only permits specific commands.

Usage: rsh -c \"<command>\"
       rsh <command> [args...]

Allowed commands: {cmds}

Supported syntax:
- Pipelines: grep TODO src/*.rs | wc -l
- Boolean operators: grep -q TODO file && echo found
- Loops: for f in *.rs; do wc -l \"$f\"; done
- Conditionals: if grep -q TODO src/main.rs; then echo found; fi
- Command substitution: wc -l $(find src -name '*.rs')
- Globs, quoted strings, semicolons, case statements

IMPORTANT — use relative paths only:
- Absolute paths (/repo, /home, /tmp, etc.) are REJECTED — always use . or relative paths
- Path traversal (..) is REJECTED
- Variable references ($HOME, etc.) and tilde (~) are REJECTED in arguments
- To explore from the working directory: ls ., find . -name '*.ts', tree .

sed (restricted — line extraction only):
- sed -n '10,20p' file                           # print lines 10-20
- sed -n '5p' file                               # print line 5
- sed -n '$p' file                               # print last line
- sed -n '5,$p' file                             # print from line 5 to end
- sed -n '1p;10,20p' file                        # multiple ranges
- cat file | sed -n '1,5p'                       # works in pipelines
- sed -n '/pattern/p' file                       # print lines matching regex
- sed -n '/START/,/END/p' file                   # print from first match to second
- sed -n '10,/pattern/p' file                    # mixed line number + regex range
- Only -n flag and 'p' command are supported (no substitution, no -i, no scripting)

Not allowed:
- Commands outside the allowlist above — the allowlist is fixed and cannot be changed
- find -exec / -execdir (use command substitution or for-loops instead)
- Instead of: find . | xargs grep pattern → use: grep -r pattern . OR grep pattern $(find . -name '*.ext')
- Function definitions, background execution (&), process substitution{redirect_note}

Patterns for multi-step reads:\n"
    );

    if has_rg {
        s.push_str(
            "  rg \"pattern\" -t rust -C 3                # search by content + file type\n",
        );
        s.push_str("  rg \"pattern\" -g \"*.ts\" .               # search with glob filter (NOT --include)\n");
        s.push_str("  rg \"pattern\" -l .                        # list matching files only\n");
    }
    s.push_str(
        "  grep -rn \"pattern\" --include=\"*.rs\" .      # search by content + file type\n",
    );
    if has_fd {
        s.push_str("  fd -e rs | head -20                        # find files by extension\n");
    }
    s.push_str(
        "  tree -L 2 .                                    # overview of directory structure\n",
    );
    s.push_str("  grep pattern $(find . -name \"*.rs\")          # find by name, then search\n");
    s.push_str(
        "  for f in $(find . -name \"*.toml\"); do head -20 \"$f\"; done  # find, then inspect\n",
    );

    s.push_str(
        "\
\nBehavior:
- stdout, stderr, and exit codes work exactly like bash
- Rejected commands print an error to stderr and exit 1
- Environment is sanitized (PATH, LANG, etc. are forwarded to commands)
- With --inherit-env, all parent environment variables are visible to commands (including printenv, env) — except LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT, DYLD_INSERT_LIBRARIES, DYLD_FRAMEWORK_PATH, and DYLD_LIBRARY_PATH, which are always stripped for security
- With --allow-redirects, output redirects follow symlinks in the working directory\n"
    );

    s
}

fn prime(al: &Allowlist, allow_redirects: bool) {
    print!("{}", prime_text(al, allow_redirects));
    std::process::exit(0);
}

pub fn find_git_root(start: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut dir = if start.is_absolute() {
        start.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(start)
    };
    loop {
        if dir.join(".git").exists() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

pub fn resolve_working_dir(dir: Option<&str>) -> std::path::PathBuf {
    match dir {
        Some(d) => std::path::PathBuf::from(d),
        None => std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
    }
}

pub fn parse_and_execute(
    command: &str,
    allowlist: Allowlist,
    working_dir: std::path::PathBuf,
    allow_redirects: bool,
    max_output: usize,
    inherit_env: bool,
) -> Output {
    let reader = std::io::Cursor::new(command);
    let mut parser = brush_parser::Parser::builder().reader(reader).build();
    let program = match parser.parse_program() {
        Ok(p) => p,
        Err(e) => return Output::error(format!("parse error: {}", e)),
    };

    if program.complete_commands.is_empty() {
        return Output::error("empty input".to_string());
    }

    let executor = Executor::new(
        allowlist,
        working_dir,
        allow_redirects,
        max_output,
        inherit_env,
    );
    executor.execute(&program)
}

fn usage() {
    eprintln!("Usage: rsh [OPTIONS] <COMMAND_STRING>");
    eprintln!("       rsh [OPTIONS] <COMMAND> [ARGS...]");
    eprintln!("       rsh [OPTIONS] -- <COMMAND> [ARGS...]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --allow-redirects   Allow output redirects (> and >>)");
    eprintln!("  --max-output <n>    Max output bytes (default: 10485760 = 10MB)");
    eprintln!("  --inherit-env       Inherit full parent environment (default: sanitized)");
    eprintln!("  --dir <path>        Working directory (default: cwd)");
    eprintln!("  --mcp               Start MCP stdio server (JSON-RPC over stdin/stdout)");
    eprintln!("  --install claude    Set up rsh for Claude Code (MCP server + SessionStart hook)");
    eprintln!("  --prime             Print an LLM-ready description of rsh's capabilities");
    eprintln!("  --version, -V       Print version");
    eprintln!("  --help              Show this help");
    eprintln!();
    eprintln!("The command allowlist is pinned at compile time and cannot be changed at runtime.");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut allow_redirects = false;
    let mut max_output: usize = 10 * 1024 * 1024; // 10MB
    let mut inherit_env = false;
    let mut working_dir: Option<String> = None;
    let mut command_string: Option<String> = None;
    let mut prime_mode = false;
    let mut mcp_mode = false;
    let mut install_target: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => usage(),
            "--version" | "-V" => {
                println!("rsh {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--mcp" => {
                mcp_mode = true;
            }
            "--install" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --install requires a target (e.g., 'claude')");
                    std::process::exit(2);
                }
                install_target = Some(args[i].clone());
            }
            "--prime" => {
                prime_mode = true;
            }
            "--allow-redirects" => {
                allow_redirects = true;
            }
            "--max-output" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --max-output requires a value");
                    std::process::exit(2);
                }
                max_output = args[i].parse().unwrap_or_else(|_| {
                    eprintln!("error: --max-output must be a positive integer");
                    std::process::exit(2);
                });
            }
            "--inherit-env" => {
                inherit_env = true;
            }
            "--dir" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --dir requires a value");
                    std::process::exit(2);
                }
                working_dir = Some(args[i].clone());
            }
            "-c" => {
                // Accept -c for bash compatibility (rsh -c "command")
                i += 1;
                if i >= args.len() {
                    eprintln!("error: -c requires a command string");
                    std::process::exit(2);
                }
                command_string = Some(args[i].clone());
            }
            "--" => {
                if i + 1 >= args.len() {
                    eprintln!("error: no command after --");
                    std::process::exit(2);
                }
                command_string = Some(shell_join(&args[i + 1..]));
                break;
            }
            _ => {
                if args[i].starts_with('-') {
                    eprintln!("error: unknown flag '{}'", args[i]);
                    std::process::exit(2);
                }
                // Single arg: use as-is for backward compat (rsh "echo hello")
                if i + 1 == args.len() {
                    command_string = Some(args[i].clone());
                } else {
                    command_string = Some(shell_join(&args[i..]));
                }
                break;
            }
        }
        i += 1;
    }

    if mcp_mode {
        let working_dir = resolve_working_dir(working_dir.as_deref());
        mcp::run_server(allow_redirects, max_output, inherit_env, working_dir);
        std::process::exit(0);
    }

    match install_target.as_deref() {
        Some("claude") => {
            install::install_claude(working_dir.as_deref(), allow_redirects, inherit_env)
        }
        Some(target) => {
            eprintln!(
                "error: unknown install target '{}' (supported: claude)",
                target
            );
            std::process::exit(2);
        }
        None => {}
    }

    if prime_mode {
        let al = Allowlist::new();
        prime(&al, allow_redirects);
    }

    let command_string = match command_string {
        Some(s) => s,
        None => {
            eprintln!("error: no command string provided");
            usage();
            unreachable!()
        }
    };

    let working_dir = resolve_working_dir(working_dir.as_deref());
    let output = parse_and_execute(
        &command_string,
        Allowlist::new(),
        working_dir,
        allow_redirects,
        max_output,
        inherit_env,
    );
    print!("{}", output.stdout);
    eprint!("{}", output.stderr);
    std::process::exit(output.exit_code);
}
