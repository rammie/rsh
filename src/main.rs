mod allowlist;
mod executor;
mod glob;
mod sed;
mod validator;

use allowlist::Allowlist;
use executor::Executor;

fn has_command(name: &str) -> bool {
    std::process::Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn prime(al: &Allowlist, allow_redirects: bool) {
    let cmds = al.allowed_commands().join(", ");
    let has_rg = has_command("rg");
    let has_fd = has_command("fd");

    print!(
        "\
Use rsh for read-only shell operations. rsh works like bash but only permits specific commands.

Usage: rsh -c \"<command>\"

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
- Only -n flag and 'p' command are supported (no substitution, no -i, no scripting)

Not allowed:
- Commands outside the allowlist above — the allowlist is fixed and cannot be changed
- find -exec / -execdir (use command substitution or for-loops instead)
- Instead of: find . | xargs grep pattern → use: grep -r pattern . OR grep pattern $(find . -name '*.ext')
- Function definitions, background execution (&), process substitution{redirect_note}

Patterns for multi-step reads:
",
        redirect_note = if allow_redirects {
            ""
        } else {
            "\n- File output redirects (> and >>)"
        },
    );
    if has_rg {
        println!("  rg \"pattern\" -t rust -C 3                # search by content + file type");
        println!("  rg \"pattern\" -g \"*.ts\" .               # search with glob filter (NOT --include)");
        println!("  rg \"pattern\" -l .                        # list matching files only");
    }
    println!("  grep -rn \"pattern\" --include=\"*.rs\" .      # search by content + file type");
    if has_fd {
        println!("  fd -e rs | head -20                        # find files by extension");
    }
    println!("  tree -L 2 .                                    # overview of directory structure");
    println!("  grep pattern $(find . -name \"*.rs\")          # find by name, then search");
    println!(
        "  for f in $(find . -name \"*.toml\"); do head -20 \"$f\"; done  # find, then inspect"
    );

    print!(
        "\
\nBehavior:
- stdout, stderr, and exit codes work exactly like bash
- Rejected commands print an error to stderr and exit 1
- Environment is sanitized (PATH, LANG, etc. are forwarded to commands)
- With --inherit-env, all parent environment variables are visible to commands (including printenv, env) — except LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT, DYLD_INSERT_LIBRARIES, DYLD_FRAMEWORK_PATH, and DYLD_LIBRARY_PATH, which are always stripped for security
- With --allow-redirects, output redirects follow symlinks in the working directory
"
    );
    std::process::exit(0);
}

fn prime_install_claude(working_dir: Option<&str>) {
    // Find project root by looking for .git directory
    let start_dir = match working_dir {
        Some(d) => std::path::PathBuf::from(d),
        None => std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
    };
    let project_root = find_git_root(&start_dir).unwrap_or(start_dir);

    let claude_dir = project_root.join(".claude");
    if let Err(e) = std::fs::create_dir_all(&claude_dir) {
        eprintln!("error: failed to create .claude directory: {}", e);
        std::process::exit(1);
    }

    let settings_path = claude_dir.join("settings.local.json");

    // Read existing settings or start with empty object
    let mut settings: serde_json::Value = match std::fs::read_to_string(&settings_path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_else(|e| {
            eprintln!(
                "error: failed to parse {}: {}",
                settings_path.display(),
                e
            );
            std::process::exit(1);
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
        Err(e) => {
            eprintln!("error: failed to read {}: {}", settings_path.display(), e);
            std::process::exit(1);
        }
    };

    // Ensure hooks.SessionStart array exists
    let hooks = settings
        .as_object_mut()
        .expect("settings must be an object")
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));
    let session_start = hooks
        .as_object_mut()
        .expect("hooks must be an object")
        .entry("SessionStart")
        .or_insert_with(|| serde_json::json!([]));
    let arr = session_start
        .as_array_mut()
        .expect("SessionStart must be an array");

    // Check for existing rsh --prime hook (dedup)
    let already_exists = arr.iter().any(|entry| {
        if let Some(hooks_arr) = entry.get("hooks").and_then(|h| h.as_array()) {
            hooks_arr.iter().any(|hook| {
                hook.get("command")
                    .and_then(|c| c.as_str())
                    .map(|c| c.contains("rsh --prime"))
                    .unwrap_or(false)
            })
        } else {
            false
        }
    });

    if !already_exists {
        arr.push(serde_json::json!({
            "matcher": "",
            "hooks": [{"type": "command", "command": "rsh --prime"}]
        }));
    }

    // Write back pretty-printed JSON
    let json_str = serde_json::to_string_pretty(&settings).unwrap();
    if let Err(e) = std::fs::write(&settings_path, format!("{}\n", json_str)) {
        eprintln!("error: failed to write {}: {}", settings_path.display(), e);
        std::process::exit(1);
    }

    if already_exists {
        eprintln!("rsh hook already exists in {}", settings_path.display());
    } else {
        eprintln!("Installed rsh SessionStart hook in {}", settings_path.display());
    }
    std::process::exit(0);
}

fn find_git_root(start: &std::path::Path) -> Option<std::path::PathBuf> {
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

fn usage() {
    eprintln!("Usage: rsh [OPTIONS] <COMMAND_STRING>");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --allow-redirects   Allow output redirects (> and >>)");
    eprintln!("  --max-output <n>    Max output bytes (default: 10485760 = 10MB)");
    eprintln!("  --inherit-env       Inherit full parent environment (default: sanitized)");
    eprintln!("  --dir <path>        Working directory (default: cwd)");
    eprintln!("  --prime             Print an LLM-ready description of rsh's capabilities");
    eprintln!("  --prime claude      Install rsh as a Claude Code SessionStart hook");
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
    let mut prime_mode: Option<&str> = None; // None, Some("print"), or Some("claude")

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => usage(),
            "--version" | "-V" => {
                println!("rsh {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--prime" => {
                if i + 1 < args.len() && args[i + 1] == "claude" {
                    i += 1;
                    prime_mode = Some("claude");
                } else {
                    prime_mode = Some("print");
                }
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
            _ => {
                if args[i].starts_with('-') {
                    eprintln!("error: unknown flag '{}'", args[i]);
                    std::process::exit(2);
                }
                command_string = Some(args[i].clone());
            }
        }
        i += 1;
    }

    match prime_mode {
        Some("claude") => prime_install_claude(working_dir.as_deref()),
        Some(_) => {
            let al = Allowlist::new();
            prime(&al, allow_redirects);
        }
        None => {}
    }

    // Load pinned allowlist
    let al = Allowlist::new();

    let command_string = match command_string {
        Some(s) => s,
        None => {
            eprintln!("error: no command string provided");
            usage();
            unreachable!()
        }
    };

    let working_dir = match working_dir {
        Some(d) => std::path::PathBuf::from(d),
        None => std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
    };

    // Parse using brush-parser
    let reader = std::io::Cursor::new(&command_string);
    let mut parser = brush_parser::Parser::builder().reader(reader).build();
    let program = match parser.parse_program() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("rsh: parse error: {}", e);
            std::process::exit(1);
        }
    };

    // Check for empty program
    if program.complete_commands.is_empty() {
        eprintln!("rsh: empty input");
        std::process::exit(1);
    }

    // Execute
    let executor = Executor::new(al, working_dir, allow_redirects, max_output, inherit_env);
    let output = executor.execute(&program);
    print!("{}", output.stdout);
    eprint!("{}", output.stderr);
    std::process::exit(output.exit_code);
}
