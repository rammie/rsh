mod allowlist;
mod executor;
mod glob;
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

Not allowed:
- awk, sed, xargs (use cut, grep, command substitution, and for-loops instead)
- find -exec / -execdir (use command substitution or for-loops instead)
- Instead of: find . | xargs grep pattern → use: grep -r pattern . OR grep pattern $(find . -name '*.ext')
- Commands outside the allowlist above
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
        println!("  rg \"pattern\" -g \"*.ts\" .                 # search with glob filter (NOT --include)");
        println!("  rg \"pattern\" -l .                         # list matching files only");
    }
    println!("  grep -rn \"pattern\" --include=\"*.rs\" .      # search by content + file type");
    if has_fd {
        println!("  fd -e rs | head -20                        # find files by extension");
    }
    println!("  tree -L 2 .                                # overview of directory structure");
    println!("  grep pattern $(find . -name \"*.rs\")         # find by name, then search");
    println!(
        "  for f in $(find . -name \"*.toml\"); do head -20 \"$f\"; done  # find, then inspect"
    );

    print!(
        "\
\nBehavior:
- stdout, stderr, and exit codes work exactly like bash
- Rejected commands print an error to stderr and exit 1
- Environment is sanitized (PATH, LANG, etc. are forwarded to commands)
"
    );
    std::process::exit(0);
}

fn usage() {
    eprintln!("Usage: rsh [OPTIONS] <COMMAND_STRING>");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --allow <cmds>      Comma-separated allowlist (overrides defaults)");
    eprintln!("  --allow-redirects   Allow output redirects (> and >>)");
    eprintln!("  --max-output <n>    Max output bytes (default: 10485760 = 10MB)");
    eprintln!("  --inherit-env       Inherit full parent environment (default: sanitized)");
    eprintln!("  --dir <path>        Working directory (default: cwd)");
    eprintln!("  --prime             Print an LLM-ready description of rsh's capabilities");
    eprintln!("  --help              Show this help");
    eprintln!();
    eprintln!("Trust model:");
    eprintln!("  The command allowlist is determined by (in priority order, last wins):");
    eprintln!("    1. Built-in defaults (read-only commands)");
    eprintln!("    2. Config file: ~/.rsh/allowlist (one command per line)");
    eprintln!("    3. Environment variable: RSH_ALLOWLIST (comma-separated)");
    eprintln!("    4. CLI flag: --allow (comma-separated)");
    eprintln!("  Sources 2-3 are trusted inputs; ensure they are not writable by");
    eprintln!("  untrusted users. The --allow flag (source 4) is the most secure");
    eprintln!("  override as it is explicit per invocation.");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut allow_flag: Option<String> = None;
    let mut allow_redirects = false;
    let mut max_output: usize = 10 * 1024 * 1024; // 10MB
    let mut inherit_env = false;
    let mut working_dir: Option<String> = None;
    let mut command_string: Option<String> = None;
    let mut show_prime = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => usage(),
            "--prime" => {
                show_prime = true;
            }
            "--allow" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --allow requires a value");
                    std::process::exit(2);
                }
                allow_flag = Some(args[i].clone());
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

    // Load allowlist (needed for --prime and execution)
    let al = Allowlist::load(allow_flag.as_deref());

    if show_prime {
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
