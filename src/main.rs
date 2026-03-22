mod allowlist;
mod executor;
mod glob;
mod validator;

use executor::Executor;

fn usage() {
    eprintln!("Usage: rsh [OPTIONS] <COMMAND_STRING>");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --allow <cmds>      Comma-separated allowlist (overrides defaults)");
    eprintln!("  --allow-absolute    Allow absolute paths in arguments, globs, and redirects");
    eprintln!("  --allow-redirects   Allow output redirects (> and >>)");
    eprintln!("  --max-output <n>    Max output bytes (default: 10485760 = 10MB)");
    eprintln!("  --timeout <secs>    Execution timeout in seconds (default: 30)");
    eprintln!("  --inherit-env       Inherit full parent environment (default: sanitized)");
    eprintln!("  --dir <path>        Working directory (default: cwd)");
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
    let mut allow_absolute = false;
    let mut allow_redirects = false;
    let mut max_output: usize = 10 * 1024 * 1024; // 10MB
    let mut timeout_secs: u64 = 30;
    let mut inherit_env = false;
    let mut working_dir: Option<String> = None;
    let mut command_string: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => usage(),
            "--allow" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --allow requires a value");
                    std::process::exit(2);
                }
                allow_flag = Some(args[i].clone());
            }
            "--allow-absolute" => {
                allow_absolute = true;
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
            "--timeout" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --timeout requires a value");
                    std::process::exit(2);
                }
                timeout_secs = args[i].parse().unwrap_or_else(|_| {
                    eprintln!("error: --timeout must be a positive integer");
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
    let al = allowlist::Allowlist::load(allow_flag.as_deref());
    let executor = Executor::new(
        al,
        working_dir,
        allow_absolute,
        allow_redirects,
        max_output,
        timeout_secs,
        inherit_env,
    );
    let output = executor.execute(&program);
    print!("{}", output.stdout);
    eprint!("{}", output.stderr);
    std::process::exit(output.exit_code);
}
