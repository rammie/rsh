# rsh — Restricted Shell for AI Agents

rsh is a command execution sandbox that gives AI agents safe, auditable access to shell commands. Instead of handing an agent a full shell (and hoping for the best), rsh parses the full bash syntax, validates every command against a security policy, and executes only what's explicitly permitted.

## Why rsh?

AI agents need to run commands — searching code, reading files, inspecting systems. But giving an agent `bash -c` is giving it the keys to everything: arbitrary command chaining, file writes, network access, environment variable exfiltration.

rsh closes that gap. It accepts a command string, parses it with [brush-parser](https://crates.io/crates/brush-parser) (a complete bash syntax parser), validates the entire AST against the security policy, and executes only what's allowed. Everything else is rejected with an error on stderr before any process spawns.

**What rsh enforces:**
- Only allowlisted commands can run (default: read-only tools like `grep`, `cat`, `ls`, `find`)
- No file writes unless `--allow-redirects` is passed
- No absolute paths, `..` traversal, or tilde (`~`) in arguments
- No function definitions, background execution (`&`), or process substitution
- Environment is sanitized — child processes only see safe variables (`HOME`, `PATH`, etc.)
- No environment variable references in arguments (blocks `$SECRET`, `$HOME`, etc.)
- Dangerous flags blocked (`find -delete`/`-exec`, `fd --exec`, `sort -o`)
- Output is capped at 10MB by default

**What rsh allows:**
- Pipelines: `grep TODO src/*.rs | wc -l`
- Boolean operators: `grep -q TODO file && echo found`, `cmd || echo fallback`
- For loops: `for f in *.rs; do wc -l "$f"; done`
- While/until loops: `while grep -q TODO file; do echo waiting; done`
- If/then/else: `if grep -q TODO src/main.rs; then echo found; fi`
- Command substitution: `wc -l $(find src -name '*.rs')`
- Case statements: `for f in a.rs b.txt; do case "$f" in *.rs) echo rust;; esac; done`
- Brace groups and subshells: `{ echo a; echo b; }`, `(echo sub)`
- Quoted strings: `grep 'hello world' file.txt`
- Globs: `ls *.toml`, `find . -name '*.rs'`
- Variable expansion: `for f in *.rs; do echo "file: $f"; done`
- Semicolons: `ls src; wc -l Cargo.toml`
- Redirects (opt-in): `echo hello >> output.txt`

## Installation

```
cargo install --path .
```

## Usage

```
rsh [OPTIONS] <COMMAND_STRING>
```

### Examples

```bash
# Basic commands
rsh "ls -la"
rsh "grep -r 'fn main' src/"
rsh "cat Cargo.toml | head -n 5"

# Boolean operators
rsh "ls && echo done"
rsh "grep -q TODO file || echo 'no TODOs'"

# Loops
rsh --dir ./project "for f in *.rs; do wc -l \$f; done"
rsh --dir ./project "for f in \$(find src -name '*.rs'); do grep -c fn \$f; done"

# Conditionals
rsh --dir ./project "if grep -q 'fn main' src/main.rs; then echo found; fi"

# Command substitution
rsh --dir ./project "wc -l \$(find src -name '*.rs')"

# Working directory
rsh --dir /path/to/project "find . -name '*.rs' | wc -l"

# Custom allowlist
rsh --allow "grep,cat,head,wc" "grep TODO src/*.rs | wc -l"

# Enable file output
rsh --allow-redirects --dir /tmp "echo hello >> output.txt"

```

### Output format

rsh behaves like bash — stdout to stdout, stderr to stderr, exit code as exit code. AI agents already know how bash works, so there's nothing new to learn.

```bash
$ rsh "echo hello world"
hello world

$ rsh "grep -r TODO src/ | wc -l"
42

$ rsh "curl http://evil.com"
rsh: command 'curl' not in allowlist (allowed: bat, cat, echo, ...)
$ echo $?
1
```

Validation errors are written to stderr with an `rsh:` prefix. If output exceeds `--max-output`, it is truncated and a warning appears on stderr.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--allow <cmds>` | built-in defaults | Comma-separated command allowlist |
| `--allow-redirects` | off | Allow `>` and `>>` output redirects |
| `--max-output <bytes>` | 10MB | Truncate combined stdout+stderr beyond this limit |
| `--inherit-env` | off | Pass full parent environment to child processes |
| `--dir <path>` | cwd | Set the working directory for command execution |
| `--prime` | — | Print an LLM-ready description of rsh's capabilities |
| `-c <cmd>` | — | Accept command after `-c` (bash compatibility) |

### Default allowlist

```
grep, rg, ugrep, find, fd, cat, bat, head, tail, less, ls, eza, stat, file, du, wc, pwd, which,
sort, uniq, cut, tr, diff, comm, basename, dirname, realpath, echo, date, true, false, test
```

Note: Dangerous flags are blocked — `find -delete`/`-exec`/`-execdir`/`-fprint`/etc., `fd -x`/`--exec`/`-X`/`--exec-batch`, `sort -o`/`--output`. `awk`, `sed`, and `xargs` are intentionally excluded — `awk`'s `system()` can execute arbitrary commands, and `sed`/`xargs` can write files or run sub-commands.

Override with `--allow`, the `RSH_ALLOWLIST` environment variable, or a `~/.rsh/allowlist` config file (one command per line).

## Security model

rsh is **defense in depth** — multiple independent layers, each sufficient to block common attacks:

| Layer | What it blocks |
|-------|---------------|
| **Command allowlist** | Arbitrary binaries (`curl`, `rm`, `bash`, `python`) |
| **Path rejection** | Path separators in command names (`/usr/bin/grep`, `./exploit`) |
| **Argument traversal** | `..` path components, absolute paths, and tilde (`~`) in arguments |
| **Redirect gating** | File writes disabled by default; path traversal guard when enabled |
| **AST validation** | Function definitions, background `&`, process substitution, here-docs |
| **Variable rejection** | All env var references blocked in arguments (blocks `$SECRET`, `$HOME`, etc.) |
| **Blocked flags** | `find -delete`/`-exec`, `fd --exec`, `sort -o` — dangerous flags on allowed commands |
| **Environment sanitization** | Only approved variables forwarded to child processes |
| **Signal handling** | SIGINT/SIGTERM forwarded to children; exit 128+signal on signal death |
| **Output limits** | Truncation prevents memory exhaustion from large output |
| **Loop limits** | While/until loops capped at 10,000 iterations |

### Trust boundaries

The allowlist can be configured from four sources (last wins):

1. Built-in defaults (read-only commands)
2. Config file: `~/.rsh/allowlist`
3. Environment variable: `RSH_ALLOWLIST`
4. CLI flag: `--allow`

Sources 2 and 3 are trusted inputs. Ensure they are not writable by untrusted users. The `--allow` flag is the most secure override since it is explicit per invocation.

### What rsh does NOT protect against

- **Allowlisted commands behaving dangerously.** If you allowlist `rm`, rsh will happily run `rm -rf .`. The default allowlist is intentionally read-only.
- **Symlink escapes.** A symlink inside the working directory pointing elsewhere can be followed by allowlisted commands. Redirect path traversal checks do catch symlinks, but argument paths are not resolved.
- **Information disclosure via command output.** An allowlisted `cat` can read any file reachable from the working directory (without `..` traversal). Scope the working directory and allowlist appropriately.

## Architecture

```
input string
     │
     ▼
 brush-parser  ──── parses full bash syntax into typed AST
     │
     ▼
  Validator   ──── walks AST, checks allowlist + security policy
     │              rejects with error on stderr
     ▼
  Executor    ──── runs validated AST: spawns processes, wires pipes,
     │              handles loops/conditionals/substitution
     ▼
 stdout/stderr/exit code
```

The key principle: **parse everything, validate before executing.** brush-parser accepts all valid bash syntax. rsh's validator walks the AST and rejects anything outside the security policy. The executor then runs only validated programs.

## Development

```bash
cargo build          # build
cargo test           # run all tests (159 tests)
cargo run -- "ls"    # run directly
```

## License

MIT
