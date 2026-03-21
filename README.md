# rsh — Restricted Shell for AI Agents

rsh is a command execution sandbox that gives AI agents safe, auditable access to shell commands. Instead of handing an agent a full shell (and hoping for the best), rsh parses and executes a restricted subset of shell syntax with enforced security boundaries.

## Why rsh?

AI agents need to run commands — searching code, reading files, inspecting systems. But giving an agent `bash -c` is giving it the keys to everything: arbitrary command chaining, file writes, network access, environment variable exfiltration.

rsh closes that gap. It accepts a command string, parses it with a purpose-built recursive descent parser (not bash), and executes only what's explicitly permitted. Everything else is rejected with a structured JSON error before any process spawns.

**What rsh enforces:**
- Only allowlisted commands can run (default: read-only tools like `grep`, `cat`, `ls`, `find`)
- No `&&`, `||`, backticks, `$()`, subshells, or shell keywords (`if`, `eval`, `for`, ...)
- No file writes unless `--allow-redirects` is passed
- No absolute paths or `..` traversal in arguments unless opted in
- Environment is sanitized — child processes only see safe variables (`HOME`, `PATH`, etc.)
- Commands time out after 30 seconds by default
- Output is capped at 10MB by default

**What rsh allows:**
- Pipelines: `grep TODO src/*.rs | wc -l`
- Quoted strings: `grep 'hello world' file.txt`
- Globs: `ls *.toml`, `find . -name '*.rs'`
- Variable expansion: `echo $HOME`, `echo "path is $PWD"`
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

# Working directory
rsh --dir /path/to/project "find . -name '*.rs' | wc -l"

# Custom allowlist
rsh --allow "grep,cat,head,wc" "grep TODO src/*.rs | wc -l"

# Enable file output
rsh --allow-redirects --dir /tmp "echo hello >> output.txt"

# Longer timeout for slow commands
rsh --timeout 120 "find . -name '*.log'"
```

### Output format

rsh always outputs structured JSON:

```json
{
  "stdout": "hello world\n",
  "stderr": "",
  "exit_code": 0,
  "commands": ["echo"],
  "error": null
}
```

On failure, `error` contains the reason and no commands are executed:

```json
{
  "stdout": "",
  "stderr": "",
  "exit_code": 1,
  "commands": [],
  "error": "command 'curl' not in allowlist (allowed: bat, cat, echo, ...)"
}
```

If output exceeds `--max-output`, it is truncated and a `"truncated": true` field appears.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--allow <cmds>` | built-in defaults | Comma-separated command allowlist |
| `--allow-absolute` | off | Allow absolute paths in arguments, globs, and redirects |
| `--allow-redirects` | off | Allow `>` and `>>` output redirects |
| `--max-output <bytes>` | 10MB | Truncate combined stdout+stderr beyond this limit |
| `--timeout <secs>` | 30 | Kill commands that exceed this duration |
| `--inherit-env` | off | Pass full parent environment to child processes |
| `--dir <path>` | cwd | Set the working directory for command execution |

### Default allowlist

```
grep, rg, ugrep, find, fd, cat, bat, head, tail, ls, eza, wc, echo, stat, pwd
```

Override with `--allow`, the `RSH_ALLOWLIST` environment variable, or a `~/.rsh/allowlist` config file (one command per line).

## Security model

rsh is **defense in depth** — multiple independent layers, each sufficient to block common attacks:

| Layer | What it blocks |
|-------|---------------|
| **Command allowlist** | Arbitrary binaries (`curl`, `rm`, `bash`, `python`) |
| **Path rejection** | Path separators in command names (`/usr/bin/grep`, `./exploit`) |
| **Argument traversal** | `..` path components and absolute paths in arguments |
| **Redirect gating** | File writes disabled by default; path traversal guard when enabled |
| **Parser restrictions** | `&&`, `\|\|`, backticks, `$()`, subshells, keywords |
| **Environment sanitization** | Only approved variables forwarded to child processes |
| **Execution timeout** | Runaway or hanging commands killed after deadline |
| **Output limits** | Truncation prevents memory exhaustion from large output |

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
  Parser  ──── rejects: &&, ||, $(), backticks, subshells, <, &
     │
     ▼
    AST   ──── Program { pipelines: [Pipeline { commands: [Command { name, args, redirects }] }] }
     │
     ▼
 Executor
  ├─ validate()  ──── allowlist, redirect gating, variable approval, pipeline redirect position
  ├─ expand()    ──── glob expansion, variable expansion, path traversal checks
  └─ execute()   ──── spawn with sanitized env, pipe wiring, timeout, output capture
     │
     ▼
 JSON output
```

## Development

```bash
cargo build          # build
cargo test           # run all tests (52 tests)
cargo run -- "ls"    # run directly
```

## License

MIT
