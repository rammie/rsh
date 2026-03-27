/// Handle `rsh --install claude`: register MCP server and install SessionStart hook.
use serde_json::{Value, json};

fn read_json_file(path: &std::path::Path) -> Value {
    match std::fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_else(|e| {
            eprintln!("error: failed to parse {}: {}", path.display(), e);
            std::process::exit(1);
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => json!({}),
        Err(e) => {
            eprintln!("error: failed to read {}: {}", path.display(), e);
            std::process::exit(1);
        }
    }
}

fn write_json_file(path: &std::path::Path, value: &Value) {
    let json_str = serde_json::to_string_pretty(value).unwrap();
    if let Err(e) = std::fs::write(path, format!("{}\n", json_str)) {
        eprintln!("error: failed to write {}: {}", path.display(), e);
        std::process::exit(1);
    }
}

fn install_mcp_server(project_root: &std::path::Path, allow_redirects: bool, inherit_env: bool) {
    let mcp_path = project_root.join(".mcp.json");

    let mut args = vec!["--mcp".to_string()];
    if allow_redirects {
        args.push("--allow-redirects".to_string());
    }
    if inherit_env {
        args.push("--inherit-env".to_string());
    }

    let rsh_entry = json!({
        "command": "rsh",
        "args": args
    });

    let mut config = read_json_file(&mcp_path);

    let Some(root) = config.as_object_mut() else {
        eprintln!("error: {} must contain a JSON object", mcp_path.display());
        std::process::exit(1);
    };
    let servers = root.entry("mcpServers").or_insert_with(|| json!({}));
    let Some(servers) = servers.as_object_mut() else {
        eprintln!(
            "error: mcpServers in {} must be a JSON object",
            mcp_path.display()
        );
        std::process::exit(1);
    };
    servers.insert("rsh".to_string(), rsh_entry);

    write_json_file(&mcp_path, &config);
    eprintln!("  MCP server: {}", mcp_path.display());
}

fn install_session_hook(project_root: &std::path::Path) {
    let claude_dir = project_root.join(".claude");
    if let Err(e) = std::fs::create_dir_all(&claude_dir) {
        eprintln!("error: failed to create .claude directory: {}", e);
        std::process::exit(1);
    }

    let settings_path = claude_dir.join("settings.local.json");
    let mut settings = read_json_file(&settings_path);

    let Some(root) = settings.as_object_mut() else {
        eprintln!(
            "error: {} must contain a JSON object",
            settings_path.display()
        );
        std::process::exit(1);
    };
    let hooks = root.entry("hooks").or_insert_with(|| json!({}));
    let Some(hooks) = hooks.as_object_mut() else {
        eprintln!(
            "error: hooks in {} must be a JSON object",
            settings_path.display()
        );
        std::process::exit(1);
    };
    let session_start = hooks.entry("SessionStart").or_insert_with(|| json!([]));
    let Some(arr) = session_start.as_array_mut() else {
        eprintln!(
            "error: SessionStart in {} must be an array",
            settings_path.display()
        );
        std::process::exit(1);
    };

    // Dedup: don't add a second hook if one already exists
    let already_exists = arr.iter().any(|entry| {
        entry
            .get("hooks")
            .and_then(|h| h.as_array())
            .is_some_and(|hooks_arr| {
                hooks_arr.iter().any(|hook| {
                    hook.get("command")
                        .and_then(|c| c.as_str())
                        .is_some_and(|c| c.contains("rsh --prime"))
                })
            })
    });

    if !already_exists {
        arr.push(json!({
            "matcher": "",
            "hooks": [{"type": "command", "command": "rsh --prime"}]
        }));
    }

    write_json_file(&settings_path, &settings);
    eprintln!("  SessionStart hook: {}", settings_path.display());
}

pub fn install_claude(working_dir: Option<&str>, allow_redirects: bool, inherit_env: bool) {
    let start_dir = crate::resolve_working_dir(working_dir);
    let project_root = crate::find_git_root(&start_dir).unwrap_or(start_dir);

    eprintln!("Installing rsh for Claude Code:");
    install_mcp_server(&project_root, allow_redirects, inherit_env);
    install_session_hook(&project_root);
    std::process::exit(0);
}
