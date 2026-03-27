/// Handle `rsh --install claude`: write/merge .mcp.json with the rsh MCP server entry.
use serde_json::{json, Value};

pub fn install_claude(
    working_dir: Option<&str>,
    allow_redirects: bool,
    inherit_env: bool,
) {
    let start_dir = crate::resolve_working_dir(working_dir);
    let project_root = crate::find_git_root(&start_dir).unwrap_or(start_dir);
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

    let mut config: Value = match std::fs::read_to_string(&mcp_path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_else(|e| {
            eprintln!("error: failed to parse {}: {}", mcp_path.display(), e);
            std::process::exit(1);
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => json!({}),
        Err(e) => {
            eprintln!("error: failed to read {}: {}", mcp_path.display(), e);
            std::process::exit(1);
        }
    };

    let Some(root) = config.as_object_mut() else {
        eprintln!("error: {} must contain a JSON object", mcp_path.display());
        std::process::exit(1);
    };
    let servers = root.entry("mcpServers").or_insert_with(|| json!({}));
    let Some(servers) = servers.as_object_mut() else {
        eprintln!("error: mcpServers in {} must be a JSON object", mcp_path.display());
        std::process::exit(1);
    };
    servers.insert("rsh".to_string(), rsh_entry);

    let json_str = serde_json::to_string_pretty(&config).unwrap();
    if let Err(e) = std::fs::write(&mcp_path, format!("{}\n", json_str)) {
        eprintln!("error: failed to write {}: {}", mcp_path.display(), e);
        std::process::exit(1);
    }

    eprintln!("Installed rsh MCP server in {}", mcp_path.display());
    std::process::exit(0);
}
