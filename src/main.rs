mod cache;
mod config;
mod field_acl;
mod gated;
mod handler;
mod registry;
mod sap_client;
mod tenant;
mod transport_http;
mod transport_stdio;
mod transport_ws;

use clap::Parser;
use handler::Handler;
use registry::Registry;
use sap_client::SapPool;

#[derive(Parser, Debug, Clone)]
#[command(name = "sa-mcp", version, about = "SAP MCP Server (Rust) - OData V2/V4 for S/4HANA: stdio | streamable-HTTP | SSE | WebSocket")]
struct Cli {
    /// Transport: stdio | http | sse | ws. `http` serves /mcp + /sse + /messages + /health.
    #[arg(long, default_value = "stdio", env = "MCP_TRANSPORT")]
    transport: String,
    /// Listen address for http/sse/ws.
    #[arg(long, default_value = "127.0.0.1:8788", env = "MCP_LISTEN")]
    listen: String,
    /// Validate SAP connectivity and exit.
    #[arg(long, default_value_t = false)]
    validate_config: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    load_dotenv_fallback();

    let cli = Cli::parse();
    let pool = SapPool::from_env()?;
    let registry = Registry::load();
    let handler = Handler::new(pool.clone(), registry);

    if cli.validate_config {
        println!("instances: {}", pool.describe_for_admin());
        for name in pool.instance_names() {
            let c = pool.get(&name)?;
            let ok = c.health_check().await;
            println!("- {name}: reachable={ok} v4={}", c.is_v4());
        }
        return Ok(());
    }

    match cli.transport.as_str() {
        "stdio" => transport_stdio::run_stdio(handler).await,
        "http" | "streamable-http" | "sse" => transport_http::run_http(handler, &cli.listen).await,
        "ws" | "websocket" => transport_ws::run_ws(handler, &cli.listen).await,
        other => anyhow::bail!("unknown transport '{other}' (use stdio|http|sse|ws)"),
    }
}

/// Minimal .env loader (no extra dependency): KEY=VALUE lines, skips # comments.
fn load_dotenv_fallback() {
    for path in [".env", ".config/sa-mcp.env"] {
        let Ok(txt) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in txt.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || !line.contains('=') {
                continue;
            }
            let (k, v) = line.split_once('=').unwrap();
            let k = k.trim().strip_prefix("export ").unwrap_or(k.trim()).trim();
            let mut v = v.trim().to_string();
            if (v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')) {
                v = v[1..v.len() - 1].to_string();
            }
            if std::env::var(k).is_err() {
                std::env::set_var(k, v);
            }
        }
    }
}
