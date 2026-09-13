use crate::handler::Handler;
use crate::tenant::Tenant;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Cursor/Python-compatible stdio: accept plain JSON-RPC (no `type` field required),
/// log to stderr so stdout stays clean.
/// stdio is a local, single-operator transport: full access (all instances).
pub async fn run_stdio(handler: Handler) -> anyhow::Result<()> {
    let tenant = Tenant::Full { id: "local".to_string() };
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();
    eprintln!("[sa-mcp] stdio transport ready (server={})", handler.server_name());
    while let Some(line) = reader.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                let resp = json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":format!("parse error: {e}")}});
                stdout.write_all(format!("{}\n", resp).as_bytes()).await?;
                stdout.flush().await?;
                continue;
            }
        };
        // support batch
        if let Some(arr) = req.as_array() {
            let mut out = vec![];
            for r in arr {
                if let Some(resp) = handler.handle(r.clone(), &tenant).await {
                    out.push(resp);
                }
            }
            if !out.is_empty() {
                stdout.write_all(format!("{}\n", Value::Array(out)).as_bytes()).await?;
                stdout.flush().await?;
            }
            continue;
        }
        if let Some(resp) = handler.handle(req, &tenant).await {
            stdout.write_all(format!("{}\n", resp).as_bytes()).await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}
