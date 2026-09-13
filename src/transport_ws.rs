use crate::handler::Handler;
use crate::tenant::{bearer_from, resolve_tenant, Tenant};
use futures::{SinkExt, StreamExt};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

type WsReq = tokio_tungstenite::tungstenite::handshake::server::Request;
type WsRes = tokio_tungstenite::tungstenite::handshake::server::Response;

/// Standalone WebSocket server. Each connection gets its own loop;
/// speaks plain JSON-RPC text frames so Python `websockets` clients work.
/// The bearer (`Authorization` header or `?token=`) is resolved ONCE at
/// handshake into a Tenant bound to the whole connection.
pub async fn run_ws(handler: Handler, listen: &str) -> anyhow::Result<()> {
    crate::transport_http::require_local_or_opt_in(listen)?;
    let listener = TcpListener::bind(listen).await?;
    eprintln!("[sa-mcp] ws listening on {listen}");
    loop {
        let (stream, addr) = listener.accept().await?;
        let h = handler.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(h, stream).await {
                eprintln!("[sa-mcp] ws {addr} closed: {e}");
            }
        });
    }
}

fn auth_enabled() -> bool {
    std::env::var("MCP_AUTH_ENABLED")
        .map(|v| crate::config::env_truthy(&v))
        .unwrap_or(false)
}

/// Resolve the handshake bearer to a tenant. Unknown tokens are rejected
/// here (401) so no unauthenticated frame is ever processed.
fn ws_resolve(req: &WsReq, h: &Handler) -> Result<Tenant, String> {
    let uri = req.uri().to_string();
    let query = uri.split_once('?').map(|(_, q)| q).unwrap_or("");
    // axum HeaderMap and http HeaderMap are the same type (http 1.x).
    let token = bearer_from(req.headers(), query);
    resolve_tenant(token.as_deref(), auth_enabled(), &h.pool.instance_tokens())
}

async fn handle_conn(
    handler: Handler,
    stream: tokio::net::TcpStream,
) -> anyhow::Result<()> {
    // Capture the resolved tenant during the handshake so it stays bound
    // to the connection afterwards.
    let captured: Arc<Mutex<Option<Tenant>>> = Arc::new(Mutex::new(None));
    let cap = captured.clone();
    let h2 = handler.clone();
    // Caps: JSON-RPC tool calls are KB-scale; 4 MiB message / 1 MiB frame
    // backstops memory exhaustion from a malicious frame flood.
    let mut ws_cfg = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
    ws_cfg.max_message_size = Some(4 * 1024 * 1024);
    ws_cfg.max_frame_size = Some(1024 * 1024);
    let ws = tokio_tungstenite::accept_hdr_async_with_config(
        stream,
        move |req: &WsReq, res: WsRes| {
            match ws_resolve(req, &h2) {
                Ok(t) => {
                    *cap.lock().unwrap() = Some(t);
                    Ok(res)
                }
                Err(_) => Err(http::Response::builder()
                    .status(401)
                    .body(Some("unauthorized".to_string()))
                    .unwrap()),
            }
        },
        Some(ws_cfg),
    )
    .await?;
    let tenant = captured
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow::anyhow!("handshake tenant missing"))?;
    let (mut tx, mut rx) = ws.split();
    while let Some(msg) = rx.next().await {
        let msg = msg?;
        match msg {
            Message::Text(t) => {
                let req: serde_json::Value = match serde_json::from_str(&t) {
                    Ok(v) => v,
                    Err(e) => {
                        let err = serde_json::json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":format!("parse error: {e}")}});
                        tx.send(Message::Text(err.to_string().into())).await?;
                        continue;
                    }
                };
                if let Some(resp) = handler.handle(req, &tenant).await {
                    tx.send(Message::Text(resp.to_string().into())).await?;
                }
            }
            Message::Binary(b) => {
                // allow binary frames containing JSON too (python clients)
                if let Ok(t) = String::from_utf8(b.to_vec()) {
                    if let Ok(req) = serde_json::from_str::<serde_json::Value>(&t) {
                        if let Some(resp) = handler.handle(req, &tenant).await {
                            tx.send(Message::Text(resp.to_string().into())).await?;
                        }
                    }
                }
            }
            Message::Close(_) => break,
            Message::Ping(p) => tx.send(Message::Pong(p)).await?,
            _ => {}
        }
    }
    Ok(())
}
