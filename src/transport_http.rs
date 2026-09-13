use crate::handler::Handler;
use crate::tenant::{bearer_from, resolve_tenant, Tenant};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response, Sse},
    routing::{get, post},
    Json, Router,
};
use futures::stream::StreamExt;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use uuid::Uuid;

type SessionVal = (String, std::time::Instant, Tenant); // (version, created, tenant)

#[derive(Clone)]
pub struct AppState {
    pub handler: Handler,
    // session_id -> (protocol version, created_at, bound tenant). Swept on
    // insert (24h TTL) so abandoned sessions (no DELETE) can't leak memory.
    // The tenant is bound at initialize: later calls on the session use the
    // BOUND tenant, so a swapped token mid-session gains nothing.
    pub sessions: Arc<RwLock<HashMap<String, SessionVal>>>,
    pub sse_tx: Arc<RwLock<HashMap<String, broadcast::Sender<String>>>>,
    // legacy SSE sid -> bound tenant (channel created at GET /sse).
    pub sse_tenant: Arc<RwLock<HashMap<String, Tenant>>>,
}

const SESSION_TTL: Duration = Duration::from_secs(24 * 3600);
const MAX_SESSIONS: usize = 2048;

fn insert_session(st: &AppState, id: String, version: String, tenant: Tenant) {
    let now = std::time::Instant::now();
    {
        let mut sessions = st.sessions.write().unwrap();
        sessions.retain(|_, (_, at, _)| now.duration_since(*at) < SESSION_TTL);
        // Hard cap as backstop: drop oldest-ish entries if still overfull.
        if sessions.len() >= MAX_SESSIONS {
            let ids: Vec<String> = sessions
                .iter()
                .filter(|(_, (_, at, _))| now.duration_since(*at) > Duration::from_secs(3600))
                .map(|(k, _)| k.clone())
                .collect();
            for k in ids {
                sessions.remove(&k);
            }
        }
        sessions.insert(id.clone(), (version, now, tenant));
    }
    // Drop orphaned SSE channels for sessions that no longer exist.
    {
        let sessions = st.sessions.read().unwrap();
        st.sse_tx.write().unwrap().retain(|k, _| sessions.contains_key(k));
    }
}

/// Resolve the caller for HTTP endpoints. Query string is passed for
/// `?token=` support (legacy SSE + Python clients).
fn resolve_http_tenant(
    st: &AppState,
    headers: &HeaderMap,
    raw_query: &str,
) -> Result<Tenant, Response> {
    let token = bearer_from(headers, raw_query);
    resolve_tenant(
        token.as_deref(),
        auth_enabled(),
        &st.handler.pool.instance_tokens(),
    )
    .map_err(|e| (StatusCode::UNAUTHORIZED, e).into_response())
}

fn auth_enabled() -> bool {
    std::env::var("MCP_AUTH_ENABLED")
        .map(|v| crate::config::env_truthy(&v))
        .unwrap_or(false)
}

fn check_origin(headers: &HeaderMap) -> Result<(), Response> {
    // opt-in allowlist; localhost always allowed; missing Origin allowed (non-browser clients incl. Python)
    let Ok(cfg) = std::env::var("MCP_ALLOWED_ORIGINS") else {
        return Ok(());
    };
    if cfg.trim().is_empty() {
        return Ok(());
    }
    let allowed: Vec<String> = cfg.split(',').map(|s| s.trim().to_string()).collect();
    let origin = headers.get("origin").and_then(|v| v.to_str().ok()).unwrap_or("");
    if origin.is_empty() {
        return Ok(());
    }
    if origin.contains("localhost") || origin.contains("127.0.0.1") || origin.contains("[::1]") {
        return Ok(());
    }
    if allowed.iter().any(|a| origin.contains(a) || a == "*") {
        return Ok(());
    }
    Err((StatusCode::FORBIDDEN, "origin not allowed").into_response())
}

pub fn router(handler: Handler) -> Router {
    let st = AppState {
        handler,
        sessions: Arc::new(RwLock::new(HashMap::new())),
        sse_tx: Arc::new(RwLock::new(HashMap::new())),
        sse_tenant: Arc::new(RwLock::new(HashMap::new())),
    };
    Router::new()
        .route("/mcp", post(mcp_post).get(mcp_get).delete(mcp_delete))
        .route("/sse", get(legacy_sse))
        .route("/messages", post(legacy_messages))
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/openapi.json", get(openapi))
        .with_state(st)
}

async fn mcp_post(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if let Err(r) = check_origin(&headers) {
        return r;
    }
    let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let sid = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    // handle initialize -> resolve tenant from bearer, mint session bound to it
    if method == "initialize" {
        let tenant = match resolve_http_tenant(&st, &headers, "") {
            Ok(t) => t,
            Err(r) => return r,
        };
        let resp = st.handler.handle(body, &tenant).await;
        let resp = resp.unwrap_or(json!({"jsonrpc":"2.0","id":null,"result":{}}));
        let session_id = Uuid::new_v4().to_string();
        insert_session(&st, session_id.clone(), "2025-11-05".into(), tenant);
        let (tx, _) = broadcast::channel::<String>(256);
        st.sse_tx.write().unwrap().insert(session_id.clone(), tx);
        return (
            StatusCode::OK,
            [("MCP-Session-Id", session_id), ("MCP-Protocol-Version", "2025-11-05".to_string())],
            Json(resp),
        )
            .into_response();
    }
    // Non-initialize: session must exist; the BOUND tenant applies
    // (a different token presented here gains nothing).
    let tenant = match sid.as_deref() {
        Some(s) => match st.sessions.read().unwrap().get(s) {
            Some((_, _, t)) => t.clone(),
            None => return (StatusCode::BAD_REQUEST, "unknown session").into_response(),
        },
        None => match resolve_http_tenant(&st, &headers, "") {
            // Stateless (sessionless) POST: resolve caller per request.
            Ok(t) => t,
            Err(r) => return r,
        },
    };
    match st.handler.handle(body, &tenant).await {
        Some(resp) => {
            // broadcast to SSE listeners
            if let Some(ref s) = sid {
                if let Some(tx) = st.sse_tx.read().unwrap().get(s) {
                    let _ = tx.send(resp.to_string());
                }
                return ([("MCP-Session-Id", s.clone())], Json(resp)).into_response();
            }
            Json(resp).into_response()
        }
        None => StatusCode::ACCEPTED.into_response(),
    }
}

async fn mcp_get(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = check_origin(&headers) {
        return r;
    }
    let sid = headers.get("mcp-session-id").and_then(|v| v.to_str().ok()).unwrap_or("");
    // Session must exist; the stream only carries that session's events.
    if !st.sessions.read().unwrap().contains_key(sid) {
        return (StatusCode::BAD_REQUEST, "unknown session, POST initialize first").into_response();
    }
    let rx = st.sse_tx.read().unwrap().get(sid).map(|tx| tx.subscribe());
    let Some(rx) = rx else {
        return (StatusCode::BAD_REQUEST, "unknown session, POST initialize first").into_response();
    };
    let stream = BroadcastStream::new(rx)
        .filter_map(|m| async move { m.ok() })
        .map(|msg| Ok::<_, Infallible>(axum::response::sse::Event::default().data(msg)));
    // keepalive every 15s
    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::new().interval(Duration::from_secs(15))).into_response()
}

async fn mcp_delete(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let sid = headers.get("mcp-session-id").and_then(|v| v.to_str().ok()).unwrap_or("");
    st.sessions.write().unwrap().remove(sid);
    st.sse_tx.write().unwrap().remove(sid);
    st.sse_tenant.write().unwrap().remove(sid);
    StatusCode::NO_CONTENT.into_response()
}

async fn legacy_sse(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let tenant = match resolve_http_tenant(&st, &headers, "") {
        Ok(t) => t,
        Err(r) => return r,
    };
    let session_id = Uuid::new_v4().to_string();
    let (tx, rx) = broadcast::channel::<String>(256);
    st.sse_tx.write().unwrap().insert(session_id.clone(), tx);
    st.sse_tenant.write().unwrap().insert(session_id.clone(), tenant);
    let endpoint = format!("/messages?sessionId={}", session_id);
    let init = futures::stream::once(async move {
        Ok::<_, Infallible>(axum::response::sse::Event::default().event("endpoint").data(endpoint))
    });
    let rest = BroadcastStream::new(rx)
        .filter_map(|m| async move { m.ok() })
        .map(|msg| Ok::<_, Infallible>(axum::response::sse::Event::default().data(msg)));
    Sse::new(init.chain(rest)).into_response()
}

async fn legacy_messages(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    let sid = q.get("sessionId").cloned().unwrap_or_default();
    if !st.sse_tx.read().unwrap().contains_key(&sid) {
        return (StatusCode::BAD_REQUEST, "unknown session, GET /sse first").into_response();
    }
    // Bound tenant from channel creation; falls back to presented token only
    // if the binding was lost (e.g. after a restart).
    let tenant = st
        .sse_tenant
        .read()
        .unwrap()
        .get(&sid)
        .cloned()
        .or_else(|| resolve_http_tenant(&st, &headers, "").ok());
    let Some(tenant) = tenant else {
        return (StatusCode::UNAUTHORIZED, "unknown token").into_response();
    };
    let resp = st.handler.handle(body, &tenant).await;
    if let Some(r) = resp {
        if let Some(tx) = st.sse_tx.read().unwrap().get(&sid) {
            let _ = tx.send(r.to_string());
        }
    }
    StatusCode::ACCEPTED.into_response()
}

async fn health(State(st): State<AppState>, headers: HeaderMap) -> Response {
    // Open (probe-friendly) minimal surface: counts only, no URLs/names.
    // Present a valid bearer for the full tenant-scoped view.
    let tenant = resolve_http_tenant(&st, &headers, "").ok();
    let count = st.handler.pool.instance_names().len();
    let mut doc = json!({
        "status": if count > 0 { "ok" } else { "degraded" },
        "version": env!("CARGO_PKG_VERSION"),
        "instance_count": count,
        "writes_enabled": crate::config::writes_enabled(),
        "field_acl": st.handler.acl.status(),
    });
    if let Some(t) = tenant {
        doc["instances"] = st.handler.pool.describe_for(&t);
        doc["rate"] = st.handler.limiter.snapshot();
    }
    Json(doc).into_response()
}

async fn metrics(State(st): State<AppState>) -> Response {
    // Prometheus text (ala sap-for-agents /metrics): op counters + sessions.
    // Non-secret by design (no instance URLs, no tokens).
    let snap: Vec<Value> = serde_json::from_value(st.handler.metrics_snapshot()).unwrap_or_default();
    let mut out = String::from("# HELP samcp_tool_calls_total MCP tool calls by op\n# TYPE samcp_tool_calls_total counter\n");
    for e in &snap {
        out.push_str(&format!(
            "samcp_tool_calls_total{{op=\"{}\"}} {}\n",
            e.get("op").and_then(|o| o.as_str()).unwrap_or("?"),
            e.get("calls").and_then(|c| c.as_u64()).unwrap_or(0)
        ));
    }
    let sessions = st.sessions.read().unwrap().len();
    out.push_str("# HELP samcp_sessions_active Active MCP sessions\n# TYPE samcp_sessions_active gauge\n");
    out.push_str(&format!("samcp_sessions_active {sessions}\n"));
    ([("content-type", "text/plain; version=0.0.4")], out).into_response()
}

async fn openapi() -> Response {
    Json(json!({
        "openapi": "3.0.0",
        "info": {"title": "sa-mcp", "version": env!("CARGO_PKG_VERSION")},
        "paths": {
            "/mcp": {"post": {"summary": "Streamable HTTP JSON-RPC"}, "get": {"summary": "SSE stream"}, "delete": {"summary": "Terminate session"}},
            "/sse": {"get": {"summary": "Legacy SSE"}},
            "/messages": {"post": {"summary": "Legacy SSE messages"}},
            "/health": {"get": {"summary": "Health check"}}
        }
    }))
    .into_response()
}

pub async fn run_http(handler: Handler, listen: &str) -> anyhow::Result<()> {
    require_local_or_opt_in(listen)?;
    let app = router(handler)
        // 2 MiB JSON cap: tool args are small; blocks oversized-payload DoS.
        // (Note: no blanket response timeout — SSE streams are long-lived by
        // design; Odoo calls already carry per-instance timeout_ms.)
        .layer(tower_http::limit::RequestBodyLimitLayer::new(2 * 1024 * 1024))
        // Global concurrent-request backstop (per-tenant fairness is rate_limit).
        .layer(tower::limit::ConcurrencyLimitLayer::new(128))
        .layer(tower_http::set_header::SetResponseHeaderLayer::if_not_present(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            axum::http::HeaderValue::from_static("nosniff"),
        ))
        .layer(tower_http::cors::CorsLayer::permissive());
    let listener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!("[sa-mcp] http listening on {listen} (/mcp, /sse, /messages, /health)");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Refuse non-loopback binds unless explicitly opted in. A remote-exposed MCP
/// endpoint without TLS/auth in front is a credential-theft waiting to happen
/// (mirrors erpipe MCP_ALLOW_REMOTE_HTTP).
pub(crate) fn require_local_or_opt_in(listen: &str) -> anyhow::Result<()> {
    let host = listen.rsplit(':').nth(1).unwrap_or(listen).trim_matches(['[', ']']);
    let local = host == "127.0.0.1" || host == "localhost" || host == "::1";
    if !local
        && !std::env::var("MCP_ALLOW_REMOTE_HTTP")
            .map(|v| crate::config::env_truthy(&v))
            .unwrap_or(false)
    {
        anyhow::bail!(
            "refusing non-local bind '{listen}': set MCP_ALLOW_REMOTE_HTTP=1 (and put TLS + auth in front)"
        );
    }
    Ok(())
}
