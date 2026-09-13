use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

pub const APPROVAL_TTL_SECS: u64 = 600;
pub const TOKEN_PREFIX: &str = "sap-write:";

/// Recursively sort object keys so token is deterministic across Python/JS/Rust.
pub fn canonical_json(v: &serde_json::Value) -> String {
    canonical(v).to_string()
}

fn canonical(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), canonical(&m[k]));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(a) => {
            serde_json::Value::Array(a.iter().map(canonical).collect())
        }
        serde_json::Value::Number(n) => {
            // normalize integral floats (python/js compat): 3.0 -> 3
            if let Some(f) = n.as_f64() {
                if f.fract() == 0.0 && f.is_finite() && f.abs() < 9e15 {
                    return serde_json::Value::Number(
                        serde_json::Number::from(f as i64),
                    );
                }
            }
            v.clone()
        }
        _ => v.clone(),
    }
}

pub fn build_approval_token(payload: &serde_json::Value) -> String {
    let c = canonical_json(payload);
    let mut h = Sha256::new();
    h.update(c.as_bytes());
    let hex = hex::encode(h.finalize());
    format!("{}{}", TOKEN_PREFIX, &hex[..32])
}

pub fn token_digest(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    let hex = hex::encode(h.finalize());
    hex[..16].to_string()
}

struct Entry {
    payload: serde_json::Value,
    expires_at: Instant,
}

#[derive(Clone, Default)]
pub struct ApprovalStore {
    inner: Arc<RwLock<HashMap<String, Entry>>>,
    ttl: Duration,
}

impl ApprovalStore {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    pub fn register(&self, token: String, payload: serde_json::Value) {
        self.sweep();
        let mut m = self.inner.write().unwrap();
        m.insert(
            token,
            Entry {
                payload,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }

    /// Verify token matches payload AND is registered AND not expired.
    /// Does NOT consume. Use `consume` on execute.
    pub fn is_valid(&self, token: &str, payload: &serde_json::Value) -> bool {
        self.sweep();
        let m = self.inner.read().unwrap();
        match m.get(token) {
            Some(e) => e.expires_at > Instant::now() && e.payload == *payload,
            None => false,
        }
    }

    /// Single-use consume: returns true only once.
    pub fn consume(&self, token: &str, payload: &serde_json::Value) -> bool {
        self.sweep();
        let mut m = self.inner.write().unwrap();
        match m.get(token) {
            Some(e) if e.expires_at > Instant::now() && e.payload == *payload => {
                m.remove(token);
                true
            }
            _ => false,
        }
    }

    fn sweep(&self) {
        let now = Instant::now();
        if let Ok(mut m) = self.inner.write() {
            m.retain(|_, e| e.expires_at > now);
        }
    }
}

/// Append one JSONL line per write-path event. Fail-open with stderr warning
/// (mirrors erpipe audit behavior). `actor` is the tenant id (token digest),
/// so multi-tenant writes are attributable.
// 8 params by design: one fixed audit schema, no good grouping.
#[allow(clippy::too_many_arguments)]
pub fn audit(event: &str, actor: &str, instance: &str, model: &str, operation: &str, token: &str, ok: bool, detail: &str) {
    let Some(path) = crate::config::audit_log_path() else {
        return;
    };
    let line = serde_json::json!({
        "ts": Utc::now().to_rfc3339(),
        "event": event,
        "actor": actor,
        "instance": instance,
        "model": model,
        "operation": operation,
        "token_digest": token_digest(token),
        "ok": ok,
        "detail": detail,
    });
    let mut s = line.to_string();
    s.push('\n');
    if let Err(e) = append_line(&path, &s) {
        eprintln!("[sa-mcp] audit append failed ({path}): {e}");
    }
}

fn append_line(path: &str, line: &str) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(line.as_bytes())?;
    Ok(())
}
