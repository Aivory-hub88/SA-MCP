use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Caller identity for multi-tenant isolation.
///
/// - `Full` (stdio, auth-disabled HTTP, or global admin token): all instances.
/// - `Restricted { id, instances }`: may use ONLY the listed instances.
///   `id` is a non-secret label (`t` + token digest prefix) used in audit logs.
#[derive(Debug, Clone)]
pub enum Tenant {
    Full { id: String },
    Restricted { id: String, instances: HashSet<String> },
}

impl Tenant {
    pub fn id(&self) -> &str {
        match self {
            Tenant::Full { id } => id,
            Tenant::Restricted { id, .. } => id,
        }
    }

    /// Choke point: every op resolves its instance through here.
    pub fn check(&self, instance: &str) -> Result<(), String> {
        match self {
            Tenant::Full { .. } => Ok(()),
            Tenant::Restricted { id, instances } => {
                if instances.contains(instance) {
                    Ok(())
                } else {
                    Err(format!("tenant '{id}' has no access to instance '{instance}'"))
                }
            }
        }
    }

    /// Visible instance list for list_instances / resources.
    pub fn filter<'a, I>(&self, names: I) -> Vec<String>
    where
        I: IntoIterator<Item = &'a String>,
    {
        match self {
            Tenant::Full { .. } => names.into_iter().cloned().collect(),
            Tenant::Restricted { instances, .. } => names
                .into_iter()
                .filter(|n| instances.contains(*n))
                .cloned()
                .collect(),
        }
    }

    /// Default instance for resource reads: pool default if allowed,
    /// else first allowed instance (sorted for determinism).
    pub fn resource_default(&self, pool_default: &str) -> Option<String> {
        match self {
            Tenant::Full { .. } => Some(pool_default.to_string()),
            Tenant::Restricted { instances, .. } => {
                if instances.contains(pool_default) {
                    return Some(pool_default.to_string());
                }
                let mut v: Vec<&String> = instances.iter().collect();
                v.sort();
                v.into_iter().next().cloned()
            }
        }
    }
}

pub fn digest_token(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    format!("t-{}", &hex::encode(h.finalize())[..12])
}

/// Resolve a caller from a bearer token against instance configs:
/// - token listed in an instance's `mcp_tokens` => Restricted to exactly those.
/// - equals global MCP_AUTH_TOKEN (when set) => Full admin.
/// - auth disabled and no token => Full local.
/// Returns Err when auth is required but the token is unknown.
pub fn resolve_tenant(
    token: Option<&str>,
    auth_enabled: bool,
    instance_tokens: &HashMap<String, Vec<String>>,
) -> Result<Tenant, String> {
    let token = token.unwrap_or("").trim();
    if token.is_empty() {
        if auth_enabled {
            return Err("missing bearer token".to_string());
        }
        return Ok(Tenant::Full { id: "local".to_string() });
    }
    let mut allowed = HashSet::new();
    for (inst, toks) in instance_tokens {
        if toks.iter().any(|t| t == token) {
            allowed.insert(inst.clone());
        }
    }
    if !allowed.is_empty() {
        return Ok(Tenant::Restricted { id: digest_token(token), instances: allowed });
    }
    if auth_enabled {
        let admin = std::env::var("MCP_AUTH_TOKEN").unwrap_or_default();
        if !admin.is_empty() && token == admin {
            return Ok(Tenant::Full { id: "admin".to_string() });
        }
        return Err("unknown token".to_string());
    }
    // Auth disabled but a token was presented and matches nothing:
    // treat as local full access (back-compat), identity labeled by digest.
    Ok(Tenant::Full { id: digest_token(token) })
}

/// Extract bearer from `Authorization: Bearer x` or `?token=x` / `?access_token=x`.
pub fn bearer_from(headers: &axum::http::HeaderMap, query: &str) -> Option<String> {
    if let Some(h) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(t) = h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer ")) {
            let t = t.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    for kv in query.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            if (k == "token" || k == "access_token") && !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Rate limiting: per (tenant, instance, tool) sliding window.
// Mode via SAP_MCP_RATE_LIMIT_MODE=off|warn|block (default off),
// window SAP_MCP_RATE_LIMIT_WINDOW secs (default 60),
// budget SAP_MCP_RATE_LIMIT_MAX_CALLS (default 120).
// ---------------------------------------------------------------------------

type RateKey = (String, String, String); // (tenant, instance, op)

#[derive(Clone, Default)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<RateKey, VecDeque<Instant>>>>,
}

impl RateLimiter {
    pub fn mode() -> String {
        std::env::var("SAP_MCP_RATE_LIMIT_MODE")
            .unwrap_or_else(|_| "off".into())
            .to_lowercase()
    }

    fn window() -> Duration {
        Duration::from_secs(
            std::env::var("SAP_MCP_RATE_LIMIT_WINDOW")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
        )
    }

    fn budget() -> usize {
        std::env::var("SAP_MCP_RATE_LIMIT_MAX_CALLS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120)
    }

    /// Returns (allowed, current_count). In warn/off mode always allowed.
    pub fn check(&self, tenant: &str, instance: &str, tool: &str) -> (bool, usize) {
        let mode = Self::mode();
        if mode == "off" {
            return (true, 0);
        }
        let now = Instant::now();
        let window = Self::window();
        let budget = Self::budget();
        let key = (tenant.to_string(), instance.to_string(), tool.to_string());
        let mut m = self.inner.lock().unwrap();
        // Bound total keys so a tenant-enumeration flood can't grow memory.
        if m.len() > 4096 && !m.contains_key(&key) {
            m.clear();
        }
        let q = m.entry(key).or_default();
        while q.front().map(|t| now.duration_since(*t) > window).unwrap_or(false) {
            q.pop_front();
        }
        q.push_back(now);
        let n = q.len();
        if mode == "block" && n > budget {
            (false, n)
        } else {
            if mode == "warn" && n == budget + 1 {
                eprintln!("[sa-mcp] rate warn tenant={tenant} instance={instance} tool={tool} count={n}");
            }
            (true, n)
        }
    }

    pub fn snapshot(&self) -> serde_json::Value {
        let now = Instant::now();
        let window = Self::window();
        let m = self.inner.lock().unwrap();
        let mut entries = vec![];
        for ((t, i, tool), q) in m.iter() {
            let n = q.iter().filter(|at| now.duration_since(**at) <= window).count();
            if n > 0 {
                entries.push(serde_json::json!({"tenant": t, "instance": i, "tool": tool, "count": n}));
            }
        }
        serde_json::Value::Array(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(pairs: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
            .collect()
    }

    #[test]
    fn tenant_isolation() {
        let m = toks(&[("a", &["tok-a"]), ("b", &["tok-b"])]);
        let ta = resolve_tenant(Some("tok-a"), true, &m).unwrap();
        assert!(ta.check("a").is_ok());
        assert!(ta.check("b").is_err());
        assert_eq!(ta.filter(&["a".to_string(), "b".to_string()]), vec!["a".to_string()]);
        let admin = resolve_tenant(Some("stranger-token"), false, &m).unwrap();
        assert!(admin.check("b").is_ok());
        assert!(resolve_tenant(Some("nope"), true, &m).is_err());
        assert!(resolve_tenant(None, true, &m).is_err());
        assert!(resolve_tenant(None, false, &m).unwrap().check("b").is_ok());
    }

    #[test]
    fn admin_token_wins() {
        std::env::set_var("MCP_AUTH_TOKEN", "adm-xyz");
        let m = toks(&[("a", &["tok-a"])]);
        let t = resolve_tenant(Some("adm-xyz"), true, &m).unwrap();
        assert!(t.check("a").is_ok());
        assert!(t.check("zzz").is_ok());
        std::env::remove_var("MCP_AUTH_TOKEN");
    }

    #[test]
    fn rate_block_and_warn() {
        std::env::set_var("SAP_MCP_RATE_LIMIT_MODE", "block");
        std::env::set_var("SAP_MCP_RATE_LIMIT_MAX_CALLS", "2");
        std::env::set_var("SAP_MCP_RATE_LIMIT_WINDOW", "60");
        let r = RateLimiter::default();
        assert!(r.check("t", "i", "tool").0);
        assert!(r.check("t", "i", "tool").0);
        assert!(!r.check("t", "i", "tool").0);
        // other tenant unaffected
        assert!(r.check("t2", "i", "tool").0);
        std::env::set_var("SAP_MCP_RATE_LIMIT_MODE", "off");
        std::env::remove_var("SAP_MCP_RATE_LIMIT_MAX_CALLS");
        std::env::remove_var("SAP_MCP_RATE_LIMIT_WINDOW");
    }
}
