use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// One SAP system (S/4HANA OData V2/V4, on-premise or cloud).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SapInstanceConfig {
    #[serde(default)]
    pub url: String,
    /// SAP client number, e.g. "100". Sent as `sap-client` query/header.
    #[serde(default)]
    pub client: Option<String>,
    /// Auth type: basic | bearer | oauth2. Default: basic.
    #[serde(default = "default_auth")]
    pub auth_type: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// Bearer/JWT token (auth_type=bearer).
    #[serde(default)]
    pub token: Option<String>,
    /// OAuth2 client-credentials (auth_type=oauth2).
    #[serde(default)]
    pub oauth_token_url: Option<String>,
    #[serde(default)]
    pub oauth_client_id: Option<String>,
    #[serde(default)]
    pub oauth_client_secret: Option<String>,
    #[serde(default)]
    pub oauth_scope: Option<String>,
    /// OData version: "v2" | "v4". Default v2 (S/4 on-premise classic).
    #[serde(default = "default_odata")]
    pub odata_version: String,
    /// Base service path, e.g. "/sap/opu/odata/sap/API_BUSINESS_PARTNER".
    /// Empty => use per-call service discovered via catalog (if configured).
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default)]
    pub verify_ssl: bool,
    /// Per-tenant MCP bearer token(s). Same semantics as Od-MCP.
    #[serde(default, alias = "mcpToken", deserialize_with = "string_or_vec")]
    pub mcp_tokens: Vec<String>,
}

fn default_auth() -> String {
    "basic".to_string()
}
fn default_odata() -> String {
    "v2".to_string()
}
fn default_timeout_ms() -> u64 {
    30000
}
fn default_max_retries() -> u32 {
    3
}

fn string_or_vec<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    struct Sv;
    impl<'de> Visitor<'de> for Sv {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string or array of strings")
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<String>, E> {
            Ok(vec![v.to_string()])
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut s: A) -> Result<Vec<String>, A::Error> {
            let mut out = vec![];
            while let Some(x) = s.next_element::<String>()? {
                out.push(x);
            }
            Ok(out)
        }
        fn visit_unit<E: de::Error>(self) -> Result<Vec<String>, E> {
            Ok(vec![])
        }
    }
    d.deserialize_any(Sv)
}

impl SapInstanceConfig {
    pub fn is_v4(&self) -> bool {
        matches!(self.odata_version.trim().to_lowercase().as_str(), "v4" | "4")
    }

    pub fn normalized_url(&self) -> String {
        normalize_url(&self.url)
    }

    /// Base URL for a service root, e.g. {url}{service} (no trailing slash).
    pub fn service_root(&self, service: Option<&str>) -> Result<String> {
        let svc = service
            .map(|s| s.to_string())
            .or_else(|| self.service.clone())
            .ok_or_else(|| anyhow::anyhow!("no service given and instance has no default service"))?;
        if !valid_service_path(&svc) {
            anyhow::bail!("invalid service path '{svc}'");
        }
        Ok(format!("{}{}", self.normalized_url(), svc))
    }
}

pub fn normalize_url(raw: &str) -> String {
    let t = raw.trim().trim_end_matches('/');
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else if t.is_empty() {
        "http://localhost:8000".to_string()
    } else {
        format!("http://{}", t)
    }
}

pub fn env_truthy(v: &str) -> bool {
    matches!(
        v.trim().to_lowercase().as_str(),
        "1" | "true" | "yes" | "y" | "on"
    )
}

pub fn writes_enabled() -> bool {
    std::env::var("SAP_MCP_ENABLE_WRITES")
        .map(|v| env_truthy(&v))
        .unwrap_or(false)
}

pub fn metadata_cache_ttl() -> u64 {
    std::env::var("SAP_METADATA_CACHE_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(600)
}

pub fn audit_log_path() -> Option<String> {
    std::env::var("SAP_MCP_AUDIT_LOG").ok().filter(|s| !s.is_empty())
}

/// OData entity-set / service / function names: letters, digits, _ only,
/// must not be empty. Blocks `$batch`/path injection via crafted names.
pub fn valid_odata_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// Service paths like "/sap/opu/odata/sap/API_BUSINESS_PARTNER".
pub fn valid_service_path(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.starts_with('/')
        && !s.contains("..")
        && s.chars()
            .all(|c| c.is_alphanumeric() || "/._-~%()='".contains(c))
}

pub fn valid_instance_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

/// Gated exposition (ala fr0ster --exposition): comma list from SAP_EXPOSITION.
/// Groups: "read" (discover/metadata/read/list, always every mode),
/// "write" (gated trio + create/update/delete). Default "readonly,high".
/// Prod recommendation: SAP_EXPOSITION=readonly (+ SAP_MCP_ENABLE_WRITES=0).
pub fn exposition() -> Vec<String> {
    std::env::var("SAP_EXPOSITION")
        .unwrap_or_else(|_| "readonly,high".into())
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn exposition_allows(group: &str) -> bool {
    let e = exposition();
    match group {
        "read" => true, // discover/search always on (fr0ster parity)
        "write" => e.iter().any(|g| g == "high" || g == "write"),
        _ => true,
    }
}

/// Entity allow/deny globs (ala lemaiwo ODATA_SERVICE_PATTERNS):
/// SAP_ENTITY_ALLOW / SAP_ENTITY_DENY, comma-separated, `*` wildcard.
/// Deny wins. Empty allow = allow all (subject to deny).
pub fn entity_allowed(entity: &str) -> bool {
    if let Ok(deny) = std::env::var("SAP_ENTITY_DENY") {
        for pat in deny.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            if glob_match(pat, entity) {
                return false;
            }
        }
    }
    match std::env::var("SAP_ENTITY_ALLOW") {
        Ok(allow) => {
            let pats: Vec<&str> = allow.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
            if pats.is_empty() {
                return true;
            }
            pats.iter().any(|p| glob_match(p, entity))
        }
        Err(_) => true,
    }
}

fn glob_match(pat: &str, s: &str) -> bool {
    // simple `*` wildcard matcher (case-sensitive, like SAP names)
    let mut px = pat.split('*');
    let Some(first) = px.next() else {
        return true;
    };
    if !s.starts_with(first) {
        return false;
    }
    let mut rest = &s[first.len()..];
    for part in px {
        if part.is_empty() {
            continue;
        }
        match rest.find(part) {
            Some(i) => rest = &rest[i + part.len()..],
            None => return false,
        }
    }
    pat.ends_with('*') || rest.is_empty()
}

/// Per-request SAP credential override (fr0ster x-sap-* style) is honored only
/// for Full tenants AND only when explicitly opted in. Default: rejected.
pub fn auth_override_allowed() -> bool {
    std::env::var("SAP_MCP_ALLOW_AUTH_OVERRIDE")
        .map(|v| env_truthy(&v))
        .unwrap_or(false)
}

/// DoS caps for free-form query strings (ala sap-for-agents MAX_* validation).
/// Percent-encode a string for use INSIDE an OData path key predicate.
/// Keeps `'` literal (already `''`-escaped by the caller) and unreserved
/// chars; everything else (spaces, slashes, unicode) is encoded so key
/// values can't break out of the path segment.
pub fn odata_path_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'\'' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

pub const MAX_PAGE_TOP: i64 = 200;
pub const MAX_FILTER_CHARS: usize = 2000;
pub const MAX_SELECT_FIELDS: usize = 50;
pub const MAX_EXPAND_ITEMS: usize = 5;

pub fn clamp_top(v: Option<serde_json::Value>, default: i64) -> i64 {
    let n = v.and_then(|x| x.as_i64().or_else(|| x.as_f64().map(|f| f as i64)));
    match n {
        Some(n) if n > 0 => n.min(MAX_PAGE_TOP),
        _ => default,
    }
}

pub fn clamp_skip(v: Option<serde_json::Value>) -> i64 {
    let n = v.and_then(|x| x.as_i64().or_else(|| x.as_f64().map(|f| f as i64)));
    match n {
        Some(n) if n >= 0 => n,
        _ => 0,
    }
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.trim().is_empty())
}

/// Priority: SAP_INSTANCES_JSON (file) > SAP_INSTANCES (inline/path) >
/// single-instance env fallback.
pub fn load_instances() -> Result<(String, HashMap<String, SapInstanceConfig>)> {
    if let Ok(p) = std::env::var("SAP_INSTANCES_JSON") {
        if !p.trim().is_empty() {
            let txt =
                std::fs::read_to_string(&p).with_context(|| format!("read SAP_INSTANCES_JSON {p}"))?;
            return parse_instances_json(&txt);
        }
    }
    if let Ok(v) = std::env::var("SAP_INSTANCES") {
        let t = v.trim();
        if !t.is_empty() {
            if (t.starts_with('/') || t.starts_with('.') || t.ends_with(".json"))
                && !t.starts_with('{')
            {
                let txt = std::fs::read_to_string(t)
                    .with_context(|| format!("read SAP_INSTANCES file {t}"))?;
                return parse_instances_json(&txt);
            }
            if t.starts_with('{') {
                return parse_instances_json(t);
            }
        }
    }
    let cfg = SapInstanceConfig {
        url: non_empty_env("SAP_URL").unwrap_or_else(|| "http://localhost:8000".into()),
        client: non_empty_env("SAP_CLIENT"),
        auth_type: non_empty_env("SAP_AUTH_TYPE").unwrap_or_else(default_auth),
        username: non_empty_env("SAP_USERNAME"),
        password: non_empty_env("SAP_PASSWORD"),
        token: non_empty_env("SAP_TOKEN"),
        oauth_token_url: non_empty_env("SAP_OAUTH_TOKEN_URL"),
        oauth_client_id: non_empty_env("SAP_OAUTH_CLIENT_ID"),
        oauth_client_secret: non_empty_env("SAP_OAUTH_CLIENT_SECRET"),
        oauth_scope: non_empty_env("SAP_OAUTH_SCOPE"),
        odata_version: non_empty_env("SAP_ODATA_VERSION").unwrap_or_else(default_odata),
        service: non_empty_env("SAP_SERVICE"),
        timeout_ms: non_empty_env("SAP_TIMEOUT_MS")
            .and_then(|v| v.parse().ok())
            .unwrap_or(30000),
        max_retries: 3,
        verify_ssl: non_empty_env("SAP_VERIFY_SSL").map(|v| env_truthy(&v)).unwrap_or(true),
        mcp_tokens: non_empty_env("SAP_MCP_TOKEN").map(|t| vec![t]).unwrap_or_default(),
    };
    let mut m = HashMap::new();
    m.insert("default".to_string(), cfg);
    Ok(("default".to_string(), validate_instances(m)?))
}

fn parse_instances_json(txt: &str) -> Result<(String, HashMap<String, SapInstanceConfig>)> {
    let v: serde_json::Value =
        serde_json::from_str(txt).context("SAP_INSTANCES is not valid JSON")?;
    if let Some(instances) = v.get("instances") {
        let map: HashMap<String, SapInstanceConfig> =
            serde_json::from_value(instances.clone()).context("parse instances map")?;
        if map.is_empty() {
            anyhow::bail!("instances map is empty");
        }
        let def = v
            .get("default")
            .and_then(|d| d.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                if map.len() == 1 {
                    map.keys().next().cloned()
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "default".to_string());
        return Ok((def, validate_instances(map)?));
    }
    let map: HashMap<String, SapInstanceConfig> =
        serde_json::from_value(v).context("parse bare instances map")?;
    if map.is_empty() {
        anyhow::bail!("instances map is empty");
    }
    let def = if map.len() == 1 {
        map.keys().next().cloned().unwrap()
    } else if map.contains_key("default") {
        "default".to_string()
    } else {
        anyhow::bail!("multi-instance JSON needs \"default\" or \"instances\" key");
    };
    Ok((def, validate_instances(map)?))
}

/// Strict multi-tenant validation: self-contained entries, fail fast.
fn validate_instances(map: HashMap<String, SapInstanceConfig>) -> Result<HashMap<String, SapInstanceConfig>> {
    for (name, cfg) in &map {
        if !valid_instance_name(name) {
            anyhow::bail!("invalid instance name '{name}'");
        }
        let auth = cfg.auth_type.to_lowercase();
        match auth.as_str() {
            "basic" => {
                let u = cfg.username.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false);
                let p = cfg.password.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false);
                if !u || !p {
                    anyhow::bail!("instance '{name}' (basic) needs username+password");
                }
            }
            "bearer" => {
                if cfg.token.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
                    anyhow::bail!("instance '{name}' (bearer) needs token");
                }
            }
            "oauth2" => {
                for (k, v) in [
                    ("oauth_token_url", &cfg.oauth_token_url),
                    ("oauth_client_id", &cfg.oauth_client_id),
                    ("oauth_client_secret", &cfg.oauth_client_secret),
                ] {
                    if v.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
                        anyhow::bail!("instance '{name}' (oauth2) needs {k}");
                    }
                }
            }
            _ => anyhow::bail!("instance '{name}' has unknown auth_type '{auth}' (basic|bearer|oauth2)"),
        }
        if cfg.timeout_ms == 0 {
            anyhow::bail!("instance '{name}' has timeout_ms=0");
        }
        for t in &cfg.mcp_tokens {
            if t.trim().is_empty() {
                anyhow::bail!("instance '{name}' has an empty mcp token");
            }
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn names_reject_injection() {
        assert!(valid_odata_name("A_BusinessPartner"));
        assert!(!valid_odata_name("A_BusinessPartner/$batch"));
        assert!(!valid_odata_name("../etc"));
        assert!(!valid_odata_name(""));
        assert!(valid_service_path("/sap/opu/odata/sap/API_BUSINESS_PARTNER"));
        assert!(!valid_service_path("/sap/../etc"));
        assert!(!valid_service_path("https://x/sap"));
    }

    #[test]
    fn paging_clamped() {
        assert_eq!(clamp_top(Some(json!(-1)), 25), 25);
        assert_eq!(clamp_top(Some(json!(100000)), 25), MAX_PAGE_TOP);
        assert_eq!(clamp_top(None, 25), 25);
        assert_eq!(clamp_skip(Some(json!(-5))), 0);
    }

    #[test]
    fn entity_globs() {
        assert!(glob_match("*", "A_BusinessPartner"));
        assert!(glob_match("A_*", "A_BusinessPartner"));
        assert!(!glob_match("B_*", "A_BusinessPartner"));
        assert!(glob_match("A_*Partner", "A_BusinessPartner"));
        assert!(!glob_match("A_*Partner", "A_BusinessPartnerX"));
        std::env::set_var("SAP_ENTITY_DENY", "T_*");
        assert!(!entity_allowed("T_001"));
        assert!(entity_allowed("A_001"));
        std::env::remove_var("SAP_ENTITY_DENY");
        std::env::set_var("SAP_ENTITY_ALLOW", "A_*");
        assert!(entity_allowed("A_001"));
        assert!(!entity_allowed("B_001"));
        std::env::remove_var("SAP_ENTITY_ALLOW");
    }
}
