use crate::config::SapInstanceConfig;
use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// SAP OData V2/V4 client for S/4HANA (cloud + on-premise).
/// Auth: basic | bearer | oauth2-client-credentials. Reads retry;
/// writes never retry (non-idempotent). V2 writes fetch X-CSRF-Token.
#[derive(Clone)]
pub struct SapClient {
    cfg: SapInstanceConfig,
    http: reqwest::Client,
    csrf: Arc<Mutex<Option<(String, Instant)>>>,
    oauth: Arc<Mutex<Option<(String, Instant)>>>,
}

impl SapClient {
    pub fn new(cfg: SapInstanceConfig) -> Result<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms.max(1000)))
            .cookie_store(true);
        if !cfg.verify_ssl {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let http = builder.build().context("build http client")?;
        Ok(Self {
            cfg,
            http,
            csrf: Arc::new(Mutex::new(None)),
            oauth: Arc::new(Mutex::new(None)),
        })
    }

    pub fn is_v4(&self) -> bool {
        self.cfg.is_v4()
    }

    async fn access_token(&self) -> Result<Option<String>> {
        match self.cfg.auth_type.to_lowercase().as_str() {
            "bearer" => Ok(self.cfg.token.clone().filter(|s| !s.trim().is_empty())),
            "oauth2" => {
                {
                    let g = self.oauth.lock().unwrap();
                    if let Some((tok, exp)) = g.clone() {
                        if Instant::now() < exp {
                            return Ok(Some(tok));
                        }
                    }
                }
                let (tok, ttl) = self.fetch_oauth_token().await?;
                // Honor provider expires_in minus 60s skew (default 1h).
                let exp = Instant::now() + Duration::from_secs(ttl.saturating_sub(60).max(60));
                *self.oauth.lock().unwrap() = Some((tok.clone(), exp));
                Ok(Some(tok))
            }
            _ => Ok(None),
        }
    }

    /// Returns (token, expires_in_secs) honoring the provider value.
    async fn fetch_oauth_token(&self) -> Result<(String, u64)> {
        let url = self.cfg.oauth_token_url.clone().unwrap_or_default();
        let mut form = vec![
            ("grant_type", "client_credentials".to_string()),
            ("client_id", self.cfg.oauth_client_id.clone().unwrap_or_default()),
            ("client_secret", self.cfg.oauth_client_secret.clone().unwrap_or_default()),
        ];
        if let Some(s) = &self.cfg.oauth_scope {
            form.push(("scope", s.clone()));
        }
        let resp = self.http.post(&url).form(&form).send().await.context("oauth token request")?;
        if !resp.status().is_success() {
            return Err(anyhow!("oauth token http {}", resp.status()));
        }
        let v: Value = resp.json().await.context("parse oauth token")?;
        let tok = v
            .get("access_token")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("oauth response has no access_token"))?;
        let ttl = v.get("expires_in").and_then(|e| e.as_u64()).unwrap_or(3600);
        Ok((tok, ttl))
    }

    fn basic_header(&self) -> Option<String> {
        if self.cfg.auth_type.to_lowercase() != "basic" {
            return None;
        }
        let u = self.cfg.username.clone().unwrap_or_default();
        let p = self.cfg.password.clone().unwrap_or_default();
        if u.is_empty() {
            return None;
        }
        Some(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
        ))
    }

    /// Append sap-client + $format=json (V2) to a URL.
    fn url_with_params(&self, base: &str, extra: &[(&str, &str)]) -> String {
        let owned: Vec<(String, String)> =
            extra.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        self.url_with_params_owned(base, &owned)
    }

    async fn send(
        &self,
        method: reqwest::Method,
        url: String,
        body: Option<Value>,
        extra_headers: Vec<(String, String)>,
        retry: bool,
    ) -> Result<reqwest::Response> {
        let max = if retry { self.cfg.max_retries } else { 0 };
        let mut attempt = 0u32;
        loop {
            let mut req = self.http.request(method.clone(), &url).header("Accept", "application/json");
            if let Some(b) = &self.basic_header() {
                req = req.header("Authorization", b.clone());
            } else if let Some(t) = self.access_token().await? {
                req = req.header("Authorization", format!("Bearer {t}"));
            }
            for (k, v) in &extra_headers {
                req = req.header(k.clone(), v.clone());
            }
            if let Some(b) = &body {
                req = req.json(b);
            }
            match req.send().await {
                Ok(r) => {
                    let s = r.status();
                    if (s.as_u16() == 429 || s.is_server_error()) && attempt < max {
                        attempt += 1;
                        tokio::time::sleep(Duration::from_millis(250 * 2u64.pow(attempt.min(6)))).await;
                        continue;
                    }
                    return Ok(r);
                }
                Err(e) if attempt < max => {
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(250 * 2u64.pow(attempt.min(6)))).await;
                    let _ = e;
                    continue;
                }
                Err(e) => return Err(anyhow!("http error: {e}")),
            }
        }
    }

    fn odata_error(txt: &str) -> String {
        // SAP returns {"error":{"code":...,"message":{"value":...}}}
        if let Ok(v) = serde_json::from_str::<Value>(txt) {
            if let Some(msg) = v.pointer("/error/message/value").and_then(|m| m.as_str()) {
                return format!("sap error: {msg}");
            }
            if let Some(e) = v.get("error") {
                return format!("sap error: {e}");
            }
        }
        format!("sap http error: {}", truncate(txt, 400))
    }

    // ---------------- metadata ----------------

    pub async fn service_metadata(&self, service: Option<&str>) -> Result<Value> {
        let root = self.cfg.service_root(service)?;
        let url = self.url_with_params(&format!("{root}/$metadata"), &[]);
        let resp = self.send(reqwest::Method::GET, url, None, vec![("Accept".into(), "application/xml".into())], true).await?;
        if !resp.status().is_success() {
            let txt = resp.text().await.unwrap_or_default();
            return Err(anyhow!(Self::odata_error(&txt)));
        }
        let xml = resp.text().await.unwrap_or_default();
        parse_edmx(&xml)
    }

    // ---------------- query ----------------

    #[allow(clippy::too_many_arguments)]
    pub async fn query(
        &self,
        service: Option<&str>,
        entity_set: &str,
        key_segment: Option<&str>,
        filter: Option<String>,
        select: Option<String>,
        expand: Option<String>,
        orderby: Option<String>,
        top: i64,
        skip: i64,
        count: bool,
    ) -> Result<Value> {
        if !crate::config::valid_odata_name(entity_set) {
            return Err(anyhow!("invalid entity set '{entity_set}'"));
        }
        let root = self.cfg.service_root(service)?;
        let mut path = format!("{root}/{entity_set}");
        if let Some(k) = key_segment {
            if k.len() > 1024 || k.contains('\n') || k.contains('\r') {
                return Err(anyhow!("invalid key segment"));
            }
            path.push_str(&format!("({k})"));
        }
        let mut params: Vec<(String, String)> = vec![];
        if let Some(f) = filter {
            params.push(("$filter".into(), f));
        }
        if let Some(s) = select {
            params.push(("$select".into(), s));
        }
        if let Some(e) = expand {
            params.push(("$expand".into(), e));
        }
        if let Some(o) = orderby {
            params.push(("$orderby".into(), o));
        }
        params.push(("$top".into(), top.to_string()));
        if skip > 0 {
            params.push(("$skip".into(), skip.to_string()));
        }
        if count {
            if self.is_v4() {
                params.push(("$count".into(), "true".into()));
            } else {
                params.push(("$inlinecount".into(), "allpages".into()));
            }
        }
        let url = self.url_with_params_owned(&path, &params);
        let resp = self.send(reqwest::Method::GET, url, None, vec![], true).await?;
        let status = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(anyhow!(Self::odata_error(&txt)));
        }
        let v: Value = serde_json::from_str(&txt).unwrap_or(Value::String(txt));
        Ok(normalize_collection(&v))
    }

    fn url_with_params_owned(&self, base: &str, extra: &[(String, String)]) -> String {
        let mut q: Vec<(String, String)> = vec![];
        if let Some(c) = &self.cfg.client {
            if !c.trim().is_empty() {
                q.push(("sap-client".into(), c.clone()));
            }
        }
        if !self.is_v4() {
            q.push(("$format".into(), "json".into()));
        }
        for (k, v) in extra {
            q.push((k.clone(), v.clone()));
        }
        let qs: Vec<String> = q.iter().map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v))).collect();
        if qs.is_empty() {
            return base.to_string();
        }
        format!("{base}?{qs}", qs = qs.join("&"))
    }

    // ---------------- writes (gated upstream) ----------------

    async fn csrf_token(&self, root: &str) -> Result<String> {
        {
            let g = self.csrf.lock().unwrap();
            if let Some((t, at)) = g.clone() {
                if at.elapsed() < Duration::from_secs(20 * 60) {
                    return Ok(t);
                }
            }
        }
        if self.is_v4() {
            return Ok(String::new()); // V4 uses If-Match/ETag, no CSRF fetch
        }
        let url = self.url_with_params(root, &[]);
        let resp = self
            .send(reqwest::Method::GET, url, None, vec![("X-CSRF-Token".into(), "Fetch".into())], true)
            .await?;
        let tok = resp
            .headers()
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        if tok.is_empty() {
            return Err(anyhow!("CSRF token fetch returned empty (check auth)"));
        }
        *self.csrf.lock().unwrap() = Some((tok.clone(), Instant::now()));
        Ok(tok)
    }

    pub async fn create(&self, service: Option<&str>, entity_set: &str, body: Value) -> Result<Value> {
        if !crate::config::valid_odata_name(entity_set) {
            return Err(anyhow!("invalid entity set '{entity_set}'"));
        }
        let root = self.cfg.service_root(service)?;
        let url = self.url_with_params(&format!("{root}/{entity_set}"), &[]);
        // A 403 here proves non-execution, so one CSRF refresh + retry is safe
        // (writes themselves are still never retried on transport errors).
        for attempt in 0..2 {
            let csrf = self.csrf_token(&root).await?;
            let mut headers = vec![];
            if !csrf.is_empty() {
                headers.push(("X-CSRF-Token".into(), csrf));
            }
            let resp = self.send(reqwest::Method::POST, url.clone(), Some(body.clone()), headers, false).await?;
            let status = resp.status();
            if status.as_u16() == 403 && attempt == 0 && !self.is_v4() {
                *self.csrf.lock().unwrap() = None;
                continue;
            }
            let txt = resp.text().await.unwrap_or_default();
            if !(status.is_success() || status.as_u16() == 201) {
                return Err(anyhow!(Self::odata_error(&txt)));
            }
            return Ok(serde_json::from_str(&txt).unwrap_or(json!({"success": true})));
        }
        Err(anyhow!("CSRF refresh retry exhausted"))
    }

    pub async fn update(
        &self,
        service: Option<&str>,
        entity_set: &str,
        key_segment: &str,
        body: Value,
        etag: Option<String>,
    ) -> Result<Value> {
        if !crate::config::valid_odata_name(entity_set) {
            return Err(anyhow!("invalid entity set '{entity_set}'"));
        }
        let root = self.cfg.service_root(service)?;
        let url = self.url_with_params(&format!("{root}/{entity_set}({key_segment})"), &[]);
        // V2 partial update = MERGE (PUT would replace the whole entity);
        // V4 = PATCH. MERGE is a static valid token, safe to expect().
        let method = if self.is_v4() { reqwest::Method::PATCH } else { reqwest::Method::from_bytes(b"MERGE").expect("static method") };
        for attempt in 0..2 {
            let csrf = self.csrf_token(&root).await?;
            let mut headers = vec![("If-Match".into(), etag.clone().unwrap_or_else(|| "*".into()))];
            if !csrf.is_empty() {
                headers.push(("X-CSRF-Token".into(), csrf));
            }
            let resp = self.send(method.clone(), url.clone(), Some(body.clone()), headers, false).await?;
            let status = resp.status();
            if status.as_u16() == 403 && attempt == 0 && !self.is_v4() {
                *self.csrf.lock().unwrap() = None;
                continue;
            }
            let txt = resp.text().await.unwrap_or_default();
            if !(status.is_success() || status.as_u16() == 204) {
                return Err(anyhow!(Self::odata_error(&txt)));
            }
            return Ok(json!({"success": true}));
        }
        Err(anyhow!("CSRF refresh retry exhausted"))
    }

    pub async fn delete(&self, service: Option<&str>, entity_set: &str, key_segment: &str, etag: Option<String>) -> Result<Value> {
        if !crate::config::valid_odata_name(entity_set) {
            return Err(anyhow!("invalid entity set '{entity_set}'"));
        }
        let root = self.cfg.service_root(service)?;
        let url = self.url_with_params(&format!("{root}/{entity_set}({key_segment})"), &[]);
        for attempt in 0..2 {
            let csrf = self.csrf_token(&root).await?;
            let mut headers = vec![("If-Match".into(), etag.clone().unwrap_or_else(|| "*".into()))];
            if !csrf.is_empty() {
                headers.push(("X-CSRF-Token".into(), csrf));
            }
            let resp = self.send(reqwest::Method::DELETE, url.clone(), None, headers, false).await?;
            let status = resp.status();
            if status.as_u16() == 403 && attempt == 0 && !self.is_v4() {
                *self.csrf.lock().unwrap() = None;
                continue;
            }
            let txt = resp.text().await.unwrap_or_default();
            if !(status.is_success() || status.as_u16() == 204) {
                return Err(anyhow!(Self::odata_error(&txt)));
            }
            return Ok(json!({"success": true}));
        }
        Err(anyhow!("CSRF refresh retry exhausted"))
    }

    pub async fn health_check(&self) -> bool {
        // Reachable if the service root answers (even 401/403 proves routing).
        let root = match self.cfg.service_root(None) {
            Ok(r) => r,
            Err(_) => return false,
        };
        let url = self.url_with_params(&root, &[]);
        match self.send(reqwest::Method::GET, url, None, vec![], false).await {
            Ok(r) => {
                let s = r.status().as_u16();
                (200..500).contains(&s) && s != 404
            }
            Err(_) => false,
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b'$' | b'\'' | b'(' | b')' | b',' | b'=' => out.push(b as char), // OData-reserved, keep readable
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Normalize V2 (`d.results`) and V4 (`value`) envelopes to
/// {"records": [...], "count": n, "total": t?}.
fn normalize_collection(v: &Value) -> Value {
    if let Some(arr) = v.pointer("/d/results").and_then(|x| x.as_array()) {
        let total = v
            .pointer("/d/__count")
            .and_then(|x| x.as_str().and_then(|s| s.parse::<i64>().ok()).or_else(|| x.as_i64()));
        let mut out = json!({"records": arr, "count": arr.len()});
        if let Some(t) = total {
            out["total"] = json!(t);
        }
        return out;
    }
    if let Some(arr) = v.get("value").and_then(|x| x.as_array()) {
        let mut out = json!({"records": arr, "count": arr.len()});
        if let Some(t) = v.get("@odata.count").and_then(|x| x.as_i64()) {
            out["total"] = json!(t);
        }
        return out;
    }
    if v.as_array().is_some() {
        return json!({"records": v, "count": v.as_array().unwrap().len()});
    }
    // single entity
    json!({"records": [v], "count": 1})
}

/// Minimal EDMX $metadata parser (quick-xml, no DOM): entity sets +
/// entity types with properties, keys, creatable/updatable/deletable flags.
pub fn parse_edmx(xml: &str) -> Result<Value> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut sets: Vec<Value> = vec![];
    let mut types: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut cur_type: Option<String> = None;
    let mut cur_props: Vec<Value> = vec![];
    let mut cur_keys: Vec<String> = vec![];
    let mut cur_base: Option<String> = None;
    let mut in_key = false;
    let mut in_complex = false;
    let decoder = reader.decoder();

    let attr = |e: &quick_xml::events::BytesStart, name: &[u8]| -> Option<String> {
        e.attributes().find_map(|a| {
            a.ok().and_then(|a| {
                if a.key.as_ref() == name {
                    // Decode XML entities (&amp; etc.) — raw bytes would leak them.
                    a.decode_and_unescape_value(decoder.clone())
                        .ok()
                        .map(|v| v.into_owned())
                } else {
                    None
                }
            })
        })
    };
    let attr_any = |e: &quick_xml::events::BytesStart, names: &[&str]| -> Option<String> {
        for n in names {
            if let Some(v) = attr(e, n.as_bytes()) {
                return Some(v);
            }
        }
        None
    };

    // Shared element handling for both <X> (Start) and <X/> (Empty).
    // Self-closing <EntityType/> is finalized immediately so no state leaks.
    let mut handle_open = |e: &quick_xml::events::BytesStart,
                           self_closing: bool,
                           sets: &mut Vec<Value>,
                           types: &mut serde_json::Map<String, Value>,
                           cur_type: &mut Option<String>,
                           cur_props: &mut Vec<Value>,
                           cur_keys: &mut Vec<String>,
                           cur_base: &mut Option<String>,
                           in_key: &mut bool,
                           in_complex: &mut bool| {
        let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
        let local = name.rsplit(':').next().unwrap_or(&name);
        match local {
            "ComplexType" => *in_complex = true,
            "EntitySet" => {
                if let Some(n) = attr(e, b"Name") {
                    let et = attr(e, b"EntityType").unwrap_or_default();
                    let flag = |k: &str| attr_any(e, &[k, &format!("sap:{k}")]).map(|v| v == "true").unwrap_or(false);
                    sets.push(json!({
                        "name": n,
                        "entity_type": et.rsplit('.').next().unwrap_or(&et),
                        "creatable": flag("creatable"),
                        "updatable": flag("updatable"),
                        "deletable": flag("deletable"),
                        "addressable": attr_any(e, &["addressable", "sap:addressable"]).map(|v| v != "false").unwrap_or(true),
                    }));
                }
            }
            "EntityType" => {
                if let Some(n) = attr(e, b"Name") {
                    if self_closing {
                        let mut obj = json!({"properties": [], "keys": []});
                        if let Some(b) = attr(e, b"BaseType") {
                            obj["base_type"] = json!(b.rsplit('.').next().unwrap_or(&b));
                        }
                        types.insert(n, obj);
                    } else {
                        *cur_type = Some(n);
                        cur_props.clear();
                        cur_keys.clear();
                        *cur_base = attr(e, b"BaseType");
                    }
                }
            }
            "Key" => *in_key = true,
            "PropertyRef" => {
                if *in_key {
                    if let Some(n) = attr(e, b"Name") {
                        cur_keys.push(n);
                    }
                }
            }
            "Property" => {
                // ComplexType properties must not pollute the entity type.
                if cur_type.is_some() && !*in_complex {
                    if let Some(n) = attr(e, b"Name") {
                        cur_props.push(json!({
                            "name": n,
                            "type": attr(e, b"Type").unwrap_or_default().rsplit('.').next().unwrap_or("").to_string(),
                            "nullable": attr(e, b"Nullable").map(|v| v != "false").unwrap_or(true),
                            "max_length": attr(e, b"MaxLength"),
                        }));
                    }
                }
            }
            _ => {}
        }
    };

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Empty(e)) => {
                handle_open(&e, true, &mut sets, &mut types, &mut cur_type, &mut cur_props, &mut cur_keys, &mut cur_base, &mut in_key, &mut in_complex);
            }
            Ok(Event::Start(e)) => {
                handle_open(&e, false, &mut sets, &mut types, &mut cur_type, &mut cur_props, &mut cur_keys, &mut cur_base, &mut in_key, &mut in_complex);
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                let local = name.rsplit(':').next().unwrap_or(&name);
                match local {
                    "Key" => in_key = false,
                    "ComplexType" => in_complex = false,
                    "EntityType" => {
                        if let Some(t) = cur_type.take() {
                            let mut obj = json!({"properties": cur_props, "keys": cur_keys});
                            if let Some(b) = cur_base.take() {
                                obj["base_type"] = json!(b.rsplit('.').next().unwrap_or(&b));
                            }
                            types.insert(t, obj);
                        }
                        cur_props = vec![];
                        cur_keys = vec![];
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow!("metadata xml error: {e}")),
            _ => {}
        }
        buf.clear();
    }
    Ok(json!({"entity_sets": sets, "entity_types": types}))
}

/// Lazy multi-system pool (tenant isolation enforced upstream in handler).
#[derive(Clone)]
pub struct SapPool {
    default: String,
    configs: HashMap<String, SapInstanceConfig>,
    clients: Arc<Mutex<HashMap<String, SapClient>>>,
}

impl SapPool {
    pub fn from_env() -> Result<Self> {
        let (default, configs) = crate::config::load_instances()?;
        Ok(Self {
            default,
            configs,
            clients: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn instance_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.configs.keys().cloned().collect();
        v.sort();
        v
    }

    pub fn default_name(&self) -> &str {
        &self.default
    }

    pub fn resolve_name(&self, req: Option<&str>) -> String {
        req.map(|s| s.to_string()).unwrap_or_else(|| self.default.clone())
    }

    pub fn get(&self, name: &str) -> Result<SapClient> {
        {
            let m = self.clients.lock().unwrap();
            if let Some(c) = m.get(name) {
                return Ok(c.clone());
            }
        }
        let cfg = self
            .configs
            .get(name)
            .ok_or_else(|| anyhow!("unknown instance '{name}'"))?
            .clone();
        let c = SapClient::new(cfg)?;
        self.clients.lock().unwrap().insert(name.to_string(), c.clone());
        Ok(c)
    }

    /// Raw config clone (for per-request credential override).
    pub fn config_for(&self, name: &str) -> Result<SapInstanceConfig> {
        self.configs
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow!("unknown instance '{name}'"))
    }

    pub fn instance_tokens(&self) -> HashMap<String, Vec<String>> {        self.configs
            .iter()
            .map(|(k, v)| (k.clone(), v.mcp_tokens.clone()))
            .collect()
    }

    /// Full describe for local admin CLI (--validate-config). Never exposed
    /// over MCP transports (those use describe_for).
    pub fn describe_for_admin(&self) -> Value {
        let admin = crate::tenant::Tenant::Full { id: "local".to_string() };
        self.describe_for(&admin)
    }

    pub fn describe_for(&self, tenant: &crate::tenant::Tenant) -> Value {
        let mut names: Vec<&String> = self.configs.keys().collect();
        names.sort();
        let visible = tenant.filter(names);
        let mut arr = vec![];
        for name in visible {
            if let Some(cfg) = self.configs.get(&name) {
                arr.push(json!({
                    "name": name,
                    "url": cfg.normalized_url(),
                    "odata": if cfg.is_v4() { "v4" } else { "v2" },
                    "service": cfg.service,
                    "is_default": name.as_str() == self.default,
                }));
            }
        }
        Value::Array(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_EDMX: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<edmx:Edmx Version="1.0" xmlns:edmx="http://schemas.microsoft.com/ado/2007/06/edmx">
<edmx:DataServices>
<Schema Namespace="API_BUSINESS_PARTNER" xmlns="http://schemas.microsoft.com/ado/2008/09/edm">
<EntityType Name="A_BusinessPartnerType">
<Key><PropertyRef Name="BusinessPartner"/></Key>
<Property Name="BusinessPartner" Type="Edm.String" Nullable="false" MaxLength="10"/>
<Property Name="BusinessPartnerFullName" Type="Edm.String" Nullable="true"/>
</EntityType>
<EntityContainer Name="API_BUSINESS_PARTNER_Entities">
<EntitySet Name="A_BusinessPartner" EntityType="API_BUSINESS_PARTNER.A_BusinessPartnerType" sap:creatable="true" sap:updatable="true" sap:deletable="false"/>
</EntityContainer>
</Schema>
</edmx:DataServices>
</edmx:Edmx>"#;

    #[test]
    fn edmx_parses_sets_types_keys_caps() {
        let md = parse_edmx(SAMPLE_EDMX).unwrap();
        let sets = md["entity_sets"].as_array().unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0]["name"], "A_BusinessPartner");
        assert_eq!(sets[0]["entity_type"], "A_BusinessPartnerType");
        assert_eq!(sets[0]["creatable"], true);
        assert_eq!(sets[0]["deletable"], false);
        let t = &md["entity_types"]["A_BusinessPartnerType"];
        assert_eq!(t["keys"], json!(["BusinessPartner"]));
        assert_eq!(t["properties"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn collection_envelopes_normalized() {
        let v2 = json!({"d": {"results": [{"a": 1}], "__count": "7"}});
        let n = normalize_collection(&v2);
        assert_eq!(n["count"], 1);
        assert_eq!(n["total"], 7);
        let v4 = json!({"value": [{"a": 1}], "@odata.count": 9});
        let n = normalize_collection(&v4);
        assert_eq!(n["total"], 9);
    }
}
