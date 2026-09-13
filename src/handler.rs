use crate::cache::MetadataCache;
use crate::gated::{audit, build_approval_token, ApprovalStore, APPROVAL_TTL_SECS};
use crate::sap_client::SapPool;
use crate::registry::{Registry, ToolDef};
use crate::tenant::{RateLimiter, Tenant};
use anyhow::anyhow;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Handler {
    pub pool: SapPool,
    pub registry: Registry,
    pub approvals: ApprovalStore,
    pub cache: MetadataCache,
    pub acl: crate::field_acl::FieldPolicy,
    pub limiter: RateLimiter,
    pub metrics: Arc<Mutex<HashMap<String, u64>>>,
}

impl Handler {
    pub fn new(pool: SapPool, registry: Registry) -> Self {
        let ttl = crate::config::metadata_cache_ttl();
        Self {
            pool,
            registry,
            approvals: ApprovalStore::new(APPROVAL_TTL_SECS),
            cache: MetadataCache::new(ttl),
            acl: crate::field_acl::FieldPolicy::load(),
            limiter: RateLimiter::default(),
            metrics: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn metrics_snapshot(&self) -> Value {
        let m = self.metrics.lock().unwrap();
        let mut v: Vec<(&String, &u64)> = m.iter().collect();
        v.sort_by_key(|(k, _)| *k);
        json!(v.iter().map(|(k, n)| json!({"op": k, "calls": n})).collect::<Vec<_>>())
    }

    fn count_op(&self, op: &str) {
        *self.metrics.lock().unwrap().entry(op.to_string()).or_insert(0) += 1;
    }

    pub fn server_name(&self) -> &str {
        &self.registry.server_name
    }

    pub async fn handle(&self, req: Value, tenant: &Tenant) -> Option<Value> {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
        let params = req.get("params").cloned().unwrap_or(json!({}));
        let is_notif = req.get("id").is_none();

        let result: Result<Value, String> = match method.as_str() {
            "initialize" => Ok(self.on_initialize(&params)),
            "notifications/initialized" | "initialized" => Ok(json!({})),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(self.on_tools_list()),
            "tools/call" => self.on_tool_call(&params, tenant).await,
            "prompts/list" => Ok(self.on_prompts_list()),
            "prompts/get" => Ok(self.on_prompt_get(&params)),
            "resources/list" => Ok(self.on_resources_list()),
            "resources/read" => self.on_resource_read(&params, tenant).await,
            _ => Err(format!("unknown method {method}")),
        };

        if is_notif {
            return None;
        }
        match result {
            Ok(r) => Some(json!({"jsonrpc":"2.0","id":id,"result":r})),
            Err(e) => Some(json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":e}})),
        }
    }

    fn on_initialize(&self, _p: &Value) -> Value {
        json!({
            "protocolVersion": "2025-11-05",
            "capabilities": {"tools": {"listChanged": false}, "prompts": {"listChanged": false}, "resources": {"listChanged": false}},
            "serverInfo": {"name": self.registry.server_name, "version": env!("CARGO_PKG_VERSION")},
            "instructions": self.registry.instructions,
        })
    }

    fn on_tools_list(&self) -> Value {
        let tools: Vec<Value> = self
            .registry
            .list_tools()
            .iter()
            .map(|t| json!({"name": t.name, "description": t.description, "inputSchema": t.input_schema}))
            .collect();
        json!({"tools": tools})
    }

    fn on_prompts_list(&self) -> Value {
        let ps: Vec<Value> = self
            .registry
            .prompts
            .iter()
            .map(|p| json!({"name": p.name, "description": p.description}))
            .collect();
        json!({"prompts": ps})
    }

    fn on_prompt_get(&self, p: &Value) -> Value {
        let name = p.get("name").and_then(|s| s.as_str()).unwrap_or("");
        match self.registry.prompts.iter().find(|x| x.name == name) {
            Some(pr) => json!({"description": pr.description, "messages": [{"role":"user","content":{"type":"text","text": pr.content}}]}),
            None => json!({"description":"","messages":[]}),
        }
    }

    fn on_resources_list(&self) -> Value {
        json!({"resources": [
            {"uri":"sap://instances","name":"instances","description":"List configured SAP systems"},
            {"uri":"sap://entities","name":"entities","description":"List entity sets (default instance/service)"}
        ]})
    }

    async fn on_resource_read(&self, p: &Value, tenant: &Tenant) -> Result<Value, String> {
        let uri = p.get("uri").and_then(|s| s.as_str()).unwrap_or("");
        if uri == "sap://instances" {
            return Ok(json!({"contents":[{"uri":uri,"text": self.pool.describe_for(tenant).to_string()}]}));
        }
        let inst = tenant
            .resource_default(self.pool.default_name())
            .ok_or_else(|| "tenant has no accessible instances".to_string())?;
        // Resources share the choke-point rules: tenant scope (above),
        // entity allow/deny + rate accounting (below).
        let (rate_ok, _) = self.limiter.check(tenant.id(), &inst, "resources/read");
        if !rate_ok {
            return Err("rate limited".to_string());
        }
        let c = self.pool.get(&inst).map_err(|e| e.to_string())?;
        if uri == "sap://entities" {
            let md = self.cached_metadata(&c, &inst, None).await.map_err(|e| e.to_string())?;
            let sets: Vec<Value> = md
                .get("entity_sets")
                .and_then(|s| s.as_array())
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|s| {
                    s.get("name").and_then(|n| n.as_str()).map(|n| crate::config::entity_allowed(n)).unwrap_or(false)
                })
                .collect();
            return Ok(json!({"contents":[{"uri":uri,"text": Value::Array(sets).to_string()}]}));
        }
        if let Some(es) = uri.strip_prefix("sap://entity/") {
            if !crate::config::valid_odata_name(es) {
                return Err("invalid entity name".to_string());
            }
            if !crate::config::entity_allowed(es) {
                return Err(format!("entity '{es}' blocked by SAP_ENTITY_ALLOW/SAP_ENTITY_DENY"));
            }
            let md = self.cached_metadata(&c, &inst, None).await.map_err(|e| e.to_string())?;
            let annotated = Self::annotate_acl(&self.acl, &inst, es, entity_meta(&md, es));
            return Ok(json!({"contents":[{"uri":uri,"text": annotated.to_string()}]}));
        }
        Err(format!("unknown resource {uri}"))
    }

    async fn on_tool_call(&self, p: &Value, tenant: &Tenant) -> Result<Value, String> {
        let name = p.get("name").and_then(|s| s.as_str()).unwrap_or("");
        let args = match p.get("arguments") {
            Some(Value::String(s)) => serde_json::from_str(s).unwrap_or(json!({})),
            Some(v) => v.clone(),
            None => json!({}),
        };
        let tool: ToolDef = self.registry.get_tool(name).ok_or_else(|| format!("unknown tool {name}"))?;
        let out = self.execute_op(&tool.op.op_type, &tool.op.map, &args, tenant).await.map_err(|e| e.to_string())?;
        Ok(json!({"content": [{"type": "text", "text": out.to_string()}]}))
    }

    async fn cached_metadata(
        &self,
        c: &crate::sap_client::SapClient,
        instance: &str,
        service: Option<&str>,
    ) -> anyhow::Result<Value> {
        let key_service = service.unwrap_or("*default*");
        if let Some(cached) = self.cache.get(instance, key_service) {
            return Ok(cached);
        }
        let md = c.service_metadata(service).await?;
        self.cache.insert(instance, key_service, md.clone());
        Ok(md)
    }

    fn annotate_acl(acl: &crate::field_acl::FieldPolicy, instance: &str, entity: &str, meta: Value) -> Value {
        let Some(props) = meta.get("properties").and_then(|p| p.as_array()) else {
            return meta;
        };
        let mut out = meta.clone();
        if let Some(arr) = out.get_mut("properties").and_then(|p| p.as_array_mut()) {
            for p in arr.iter_mut() {
                if let Some(fname) = p.get("name").and_then(|n| n.as_str()) {
                    if acl.is_denied(instance, entity, fname) {
                        p["access"] = json!("restricted");
                    }
                }
            }
        }
        let _ = props;
        out
    }

    // ---------- op dispatch (tenant choke point, same contract as Od-MCP) ----------
    async fn execute_op(
        &self,
        op: &str,
        map: &std::collections::HashMap<String, String>,
        args: &Value,
        tenant: &Tenant,
    ) -> anyhow::Result<Value> {
        let get = |key: &str| -> Option<Value> {
            map.get(key).and_then(|ptr| {
                let field = ptr.replace('/', ".").trim_start_matches('.').to_string();
                args.get(&field).cloned()
            })
        };
        let req_str = |key: &str| -> anyhow::Result<String> {
            get(key)
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .ok_or_else(|| anyhow!("missing '{key}'"))
        };
        let opt_str = |key: &str| -> Option<String> {
            get(key).and_then(|v| v.as_str().map(|s| s.to_string()))
        };
        let req_entity = |key: &str| -> anyhow::Result<String> {
            let e = req_str(key)?;
            if !crate::config::valid_odata_name(&e) {
                return Err(anyhow!("invalid entity name '{e}'"));
            }
            Ok(e)
        };

        let instance_opt = get("instance").and_then(|v| match v {
            Value::String(s) => Some(s),
            _ => None,
        });
        if let Some(ref name) = instance_opt {
            if !crate::config::valid_instance_name(name) {
                return Err(anyhow!("invalid instance name '{name}'"));
            }
        }
        let instance = self.pool.resolve_name(instance_opt.as_deref());
        if op == "list_instances" {
            return Ok(self.pool.describe_for(tenant));
        }
        tenant.check(&instance).map_err(|e| anyhow!(e))?;
        let (allowed, count) = self.limiter.check(tenant.id(), &instance, op);
        if !allowed {
            return Err(anyhow!(
                "rate limited: tenant '{}' instance '{instance}' op '{op}' ({count} calls in window)",
                tenant.id()
            ));
        }
        self.count_op(op);
        // Per-request SAP credential override (fr0ster x-sap-* style):
        // Full tenants only + explicit opt-in; otherwise rejected outright.
        // Secrets travel in args only and are never logged (audit uses digests).
        let client = self.client_for(tenant, &instance, args)?;
        // Entity allow/deny gate (ala lemaiwo ODATA_SERVICE_PATTERNS).
        // Runs before metadata fetch so denied entities cost nothing.
        if let Some(e) = get("entity").and_then(|v| v.as_str().map(|s| s.to_string())) {
            if !crate::config::entity_allowed(&e) {
                return Err(anyhow!("entity '{e}' blocked by SAP_ENTITY_ALLOW/SAP_ENTITY_DENY"));
            }
        }

        match op {
            // L1 discover: minimal entity-set list from $metadata (cached).
            "discover" => {
                let service = opt_str("service");
                let md = self.cached_metadata(&client, &instance, service.as_deref()).await?;
                let sets = md.get("entity_sets").cloned().unwrap_or(json!([]));
                let q = opt_str("query").unwrap_or_default().to_lowercase();
                let out: Vec<Value> = sets
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|s| {
                        let name_ok = s.get("name").and_then(|n| n.as_str()).map(|n| crate::config::entity_allowed(n)).unwrap_or(false);
                        let q_ok = q.is_empty()
                            || s.get("name").and_then(|n| n.as_str()).map(|n| n.to_lowercase().contains(&q)).unwrap_or(false);
                        name_ok && q_ok
                    })
                    .map(|mut s| {
                        // minimal footprint: name + capabilities only
                        if let Some(o) = s.as_object_mut() {
                            o.remove("addressable");
                        }
                        s
                    })
                    .collect();
                Ok(json!({"entities": out, "count": out.len()}))
            }
            // L2 metadata: full properties/keys/capabilities for one entity.
            "entity_metadata" => {
                let service = opt_str("service");
                let entity = req_entity("entity")?;
                let md = self.cached_metadata(&client, &instance, service.as_deref()).await?;
                let meta = entity_meta(&md, &entity);
                if meta.is_null() {
                    return Err(anyhow!("unknown entity '{entity}'"));
                }
                let annotated = Self::annotate_acl(&self.acl, &instance, &entity, meta);
                Ok(json!({"entity": entity, "metadata": annotated, "field_acl": self.acl.status()}))
            }
            // L3 read collection.
            "read" => {
                let service = opt_str("service");
                let entity = req_entity("entity")?;
                check_query_caps(opt_str("filter").as_deref(), opt_str("select").as_deref(), opt_str("expand").as_deref())?;
                let top = crate::config::clamp_top(get("top"), 25);
                let skip = crate::config::clamp_skip(get("skip"));
                let mut res = client
                    .query(
                        service.as_deref(),
                        &entity,
                        None,
                        opt_str("filter"),
                        opt_str("select"),
                        opt_str("expand"),
                        opt_str("orderby"),
                        top,
                        skip,
                        get("count").and_then(|v| v.as_bool()).unwrap_or(false),
                    )
                    .await?;
                redact_collection(&self.acl, &instance, &entity, &mut res);
                Ok(res)
            }
            // L3 read single by key.
            "read_one" => {
                let service = opt_str("service");
                let entity = req_entity("entity")?;
                check_query_caps(None, opt_str("select").as_deref(), opt_str("expand").as_deref())?;
                let keys = get("keys").ok_or_else(|| anyhow!("missing 'keys' object"))?;
                let seg = self.key_for(&client, &instance, service.as_deref(), &entity, &keys).await?;
                let mut res = client
                    .query(service.as_deref(), &entity, Some(&seg), None, opt_str("select"), opt_str("expand"), None, 1, 0, false)
                    .await?;
                redact_collection(&self.acl, &instance, &entity, &mut res);
                Ok(res)
            }
            // ----- gated writes (preview -> validate -> execute) -----
            "preview_write" => {
                let service = opt_str("service");
                let entity = req_entity("entity")?;
                let operation = opt_str("operation").unwrap_or_else(|| "create".into());
                if !["create", "update", "delete"].contains(&operation.as_str()) {
                    return Err(anyhow!("invalid operation '{operation}' (create|update|delete)"));
                }
                let payload = json!({
                    "instance": instance,
                    "service": service,
                    "model": entity,
                    "operation": operation,
                    "keys": get("keys").unwrap_or(Value::Null),
                    "values": get("values").unwrap_or(Value::Null),
                    "etag": get("etag").unwrap_or(Value::Null),
                    "auth_fp": auth_fp(args),
                });
                let token = build_approval_token(&payload);
                audit("preview", tenant.id(), &instance, &entity, &operation, &token, true, "preview created");
                Ok(json!({"approval": {"token": token, "payload": payload}, "preview": payload, "next": "call sap_validate_write with same payload"}))
            }
            "validate_write" => {
                let service = opt_str("service");
                let entity = req_entity("entity")?;
                let operation = opt_str("operation").unwrap_or_else(|| "create".into());
                if !["create", "update", "delete"].contains(&operation.as_str()) {
                    return Err(anyhow!("invalid operation '{operation}' (create|update|delete)"));
                }
                // Live metadata required: unknown-entity/unknown-property check.
                let md = self.cached_metadata(&client, &instance, service.as_deref()).await?;
                let meta = entity_meta(&md, &entity);
                if meta.is_null() {
                    return Err(anyhow!("unknown entity '{entity}'"));
                }
                let known: Vec<String> = meta
                    .get("properties")
                    .and_then(|p| p.as_array())
                    .map(|a| a.iter().filter_map(|x| x.get("name").and_then(|n| n.as_str()).map(|s| s.to_string())).collect())
                    .unwrap_or_default();
                let values = get("values").unwrap_or(json!({}));
                if (operation == "create" || operation == "update") && !values.is_object() {
                    return Err(anyhow!("'values' must be an object for {operation}"));
                }
                let mut issues: Vec<Value> = vec![];
                if let Some(obj) = values.as_object() {
                    for k in obj.keys() {
                        if !known.iter().any(|x| x == k) {
                            issues.push(json!({"field": k, "issue": "unknown_property"}));
                        }
                    }
                }
                if operation != "create" {
                    let keys = get("keys");
                    match &keys {
                        Some(Value::Object(o)) if !o.is_empty() => {}
                        _ => issues.push(json!({"issue": "keys_required_for_update_delete"})),
                    }
                    // capability gate from $metadata sap:updatable/deletable
                    let sets = md.get("entity_sets").and_then(|s| s.as_array()).cloned().unwrap_or_default();
                    if let Some(es) = sets.iter().find(|s| s.get("name").and_then(|n| n.as_str()) == Some(&entity)) {
                        let cap = if operation == "update" { "updatable" } else { "deletable" };
                        if es.get(cap).and_then(|v| v.as_bool()) == Some(false) {
                            issues.push(json!({"issue": format!("entity_not_{cap}_per_metadata")}));
                        }
                    }
                }
                // create: entity must allow it per metadata (when advertised)
                if operation == "create" {
                    let sets = md.get("entity_sets").and_then(|s| s.as_array()).cloned().unwrap_or_default();
                    if let Some(es) = sets.iter().find(|s| s.get("name").and_then(|n| n.as_str()) == Some(&entity)) {
                        if es.get("creatable").and_then(|v| v.as_bool()) == Some(false) {
                            issues.push(json!({"issue": "entity_not_creatable_per_metadata"}));
                        }
                    }
                }
                let payload = json!({
                    "instance": instance,
                    "service": service,
                    "model": entity,
                    "operation": operation,
                    "keys": get("keys").unwrap_or(Value::Null),
                    "values": get("values").unwrap_or(Value::Null),
                    "etag": get("etag").unwrap_or(Value::Null),
                    "auth_fp": auth_fp(args),
                });
                let token = build_approval_token(&payload);
                let hard_fail = issues.iter().any(|i| {
                    i.get("issue").map(|x| x == "unknown_property" || x == "keys_required_for_update_delete").unwrap_or(false)
                });
                if !hard_fail {
                    self.approvals.register(token.clone(), payload.clone());
                }
                audit("validate", tenant.id(), &instance, &entity, &operation, &token, !hard_fail, &format!("issues={}", issues.len()));
                Ok(json!({
                    "approval": {"token": token, "payload": payload},
                    "approval_status": {"stored": !hard_fail, "expires_in_seconds": APPROVAL_TTL_SECS},
                    "issues": issues,
                    "metadata_source": "server",
                }))
            }
            "execute_approved_write" => {
                Self::require_writes_enabled()?;
                let approval = get("approval").ok_or_else(|| anyhow!("missing 'approval' (need token from validate_write)"))?;
                let token = approval.get("token").and_then(|s| s.as_str()).ok_or_else(|| anyhow!("approval.token missing"))?;
                let payload = approval.get("payload").cloned().ok_or_else(|| anyhow!("approval.payload missing"))?;
                let confirm = get("confirm").and_then(|v| v.as_bool()).unwrap_or(false);
                if !confirm {
                    return Err(anyhow!("confirm=true required"));
                }
                let payload_inst = payload.get("instance").and_then(|s| s.as_str()).unwrap_or(&instance).to_string();
                if payload_inst != instance {
                    audit("execute", tenant.id(), &payload_inst, "", "", token, false, "instance mismatch");
                    return Err(anyhow!("approval was issued for instance '{payload_inst}', not '{instance}'"));
                }
                // Credential-override binding: the executing call must present
                // the same override (or none) as the validated call.
                let fp_now = auth_fp(args);
                let fp_was = payload.get("auth_fp").and_then(|s| s.as_str()).unwrap_or("none");
                if fp_now != fp_was {
                    audit("execute", tenant.id(), &payload_inst, "", "", token, false, "auth override mismatch");
                    return Err(anyhow!("approval was validated with different SAP credentials"));
                }
                if !self.approvals.consume(token, &payload) {
                    let reason = if self.approvals.is_valid(token, &payload) {
                        "approval could not be consumed (concurrent use?)"
                    } else {
                        "invalid, expired, or already-consumed approval token. Re-run preview->validate."
                    };
                    audit("execute", tenant.id(), &payload_inst, "", "", token, false, reason);
                    return Err(anyhow!(reason.to_string()));
                }
                let res = self.exec_payload(&client, &payload_inst, &payload).await?;
                let entity = payload.get("model").and_then(|s| s.as_str()).unwrap_or("");
                let operation = payload.get("operation").and_then(|s| s.as_str()).unwrap_or("");
                audit("execute", tenant.id(), &payload_inst, entity, operation, token, true, "ok");
                Ok(json!({"success": true, "result": res}))
            }
            // direct ops: token + payload-bound execution (same as Od-MCP).
            "create" | "update" | "delete" => {
                Self::require_writes_enabled()?;
                let appr = get("approval").ok_or_else(|| anyhow!("gated write: call sap_preview_write + sap_validate_write first, then pass approval + confirm:true"))?;
                let token = appr.get("token").and_then(|s| s.as_str()).unwrap_or("");
                let payload = appr.get("payload").cloned().unwrap_or(json!({}));
                let confirm = get("confirm").and_then(|v| v.as_bool()).unwrap_or(false);
                if !confirm {
                    return Err(anyhow!("confirm=true required with approval"));
                }
                if !self.approvals.consume(token, &payload) {
                    return Err(anyhow!("invalid, expired, or already-consumed approval token"));
                }
                let p_inst = payload.get("instance").and_then(|s| s.as_str()).unwrap_or("");
                if p_inst != instance {
                    return Err(anyhow!("approval was issued for instance '{p_inst}', not '{instance}'"));
                }
                if payload.get("auth_fp").and_then(|s| s.as_str()).unwrap_or("none") != auth_fp(args) {
                    return Err(anyhow!("approval was validated with different SAP credentials"));
                }
                let entity = req_entity("entity")?;
                let p_entity = payload.get("model").and_then(|s| s.as_str()).unwrap_or("");
                let p_op = payload.get("operation").and_then(|s| s.as_str()).unwrap_or("");
                if p_entity != entity || p_op != op {
                    return Err(anyhow!("request does not match validated approval (entity/operation mismatch)"));
                }
                let res = self.exec_payload(&client, &instance, &payload).await?;
                audit("execute", tenant.id(), &instance, &entity, p_op, token, true, "ok (direct op)");
                Ok(json!({"success": true, "result": res}))
            }
            _ => Err(anyhow!("unknown op.type {op}")),
        }
    }

    /// Resolve the SAP client: pooled instance client by default, or a
    /// one-off client with per-request credentials when (and only when) the
    /// caller is a Full tenant and SAP_MCP_ALLOW_AUTH_OVERRIDE=1.
    fn client_for(
        &self,
        tenant: &Tenant,
        instance: &str,
        args: &Value,
    ) -> anyhow::Result<crate::sap_client::SapClient> {
        let has_override = args.get("auth_username").is_some()
            || args.get("auth_password").is_some()
            || args.get("auth_token").is_some();
        if !has_override {
            return self.pool.get(instance);
        }
        let is_full = matches!(tenant, Tenant::Full { .. });
        if !is_full || !crate::config::auth_override_allowed() {
            return Err(anyhow!(
                "per-request SAP credentials require a Full tenant and SAP_MCP_ALLOW_AUTH_OVERRIDE=1"
            ));
        }
        let mut cfg = self.pool.config_for(instance)?;
        if let Some(u) = args.get("auth_username").and_then(|v| v.as_str()) {
            cfg.username = Some(u.to_string());
            cfg.auth_type = "basic".to_string();
        }
        if let Some(p) = args.get("auth_password").and_then(|v| v.as_str()) {
            cfg.password = Some(p.to_string());
            cfg.auth_type = "basic".to_string();
        }
        if let Some(t) = args.get("auth_token").and_then(|v| v.as_str()) {
            cfg.token = Some(t.to_string());
            cfg.auth_type = "bearer".to_string();
        }
        crate::sap_client::SapClient::new(cfg)
    }

    /// Execute a validated payload with the EFFECTIVE client (honors the same
    /// per-request override used at validate time; the approval binds the
    /// override fingerprint, so creds can't be swapped between steps).
    async fn exec_payload(
        &self,
        client: &crate::sap_client::SapClient,
        instance: &str,
        payload: &Value,
    ) -> anyhow::Result<Value> {
        // NOTE: uses the passed-in effective client (possibly per-request
        // override). Re-resolving pooled here would silently drop override
        // credentials. `instance` is kept for audit context.
        let c = client;
        let entity = payload.get("model").and_then(|s| s.as_str()).unwrap_or("");
        if !crate::config::valid_odata_name(entity) {
            return Err(anyhow!("invalid entity name in approval"));
        }
        if !crate::config::entity_allowed(entity) {
            return Err(anyhow!("entity '{entity}' blocked by SAP_ENTITY_ALLOW/SAP_ENTITY_DENY")); 
        }
        let service = payload.get("service").and_then(|s| s.as_str());
        let operation = payload.get("operation").and_then(|s| s.as_str()).unwrap_or("");
        match operation {
            "create" => {
                c.create(service, entity, payload.get("values").cloned().unwrap_or(json!({}))).await
            }
            "update" => {
                let seg = self.key_for(&c, instance, service, entity, &payload.get("keys").cloned().unwrap_or(Value::Null)).await?;
                let etag = payload.get("etag").and_then(|s| s.as_str()).map(|s| s.to_string());
                c.update(service, entity, &seg, payload.get("values").cloned().unwrap_or(json!({})), etag).await
            }
            "delete" => {
                let seg = self.key_for(&c, instance, service, entity, &payload.get("keys").cloned().unwrap_or(Value::Null)).await?;
                let etag = payload.get("etag").and_then(|s| s.as_str()).map(|s| s.to_string());
                c.delete(service, entity, &seg, etag).await
            }
            _ => Err(anyhow!("unknown operation {operation}")),
        }
    }

    /// Build an OData key segment using live $metadata Edm types when
    /// available (ala lemaiwo formatKeyValue), heuristic fallback otherwise.
    async fn key_for(
        &self,
        c: &crate::sap_client::SapClient,
        instance: &str,
        service: Option<&str>,
        entity: &str,
        keys: &Value,
    ) -> anyhow::Result<String> {
        let types = self
            .cached_metadata(c, instance, service)
            .await
            .ok()
            .map(|md| prop_types(&entity_meta(&md, entity)))
            .unwrap_or_default();
        key_segment_typed(keys, &types)
    }

    fn require_writes_enabled() -> anyhow::Result<()> {
        if crate::config::writes_enabled() {
            Ok(())
        } else {
            Err(anyhow!("writes disabled: set SAP_MCP_ENABLE_WRITES=1"))
        }
    }
}

/// Fingerprint of per-request SAP credential override for approval binding.
/// Raw secrets never enter the payload (it travels through agent context);
/// only a sha256 prefix. "none" when no override is used.
fn auth_fp(args: &Value) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let u = args.get("auth_username").and_then(|v| v.as_str()).unwrap_or("");
    let p = args.get("auth_password").and_then(|v| v.as_str()).unwrap_or("");
    let t = args.get("auth_token").and_then(|v| v.as_str()).unwrap_or("");
    if u.is_empty() && p.is_empty() && t.is_empty() {
        return "none".to_string();
    }
    h.update(format!("{u}\u{1f}{p}\u{1f}{t}").as_bytes());
    format!("ovr-{}", &hex::encode(h.finalize())[..16])
}

/// Extract one entity's metadata object from parsed $metadata.
fn entity_meta(md: &Value, entity_set: &str) -> Value {
    let sets = md.get("entity_sets").and_then(|s| s.as_array()).cloned().unwrap_or_default();
    let et = sets
        .iter()
        .find(|s| s.get("name").and_then(|n| n.as_str()) == Some(entity_set))
        .and_then(|s| s.get("entity_type").and_then(|t| t.as_str()))
        .unwrap_or(entity_set)
        .to_string();
    // entity_type may equal the set name when ET name == set name.
    let types = md.get("entity_types").and_then(|t| t.as_object()).cloned().unwrap_or_default();
    types.get(&et).cloned().or_else(|| types.get(entity_set).cloned()).unwrap_or(Value::Null)
}

/// Build an OData key segment from {"K1": v}: single or composite.
/// Edm-aware quoting when live $metadata types are known (ala lemaiwo
/// formatKeyValue); heuristic fallback otherwise.
fn key_segment_typed(keys: &Value, types: &HashMap<String, String>) -> anyhow::Result<String> {
    let obj = keys.as_object().ok_or_else(|| anyhow!("'keys' must be an object"))?;
    if obj.is_empty() {
        return Err(anyhow!("'keys' must not be empty"));
    }
    for k in obj.keys() {
        if !crate::config::valid_odata_name(k) {
            return Err(anyhow!("invalid key name '{k}'"));
        }
    }
    let fmt = |k: &str, v: &Value| -> String {
        // String branches are path-encoded AFTER ''-escaping so values with
        // spaces/slashes/unicode can't break the key predicate path.
        let qs = |s: &str| crate::config::odata_path_encode(&s.replace('\'', "''"));
        match types.get(k).map(|s| s.as_str()) {
            // Quoted literals.
            Some("String") | Some("Guid") | Some("Date") | Some("DateTime")
            | Some("DateTimeOffset") | Some("Time") | Some("Binary") | Some("Stream") => {
                match v {
                    Value::String(s) => format!("'{}'", qs(s)),
                    _ => format!("'{}'", qs(&v.to_string())),
                }
            }
            // Raw numerics / bool. String inputs are re-validated: a hostile
            // "1)/Evil(" string must not pass through raw into the path.
            Some("Boolean") | Some("Byte") | Some("SByte") | Some("Int16")
            | Some("Int32") | Some("Int64") => match v {
                Value::String(s) if s.parse::<i64>().is_ok() || s.parse::<f64>().is_ok() || s == "true" || s == "false" => {
                    s.clone()
                }
                Value::String(s) => format!("'{}'", qs(s)),
                _ => v.to_string(),
            },
            Some("Decimal") => match v {
                Value::String(s) if s.parse::<f64>().is_ok() => format!("{s}M"),
                Value::String(s) => format!("'{}'", qs(s)),
                _ => format!("{}M", v),
            },
            Some("Double") | Some("Single") => match v {
                Value::String(s) if s.parse::<f64>().is_ok() => format!("{s}d"),
                Value::String(s) => format!("'{}'", qs(s)),
                _ => format!("{}d", v),
            },
            // Unknown type: heuristic (strings quoted, numbers/bools raw).
            _ => match v {
                Value::String(s) => format!("'{}'", qs(s)),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => format!("'{}'", qs(&v.to_string())),
            },
        }
    };
    Ok(obj.iter().map(|(k, v)| format!("{k}={}", fmt(k, v))).collect::<Vec<_>>().join(","))
}

/// Legacy heuristic entry (kept for tests/back-compat).
fn key_segment(keys: &Value) -> anyhow::Result<String> {
    key_segment_typed(keys, &HashMap::new())
}

/// Property name -> Edm type for one entity's metadata.
fn prop_types(meta: &Value) -> HashMap<String, String> {
    meta.get("properties")
        .and_then(|p| p.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| {
                    Some((
                        x.get("name")?.as_str()?.to_string(),
                        x.get("type")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Free-form query caps (DoS guard): filter length, select/expand breadth.
fn check_query_caps(filter: Option<&str>, select: Option<&str>, expand: Option<&str>) -> anyhow::Result<()> {
    if let Some(f) = filter {
        if f.len() > crate::config::MAX_FILTER_CHARS {
            return Err(anyhow!("$filter too long (max {} chars)", crate::config::MAX_FILTER_CHARS));
        }
    }
    if let Some(s) = select {
        let n = s.split(',').filter(|x| !x.trim().is_empty()).count();
        if n > crate::config::MAX_SELECT_FIELDS {
            return Err(anyhow!("$select too broad (max {} fields)", crate::config::MAX_SELECT_FIELDS));
        }
    }
    if let Some(e) = expand {
        let n = e.split(',').filter(|x| !x.trim().is_empty()).count();
        if n > crate::config::MAX_EXPAND_ITEMS {
            return Err(anyhow!("$expand too broad (max {} items)", crate::config::MAX_EXPAND_ITEMS));
        }
    }
    Ok(())
}

/// Strip ACL-denied properties from read results.
fn redact_collection(acl: &crate::field_acl::FieldPolicy, instance: &str, entity: &str, res: &mut Value) {
    if let Some(arr) = res.get_mut("records").and_then(|r| r.as_array_mut()) {
        let mut vec = arr.clone();
        acl.redact_records(instance, entity, &mut vec);
        *arr = vec;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_segments() {
        assert_eq!(key_segment(&json!({"BusinessPartner": "1000001"})).unwrap(), "BusinessPartner='1000001'");
        assert_eq!(key_segment(&json!({"K1": "a'b", "K2": 3})).unwrap(), "K1='a''b',K2=3");
        assert!(key_segment(&json!({})).is_err());
        assert!(key_segment(&json!({"a/b": 1})).is_err());
        // Edm-aware: Guid quoted, Int raw even as string, Decimal M-suffix.
        let mut t = HashMap::new();
        t.insert("G".into(), "Guid".into());
        t.insert("N".into(), "Int32".into());
        t.insert("A".into(), "Decimal".into());
        assert_eq!(
            key_segment_typed(&json!({"G": "abc", "N": "7", "A": 1.5}), &t).unwrap(),
            "A=1.5M,G='abc',N=7"
        );
    }

    #[test]
    fn query_caps_reject_abuse() {
        assert!(check_query_caps(Some(&"x".repeat(5000)), None, None).is_err());
        assert!(check_query_caps(None, Some(&(0..60).map(|i| format!("F{i}")).collect::<Vec<_>>().join(",")), None).is_err());
        assert!(check_query_caps(None, None, Some("a,b,c,d,e,f")).is_err());
        assert!(check_query_caps(Some("ID eq '1'"), Some("ID,Name"), Some("Nav")).is_ok());
    }

    #[test]
    fn key_values_are_path_safe() {
        // spaces/slashes/unicode encoded, quotes ''-escaped but literal.
        assert_eq!(
            key_segment(&json!({"Name": "a b/cüd"})).unwrap(),
            "Name='a%20b%2Fc%C3%BCd'"
        );
        // hostile numeric strings fall back to quoted form.
        let mut t = HashMap::new();
        t.insert("N".into(), "Int32".into());
        assert_eq!(
            key_segment_typed(&json!({"N": "1)/Evil("}), &t).unwrap(),
            "N='1%29%2FEvil%28'"
        );
        // auth fingerprint binds override identity without raw secrets.
        let a = json!({"auth_username": "u", "auth_password": "p"});
        let b = json!({"auth_username": "u", "auth_password": "other"});
        assert_ne!(auth_fp(&a), auth_fp(&b));
        assert_eq!(auth_fp(&json!({})), "none");
        assert!(!auth_fp(&a).contains('u'));
    }
}
