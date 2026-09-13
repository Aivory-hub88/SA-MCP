use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

/// Field-level ACL, ported from erpipe `field_policy.py` semantics:
/// policy file shape:
/// {
///   "field_acl": {
///     "<instance>": {
///       "<model>": {"deny": ["field", ...]} | {"allow": ["field", ...]},
///       "*": {"deny": [...]}
///     },
///     "*": { "<model>": {...}, "*": {...} }
///   }
/// }
/// or a dedicated file containing just the {"<instance>": ...} map.
/// Rules: "*" entries merge with model-specific (allow=intersect, deny=union).
/// `id` is never redacted.
#[derive(Clone, Default)]
pub struct FieldPolicy {
    inner: Arc<RwLock<PolicyData>>,
}

#[derive(Default)]
struct PolicyData {
    /// (instance_pat, model_pat) -> Rule, kept as nested maps for lookup.
    map: HashMap<String, HashMap<String, Rule>>,
    source: String,
    error: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct Rule {
    allow: Option<HashSet<String>>,
    deny: HashSet<String>,
}

impl FieldPolicy {
    pub fn load() -> Self {
        let p = Self::default();
        p.reload();
        p
    }

    pub fn reload(&self) {
        let (map, source, error) = read_policy_file();
        let mut inner = self.inner.write().unwrap();
        inner.map = map;
        inner.source = source;
        inner.error = error;
    }

    pub fn status(&self) -> Value {
        let inner = self.inner.read().unwrap();
        let enabled = !inner.map.is_empty();
        serde_json::json!({
            "enabled": enabled,
            "source": inner.source,
            "error": inner.error,
        })
    }

    fn rules_for(&self, instance: &str, model: &str) -> Vec<Rule> {
        let inner = self.inner.read().unwrap();
        let mut out = vec![];
        for inst_pat in [instance.to_string(), "*".to_string()] {
            if let Some(models) = inner.map.get(&inst_pat) {
                for model_pat in [model.to_string(), "*".to_string()] {
                    if let Some(r) = models.get(&model_pat) {
                        out.push(r.clone());
                    }
                }
            }
        }
        out
    }

    /// true if field must be hidden for (instance, model).
    pub fn is_denied(&self, instance: &str, model: &str, field: &str) -> bool {
        if field == "id" {
            return false; // id never redacted (erpipe parity)
        }
        let rules = self.rules_for(instance, model);
        if rules.is_empty() {
            return false;
        }
        // deny = union
        if rules.iter().any(|r| r.deny.contains(field)) {
            return true;
        }
        // allow = intersect across rules that specify allow
        let allows: Vec<&HashSet<String>> =
            rules.iter().filter_map(|r| r.allow.as_ref()).collect();
        if allows.is_empty() {
            return false;
        }
        !allows.iter().all(|s| s.contains(field))
    }

    /// Filter a requested field list; denied fields removed.
    /// Returns (kept, removed).
    /// (Unused in SA-MCP: OData $select is a free-form string, so enforcement
    /// happens post-fetch via redact_records + metadata annotation.)
    #[allow(dead_code)]
    pub fn filter_fields(
        &self,
        instance: &str,
        model: &str,
        fields: Vec<String>,
    ) -> (Vec<String>, Vec<String>) {
        let mut kept = vec![];
        let mut removed = vec![];
        for f in fields {
            if self.is_denied(instance, model, &f) {
                removed.push(f);
            } else {
                kept.push(f);
            }
        }
        (kept, removed)
    }

    /// Redact denied keys from a record object in place. Returns removed keys.
    pub fn redact_record(&self, instance: &str, model: &str, rec: &mut serde_json::Map<String, Value>) -> Vec<String> {
        let denied: Vec<String> = rec
            .keys()
            .filter(|k| self.is_denied(instance, model, k))
            .cloned()
            .collect();
        for k in &denied {
            rec.remove(k);
        }
        denied
    }

    /// Redact an array of records. Returns total removed count.
    pub fn redact_records(&self, instance: &str, model: &str, arr: &mut [Value]) -> usize {
        let mut n = 0;
        for v in arr.iter_mut() {
            if let Some(obj) = v.as_object_mut() {
                n += self.redact_record(instance, model, obj).len();
            }
        }
        n
    }

    /// Guard for aggregate-style queries: reject if any measured/grouped field denied.
    /// (Unused in SA-MCP: no $apply aggregation surface yet.)
    #[allow(dead_code)]
    pub fn check_aggregate(
        &self,
        instance: &str,
        model: &str,
        fields: &[String],
        groupby: &[String],
    ) -> Result<(), String> {
        let mut bad = vec![];
        for f in fields.iter().chain(groupby.iter()) {
            // strip aggregate spec like "amount_total:sum"
            let base = f.split(':').next().unwrap_or(f);
            if self.is_denied(instance, model, base) {
                bad.push(f.clone());
            }
        }
        if bad.is_empty() {
            Ok(())
        } else {
            Err(format!("aggregate blocked: field(s) restricted by policy: {}", bad.join(", ")))
        }
    }
}

fn policy_file_path() -> Option<String> {
    // dedicated file wins, else shared policy file's field_acl key
    if let Ok(p) = std::env::var("SAP_MCP_FIELD_POLICY_FILE") {
        if !p.trim().is_empty() {
            return Some(p);
        }
    }
    if let Ok(p) = std::env::var("SAP_MCP_POLICY_FILE") {
        if !p.trim().is_empty() {
            return Some(p);
        }
    }
    // default location if present
    for cand in ["./odoo_mcp_policy.json", "./field_acl.json", "config/field_acl.json"] {
        if std::path::Path::new(cand).exists() {
            return Some(cand.to_string());
        }
    }
    None
}

fn read_policy_file() -> (HashMap<String, HashMap<String, Rule>>, String, Option<String>) {
    let empty = HashMap::new();
    let Some(path) = policy_file_path() else {
        return (empty, String::new(), None);
    };
    // dedicated file env takes precedence marker
    let dedicated = std::env::var("SAP_MCP_FIELD_POLICY_FILE")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    let txt = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            // fail-open with recorded error (health surfaces it); erpipe fails closed at startup,
            // but hot-reloadable Rust server warns instead of refusing to boot.
            eprintln!("[sa-mcp] field-ACL: cannot read {path}: {e}");
            return (empty, path, Some(format!("read error: {e}")));
        }
    };
    let v: Value = match serde_json::from_str(&txt) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[sa-mcp] field-ACL: invalid JSON {path}: {e}");
            return (empty, path, Some(format!("parse error: {e}")));
        }
    };
    // dedicated file: root IS the instance map; shared file: root.field_acl
    let acl = if dedicated {
        if v.get("field_acl").is_some() {
            v.get("field_acl").cloned().unwrap_or(Value::Null)
        } else {
            v.clone()
        }
    } else {
        v.get("field_acl").cloned().unwrap_or(Value::Null)
    };
    if acl.is_null() {
        return (empty, path, None);
    }
    let map = parse_acl_map(&acl);
    (map, path, None)
}

fn parse_acl_map(v: &Value) -> HashMap<String, HashMap<String, Rule>> {
    let mut out: HashMap<String, HashMap<String, Rule>> = HashMap::new();
    let Some(instances) = v.as_object() else {
        return out;
    };
    for (inst, models) in instances {
        let Some(models_obj) = models.as_object() else {
            continue;
        };
        let mut m: HashMap<String, Rule> = HashMap::new();
        for (model, rule_v) in models_obj {
            m.insert(model.clone(), parse_rule(rule_v));
        }
        out.insert(inst.clone(), m);
    }
    out
}

fn parse_rule(v: &Value) -> Rule {
    let mut r = Rule::default();
    if let Some(a) = v.get("allow").and_then(|x| x.as_array()) {
        r.allow = Some(a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect());
    }
    if let Some(d) = v.get("deny").and_then(|x| x.as_array()) {
        r.deny = d.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect();
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with(json: Value) -> FieldPolicy {
        let acl = json.get("field_acl").cloned().unwrap_or(json);
        let map = parse_acl_map(&acl);
        FieldPolicy {
            inner: Arc::new(RwLock::new(PolicyData { map, source: "test".into(), error: None })),
        }
    }

    #[test]
    fn deny_union_and_id_never_redacted() {
        let p = policy_with(serde_json::json!({"field_acl": {"*": {"*": {"deny": ["email"]}}}}));
        assert!(p.is_denied("prod", "res.partner", "email"));
        assert!(!p.is_denied("prod", "res.partner", "id"));
        assert!(!p.is_denied("prod", "res.partner", "name"));
    }

    #[test]
    fn allow_intersect() {
        let p = policy_with(serde_json::json!({"field_acl": {
            "*": {"res.partner": {"allow": ["name", "email"]}},
            "prod": {"res.partner": {"allow": ["name"]}}
        }}));
        assert!(!p.is_denied("prod", "res.partner", "name"));
        assert!(p.is_denied("prod", "res.partner", "email"));
        assert!(!p.is_denied("other", "res.partner", "email"));
    }

    #[test]
    fn redact_record_removes_denied() {
        let p = policy_with(serde_json::json!({"field_acl": {"*": {"*": {"deny": ["password"]}}}}));
        let mut rec = serde_json::json!({"id": 1, "name": "a", "password": "x"}).as_object().unwrap().clone();
        let removed = p.redact_record("a", "res.users", &mut rec);
        assert_eq!(removed, vec!["password".to_string()]);
        assert!(rec.get("id").is_some());
    }

    #[test]
    fn aggregate_blocked_on_denied() {
        let p = policy_with(serde_json::json!({"field_acl": {"*": {"account.move": {"deny": ["amount_total"]}}}}));
        assert!(p.check_aggregate("a", "account.move", &["amount_total:sum".into()], &[]).is_err());
        assert!(p.check_aggregate("a", "account.move", &["name".into()], &["date".into()]).is_ok());
    }
}
