use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Declarative tool definition (mirrors rachmataditiya tools.json, Cursor-safe).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
    #[serde(default)]
    pub op: OpSpec,
    #[serde(default)]
    pub guards: Option<ToolGuards>,
    /// Exposition group: "read" (default) or "write". Gated by SAP_EXPOSITION
    /// (ala fr0ster --exposition) on top of guards.requiresEnvTrue.
    #[serde(default = "default_group")]
    pub group: String,
}

fn default_group() -> String {
    "read".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpSpec {
    #[serde(rename = "type", default)]
    pub op_type: String,
    #[serde(default)]
    pub map: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolGuards {
    #[serde(rename = "requiresEnvTrue", default)]
    pub requires_env_true: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptDef {
    pub name: String,
    pub description: String,
    pub content: String,
}

pub const SEED_TOOLS: &str = include_str!("../config/tools.json");
pub const SEED_PROMPTS: &str = include_str!("../config/prompts.json");
pub const SEED_SERVER: &str = include_str!("../config/server.json");

#[derive(Clone)]
pub struct Registry {
    pub tools: Vec<ToolDef>,
    pub prompts: Vec<PromptDef>,
    pub server_name: String,
    pub instructions: String,
}

impl Registry {
    pub fn load() -> Self {
        let tools = load_tools();
        let prompts = load_prompts();
        let (server_name, instructions) = load_server();
        Self {
            tools,
            prompts,
            server_name,
            instructions,
        }
    }

    pub fn list_tools(&self) -> Vec<ToolDef> {
        self.tools
            .iter()
            .filter(|t| guard_allows(&t.guards) && crate::config::exposition_allows(&t.group))
            .cloned()
            .collect()
    }

    pub fn get_tool(&self, name: &str) -> Option<ToolDef> {
        self.tools
            .iter()
            .find(|t| t.name == name)
            .filter(|t| guard_allows(&t.guards) && crate::config::exposition_allows(&t.group))
            .cloned()
    }
}

pub fn guard_allows(g: &Option<ToolGuards>) -> bool {
    match g {
        None => true,
        Some(gu) => match &gu.requires_env_true {
            None => true,
            Some(env) => std::env::var(env)
                .map(|v| crate::config::env_truthy(&v))
                .unwrap_or(false),
        },
    }
}

fn config_path(env_key: &str, fallback: &str) -> String {
    std::env::var(env_key).unwrap_or_else(|_| fallback.to_string())
}

fn load_tools() -> Vec<ToolDef> {
    let path = config_path("MCP_TOOLS_JSON", "config/tools.json");
    let txt = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[sa-mcp] cannot read {path} ({e}); using built-in tools");
            SEED_TOOLS.to_string()
        }
    };
    let v: serde_json::Value = match serde_json::from_str(&txt) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[sa-mcp] invalid JSON in {path} ({e}); using built-in tools");
            serde_json::from_str(SEED_TOOLS).unwrap()
        }
    };
    let arr = v.get("tools").unwrap_or(&v);
    let tools: Vec<ToolDef> = serde_json::from_value(arr.clone()).unwrap_or_default();
    for t in &tools {
        if let Err(e) = validate_cursor_schema(&t.input_schema) {
            eprintln!("[sa-mcp] tool '{}' schema Janet/Cursor risk: {e}", t.name);
        }
    }
    tools
}

fn load_prompts() -> Vec<PromptDef> {
    let path = config_path("MCP_PROMPTS_JSON", "config/prompts.json");
    let txt = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[sa-mcp] cannot read {path} ({e}); using built-in prompts");
            SEED_PROMPTS.to_string()
        }
    };
    let v: serde_json::Value = match serde_json::from_str(&txt) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[sa-mcp] invalid JSON in {path} ({e}); using built-in prompts");
            serde_json::from_str(SEED_PROMPTS).unwrap()
        }
    };
    let arr = v.get("prompts").unwrap_or(&v);
    serde_json::from_value(arr.clone()).unwrap_or_default()
}

fn load_server() -> (String, String) {
    let path = config_path("MCP_SERVER_JSON", "config/server.json");
    let txt = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => SEED_SERVER.to_string(),
    };
    let v: serde_json::Value =
        serde_json::from_str(&txt).unwrap_or_else(|_| serde_json::from_str(SEED_SERVER).unwrap());
    let name = v
        .get("serverName")
        .and_then(|s| s.as_str())
        .unwrap_or("sa-mcp")
        .to_string();
    let instr = v
        .get("instructions")
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    (name, instr)
}

/// Validate Cursor schema constraints (no anyOf/oneOf/allOf/$ref/definitions/type-array).
pub fn validate_cursor_schema(schema: &serde_json::Value) -> Result<(), String> {
    let s = schema.to_string();
    for bad in ["anyOf", "oneOf", "allOf", "$ref", "definitions"] {
        if s.contains(&format!("\"{}\"", bad)) {
            return Err(format!("schema contains forbidden keyword {}", bad));
        }
    }
    Ok(())
}
