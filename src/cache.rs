use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type CacheKey = (String, String);
type CacheEntry = (serde_json::Value, Instant);

#[derive(Clone)]
pub struct MetadataCache {
    inner: Arc<Mutex<HashMap<CacheKey, CacheEntry>>>,
    ttl: Duration,
}

impl MetadataCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    pub fn get(&self, instance: &str, model: &str) -> Option<serde_json::Value> {
        if self.ttl.is_zero() {
            return None;
        }
        let map = self.inner.lock().ok()?;
        let (v, at) = map.get(&(instance.to_string(), model.to_string()))?;
        if at.elapsed() > self.ttl {
            return None;
        }
        Some(v.clone())
    }

    pub fn insert(&self, instance: &str, model: &str, v: serde_json::Value) {
        if self.ttl.is_zero() {
            return;
        }
        if let Ok(mut map) = self.inner.lock() {
            map.insert(
                (instance.to_string(), model.to_string()),
                (v, Instant::now()),
            );
        }
    }
}
