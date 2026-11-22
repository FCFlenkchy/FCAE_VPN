//! In-app control boundary for the userspace routing policy.
use serde_json::{json, Value};
pub fn request(input: &str) -> String {
    if input.len() > 65536 {
        return json!({"ok":false,"message":"request too large"}).to_string();
    }
    let value: Value = match serde_json::from_str(input) {
        Ok(value) => value,
        Err(_) => return json!({"ok":false,"message":"invalid routing request"}).to_string(),
    };
    if value["action"]
        .as_str()
        .is_some_and(|action| action.starts_with("flow_"))
    {
        crate::desktop_flow_routing::request(&value).to_string()
    } else if matches!(
        value["action"].as_str(),
        Some("shutdown" | "stop" | "status")
    ) {
        json!({"ok":true,"active":false,"message":""}).to_string()
    } else {
        json!({"ok":false,"message":"unsupported routing operation"}).to_string()
    }
}
