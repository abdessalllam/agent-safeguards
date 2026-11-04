use std::sync::OnceLock;

use serde_json::{Map, Value};

const SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../locales/en.json"));

static TABLE: OnceLock<Map<String, Value>> = OnceLock::new();

fn table() -> &'static Map<String, Value> {
    TABLE.get_or_init(|| match serde_json::from_str::<Value>(SOURCE) {
        Ok(Value::Object(map)) => map,
        _ => Map::new(),
    })
}

pub fn message(key: &str, values: &[(&str, &str)]) -> String {
    let Some(template) = table().get(key).and_then(Value::as_str) else {
        return key.to_owned();
    };
    let mut out = String::with_capacity(template.len().saturating_add(32));
    let bytes = template.as_bytes();
    let mut i = 0usize;
    while let Some(byte) = bytes.get(i) {
        if *byte == b'{' {
            let name_start = i.saturating_add(1);
            if let Some(close) = template.get(name_start..).and_then(|rest| rest.find('}')) {
                let name_end = name_start.saturating_add(close);
                if let Some(name) = template.get(name_start..name_end) {
                    if let Some((_, value)) = values.iter().find(|(k, _)| *k == name) {
                        out.push_str(value);
                        i = name_end.saturating_add(1);
                        continue;
                    }
                }
            }
        }
        match template.get(i..).and_then(|rest| rest.chars().next()) {
            Some(c) => {
                out.push(c);
                i = i.saturating_add(c.len_utf8());
            }
            None => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::message;

    #[test]
    fn replaces_known_placeholders_and_keeps_unknown_ones() {
        let text = message("comment_guard.detail.too_long", &[("file", "a.rs"), ("limit", "100")]);
        assert!(text.contains("a.rs"));
        assert!(text.contains("100"));
        let raw = message("comment_guard.detail.too_long", &[("file", "a.rs")]);
        assert!(raw.contains("{limit}"));
    }

    #[test]
    fn unknown_key_returns_itself() {
        let key = format!("comment_guard.{}", "nope");
        assert_eq!(message(&key, &[]), key);
    }
}
