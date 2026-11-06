use std::io::Write;

use serde_json::{Map, Number, Value};

pub fn dumps(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

pub fn emit(payload: &Value) {
    let encoded = dumps(payload);
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(encoded.as_bytes());
    let _ = stdout.write_all(b"\n");
}

pub fn emit_decision(decision: &str, reason: &str, event: &str) {
    emit(&decision_value(decision, reason, event));
}

pub fn decision_value(decision: &str, reason: &str, event: &str) -> Value {
    let mut inner = Map::new();
    inner.insert("hookEventName".to_owned(), Value::String(event.to_owned()));
    inner.insert(
        "permissionDecision".to_owned(),
        Value::String(decision.to_owned()),
    );
    inner.insert(
        "permissionDecisionReason".to_owned(),
        Value::String(reason.to_owned()),
    );
    let mut outer = Map::new();
    outer.insert("hookSpecificOutput".to_owned(), Value::Object(inner));
    Value::Object(outer)
}

pub fn python_float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_owned();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() {
            "-inf".to_owned()
        } else {
            "inf".to_owned()
        };
    }
    if value == 0.0 && value.is_sign_negative() {
        return "-0.0".to_owned();
    }
    let rendered = format!("{value:?}");
    normalize_python_float(&rendered)
}

fn python_json_float(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() {
            "-Infinity".to_owned()
        } else {
            "Infinity".to_owned()
        };
    }
    python_float_repr(value)
}

fn normalize_python_float(rendered: &str) -> String {
    let Some(marker) = rendered.find(['e', 'E']) else {
        if rendered.contains('.') {
            return rendered.to_owned();
        }
        let mut out = rendered.to_owned();
        out.push_str(".0");
        return out;
    };
    let mantissa = rendered.get(..marker).unwrap_or(rendered);
    let exponent = rendered.get(marker.saturating_add(1)..).unwrap_or("");
    let (sign, digits) = if let Some(rest) = exponent.strip_prefix('+') {
        ("+", rest)
    } else if let Some(rest) = exponent.strip_prefix('-') {
        ("-", rest)
    } else {
        ("+", exponent)
    };
    let width = digits.len().max(2);
    format!("{mantissa}e{sign}{digits:0>width$}")
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => write_number(out, number),
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => write_object(out, map),
    }
}

fn write_number(out: &mut String, number: &Number) {
    if let Some(text) = crate::pyjson::integer_text(number) {
        out.push_str(&text);
        return;
    }
    if let Some(value) = number.as_f64() {
        out.push_str(&python_json_float(value));
    }
}

fn write_object(out: &mut String, map: &Map<String, Value>) {
    let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
    keys.sort_unstable();
    out.push('{');
    for (index, key) in keys.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_string(out, key);
        out.push(':');
        if let Some(value) = map.get(*key) {
            write_value(out, value);
        } else {
            out.push_str("null");
        }
    }
    out.push('}');
}

fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        let code = ch as u32;
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ if code < 0x20 || code == 0x7f => push_u(out, code),
            _ if code < 0x7f => out.push(ch),
            _ if code <= 0xffff => push_u(out, code),
            _ => {
                let shifted = code - 0x1_0000;
                push_u(out, 0xD800 + ((shifted >> 10) & 0x3ff));
                push_u(out, 0xDC00 + (shifted & 0x3ff));
            }
        }
    }
    out.push('"');
}

fn push_u(out: &mut String, code: u32) {
    out.push_str("\\u");
    for shift in [12u32, 8, 4, 0] {
        let digit = ((code >> shift) & 0xf) as usize;
        let hex = b"0123456789abcdef";
        out.push(*hex.get(digit).unwrap_or(&b'0') as char);
    }
}

#[cfg(test)]
mod tests {
    use super::{decision_value, dumps, python_float_repr};
    use serde_json::json;

    #[test]
    fn dumps_matches_python_shape_for_mixed_values() {
        let value = json!({
            "b": [1, 1.0, true, null],
            "a": "café\n",
            "c": {"z": false, "y": ""}
        });
        assert_eq!(
            dumps(&value),
            "{\"a\":\"caf\\u00e9\\n\",\"b\":[1,1.0,true,null],\"c\":{\"y\":\"\",\"z\":false}}"
        );
    }

    #[test]
    fn control_del_and_non_bmp_use_python_escapes() {
        let value = json!(["\u{0000}", "\u{007f}", "\u{1f600}"]);
        assert_eq!(dumps(&value), r#"["\u0000","\u007f","\ud83d\ude00"]"#);
    }

    #[test]
    fn decision_payload_sorts_keys() {
        let payload = decision_value("deny", "no", "PreToolUse");
        assert_eq!(
            dumps(&payload),
            "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"no\"}}"
        );
    }

    #[test]
    fn float_repr_uses_python_exponent_form() {
        assert_eq!(python_float_repr(0.0), "0.0");
        assert_eq!(python_float_repr(-0.0), "-0.0");
        assert_eq!(python_float_repr(1.0), "1.0");
        assert_eq!(python_float_repr(0.1), "0.1");
        assert_eq!(python_float_repr(1e16), "1e+16");
        assert_eq!(python_float_repr(1e-5), "1e-05");
    }
}
