use serde_json::{Number, Value};

// Measured on Python 3.12: json.loads parses 9997 levels and refuses 9998.
pub const MAX_NESTING: usize = 9997;

pub fn nesting_exceeds(raw: &[u8]) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in raw {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth = depth.saturating_add(1);
                if depth > MAX_NESTING {
                    return true;
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

pub fn loads(raw: &[u8]) -> Option<Value> {
    if nesting_exceeds(raw) {
        return None;
    }
    let mut reader = serde_json::Deserializer::from_slice(raw);
    reader.disable_recursion_limit();
    let mut stream = reader.into_iter::<Value>();
    let value = stream.next()?.ok()?;
    let rest = raw.get(stream.byte_offset()..)?;
    rest.iter()
        .all(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        .then_some(value)
}

pub fn integer_text(number: &Number) -> Option<String> {
    let lexeme = number.to_string();
    let digits = lexeme.strip_prefix('-').unwrap_or(&lexeme);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if lexeme.starts_with('-') && digits.bytes().all(|byte| byte == b'0') {
        return Some("0".to_owned());
    }
    Some(lexeme)
}

#[cfg(test)]
mod tests {
    use super::{integer_text, loads, nesting_exceeds, MAX_NESTING};
    use serde_json::Value;

    fn nested(count: usize) -> Vec<u8> {
        let mut raw = vec![b'['; count];
        raw.extend(vec![b']'; count]);
        raw
    }

    #[test]
    fn nesting_is_accepted_up_to_the_python_limit_and_refused_beyond() {
        let worker = std::thread::Builder::new().stack_size(256 * 1024 * 1024).spawn(|| {
            assert!(loads(&nested(MAX_NESTING)).is_some());
            assert!(!nesting_exceeds(&nested(MAX_NESTING)));
            assert!(loads(&nested(MAX_NESTING + 1)).is_none());
            assert!(nesting_exceeds(&nested(MAX_NESTING + 1)));
            let quoted = format!("[{}\"\"]", "\"[[[[\",".repeat(MAX_NESTING + 5));
            assert!(loads(quoted.as_bytes()).is_some());
        });
        assert!(worker.expect("spawn").join().is_ok());
    }

    #[test]
    fn trailing_data_and_empty_input_are_refused() {
        assert!(loads(b"{} \n\t\r").is_some());
        assert!(loads(b"{} x").is_none());
        assert!(loads(b"{}{}").is_none());
        assert!(loads(b"").is_none());
        assert!(loads(b"   ").is_none());
    }

    #[test]
    fn integers_keep_every_digit_and_floats_are_not_integers() {
        let parse = |text: &str| match loads(text.as_bytes()) {
            Some(Value::Number(number)) => integer_text(&number),
            _ => None,
        };
        assert_eq!(parse("18446744073709551616").as_deref(), Some("18446744073709551616"));
        assert_eq!(parse("-18446744073709551617").as_deref(), Some("-18446744073709551617"));
        assert_eq!(parse("-0").as_deref(), Some("0"));
        assert_eq!(parse("7").as_deref(), Some("7"));
        assert_eq!(parse("1.5"), None);
        assert_eq!(parse("1e3"), None);
        assert_eq!(parse("-0.0"), None);
    }
}
