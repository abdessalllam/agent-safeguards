use serde_json::{Map, Number, Value};

// Measured on Python 3.12: json.loads parses 9997 levels and refuses 9998.
pub const MAX_NESTING: usize = 9997;
const MAX_INT_DIGITS: usize = 4300;

fn decode_utf16(raw: &[u8], big: bool) -> Option<String> {
    if !raw.len().is_multiple_of(2) {
        return None;
    }
    let units = raw.chunks_exact(2).map(|pair| {
        let first = pair.first().copied().unwrap_or(0);
        let second = pair.get(1).copied().unwrap_or(0);
        if big {
            u16::from_be_bytes([first, second])
        } else {
            u16::from_le_bytes([first, second])
        }
    });
    char::decode_utf16(units).collect::<Result<String, _>>().ok()
}

fn decode_utf32(raw: &[u8], big: bool) -> Option<String> {
    if !raw.len().is_multiple_of(4) {
        return None;
    }
    raw.chunks_exact(4)
        .map(|quad| {
            let bytes = [
                quad.first().copied().unwrap_or(0),
                quad.get(1).copied().unwrap_or(0),
                quad.get(2).copied().unwrap_or(0),
                quad.get(3).copied().unwrap_or(0),
            ];
            let code = if big { u32::from_be_bytes(bytes) } else { u32::from_le_bytes(bytes) };
            char::from_u32(code)
        })
        .collect()
}

fn decode_text(raw: &[u8]) -> Option<String> {
    if raw.starts_with(&[0xFF, 0xFE, 0, 0]) {
        return decode_utf32(raw.get(4..)?, false);
    }
    if raw.starts_with(&[0, 0, 0xFE, 0xFF]) {
        return decode_utf32(raw.get(4..)?, true);
    }
    if raw.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16(raw.get(2..)?, false);
    }
    if raw.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16(raw.get(2..)?, true);
    }
    if raw.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return std::str::from_utf8(raw.get(3..)?).ok().map(str::to_owned);
    }
    let first = raw.first().copied().unwrap_or(1);
    let second = raw.get(1).copied().unwrap_or(1);
    if raw.len() >= 4 {
        let third = raw.get(2).copied().unwrap_or(0);
        let fourth = raw.get(3).copied().unwrap_or(0);
        if first == 0 {
            return if second != 0 { decode_utf16(raw, true) } else { decode_utf32(raw, true) };
        }
        if second == 0 {
            return if third != 0 || fourth != 0 { decode_utf16(raw, false) } else { decode_utf32(raw, false) };
        }
    } else if raw.len() == 2 {
        if first == 0 {
            return decode_utf16(raw, true);
        }
        if second == 0 {
            return decode_utf16(raw, false);
        }
    }
    std::str::from_utf8(raw).ok().map(str::to_owned)
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at = self.at.saturating_add(1);
        }
    }

    fn literal(&mut self, word: &str) -> bool {
        let found = self.bytes.get(self.at..).is_some_and(|rest| rest.starts_with(word.as_bytes()));
        if found {
            self.at = self.at.saturating_add(word.len());
        }
        found
    }

    fn value(&mut self, depth: usize) -> Option<Value> {
        match self.peek()? {
            b'"' => self.string().map(Value::String),
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'n' => self.literal("null").then_some(Value::Null),
            b't' => self.literal("true").then_some(Value::Bool(true)),
            b'f' => self.literal("false").then_some(Value::Bool(false)),
            b'N' => self.literal("NaN").then_some(Value::Null),
            b'I' => self.literal("Infinity").then_some(Value::Null),
            b'-' if self.bytes.get(self.at..).is_some_and(|rest| rest.starts_with(b"-Infinity")) => {
                self.literal("-Infinity").then_some(Value::Null)
            }
            _ => self.number(),
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.at;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.at = self.at.saturating_add(1);
        }
        self.at.saturating_sub(start)
    }

    fn number(&mut self) -> Option<Value> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at = self.at.saturating_add(1);
        }
        let integer_digits = match self.peek()? {
            b'0' => {
                self.at = self.at.saturating_add(1);
                1
            }
            b'1'..=b'9' => self.digits(),
            _ => return None,
        };
        let mut is_float = false;
        if self.peek() == Some(b'.') && self.bytes.get(self.at.saturating_add(1)).is_some_and(u8::is_ascii_digit) {
            self.at = self.at.saturating_add(1);
            self.digits();
            is_float = true;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            let mut probe = self.at.saturating_add(1);
            if matches!(self.bytes.get(probe), Some(b'+' | b'-')) {
                probe = probe.saturating_add(1);
            }
            if self.bytes.get(probe).is_some_and(u8::is_ascii_digit) {
                self.at = probe;
                self.digits();
                is_float = true;
            }
        }
        if !is_float && integer_digits > MAX_INT_DIGITS {
            return None;
        }
        let lexeme = std::str::from_utf8(self.bytes.get(start..self.at)?).ok()?;
        serde_json::from_str::<Number>(lexeme).ok().map(Value::Number)
    }

    fn hex4(&mut self) -> Option<u32> {
        let quad = self.bytes.get(self.at..self.at.saturating_add(4))?;
        let text = std::str::from_utf8(quad).ok()?;
        if !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        self.at = self.at.saturating_add(4);
        u32::from_str_radix(text, 16).ok()
    }

    fn string(&mut self) -> Option<String> {
        self.at = self.at.saturating_add(1);
        let mut out = String::new();
        loop {
            let start = self.at;
            while self.peek().is_some_and(|byte| byte != b'"' && byte != b'\\' && byte >= 0x20) {
                self.at = self.at.saturating_add(1);
            }
            out.push_str(std::str::from_utf8(self.bytes.get(start..self.at)?).ok()?);
            match self.peek()? {
                b'"' => {
                    self.at = self.at.saturating_add(1);
                    return Some(out);
                }
                b'\\' => {
                    self.at = self.at.saturating_add(1);
                    let escape = self.peek()?;
                    self.at = self.at.saturating_add(1);
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let unit = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&unit) {
                                if !self.literal("\\u") {
                                    return None;
                                }
                                let low = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&low) {
                                    return None;
                                }
                                0x1_0000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
                            } else {
                                unit
                            };
                            out.push(char::from_u32(code)?);
                        }
                        _ => return None,
                    }
                }
                _ => return None,
            }
        }
    }

    fn object(&mut self, depth: usize) -> Option<Value> {
        let depth = depth.saturating_add(1);
        if depth > MAX_NESTING {
            return None;
        }
        self.at = self.at.saturating_add(1);
        let mut map = Map::new();
        self.skip_space();
        if self.peek() == Some(b'}') {
            self.at = self.at.saturating_add(1);
            return Some(Value::Object(map));
        }
        loop {
            self.skip_space();
            if self.peek() != Some(b'"') {
                return None;
            }
            let key = self.string()?;
            self.skip_space();
            if self.peek() != Some(b':') {
                return None;
            }
            self.at = self.at.saturating_add(1);
            self.skip_space();
            let value = self.value(depth)?;
            map.insert(key, value);
            self.skip_space();
            match self.peek()? {
                b',' => self.at = self.at.saturating_add(1),
                b'}' => {
                    self.at = self.at.saturating_add(1);
                    return Some(Value::Object(map));
                }
                _ => return None,
            }
        }
    }

    fn array(&mut self, depth: usize) -> Option<Value> {
        let depth = depth.saturating_add(1);
        if depth > MAX_NESTING {
            return None;
        }
        self.at = self.at.saturating_add(1);
        let mut items = Vec::new();
        self.skip_space();
        if self.peek() == Some(b']') {
            self.at = self.at.saturating_add(1);
            return Some(Value::Array(items));
        }
        loop {
            self.skip_space();
            items.push(self.value(depth)?);
            self.skip_space();
            match self.peek()? {
                b',' => self.at = self.at.saturating_add(1),
                b']' => {
                    self.at = self.at.saturating_add(1);
                    return Some(Value::Array(items));
                }
                _ => return None,
            }
        }
    }
}

pub fn loads(raw: &[u8]) -> Option<Value> {
    let text = decode_text(raw)?;
    if text.starts_with('\u{feff}') {
        return None;
    }
    let mut parser = Parser { bytes: text.as_bytes(), at: 0 };
    parser.skip_space();
    let value = parser.value(0)?;
    parser.skip_space();
    (parser.at == parser.bytes.len()).then_some(value)
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
    use super::{integer_text, loads, MAX_NESTING};
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
            assert!(loads(&nested(MAX_NESTING + 1)).is_none());
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
        assert!(loads(b"[1,]").is_none());
        assert!(loads(b"{\"a\":1,}").is_none());
        assert!(loads(b"01").is_none());
        assert!(loads(b"1.").is_none());
        assert!(loads(b"\"a\nb\"").is_none());
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
        assert!(loads("9".repeat(4300).as_bytes()).is_some());
        assert!(loads("9".repeat(4301).as_bytes()).is_none());
        assert!(loads(format!("{}.5", "9".repeat(5000)).as_bytes()).is_some());
    }

    #[test]
    fn byte_encodings_follow_python() {
        let object = "{\"a\":\"é\"}";
        let expected = loads(object.as_bytes()).expect("utf-8");
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend(object.as_bytes());
        assert_eq!(loads(&bom), Some(expected.clone()));
        let units: Vec<u16> = object.encode_utf16().collect();
        let le: Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        let be: Vec<u8> = units.iter().flat_map(|unit| unit.to_be_bytes()).collect();
        assert_eq!(loads(&le), Some(expected.clone()));
        assert_eq!(loads(&be), Some(expected.clone()));
        let mut with_bom = vec![0xFF, 0xFE];
        with_bom.extend(&le);
        assert_eq!(loads(&with_bom), Some(expected.clone()));
        let wide: Vec<u8> = object.chars().flat_map(|c| (c as u32).to_be_bytes()).collect();
        assert_eq!(loads(&wide), Some(expected));
        assert!(loads(&[0xFF, 0xFE, b'{']).is_none());
        assert!(loads(b"\xef\xbb\xbf\xef\xbb\xbf{}").is_none());
        assert!(loads(&[b'{', 0xC3, b'}']).is_none());
    }

    #[test]
    fn strings_objects_and_literals_follow_python() {
        let marker = loads(b"{\"$serde_json::private::Number\":\"0\",\"a\":1}").expect("marker key");
        assert_eq!(marker.get("a"), Some(&Value::Number(1.into())));
        assert_eq!(marker.get("$serde_json::private::Number"), Some(&Value::String("0".into())));
        let doubled = loads(b"{\"a\":1,\"a\":2}").expect("duplicate keys");
        assert_eq!(doubled.get("a"), Some(&Value::Number(2.into())));
        let text = loads(b"\"\\ud83d\\ude00 \\u00e9\\n\\/\"").and_then(|value| value.as_str().map(str::to_owned));
        assert_eq!(text, Some("\u{1f600} é\n/".to_owned()));
        assert!(loads(b"\"\\ud83d\"").is_none());
        assert!(loads(b"\"\\q\"").is_none());
        assert!(loads(b"\"\\u12\"").is_none());
        let literals = loads(b"[NaN,Infinity,-Infinity,null,true,false]").map(|value| value.to_string());
        assert_eq!(literals, Some("[null,null,null,null,true,false]".to_owned()));
    }
}
