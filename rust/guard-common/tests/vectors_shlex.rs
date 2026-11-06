use guard_common::shlex::{quote, split, Lexer, ShlexError};

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Null,
    Bool(bool),
    Number(i64),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

#[test]
fn shlex_vectors_match_python() {
    let parsed = parse_json(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/shlex.json")).expect("vector file missing: run rust/gen-vectors.sh"));
    let Value::Array(rows) = parsed else {
        panic!("vector file is not a list");
    };
    for row in &rows {
        let name = text(field(row, "fn"));
        let args = array(field(row, "args"));
        let expected = field(row, "ret");
        let exc = field(row, "exc");
        let actual = replay(&name, args);
        match exc {
            Value::Null => match actual {
                Ok(value) => assert_eq!(&value, expected, "{name}"),
                Err(error) => panic!("{name} raised {} expected {expected:?}", error.message),
            },
            Value::String(kind) => match actual {
                Err(error) => {
                    assert_eq!(kind, "ValueError", "{name}");
                    if let Value::String(message) = expected {
                        assert_eq!(&error.message, message, "{name}");
                    }
                }
                Ok(value) => panic!("{name} returned {value:?} expected {kind}"),
            },
            other => panic!("bad exc {other:?}"),
        }
    }
}

fn replay(name: &str, args: &[Value]) -> Result<Value, ShlexError> {
    match name {
        "quote" => Ok(Value::String(quote(&text(&args[0])))),
        "split" => split(&text(&args[0])).map(strings),
        "tokens" => {
            let spec = &args[0];
            let mut lexer = Lexer::new(&text(field(spec, "text"))).posix(flag(field(spec, "posix")));
            lexer = lexer.punctuation_chars(&text(field(spec, "punctuation_chars")));
            lexer = lexer.whitespace(&text(field(spec, "whitespace")));
            lexer = lexer.whitespace_split(flag(field(spec, "whitespace_split")));
            lexer = lexer.commenters(&text(field(spec, "commenters")));
            lexer.tokens().map(strings)
        }
        other => panic!("unknown fn {other}"),
    }
}

fn strings(items: Vec<String>) -> Value {
    Value::Array(items.into_iter().map(Value::String).collect())
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    let Value::Object(fields) = value else {
        panic!("expected object");
    };
    fields.iter().find(|(name, _)| name == key).map(|(_, item)| item).unwrap_or(&Value::Null)
}

fn array(value: &Value) -> &[Value] {
    match value {
        Value::Array(items) => items,
        _ => panic!("expected array"),
    }
}

fn text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        _ => panic!("expected string, got {value:?}"),
    }
}

fn flag(value: &Value) -> bool {
    match value {
        Value::Bool(flag) => *flag,
        _ => panic!("expected bool"),
    }
}

fn parse_json(text: &str) -> Value {
    let mut parser = Parser { bytes: text.as_bytes(), index: 0 };
    let value = parser.value();
    parser.skip();
    assert!(parser.index == parser.bytes.len(), "trailing json");
    value
}

struct Parser<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> Parser<'a> {
    fn value(&mut self) -> Value {
        self.skip();
        match self.peek() {
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'"') => Value::String(self.string()),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(b'-') | Some(b'0'..=b'9') => Value::Number(self.number()),
            other => panic!("bad json at {} {:?}", self.index, other),
        }
    }

    fn literal(&mut self, text: &[u8], value: Value) -> Value {
        for byte in text {
            assert_eq!(self.bump(), *byte);
        }
        value
    }

    fn array(&mut self) -> Value {
        assert_eq!(self.bump(), b'[');
        let mut items = Vec::new();
        self.skip();
        if self.peek() == Some(b']') {
            self.bump();
            return Value::Array(items);
        }
        loop {
            items.push(self.value());
            self.skip();
            match self.bump() {
                b']' => break,
                b',' => continue,
                other => panic!("bad array {other}"),
            }
        }
        Value::Array(items)
    }

    fn object(&mut self) -> Value {
        assert_eq!(self.bump(), b'{');
        let mut fields = Vec::new();
        self.skip();
        if self.peek() == Some(b'}') {
            self.bump();
            return Value::Object(fields);
        }
        loop {
            self.skip();
            let key = self.string();
            self.skip();
            assert_eq!(self.bump(), b':');
            let value = self.value();
            fields.push((key, value));
            self.skip();
            match self.bump() {
                b'}' => break,
                b',' => continue,
                other => panic!("bad object {other}"),
            }
        }
        Value::Object(fields)
    }

    fn number(&mut self) -> i64 {
        let start = self.index;
        if self.peek() == Some(b'-') {
            self.index += 1;
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.index += 1;
        }
        std::str::from_utf8(&self.bytes[start..self.index]).unwrap().parse().unwrap()
    }

    fn string(&mut self) -> String {
        assert_eq!(self.bump(), b'"');
        let mut out = String::new();
        loop {
            let byte = self.bump();
            match byte {
                b'"' => return out,
                b'\\' => match self.bump() {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000c}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let mut code = 0u32;
                        for _ in 0..4 {
                            code = code * 16 + hex(self.bump());
                        }
                        out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                    }
                    other => out.push(other as char),
                },
                below if below < 0x80 => out.push(below as char),
                lead => {
                    let width = if lead & 0xe0 == 0xc0 {
                        2
                    } else if lead & 0xf0 == 0xe0 {
                        3
                    } else {
                        4
                    };
                    let mut buf = vec![lead];
                    for _ in 1..width {
                        buf.push(self.bump());
                    }
                    out.push_str(std::str::from_utf8(&buf).unwrap());
                }
            }
        }
    }

    fn skip(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.index += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn bump(&mut self) -> u8 {
        let byte = self.peek().unwrap();
        self.index += 1;
        byte
    }
}

fn hex(byte: u8) -> u32 {
    match byte {
        b'0'..=b'9' => u32::from(byte - b'0'),
        b'a'..=b'f' => u32::from(byte - b'a') + 10,
        b'A'..=b'F' => u32::from(byte - b'A') + 10,
        _ => panic!("bad hex"),
    }
}
