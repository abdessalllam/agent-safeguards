use std::collections::HashSet;

use guard_common::shell::{
    at_command_start, brace_options, closing_backtick, closing_parenthesis, closing_quote,
    command_substitutions, double_parenthesis_end, drop_descriptor, expand_braces, expression_end,
    find_terminator, first_operand, heredocs, mark_opening_quotes, normalize_command, option_names,
    option_value, read_bodies, read_delimiter, scan_code, scan_double_quoted, skip_operand,
    skip_quoted, split_options, strip_wrappers, strip_wrappers_with_directory, test_end,
    unquoted_lines, unquoted_text, BraceError, HereDocument, PendingHere, HEREDOC_FORBIDDEN,
};

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
fn shell_vectors_match_python() {
    let parsed = parse_json(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/fuzz_shell.json")).expect("vector file missing: run rust/gen-vectors.sh"));
    let Value::Array(rows) = parsed else {
        panic!("vector file is not a list");
    };
    let mut mismatches = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let name = text(field(row, "fn"));
        let args = array(field(row, "args"));
        let expected = field(row, "ret");
        let actual = replay(&name, args);
        let mismatch = match field(row, "exc") {
            Value::Null => match actual {
                Ok(value) if &value == expected => None,
                Ok(value) => Some(format!(
                    "row {index} {name} args {} got {} expected {}",
                    preview(args),
                    short(&value),
                    short(expected)
                )),
                Err(error) => Some(format!(
                    "row {index} {name} args {} raised {error} expected {}",
                    preview(args),
                    short(expected)
                )),
            },
            Value::String(kind) => match actual {
                Err(error) if &error == kind => None,
                Err(error) => Some(format!(
                    "row {index} {name} args {} raised {error} expected {kind}",
                    preview(args)
                )),
                Ok(value) => Some(format!(
                    "row {index} {name} args {} returned {} expected {kind}",
                    preview(args),
                    short(&value)
                )),
            },
            other => Some(format!("row {index} bad exc {}", short(other))),
        };
        if let Some(line) = mismatch {
            mismatches.push(line);
        }
    }
    if !mismatches.is_empty() {
        let shown = mismatches.len().min(60);
        let mut report = format!("{} mismatches\n", mismatches.len());
        for line in mismatches.iter().take(shown) {
            println!("{line}");
            report.push_str(line);
            report.push('\n');
        }
        panic!("{report}");
    }
}

fn replay(name: &str, args: &[Value]) -> Result<Value, String> {
    match name {
        "closing_quote" => match closing_quote(&text(&args[0]), as_usize(&args[1])) {
            Ok(Some(index)) => Ok(num(index)),
            Ok(None) => Ok(Value::Null),
            Err(_) => Err("IndexError".to_string()),
        },
        "skip_quoted" => match skip_quoted(&text(&args[0]), as_usize(&args[1])) {
            Ok(index) => Ok(num(index)),
            Err(_) => Err("IndexError".to_string()),
        },
        "skip_operand" => Ok(num(skip_operand(&text(&args[0]), as_usize(&args[1])))),
        "at_command_start" => Ok(Value::Bool(at_command_start(&words(&args[0])))),
        "test_end" => Ok(opt_num(test_end(&text(&args[0]), as_usize(&args[1])))),
        "expression_end" => Ok(opt_num(expression_end(
            &text(&args[0]),
            as_usize(&args[1]),
            flag(&args[2]),
            &words(&args[3]),
        ))),
        "double_parenthesis_end" => Ok(opt_num(double_parenthesis_end(&text(&args[0]), as_usize(&args[1])))),
        "drop_descriptor" => {
            let mut kept = words(&args[0]);
            let dropped = drop_descriptor(&mut kept);
            Ok(object(&[("dropped", Value::String(dropped)), ("kept", strs(kept))]))
        }
        "first_operand" => Ok(opt_num(first_operand(&words(&args[0]), &text(&args[1]), &set_of(&args[2])))),
        "split_options" => Ok(strs(split_options(&words(&args[0]), &text(&args[1]), &set_of(&args[2])))),
        "normalize_command" => {
            let command = text(&args[0]);
            if matches!(args.get(1), Some(Value::Null)) {
                Ok(Value::String(normalize_command(&command, None)))
            } else {
                let mut redirects = triples(args.get(1).unwrap_or(&Value::Null));
                let text = normalize_command(&command, Some(&mut redirects));
                Ok(object(&[("text", Value::String(text)), ("redirects", triples_value(redirects))]))
            }
        }
        "unquoted_text" => Ok(Value::String(unquoted_text(&text(&args[0])))),
        "unquoted_lines" => Ok(strs(unquoted_lines(&text(&args[0])))),
        "mark_opening_quotes" => Ok(Value::String(mark_opening_quotes(&text(&args[0])))),
        "read_delimiter" => Ok(match read_delimiter(&text(&args[0]), as_usize(&args[1])) {
            None => Value::Null,
            Some((delimiter, quoted, index)) => Value::Array(vec![Value::String(delimiter), Value::Bool(quoted), num(index)]),
        }),
        "find_terminator" => Ok(match find_terminator(&text(&args[0]), as_usize(&args[1]), &text(&args[2]), flag(&args[3])) {
            None => Value::Null,
            Some((start, end)) => Value::Array(vec![num(start), num(end)]),
        }),
        "read_bodies" => match read_bodies(&text(&args[0]), as_usize(&args[1]), &pending(&args[2])) {
            Ok((index, found)) => Ok(scan_value(index, &found)),
            Err(_) => Err("Unplaceable".to_string()),
        },
        "scan_double_quoted" => {
            match scan_double_quoted(&text(&args[0]), as_usize(&args[1]), as_usize(&args[2]), as_usize(&args[3])) {
                Ok((index, found)) => Ok(scan_value(index, &found)),
                Err(_) => Err("Unplaceable".to_string()),
            }
        }
        "scan_code" => match scan_code(&text(&args[0]), as_usize(&args[1]), flag(&args[2]), as_usize(&args[3]), outer(&args[4])) {
            Ok((index, found)) => Ok(scan_value(index, &found)),
            Err(_) => Err("Unplaceable".to_string()),
        },
        "heredocs" => Ok(Value::Array(heredocs(&text(&args[0])).iter().map(document).collect())),
        "closing_parenthesis" => Ok(num(closing_parenthesis(&text(&args[0]), as_usize(&args[1])))),
        "closing_backtick" => Ok(num(closing_backtick(&text(&args[0]), as_usize(&args[1])))),
        "command_substitutions" => Ok(strs(command_substitutions(&text(&args[0])))),
        "brace_options" => match brace_options(&text(&args[0])) {
            Ok(Some(values)) => Ok(strs(values)),
            Ok(None) => Ok(Value::Null),
            Err(BraceError::NoMatch) => Err("NoMatch".to_string()),
            Err(BraceError::ValueError) => Err("ValueError".to_string()),
        },
        "expand_braces" => match expand_braces(&text(&args[0])) {
            Ok(Some(values)) => Ok(strs(values)),
            Ok(None) => Ok(Value::Null),
            Err(_) => Err("ValueError".to_string()),
        },
        "option_names" => {
            let (names, takes_next) = option_names(&text(&args[0]), &set_of(&args[1]));
            Ok(Value::Array(vec![strs(names), Value::Bool(takes_next)]))
        }
        "option_value" => match option_value(&text(&args[0]), &text(&args[1]), &words(&args[2]), as_usize(&args[3])) {
            Ok(value) => Ok(Value::String(value)),
            Err(_) => Err("ValueError".to_string()),
        },
        "strip_wrappers_with_directory" => match strip_wrappers_with_directory(&words(&args[0]), &set_of(&args[1])) {
            Ok((rest, moved)) => Ok(Value::Array(vec![strs(rest), strs(moved)])),
            Err(_) => Err("UnresolvableCommand".to_string()),
        },
        "strip_wrappers" => match strip_wrappers(&words(&args[0]), &set_of(&args[1])) {
            Ok(rest) => Ok(strs(rest)),
            Err(_) => Err("UnresolvableCommand".to_string()),
        },
        "heredoc_forbidden" => Ok(Value::Bool(HEREDOC_FORBIDDEN.is_match(&text(&args[0])))),
        "assignment_matches" => Ok(Value::Bool(assignment_matches(&text(&args[0])))),
        "duration_matches" => Ok(Value::Bool(duration_matches(&text(&args[0])))),
        other => panic!("unknown fn {other}"),
    }
}

fn assignment_matches(text: &str) -> bool {
    guard_common::shell::ASSIGNMENT.is_match(text)
}

fn duration_matches(text: &str) -> bool {
    guard_common::shell::DURATION.is_match(text)
}

fn document(doc: &HereDocument) -> Value {
    object(&[
        ("line_start", num(doc.line_start)),
        ("marker_start", num(doc.marker_start)),
        ("delimiter_end", num(doc.delimiter_end)),
        ("line_end", num(doc.line_end)),
        ("body_start", num(doc.body_start)),
        ("body_end", num(doc.body_end)),
        ("end", num(doc.end)),
        ("quoted", Value::Bool(doc.quoted)),
        ("outer", outer_value(&doc.outer)),
    ])
}

fn scan_value(index: usize, found: &[HereDocument]) -> Value {
    object(&[("index", num(index)), ("found", Value::Array(found.iter().map(document).collect()))])
}

fn outer_value(outer: &Option<(i64, i64, String)>) -> Value {
    match outer {
        None => Value::Null,
        Some((left, right, text)) => Value::Array(vec![Value::Number(*left), Value::Number(*right), Value::String(text.clone())]),
    }
}

fn pending(value: &Value) -> Vec<PendingHere> {
    array(value)
        .iter()
        .map(|item| PendingHere {
            line_start: as_usize(field(item, "line_start")),
            marker_start: as_usize(field(item, "marker_start")),
            delimiter_end: as_usize(field(item, "delimiter_end")),
            delimiter: text(field(item, "delimiter")),
            strip_tabs: flag(field(item, "strip_tabs")),
            quoted: flag(field(item, "quoted")),
            outer: outer(field(item, "outer")),
        })
        .collect()
}

fn outer(value: &Value) -> Option<(i64, i64, String)> {
    match value {
        Value::Null => None,
        Value::Array(items) => Some((as_i64(&items[0]), as_i64(&items[1]), text(&items[2]))),
        _ => panic!("bad outer"),
    }
}

fn triples(value: &Value) -> Vec<(String, String, String)> {
    array(value)
        .iter()
        .map(|item| {
            let parts = array(item);
            (text(&parts[0]), text(&parts[1]), text(&parts[2]))
        })
        .collect()
}

fn triples_value(items: Vec<(String, String, String)>) -> Value {
    Value::Array(
        items
            .into_iter()
            .map(|(left, mid, right)| Value::Array(vec![Value::String(left), Value::String(mid), Value::String(right)]))
            .collect(),
    )
}

fn object(fields: &[(&str, Value)]) -> Value {
    Value::Object(fields.iter().map(|(key, value)| ((*key).to_string(), value.clone())).collect())
}

fn strs(items: Vec<String>) -> Value {
    Value::Array(items.into_iter().map(Value::String).collect())
}

fn words(value: &Value) -> Vec<String> {
    array(value).iter().map(text).collect()
}

fn set_of(value: &Value) -> HashSet<String> {
    words(value).into_iter().collect()
}

fn num(value: usize) -> Value {
    Value::Number(i64::try_from(value).unwrap_or(i64::MAX))
}

fn opt_num(value: Option<usize>) -> Value {
    match value {
        Some(index) => num(index),
        None => Value::Null,
    }
}

fn preview(args: &[Value]) -> String {
    format!("{args:?}")
}

fn short(value: &Value) -> String {
    let mut text = format!("{value:?}");
    if text.len() > 240 {
        text.truncate(240);
    }
    text
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
        _ => panic!("expected array, got {value:?}"),
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
        _ => panic!("expected bool, got {value:?}"),
    }
}

fn as_usize(value: &Value) -> usize {
    usize::try_from(as_i64(value)).unwrap_or(0)
}

fn as_i64(value: &Value) -> i64 {
    match value {
        Value::Number(number) => *number,
        _ => panic!("expected number, got {value:?}"),
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
            fields.push((key, self.value()));
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
            match self.bump() {
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
