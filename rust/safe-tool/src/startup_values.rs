use std::collections::HashMap;

#[derive(Clone, Copy)]
struct Variant {
    truncate_nul: bool,
    zsh_control: bool,
}

const BASH: Variant = Variant { truncate_nul: true, zsh_control: false };
const ZSH: Variant = Variant { truncate_nul: false, zsh_control: true };
const PLAIN: Variant = Variant { truncate_nul: false, zsh_control: false };

struct Word {
    text: String,
    value: Option<String>,
}

fn push_char(out: &mut Vec<u8>, value: u32) {
    if let Some(ch) = char::from_u32(value) {
        let mut buffer = [0u8; 4];
        out.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
    }
}

fn digits(chars: &[char], at: &mut usize, radix: u32, limit: usize) -> Option<u32> {
    let mut value = 0u32;
    let mut count = 0usize;
    while count < limit {
        let Some(digit) = chars.get(*at).and_then(|ch| ch.to_digit(radix)) else {
            break;
        };
        value = value.saturating_mul(radix).saturating_add(digit);
        *at = at.saturating_add(1);
        count = count.saturating_add(1);
    }
    (count > 0).then_some(value)
}

// Bash `$'...'` escapes, with the places where bash and zsh differ read both ways.
fn decode_ansi_c(text: &str, variant: Variant) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out: Vec<u8> = Vec::new();
    let mut at = 0usize;
    while let Some(&ch) = chars.get(at) {
        at = at.saturating_add(1);
        if ch != '\\' {
            push_char(&mut out, u32::from(ch));
            continue;
        }
        let Some(&next) = chars.get(at) else {
            out.push(b'\\');
            break;
        };
        at = at.saturating_add(1);
        match next {
            'a' => out.push(7),
            'b' => out.push(8),
            'e' | 'E' => out.push(27),
            'f' => out.push(12),
            'n' => out.push(10),
            'r' => out.push(13),
            't' => out.push(9),
            'v' => out.push(11),
            '\\' | '\'' | '"' | '?' => push_char(&mut out, u32::from(next)),
            'c' if variant.zsh_control => out.push(b'c'),
            'c' => match chars.get(at) {
                Some(&control) => {
                    at = at.saturating_add(1);
                    let code = if control == '?' { 127 } else { u32::from(control) & 0x1f };
                    out.push(u8::try_from(code).unwrap_or(0));
                }
                None => out.extend_from_slice(b"\\c"),
            },
            'x' => match digits(&chars, &mut at, 16, 2) {
                Some(value) => out.push(u8::try_from(value & 0xff).unwrap_or(0)),
                None => out.extend_from_slice(b"\\x"),
            },
            'u' | 'U' => {
                let limit = if next == 'u' { 4 } else { 8 };
                match digits(&chars, &mut at, 16, limit) {
                    Some(value) => push_char(&mut out, value),
                    None => push_char(&mut out, u32::from(next)),
                }
            }
            '0'..='7' => {
                at = at.saturating_sub(1);
                let value = digits(&chars, &mut at, 8, 3).unwrap_or(0);
                out.push(u8::try_from(value & 0xff).unwrap_or(0));
            }
            other => {
                out.push(b'\\');
                push_char(&mut out, u32::from(other));
            }
        }
    }
    if variant.truncate_nul {
        if let Some(place) = out.iter().position(|byte| *byte == 0) {
            out.truncate(place);
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

struct Lexer<'a> {
    chars: Vec<char>,
    at: usize,
    line: usize,
    starts: Vec<usize>,
    exact: HashMap<&'a str, Vec<usize>>,
    stripped: HashMap<&'a str, Vec<usize>>,
    variant: Variant,
}

fn first_from(positions: Option<&Vec<usize>>, from: usize) -> Option<usize> {
    let list = positions?;
    list.get(list.partition_point(|place| *place < from)).copied()
}

fn separator(ch: char) -> bool {
    ch.is_whitespace() || ";&|()<>".contains(ch)
}

impl Lexer<'_> {
    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.at.saturating_add(ahead)).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek(0)?;
        self.at = self.at.saturating_add(1);
        if ch == '\n' {
            self.line = self.line.saturating_add(1);
        }
        Some(ch)
    }

    fn until(&mut self, close: char, out: &mut String) {
        while let Some(ch) = self.bump() {
            if ch == close {
                return;
            }
            out.push(ch);
        }
    }

    fn double_quoted(&mut self, out: &mut String) {
        while let Some(ch) = self.bump() {
            match ch {
                '"' => return,
                '\\' => match self.peek(0) {
                    Some('\n') => {
                        self.bump();
                    }
                    Some(next) if "$`\"\\".contains(next) => {
                        self.bump();
                        out.push(next);
                    }
                    _ => out.push('\\'),
                },
                '$' if self.peek(0) == Some('(') => {
                    out.push('$');
                    self.parenthesized(out);
                }
                _ => out.push(ch),
            }
        }
    }

    // A `$( ... )` in double quotes is copied whole, nested quotes included.
    fn parenthesized(&mut self, out: &mut String) {
        let mut depth = 0usize;
        while let Some(ch) = self.bump() {
            out.push(ch);
            match ch {
                '(' => depth = depth.saturating_add(1),
                ')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return;
                    }
                }
                '\'' => self.until('\'', out),
                '"' => self.double_quoted(out),
                _ => {}
            }
        }
    }

    fn ansi_quoted(&mut self, out: &mut String) {
        let mut raw = String::new();
        while let Some(ch) = self.bump() {
            if ch == '\'' {
                break;
            }
            raw.push(ch);
            if ch == '\\' {
                if let Some(escaped) = self.bump() {
                    raw.push(escaped);
                }
            }
        }
        out.push_str(&decode_ansi_c(&raw, self.variant));
    }

    fn braced(&mut self, out: &mut String) {
        let mut depth = 0usize;
        while let Some(ch) = self.bump() {
            out.push(ch);
            match ch {
                '{' => depth = depth.saturating_add(1),
                '}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return;
                    }
                }
                _ => {}
            }
        }
    }

    fn read_word(&mut self) -> Word {
        let mut text = String::new();
        let mut plain_name = true;
        let mut equals: Option<usize> = None;
        while let Some(ch) = self.peek(0) {
            if separator(ch) {
                break;
            }
            self.bump();
            let quoted = matches!(ch, '\'' | '"' | '`' | '\\' | '$');
            match ch {
                '\'' => self.until('\'', &mut text),
                '"' => self.double_quoted(&mut text),
                '`' => {
                    text.push('`');
                    self.until('`', &mut text);
                    text.push('`');
                }
                '\\' => match self.bump() {
                    Some('\n') | None => {}
                    Some(escaped) => text.push(escaped),
                },
                '$' => match self.peek(0) {
                    Some('\'') => {
                        self.bump();
                        self.ansi_quoted(&mut text);
                    }
                    Some('"') => {
                        self.bump();
                        self.double_quoted(&mut text);
                    }
                    Some('{') => {
                        text.push('$');
                        self.bump();
                        text.push('{');
                        self.braced(&mut text);
                    }
                    _ => text.push('$'),
                },
                _ => {
                    if equals.is_none() {
                        let plus_then_equals = ch == '+' && self.peek(0) == Some('=') && !text.is_empty();
                        if ch == '=' && !text.is_empty() && plain_name {
                            equals = Some(text.len());
                        } else if !plus_then_equals
                            && (!(ch.is_ascii_alphanumeric() || ch == '_')
                                || (text.is_empty() && ch.is_ascii_digit()))
                        {
                            plain_name = false;
                        }
                    }
                    text.push(ch);
                }
            }
            if quoted && equals.is_none() {
                plain_name = false;
            }
        }
        let value = equals.and_then(|place| text.get(place.saturating_add(1)..).map(str::to_owned));
        Word { text, value }
    }

    fn heredoc_here(&self) -> bool {
        let before = self.at.checked_sub(1).and_then(|place| self.chars.get(place)).copied();
        self.peek(0) == Some('<') && self.peek(1) == Some('<') && self.peek(2) != Some('<') && before != Some('<')
    }

    // Bodies are skipped only when a line equal to each delimiter follows, in order.
    fn skip_bodies(&mut self, pending: &[(String, bool)]) {
        let mut from = self.line;
        for (word, dash) in pending {
            let table = if *dash { &self.stripped } else { &self.exact };
            let Some(found) = first_from(table.get(word.as_str()), from) else {
                return;
            };
            from = found.saturating_add(1);
        }
        self.line = from;
        self.at = self.starts.get(from).copied().unwrap_or(self.chars.len());
    }

    fn commands(&mut self) -> Vec<Vec<Word>> {
        let mut commands: Vec<Vec<Word>> = Vec::new();
        let mut current: Vec<Word> = Vec::new();
        let mut pending: Vec<(String, bool)> = Vec::new();
        while let Some(ch) = self.peek(0) {
            match ch {
                ' ' | '\t' => self.at = self.at.saturating_add(1),
                '\n' => {
                    self.bump();
                    commands.push(std::mem::take(&mut current));
                    if !pending.is_empty() {
                        self.skip_bodies(&pending);
                        pending.clear();
                    }
                }
                '\\' if self.peek(1) == Some('\n') => {
                    self.bump();
                    self.bump();
                }
                '#' => {
                    while self.peek(0).is_some_and(|next| next != '\n') {
                        self.bump();
                    }
                }
                ';' | '&' | '|' | '(' | ')' => {
                    self.bump();
                    commands.push(std::mem::take(&mut current));
                }
                '<' if self.heredoc_here() => {
                    self.at = self.at.saturating_add(2);
                    let dash = self.peek(0) == Some('-');
                    if dash {
                        self.bump();
                    }
                    while matches!(self.peek(0), Some(' ' | '\t')) {
                        self.bump();
                    }
                    let quoted = matches!(self.peek(0), Some('\'' | '"'));
                    let delimiter = self.read_word().text;
                    if quoted || !delimiter.is_empty() {
                        pending.push((delimiter, dash));
                    }
                }
                '<' | '>' => {
                    self.bump();
                }
                _ => {
                    let word = self.read_word();
                    current.push(word);
                }
            }
        }
        commands.push(current);
        commands
    }
}

fn collect(commands: Vec<Vec<Word>>, out: &mut Vec<(bool, String)>) {
    for command in commands {
        let first = command.first().map(|word| word.text.as_str());
        match first {
            Some("alias") => {
                for word in command.iter().skip(1).filter(|word| !word.text.starts_with('-')) {
                    if let Some((name, body)) = word.text.split_once('=') {
                        if !name.is_empty() {
                            out.push((true, body.to_owned()));
                        }
                    }
                }
            }
            Some("set") => {
                let mut operands = command.iter().skip(1).filter(|word| !word.text.starts_with('-'));
                if operands.next().is_some_and(|name| {
                    !name.text.is_empty() && name.text.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
                }) {
                    out.extend(operands.map(|word| (false, word.text.clone())));
                }
            }
            _ => {}
        }
        if first != Some("alias") {
            out.extend(command.iter().filter_map(|word| word.value.clone()).map(|value| (false, value)));
        }
    }
}

// Every unquoted NAME=value word and alias body, read as the shell reads the text.
pub fn values_in_text(text: &str, out: &mut Vec<(bool, String)>) {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut exact: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut stripped: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, line) in lines.iter().enumerate() {
        exact.entry(line).or_default().push(index);
        stripped.entry(line.trim_start_matches('\t')).or_default().push(index);
    }
    let chars: Vec<char> = text.chars().collect();
    let mut starts = vec![0usize];
    for (place, ch) in chars.iter().enumerate() {
        if *ch == '\n' {
            starts.push(place.saturating_add(1));
        }
    }
    let variants: &[Variant] = if text.contains("$'") { &[BASH, ZSH, PLAIN] } else { &[PLAIN] };
    for variant in variants {
        let mut lexer = Lexer {
            chars: chars.clone(),
            at: 0,
            line: 0,
            starts: starts.clone(),
            exact: exact.clone(),
            stripped: stripped.clone(),
            variant: *variant,
        };
        collect(lexer.commands(), out);
    }
}

#[cfg(test)]
mod tests {
    use super::values_in_text;

    fn values(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        values_in_text(text, &mut out);
        out.into_iter().map(|(_, value)| value).collect()
    }

    fn has(text: &str, value: &str) -> bool {
        values(text).iter().any(|found| found == value)
    }

    #[test]
    fn plain_export_alias_and_local_forms_are_collected() {
        assert!(has("envkey=value1\n", "value1"));
        assert!(has("export envkey2=value2\n", "value2"));
        assert!(has("alias secretcommand1=\"value3\"\n", "value3"));
        assert!(has("f() {\nlocal A=gardenpiano\n}\n", "gardenpiano"));
        assert!(has("f() { A=gardenpiano; }\n", "gardenpiano"));
        assert!(has("case x in\nx) A=gardenpiano;;\nesac\n", "gardenpiano"));
        assert!(has("A=river#harp\n", "river#harp"));
        assert!(has("set -gx NAME gardenpiano\n", "gardenpiano"));
    }

    #[test]
    fn quotes_continuations_and_comments_follow_the_shell() {
        assert!(has("A='garden\npiano'\n", "garden\npiano"));
        assert!(has("# note \\\nA=gardenpiano\n", "gardenpiano"));
        assert!(has("A=garden\\\npiano\n", "gardenpiano"));
        assert!(has("A='garden\\\npiano'\n", "garden\\\npiano"));
        assert!(!has("echo \"A=always\"\n", "always"));
        assert!(!has("# A=always\n", "always"));
    }

    #[test]
    fn here_documents_are_data_when_their_delimiter_follows() {
        assert!(!has("cat <<EOF\nA=always\nEOF\n", "always"));
        assert!(!has("cat <<\"E\\\"OF\"\nA=always\nE\"OF\n", "always"));
        assert!(!has("cat <<''\nA=always\n\n", "always"));
        assert!(!has("X=\"$(cat <<'EOF'\nA=always\nEOF\n)\"\n", "always"));
        assert!(has("# cat <<EOF\nA=gardenpiano\ncat <<EOF\nx\nEOF\n", "gardenpiano"));
        assert!(has("HELP='\n<<EOF\n'\nA=gardenpiano\ncat <<EOF\nx\nEOF\n", "gardenpiano"));
        assert!(has("cat <<NEVER\nA=gardenpiano\n", "gardenpiano"));
    }

    #[test]
    fn ansi_c_values_are_read_both_ways_where_shells_differ() {
        assert!(has("A=$'garden\\x70iano'\n", "gardenpiano"));
        assert!(has("A=$'garden\\cApiano'\n", "garden\u{1}piano"));
        assert!(has("A=$'garden\\cApiano'\n", "gardencApiano"));
        assert!(has("A=$'gardenpiano\\0tail'\n", "gardenpiano"));
    }
}
