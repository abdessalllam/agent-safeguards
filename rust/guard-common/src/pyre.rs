use regex::Regex;

const EXTRA_SPACE: &str = r"\x1c-\x1f";
const WORD: &str = r"\p{L}\p{N}_";
const DOTTED_I: &str = r"\u{131}\u{130}";

struct Translator {
    chars: Vec<char>,
    index: usize,
    out: String,
    scopes: Vec<bool>,
    ignore_case: bool,
}

/// Python `re` source to `regex` crate source: `\s` takes U+001C-U+001F, `\w` is letters,
/// numbers and `_`, and with `i` the letters `i` and `I` also match U+0130 and U+0131.
pub fn translate(source: &str) -> String {
    let mut translator = Translator {
        chars: source.chars().collect(),
        index: 0,
        out: String::with_capacity(source.len() + 16),
        scopes: Vec::new(),
        ignore_case: false,
    };
    translator.run();
    translator.out
}

impl Translator {
    fn peek(&self, offset: usize) -> Option<char> {
        self.chars.get(self.index + offset).copied()
    }

    fn take(&mut self) -> Option<char> {
        let found = self.peek(0);
        if found.is_some() {
            self.index += 1;
        }
        found
    }

    fn copy_braced(&mut self) {
        if self.peek(0) == Some('{') {
            while let Some(ch) = self.take() {
                self.out.push(ch);
                if ch == '}' {
                    break;
                }
            }
        } else if let Some(ch) = self.take() {
            self.out.push(ch);
        }
    }

    fn run(&mut self) {
        while let Some(current) = self.peek(0) {
            match current {
                '\\' => self.escape(false),
                '[' => self.class(),
                '(' => self.group(),
                ')' => {
                    self.index += 1;
                    self.out.push(')');
                    if let Some(previous) = self.scopes.pop() {
                        self.ignore_case = previous;
                    }
                }
                'i' | 'I' if self.ignore_case => {
                    self.index += 1;
                    self.out.push_str(&format!("[iI{DOTTED_I}]"));
                }
                other => {
                    self.index += 1;
                    self.out.push(other);
                }
            }
        }
    }

    fn group(&mut self) {
        self.index += 1;
        self.out.push('(');
        let saved = self.ignore_case;
        if self.peek(0) != Some('?') {
            self.scopes.push(saved);
            return;
        }
        self.index += 1;
        self.out.push('?');
        if self.peek(0) == Some('P') && self.peek(1) == Some('<') {
            for _ in 0..2 {
                if let Some(ch) = self.take() {
                    self.out.push(ch);
                }
            }
            while let Some(ch) = self.take() {
                self.out.push(ch);
                if ch == '>' {
                    break;
                }
            }
            self.scopes.push(saved);
            return;
        }
        if self.peek(0) == Some('<') && self.peek(1).is_some_and(|ch| ch.is_ascii_alphabetic()) {
            while let Some(ch) = self.take() {
                self.out.push(ch);
                if ch == '>' {
                    break;
                }
            }
            self.scopes.push(saved);
            return;
        }
        let mut flags = String::new();
        let mut at = 0usize;
        while let Some(ch) = self.peek(at) {
            if ch.is_ascii_alphabetic() || ch == '-' {
                flags.push(ch);
                at += 1;
            } else {
                break;
            }
        }
        let closer = self.peek(at);
        if !flags.is_empty() && (closer == Some(')') || closer == Some(':')) {
            let (enabled, disabled) = flags.split_once('-').unwrap_or((flags.as_str(), ""));
            let mut ignore = saved;
            if enabled.contains('i') {
                ignore = true;
            }
            if disabled.contains('i') {
                ignore = false;
            }
            for _ in 0..=at {
                if let Some(ch) = self.take() {
                    self.out.push(ch);
                }
            }
            if closer == Some(':') {
                self.scopes.push(saved);
                self.ignore_case = ignore;
            } else {
                self.ignore_case = ignore;
            }
            return;
        }
        self.scopes.push(saved);
    }

    fn escape(&mut self, in_class: bool) {
        let Some(escaped) = self.peek(1) else {
            self.index += 1;
            self.out.push('\\');
            return;
        };
        let already: String = self.chars.iter().skip(self.index + 2).take(EXTRA_SPACE.len()).collect();
        self.index += 2;
        match escaped {
            's' if already == EXTRA_SPACE => self.out.push_str(r"\s"),
            's' if in_class => self.out.push_str(&format!(r"\s{EXTRA_SPACE}")),
            's' => self.out.push_str(&format!(r"[\s{EXTRA_SPACE}]")),
            'S' if !in_class => self.out.push_str(&format!(r"[^\s{EXTRA_SPACE}]")),
            'w' if in_class => self.out.push_str(WORD),
            'w' => self.out.push_str(&format!("[{WORD}]")),
            'W' if !in_class => self.out.push_str(&format!("[^{WORD}]")),
            'p' | 'P' => {
                self.out.push('\\');
                self.out.push(escaped);
                self.copy_braced();
            }
            other => {
                self.out.push('\\');
                self.out.push(other);
            }
        }
    }

    fn class(&mut self) {
        let start = self.index;
        let mut cursor = start + 1;
        if self.chars.get(cursor) == Some(&'^') {
            cursor += 1;
        }
        let mut first = true;
        let mut depth = 1usize;
        let mut covers = false;
        let mut previous: Option<char> = None;
        let mut range_open = false;
        while let Some(&ch) = self.chars.get(cursor) {
            if ch == ']' && !first {
                depth -= 1;
                if depth == 0 {
                    break;
                }
                cursor += 1;
                continue;
            }
            first = false;
            if ch == '[' && self.chars.get(cursor + 1) == Some(&':') {
                depth += 1;
                cursor += 1;
                continue;
            }
            let literal = if ch == '\\' {
                let next = self.chars.get(cursor + 1).copied();
                cursor += 2;
                if matches!(next, Some('p' | 'P')) && self.chars.get(cursor) == Some(&'{') {
                    while self.chars.get(cursor).is_some_and(|inner| *inner != '}') {
                        cursor += 1;
                    }
                    cursor += 1;
                    previous = None;
                    range_open = false;
                    continue;
                }
                if matches!(next, Some('x')) {
                    cursor += 2;
                    previous = None;
                    range_open = false;
                    continue;
                }
                if matches!(next, Some('u')) {
                    if self.chars.get(cursor) == Some(&'{') {
                        while self.chars.get(cursor).is_some_and(|inner| *inner != '}') {
                            cursor += 1;
                        }
                        cursor += 1;
                    } else {
                        cursor += 4;
                    }
                    previous = None;
                    range_open = false;
                    continue;
                }
                match next {
                    Some('d' | 'D' | 's' | 'S' | 'w' | 'W') | None => {
                        previous = None;
                        range_open = false;
                        continue;
                    }
                    Some(other) => other,
                }
            } else {
                cursor += 1;
                if ch == '-' && previous.is_some() && !range_open && self.chars.get(cursor).is_some_and(|next| *next != ']') {
                    range_open = true;
                    continue;
                }
                ch
            };
            if range_open {
                if let Some(low) = previous {
                    if (low <= 'i' && 'i' <= literal) || (low <= 'I' && 'I' <= literal) {
                        covers = true;
                    }
                }
                range_open = false;
                previous = None;
                continue;
            }
            if literal == 'i' || literal == 'I' {
                covers = true;
            }
            previous = Some(literal);
        }
        self.out.push('[');
        self.index = start + 1;
        if self.peek(0) == Some('^') {
            self.index += 1;
            self.out.push('^');
        }
        if self.ignore_case && covers {
            self.out.push_str(DOTTED_I);
        }
        if self.peek(0) == Some(']') {
            self.index += 1;
            self.out.push_str(r"\]");
        }
        let mut nested = 0usize;
        while let Some(ch) = self.peek(0) {
            if ch == ']' && nested == 0 {
                self.index += 1;
                break;
            }
            if ch == '\\' {
                self.escape(true);
                continue;
            }
            if ch == '[' {
                nested += 1;
            }
            if ch == ']' {
                nested -= 1;
            }
            self.index += 1;
            self.out.push(ch);
        }
        self.out.push(']');
    }
}

pub fn new(source: &str) -> Result<Regex, regex::Error> {
    Regex::new(&translate(source))
}

#[cfg(test)]
mod tests {
    use super::{new, translate};

    #[test]
    fn spaces_and_words_follow_python() {
        assert_eq!(translate(r"a\s+b"), r"a[\s\x1c-\x1f]+b");
        assert_eq!(translate(r"[\s,]"), r"[\s\x1c-\x1f,]");
        assert_eq!(translate(r"[^\s\x1c-\x1f]"), r"[^\s\x1c-\x1f]");
        assert_eq!(translate(r"\S"), r"[^\s\x1c-\x1f]");
        assert_eq!(translate(r"\\s"), r"\\s");
        assert_eq!(translate(r"[\w.-]"), r"[\p{L}\p{N}_.-]");
        assert_eq!(translate(r"\w+\W"), r"[\p{L}\p{N}_]+[^\p{L}\p{N}_]");
        assert_eq!(translate(r"[]a\s]"), r"[\]a\s\x1c-\x1f]");
        assert!(new(r"\s").is_ok_and(|found| found.is_match("\u{1c}")));
        assert!(new(r"\w").is_ok_and(|found| found.is_match("\u{b2}") && !found.is_match("\u{301}")));
    }

    #[test]
    fn ignore_case_letter_i_takes_the_dotted_and_dotless_forms() {
        assert!(new(r"(?i)token").is_ok_and(|found| found.is_match("TOKEN") && found.is_match("token")));
        assert!(new(r"(?i)\bkey").is_ok_and(|found| found.is_match("KEY")));
        assert!(new(r"(?i)pri").is_ok_and(|found| found.is_match("PR\u{130}") && found.is_match("pr\u{131}")));
        assert!(new(r"(?i)[a-z]+").is_ok_and(|found| found.find("\u{130}\u{131}").is_some_and(|hit| hit.end() == 4)));
        assert!(new(r"(?i)[^a-z]").is_ok_and(|found| !found.is_match("\u{130}")));
        assert!(new(r"(?i)[^a-h]").is_ok_and(|found| found.is_match("\u{130}")));
        assert!(new(r"pri").is_ok_and(|found| !found.is_match("pr\u{130}")));
        assert!(new(r"(?i:pri)x").is_ok_and(|found| found.is_match("PR\u{130}x") && !found.is_match("PR\u{130}X")));
        assert!(new(r"(?P<site>i)(?i)").is_ok());
        assert!(new(r"\A(?:(?i)i)\z").is_ok_and(|found| found.is_match("\u{130}")));
        assert!(new(r"(?i)\p{Latin}").is_ok());
    }
}
