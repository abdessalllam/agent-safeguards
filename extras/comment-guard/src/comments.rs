use crate::languages::Language;

#[derive(Clone, Copy)]
pub enum LineKind<'a> {
    Comment(&'a str),
    Other,
}

const EXEMPT: [&str; 35] = [
    "noqa",
    "type:",
    "pragma",
    "pylint:",
    "mypy:",
    "ruff:",
    "fmt:",
    "isort:",
    "pyright:",
    "eslint-",
    "prettier-ignore",
    "@ts-",
    "istanbul ",
    "c8 ",
    "go:",
    "nolint",
    "swiftlint:",
    "mark:",
    "region",
    "endregion",
    "spdx-license-identifier",
    "copyright",
    "license",
    "shellcheck",
    "vim:",
    "nosec",
    "cspell:",
    "-*-",
    "eslint-disable",
    "lint:",
    "clippy::",
    "rustfmt::",
    "+build",
    "@flow",
    "@jsx",
];

const DOC_ATTRIBUTES: [&str; 3] = ["@doc", "@moduledoc", "@typedoc"];

pub fn body(line: &str) -> &str {
    let line = line.trim_start();
    let markers: &[char] = if line.starts_with('#') {
        &['#']
    } else if line.starts_with("<!--") {
        &['<', '!', '-']
    } else if line.starts_with('-') {
        &['-']
    } else if line.starts_with('{') {
        &['{', '-', '/', '*']
    } else if line.starts_with('"') || line.starts_with('\'') {
        &['"', '\'']
    } else if line.starts_with('=') {
        &['=']
    } else {
        &['/', '*']
    };
    let line = if line.starts_with("//!") {
        line.get(3..).unwrap_or(line)
    } else {
        line
    };
    line.trim_start_matches(|c: char| c.is_whitespace() || markers.contains(&c))
}

fn starts_ignore_case(text: &str, prefix: &str) -> bool {
    match text.as_bytes().get(..prefix.len()) {
        Some(head) => head.eq_ignore_ascii_case(prefix.as_bytes()),
        None => false,
    }
}

fn is_exempt(text: &str) -> bool {
    EXEMPT.iter().any(|prefix| starts_ignore_case(text, prefix))
}

fn find_unescaped(text: &str, needle: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut at = 0usize;
    while at < bytes.len() {
        if bytes.get(at) == Some(&b'\\') {
            at = at.saturating_add(2);
            continue;
        }
        if text.get(at..).is_some_and(|rest| rest.starts_with(needle)) {
            return Some(at);
        }
        at = at.saturating_add(1);
    }
    None
}

fn string_length(rest: &str, quote: char) -> Option<usize> {
    let bytes = rest.as_bytes();
    let mut at = quote.len_utf8();
    while let Some(byte) = bytes.get(at) {
        if *byte == b'\\' {
            at = at.saturating_add(2);
            continue;
        }
        if *byte == quote as u8 {
            return Some(at.saturating_add(1));
        }
        at = at.saturating_add(1);
    }
    None
}

fn char_literal_length(rest: &str) -> Option<usize> {
    let after = rest.get(1..)?;
    let mut chars = after.chars();
    let first = chars.next()?;
    if first == '\\' {
        let escaped = after.get(1..)?.chars().next()?;
        let tail = after.get(1usize.saturating_add(escaped.len_utf8())..)?;
        let end = tail.find('\'')?;
        return Some(escaped.len_utf8().saturating_add(end).saturating_add(3));
    }
    if chars.next() == Some('\'') {
        return Some(first.len_utf8().saturating_add(2));
    }
    None
}

fn block_scan(text: &str, open: &str, close: &str, nested: bool, start: u32) -> (u32, usize) {
    let mut depth = start;
    let mut at = 0usize;
    while at < text.len() {
        let Some(rest) = text.get(at..) else {
            at = at.saturating_add(1);
            continue;
        };
        if rest.starts_with(close) {
            depth = depth.saturating_sub(1);
            at = at.saturating_add(close.len());
            if depth == 0 {
                return (0, at);
            }
            continue;
        }
        if nested && rest.starts_with(open) {
            depth = depth.saturating_add(1);
            at = at.saturating_add(open.len());
            continue;
        }
        at = at.saturating_add(1);
    }
    (depth, text.len())
}

#[derive(Clone, Copy)]
enum State {
    Code,
    Block {
        open: &'static str,
        close: &'static str,
        depth: u32,
    },
    ColumnZero(&'static str),
    Pod,
    Triple { delim: &'static str, doc: bool },
    Backtick,
}

pub struct Scan<'a> {
    lines: std::str::Split<'a, char>,
    lang: Language,
    state: State,
}

pub fn scan(text: &str, lang: Language) -> Scan<'_> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    Scan {
        lines: text.split('\n'),
        lang,
        state: State::Code,
    }
}

impl<'a> Iterator for Scan<'a> {
    type Item = LineKind<'a>;

    fn next(&mut self) -> Option<LineKind<'a>> {
        let line = self.lines.next()?;
        let kind = self.classify(line);
        Some(match kind {
            LineKind::Comment(text) if is_exempt(body(text)) => LineKind::Other,
            other => other,
        })
    }
}

impl<'a> Scan<'a> {
    fn classify(&mut self, line: &'a str) -> LineKind<'a> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return LineKind::Other;
        }
        match self.state {
            State::Block { open, close, depth } => {
                let (left, end) = block_scan(trimmed, open, close, self.lang.nested, depth);
                if left == 0 {
                    self.state = State::Code;
                    return LineKind::Comment(trimmed.get(..end).unwrap_or(trimmed));
                }
                self.state = State::Block { open, close, depth: left };
                LineKind::Comment(trimmed)
            }
            State::ColumnZero(close) => {
                if line.starts_with(close) {
                    self.state = State::Code;
                }
                LineKind::Comment(trimmed)
            }
            State::Pod => {
                if line.starts_with("=cut") {
                    self.state = State::Code;
                }
                LineKind::Comment(trimmed)
            }
            State::Triple { delim, doc } => self.in_triple(trimmed, delim, doc),
            State::Backtick => match find_unescaped(trimmed, "`") {
                Some(end) => {
                    self.state = State::Code;
                    match trimmed.get(end.saturating_add(1)..) {
                        Some(rest) => self.code(rest, Some(b'`')),
                        None => LineKind::Other,
                    }
                }
                None => LineKind::Other,
            },
            State::Code => match self.leading(line, trimmed) {
                Some(kind) => kind,
                None => self.code(trimmed, None),
            },
        }
    }

    fn in_triple(&mut self, trimmed: &'a str, delim: &'static str, doc: bool) -> LineKind<'a> {
        let closed = find_unescaped(trimmed, delim);
        if closed.is_some() {
            self.state = State::Code;
        }
        if doc {
            return if trimmed == delim {
                LineKind::Other
            } else {
                LineKind::Comment(trimmed)
            };
        }
        match closed.and_then(|end| trimmed.get(end.saturating_add(delim.len())..)) {
            Some(rest) => self.code(rest, Some(b'"')),
            None => LineKind::Other,
        }
    }

    fn leading(&mut self, line: &'a str, trimmed: &'a str) -> Option<LineKind<'a>> {
        let lang = self.lang;
        for &(open, close) in lang.column_zero {
            if line.starts_with(open) {
                self.state = State::ColumnZero(close);
                return Some(LineKind::Comment(trimmed));
            }
        }
        if lang.pod
            && line.starts_with('=')
            && line.chars().nth(1).is_some_and(|c| c.is_ascii_alphabetic())
            && !line.starts_with("=cut")
        {
            self.state = State::Pod;
            return Some(LineKind::Comment(trimmed));
        }
        for &(open, close) in lang.block {
            if let Some(rest) = trimmed.strip_prefix(open) {
                let (left, end) = block_scan(rest, open, close, lang.nested, 1);
                if left > 0 {
                    self.state = State::Block { open, close, depth: left };
                    return Some(LineKind::Comment(trimmed));
                }
                let upto = open.len().saturating_add(end);
                return Some(LineKind::Comment(trimmed.get(..upto).unwrap_or(trimmed)));
            }
        }
        for &marker in lang.line {
            if trimmed.starts_with(marker) {
                let shebang = marker == "#" && trimmed.starts_with("#!");
                let attribute = lang.php && marker == "#" && trimmed.starts_with("#[");
                if shebang || attribute {
                    return Some(LineKind::Other);
                }
                return Some(LineKind::Comment(trimmed));
            }
        }
        if lang.docstring {
            return self.open_doc(trimmed, trimmed);
        }
        if lang.doc_attributes {
            for attribute in DOC_ATTRIBUTES {
                let Some(rest) = trimmed.strip_prefix(attribute) else {
                    continue;
                };
                if !rest.starts_with(char::is_whitespace) {
                    continue;
                }
                let rest = rest.trim_start();
                if let Some(kind) = self.open_doc(trimmed, rest) {
                    return Some(kind);
                }
                if rest.starts_with('"') {
                    return Some(LineKind::Comment(trimmed));
                }
            }
        }
        None
    }

    fn open_doc(&mut self, trimmed: &'a str, from: &'a str) -> Option<LineKind<'a>> {
        let stripped = from.trim_start_matches(|c: char| "rRuUbBfF".contains(c));
        if from.len().saturating_sub(stripped.len()) > 2 {
            return None;
        }
        let delim = self
            .lang
            .triple
            .iter()
            .copied()
            .find(|delim| stripped.starts_with(*delim))?;
        let after = stripped.get(delim.len()..)?;
        match find_unescaped(after, delim) {
            Some(end) => {
                let content = after.get(..end).unwrap_or("");
                Some(if content.trim().is_empty() {
                    LineKind::Other
                } else {
                    LineKind::Comment(trimmed)
                })
            }
            None => {
                self.state = State::Triple { delim, doc: true };
                Some(if after.trim().is_empty() {
                    LineKind::Other
                } else {
                    LineKind::Comment(trimmed)
                })
            }
        }
    }

    fn code(&mut self, text: &'a str, start: Option<u8>) -> LineKind<'a> {
        let lang = self.lang;
        let bytes = text.as_bytes();
        let mut at = 0usize;
        let mut previous = start;
        while at < bytes.len() {
            let Some(rest) = text.get(at..) else {
                at = at.saturating_add(1);
                continue;
            };
            let Some(first) = rest.chars().next() else {
                break;
            };
            if let Some(delim) = lang.triple.iter().copied().find(|delim| rest.starts_with(*delim)) {
                match rest.get(delim.len()..).and_then(|tail| find_unescaped(tail, delim)) {
                    Some(end) => {
                        let consumed = end.saturating_add(delim.len().saturating_mul(2));
                        at = at.saturating_add(consumed);
                        previous = Some(b'"');
                        continue;
                    }
                    None => {
                        self.state = State::Triple { delim, doc: false };
                        return LineKind::Other;
                    }
                }
            }
            if lang.lifetimes && first == '\'' {
                at = at.saturating_add(char_literal_length(rest).unwrap_or(1));
                previous = Some(b'\'');
                continue;
            }
            if lang.quotes.contains(first) {
                match string_length(rest, first) {
                    Some(length) => at = at.saturating_add(length),
                    None => return LineKind::Other,
                }
                previous = Some(first as u8);
                continue;
            }
            if lang.backtick && first == '`' {
                match rest.get(1..).and_then(|tail| find_unescaped(tail, "`")) {
                    Some(end) => {
                        at = at.saturating_add(end.saturating_add(2));
                        previous = Some(b'`');
                        continue;
                    }
                    None => {
                        self.state = State::Backtick;
                        return LineKind::Other;
                    }
                }
            }
            if first == '\\' {
                at = at.saturating_add(2);
                previous = None;
                continue;
            }
            for &(open, close) in lang.block {
                if let Some(tail) = rest.strip_prefix(open) {
                    let (left, end) = block_scan(tail, open, close, lang.nested, 1);
                    if left > 0 {
                        self.state = State::Block { open, close, depth: left };
                        return LineKind::Comment(rest);
                    }
                    let upto = open.len().saturating_add(end);
                    return LineKind::Comment(rest.get(..upto).unwrap_or(rest));
                }
            }
            for &marker in lang.line {
                if rest.starts_with(marker) && marker_fits(lang, marker, previous, rest) {
                    return LineKind::Comment(rest);
                }
            }
            previous = rest.as_bytes().first().copied();
            at = at.saturating_add(first.len_utf8());
        }
        LineKind::Other
    }
}

fn is_symbol(byte: u8) -> bool {
    b"!#$%&*+./<=>?@\\^|~:".contains(&byte)
}

fn marker_fits(lang: Language, marker: &str, previous: Option<u8>, rest: &str) -> bool {
    let after = rest.get(marker.len()..).unwrap_or("");
    match marker {
        "//" => previous != Some(b':'),
        "#" => {
            if lang.php && after.starts_with('[') {
                return false;
            }
            !lang.hash_after_space || previous.is_some_and(|byte| byte.is_ascii_whitespace())
        }
        "--" => {
            if !lang.dash_symbols {
                return true;
            }
            let before = previous.is_some_and(|byte| is_symbol(byte) || byte == b'-');
            let beyond = after.trim_start_matches('-').bytes().next();
            !before && !beyond.is_some_and(is_symbol)
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::{body, scan, LineKind};
    use crate::languages::{
        Language, COMPONENT, CSS, ELIXIR, HASH, HASKELL, HTML, LUA, PERL, PHP, PYTHON, RUBY, RUST, SCRIPT,
        SHELL, SLASH, SQL,
    };

    fn comments(text: &str, lang: Language) -> Vec<&str> {
        scan(text, lang)
            .filter_map(|kind| match kind {
                LineKind::Comment(line) => Some(line),
                LineKind::Other => None,
            })
            .collect()
    }

    #[test]
    fn strips_markers_and_whitespace() {
        assert_eq!(body("   #   hello"), "hello");
        assert_eq!(body("/// doc"), "doc");
        assert_eq!(body("-- note"), "note");
        assert_eq!(body("plain"), "plain");
        assert_eq!(body("# -*- coding: utf-8 -*-"), "-*- coding: utf-8 -*-");
        assert_eq!(body("# - item"), "- item");
        assert_eq!(body("//! inner doc"), "inner doc");
        assert_eq!(body("// ! noqa"), "! noqa");
        assert_eq!(body("<!-- note -->"), "note -->");
        assert_eq!(body("{/* note */}"), "note */}");
        assert_eq!(body("\"\"\"Copyright"), "Copyright");
    }

    #[test]
    fn shebang_and_php_attribute_are_not_comments() {
        assert!(comments("#!/bin/sh\n# x", HASH).len() == 1);
        assert_eq!(comments("#[Attr]\n# x", PHP).len(), 1);
    }

    #[test]
    fn block_state_spans_lines_and_closes() {
        assert_eq!(comments("/*\n * a\n */\ncode", SLASH).len(), 3);
        assert_eq!(comments("/* one */\ncode", SLASH).len(), 1);
    }

    #[test]
    fn a_slash_star_slash_opener_stays_open() {
        assert_eq!(comments("/*/\n * a\n * b\n", SLASH).len(), 3);
    }

    #[test]
    fn exempt_line_is_not_a_comment_but_keeps_the_block_open() {
        assert!(comments("# noqa: E501", HASH).is_empty());
        assert_eq!(comments("/*\n * noqa\n * a\n */", SLASH).len(), 3);
    }

    #[test]
    fn a_leading_byte_order_mark_does_not_hide_the_first_line() {
        assert_eq!(comments("\u{feff}# one\n# two\n", HASH).len(), 2);
    }

    #[test]
    fn trailing_comments_count_outside_strings_only() {
        assert_eq!(comments("a = 1  # one\nb = 2  # two\n", PYTHON).len(), 2);
        assert_eq!(comments("const a = 1; // one\n", SCRIPT), vec!["// one"]);
        assert_eq!(comments("let x = 1; /* tail */\n", SLASH), vec!["/* tail */"]);
        assert!(comments("url = \"http://x\"  \n", SCRIPT).is_empty());
        assert!(comments("s = 'a # b'\nt = \"c // d\"\n", PYTHON).is_empty());
        assert!(comments("echo $# args\nx=${y#p}\n", SHELL).is_empty());
        assert!(comments("a = b // c\n", HASH).is_empty());
        assert_eq!(comments("echo hi # note\n", SHELL), vec!["# note"]);
        assert!(comments("a=1# not a comment in a shell word\n", SHELL).is_empty());
        assert!(comments("let s: &'static str = \"a\"; let t = 1;\n", RUST).is_empty());
        assert_eq!(comments("let c = 'x'; // why\n", RUST), vec!["// why"]);
        assert_eq!(comments("fn f<'a>(x: &'a str) {} // why\n", RUST), vec!["// why"]);
    }

    #[test]
    fn a_trailing_marker_needs_no_space_where_the_language_allows_none() {
        assert_eq!(comments("a=1# one\n", PYTHON), vec!["# one"]);
        assert_eq!(comments("const a=1;// one\n", SCRIPT), vec!["// one"]);
        assert_eq!(comments("a--b\n", LUA), vec!["--b"]);
        assert_eq!(comments("x = 1 --reason\n", LUA), vec!["--reason"]);
        assert!(comments("see http://example.com/x\n", SCRIPT).is_empty());
    }

    #[test]
    fn rust_character_literals_do_not_hide_a_trailing_comment() {
        assert_eq!(comments("let a = '\"'; // one\n", RUST), vec!["// one"]);
        assert_eq!(comments("let b = '\\''; // two\n", RUST), vec!["// two"]);
        assert_eq!(comments("let c = '\\u{1F600}'; // three\n", RUST), vec!["// three"]);
    }

    #[test]
    fn an_inline_block_comment_is_keyed_without_the_code_around_it() {
        assert_eq!(comments("int a = /* stable a */ 1;\n", SLASH), vec!["/* stable a */"]);
        assert_eq!(comments("/* c */ x = 1;\n", SLASH), vec!["/* c */"]);
        assert_eq!(comments("*/ y = 2;\n", SLASH), Vec::<&str>::new());
    }

    #[test]
    fn nested_block_comments_stay_open_until_every_level_closes() {
        assert_eq!(comments("{- {- inner -}\none\ntwo\n-}\nx = 1\n", HASKELL).len(), 4);
        assert_eq!(comments("/* a /* b */\nc\nd\n*/\nfn f() {}\n", RUST).len(), 4);
        assert_eq!(comments("/* a /* b */\nint x;\n", SLASH).len(), 1);
    }

    #[test]
    fn trailing_dash_rules_follow_the_language() {
        assert!(comments("x --> y\n", HASKELL).is_empty());
        assert!(comments("x |-- y\n", HASKELL).is_empty());
        assert_eq!(comments("x = 1 -- why\n", HASKELL), vec!["-- why"]);
        assert_eq!(comments("select 1 -- why\n", SQL), vec!["-- why"]);
    }

    #[test]
    fn exempt_trailing_comment_is_not_counted() {
        assert!(comments("x = 1  # noqa: E501\n", PYTHON).is_empty());
        assert!(comments("y = 2 // eslint-disable-line\n", SCRIPT).is_empty());
    }

    #[test]
    fn python_docstrings_count_their_text_lines() {
        let text = "def f():\n    \"\"\"\n    one\n    two\n    three\n    \"\"\"\n    return 1\n";
        assert_eq!(comments(text, PYTHON).len(), 3);
        assert_eq!(comments("\"\"\"One line.\"\"\"\n", PYTHON).len(), 1);
        assert_eq!(comments("r'''raw doc\nmore'''\n", PYTHON).len(), 2);
        assert!(comments("\"\"\"\"\"\"\n", PYTHON).is_empty());
    }

    #[test]
    fn a_triple_quoted_value_is_data_not_a_comment() {
        let text = "SQL = \"\"\"\n# not a comment\nselect 1  # nor this\n\"\"\"\nx = 1  # real\n";
        assert_eq!(comments(text, PYTHON), vec!["# real"]);
    }

    #[test]
    fn elixir_doc_heredocs_and_strings_count() {
        let text = "@doc \"\"\"\nOne.\nTwo.\n\"\"\"\ndef f, do: 1\n@doc \"short\"\n";
        assert_eq!(comments(text, ELIXIR).len(), 3);
    }

    #[test]
    fn backtick_strings_hide_their_lines_and_the_tail_is_scanned() {
        let text = "const t = `\n// inside\n` // after\n";
        assert_eq!(comments(text, SCRIPT), vec!["// after"]);
    }

    #[test]
    fn jsx_comments_count() {
        assert_eq!(comments("<div>\n{/* a */}\n{/* b */}\n</div>\n", SCRIPT).len(), 2);
        assert_eq!(comments("{/*\n a\n */}\n<p/>\n", SCRIPT).len(), 3);
    }

    #[test]
    fn other_block_comment_styles_count_every_line() {
        assert_eq!(comments("--[[\na\nb\n]]\nx = 1\n", LUA).len(), 4);
        assert_eq!(comments("{-\na\nb\n-}\nx = 1\n", HASKELL).len(), 4);
        assert_eq!(comments("/*\na\n*/\nselect 1;\n", SQL).len(), 3);
        assert_eq!(comments("=begin\na\nb\n=end\nx = 1\n", RUBY).len(), 4);
        assert_eq!(comments("=pod\n\ntext\n\n=cut\nprint 1;\n", PERL).len(), 3);
        assert_eq!(comments("<!--\na\n-->\n<p>x</p>\n", HTML).len(), 3);
        assert_eq!(comments("/* a */\n/* b */\n", CSS).len(), 2);
        assert_eq!(comments("<template>\n<!-- a -->\n</template>\n<script>\n// b\n</script>\n", COMPONENT).len(), 2);
    }

    #[test]
    fn a_comment_in_a_quoted_attribute_is_not_a_comment() {
        assert!(comments("<a href=\"a // b\">x</a>\n", HTML).is_empty());
    }
}
