use crate::languages::Language;

#[derive(Clone, Copy)]
pub enum LineKind<'a> {
    Comment(&'a str),
    Also(&'a str),
    Other,
}

#[derive(Clone, Copy)]
enum Tail {
    Words,
    Licence,
    Compact,
    Go,
}

// A tool directive is exempt only while what follows is its own arguments (codes, rule names),
// never free text.
const EXEMPT: &[(&str, Tail)] = &[
    ("noqa", Tail::Words),
    ("type:", Tail::Words),
    ("pragma", Tail::Words),
    ("pylint:", Tail::Words),
    ("mypy:", Tail::Words),
    ("ruff:", Tail::Words),
    ("fmt:", Tail::Words),
    ("isort:", Tail::Words),
    ("pyright:", Tail::Words),
    ("eslint-", Tail::Words),
    ("prettier-ignore", Tail::Words),
    ("@ts-", Tail::Words),
    ("istanbul ", Tail::Words),
    ("c8 ", Tail::Words),
    ("go:", Tail::Go),
    ("nolint", Tail::Compact),
    ("swiftlint:", Tail::Words),
    ("spdx-license-identifier", Tail::Licence),
    ("shellcheck", Tail::Words),
    ("nosec", Tail::Words),
    ("cspell:", Tail::Words),
    ("-*-", Tail::Words),
    ("lint:", Tail::Words),
    ("clippy::", Tail::Words),
    ("rustfmt::", Tail::Words),
    ("+build", Tail::Words),
    ("@flow", Tail::Words),
    ("@jsx", Tail::Words),
    ("eslint-disable", Tail::Words),
];

const DIRECTIVE_WORDS: &[&str] = &[
    "ignore", "noqa", "env", "off", "on", "skip", "next", "line", "file", "no", "cover", "branch", "disable", "enable", "all",
    "secret", "allowlist", "nextline", "start", "stop", "begin", "end", "if", "else", "set", "coding", "mode",
    "encoding", "basic", "strict", "standard", "once", "node", "browser", "jest", "mocha", "jsx", "h", "check",
    "nocheck", "expect", "and", "or", "with", "linux", "darwin", "windows", "freebsd", "netbsd", "openbsd", "solaris",
    "plan9", "android", "ios", "js", "wasm", "aix", "illumos", "amd64", "arm", "arm64", "mips", "ppc64", "riscv64",
    "s390x", "cgo", "race", "gc", "unix", "tag", "block", "nextblock", "generate", "build", "embed",
];

const GO_DIRECTIVES: &[&str] = &[
    "generate", "build", "embed", "linkname", "noinline", "nosplit", "noescape", "norace", "nocheckptr", "debug",
    "uintptrescapes", "wasmimport",
];

fn code_like(token: &str) -> bool {
    token.chars().any(|c| c.is_ascii_digit() || "_-.[]=/@()<>|*&#$%^~+!".contains(c))
}

fn directive_words(tail: &str, upper: bool) -> bool {
    let mut count = 0usize;
    for token in tail
        .split(|c: char| c.is_whitespace() || matches!(c, ',' | ':' | ';'))
        .filter(|token| !token.is_empty())
    {
        count = count.saturating_add(1);
        if count > 8 || token.chars().count() > 48 {
            return false;
        }
        let word = token.to_ascii_lowercase();
        let plain_upper = upper && token.len() <= 12 && token.chars().all(|c| c.is_ascii_uppercase());
        if !(code_like(token) || plain_upper || DIRECTIVE_WORDS.contains(&word.as_str())) {
            return false;
        }
    }
    true
}

fn directive_tail(kind: Tail, tail: &str) -> bool {
    match kind {
        Tail::Words => directive_words(tail, false),
        Tail::Licence => directive_words(tail, true),
        Tail::Compact => {
            let rest = tail.trim_end();
            rest.is_empty()
                || (rest.starts_with(':')
                    && rest.len() > 1
                    && rest.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | ',' | '_' | '-' | '.')))
        }
        Tail::Go => {
            let rest = tail.trim_start();
            let name: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            if !GO_DIRECTIVES.contains(&name.as_str()) && !name.starts_with("cgo_") {
                return false;
            }
            name == "generate" || directive_words(rest.get(name.len()..).unwrap_or(""), false)
        }
    }
}

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
    EXEMPT.iter().any(|(prefix, kind)| {
        starts_ignore_case(text, prefix) && text.get(prefix.len()..).is_some_and(|tail| directive_tail(*kind, tail))
    })
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

fn regex_allowed(significant: Option<u8>) -> bool {
    match significant {
        None => true,
        Some(byte) => b"(,=:[!&|?{;+-*%>~^".contains(&byte),
    }
}

fn regex_length(rest: &str) -> Option<usize> {
    let bytes = rest.as_bytes();
    if matches!(bytes.get(1), None | Some(b'/') | Some(b'*')) {
        return None;
    }
    let mut at = 1usize;
    let mut in_class = false;
    while let Some(byte) = bytes.get(at) {
        match *byte {
            b'\\' => at = at.saturating_add(2),
            b'[' => {
                in_class = true;
                at = at.saturating_add(1);
            }
            b']' => {
                in_class = false;
                at = at.saturating_add(1);
            }
            b'/' if !in_class => {
                let mut end = at.saturating_add(1);
                while bytes.get(end).is_some_and(|flag| flag.is_ascii_alphabetic()) {
                    end = end.saturating_add(1);
                }
                return Some(end);
            }
            _ => at = at.saturating_add(1),
        }
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
    extra: std::collections::VecDeque<&'a str>,
}

pub fn scan(text: &str, lang: Language) -> Scan<'_> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    Scan {
        lines: text.split('\n'),
        lang,
        state: State::Code,
        extra: std::collections::VecDeque::new(),
    }
}

impl<'a> Iterator for Scan<'a> {
    type Item = LineKind<'a>;

    fn next(&mut self) -> Option<LineKind<'a>> {
        loop {
            if let Some(text) = self.extra.pop_front() {
                if is_exempt(body(text)) {
                    continue;
                }
                return Some(LineKind::Also(text));
            }
            let line = self.lines.next()?;
            return Some(match self.classify(line) {
                LineKind::Comment(text) if is_exempt(body(text)) => LineKind::Other,
                other => other,
            });
        }
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
                    self.trailing_after(trimmed.get(end..), close);
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

    fn trailing_after(&mut self, remainder: Option<&'a str>, delimiter: &str) {
        let Some(rest) = remainder else {
            return;
        };
        let last = delimiter.as_bytes().last().copied();
        if let LineKind::Comment(next) = self.code(rest, last) {
            self.extra.push_front(next);
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
                self.trailing_after(trimmed.get(upto..), close);
                return Some(LineKind::Comment(trimmed.get(..upto).unwrap_or(trimmed)));
            }
        }
        if lang.rem {
            let word = trimmed.trim_start_matches('@');
            let remark = word.get(..3).is_some_and(|head| head.eq_ignore_ascii_case("rem"))
                && word.get(3..).is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace));
            if remark || trimmed.starts_with("::") {
                return Some(LineKind::Comment(trimmed));
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
        let mut found: Vec<&'a str> = Vec::new();
        self.scan_code(text, start, &mut found);
        let mut found = found.into_iter();
        let Some(first) = found.next() else {
            return LineKind::Other;
        };
        self.extra.extend(found);
        LineKind::Comment(first)
    }

    fn scan_code(&mut self, text: &'a str, start: Option<u8>, found: &mut Vec<&'a str>) {
        let lang = self.lang;
        let bytes = text.as_bytes();
        let mut at = 0usize;
        let mut previous = start;
        let mut significant = start;
        'scan: while at < bytes.len() {
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
                        significant = previous;
                        continue;
                    }
                    None => {
                        self.state = State::Triple { delim, doc: false };
                        return;
                    }
                }
            }
            if lang.lifetimes && first == '\'' {
                at = at.saturating_add(char_literal_length(rest).unwrap_or(1));
                previous = Some(b'\'');
                significant = previous;
                continue;
            }
            if lang.quotes.contains(first) {
                match string_length(rest, first) {
                    Some(length) => at = at.saturating_add(length),
                    None => return,
                }
                previous = Some(first as u8);
                significant = previous;
                continue;
            }
            if lang.backtick && first == '`' {
                match rest.get(1..).and_then(|tail| find_unescaped(tail, "`")) {
                    Some(end) => {
                        at = at.saturating_add(end.saturating_add(2));
                        previous = Some(b'`');
                        significant = previous;
                        continue;
                    }
                    None => {
                        self.state = State::Backtick;
                        return;
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
                        found.push(rest);
                        return;
                    }
                    let upto = open.len().saturating_add(end);
                    found.push(rest.get(..upto).unwrap_or(rest));
                    at = at.saturating_add(upto);
                    previous = close.as_bytes().last().copied();
                    continue 'scan;
                }
            }
            for &marker in lang.line {
                if rest.starts_with(marker) && marker_fits(lang, marker, previous, rest) {
                    found.push(rest);
                    return;
                }
            }
            if lang.regex && first == '/' && regex_allowed(significant) {
                if let Some(length) = regex_length(rest) {
                    at = at.saturating_add(length);
                    previous = Some(b')');
                    significant = previous;
                    continue;
                }
            }
            previous = rest.as_bytes().first().copied();
            if !first.is_whitespace() {
                significant = previous;
            }
            at = at.saturating_add(first.len_utf8());
        }
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
        Language, BASIC, BATCH, COMPONENT, CSS, ELIXIR, GO, HASH, HASKELL, HTML, LISP, LUA, OCAML, PERL, PHP,
        POWERSHELL, PYTHON, RUBY, RUST, SCRIPT, SHELL, SLASH, SQL,
    };

    #[test]
    fn rem_and_double_colon_lines_are_batch_comments() {
        assert_eq!(comments("REM one\n@rem two\n:: three\nrem\necho hi\n", BATCH).len(), 4);
        assert!(comments("remember to save\necho rem\nset a=rem\n", BATCH).is_empty());
        assert_eq!(comments("x = 1\nREM note\n' other\n", BASIC), vec!["REM note", "' other"]);
    }

    #[test]
    fn lisp_ocaml_and_powershell_comment_forms_are_read() {
        assert_eq!(comments("(a)\n; one\n#| two\nthree |#\n", LISP).len(), 3);
        assert_eq!(comments("let a = 1 (* one *)\n(* two\nthree *)\n", OCAML).len(), 3);
        assert_eq!(comments("$a = 1\n<#\none\n#>\n# two\n", POWERSHELL).len(), 4);
        assert!(comments("$a = '# not'\n", POWERSHELL).is_empty());
    }

    fn comments(text: &str, lang: Language) -> Vec<&str> {
        scan(text, lang)
            .filter_map(|kind| match kind {
                LineKind::Comment(line) | LineKind::Also(line) => Some(line),
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
    fn several_comments_on_one_line_are_each_counted() {
        assert_eq!(
            comments("int x = /* stable */ 1; // previously broken\n", SLASH),
            vec!["/* stable */", "// previously broken"]
        );
        assert_eq!(comments("/* a */ x(); // b\n", SLASH), vec!["/* a */", "// b"]);
        assert_eq!(comments("/*\na\n*/ y(); // c\n", SLASH), vec!["/*", "a", "*/", "// c"]);
        assert_eq!(comments("f(/* a */ 1, /* b */ 2);\n", SLASH), vec!["/* a */", "/* b */"]);
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
    fn regex_literals_do_not_open_strings_or_hide_comments() {
        assert_eq!(comments("const a = /`\\n/;\n// one\n// two\n// three\n", SCRIPT).len(), 3);
        assert_eq!(comments("x = a / b; // one\n", SCRIPT), vec!["// one"]);
        assert_eq!(comments("s.replace(/\"/g, 'x'); // c\n", SCRIPT), vec!["// c"]);
        assert_eq!(comments("p.split(/[/\\\\]/); // c\n", SCRIPT), vec!["// c"]);
        assert_eq!(comments("y = (a + b) / 2; // c\n", SCRIPT), vec!["// c"]);
        assert_eq!(comments("const u = 'http://x'; // c\n", SCRIPT), vec!["// c"]);
        assert!(comments("let r = /ab+c/i.test(s);\n", SCRIPT).is_empty());
    }

    #[test]
    fn go_keeps_backtick_strings_and_has_no_regex_literals() {
        assert_eq!(comments("x := `a\n// inside\n` // after\n", GO), vec!["// after"]);
        assert_eq!(comments("n := (a) / 2 // c\n", GO), vec!["// c"]);
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
