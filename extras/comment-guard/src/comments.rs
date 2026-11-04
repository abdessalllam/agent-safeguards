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

pub fn body(line: &str) -> &str {
    let line = line.trim_start();
    let markers: &[char] = if line.starts_with('#') {
        &['#']
    } else if line.starts_with('-') {
        &['-']
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

pub struct Scan<'a> {
    lines: std::str::Split<'a, char>,
    lang: Language,
    in_block: bool,
}

pub fn scan(text: &str, lang: Language) -> Scan<'_> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    Scan {
        lines: text.split('\n'),
        lang,
        in_block: false,
    }
}

impl<'a> Iterator for Scan<'a> {
    type Item = LineKind<'a>;

    fn next(&mut self) -> Option<LineKind<'a>> {
        let line = self.lines.next()?;
        let lang = self.lang;
        let trimmed = line.trim();
        let mut kind = LineKind::Other;
        if !trimmed.is_empty() {
            if lang.slash && self.in_block {
                kind = LineKind::Comment(trimmed);
                if trimmed.contains("*/") {
                    self.in_block = false;
                }
            } else if lang.slash && trimmed.starts_with("//") {
                kind = LineKind::Comment(trimmed);
            } else if lang.slash && trimmed.starts_with("/*") {
                kind = LineKind::Comment(trimmed);
                if !trimmed.get(2..).is_some_and(|rest| rest.contains("*/")) {
                    self.in_block = true;
                }
            } else if lang.hash && trimmed.starts_with('#') {
                let shebang = trimmed.starts_with("#!");
                let attribute = lang.php && trimmed.starts_with("#[");
                if !shebang && !attribute {
                    kind = LineKind::Comment(trimmed);
                }
            } else if lang.dash && trimmed.starts_with("--") {
                kind = LineKind::Comment(trimmed);
            }
        }
        if let LineKind::Comment(text) = kind {
            if is_exempt(body(text)) {
                kind = LineKind::Other;
            }
        }
        Some(kind)
    }
}

#[cfg(test)]
mod tests {
    use super::{body, scan, LineKind};
    use crate::languages::{HASH, PHP, SLASH};

    fn comments(text: &str, lang: crate::languages::Language) -> Vec<&str> {
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
        assert!(comments("code /* tail */", SLASH).is_empty());
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
}
