use std::collections::HashMap;

use crate::comments::{body, scan, LineKind};
use crate::languages::language_for;
use crate::locale::message;

pub const MAX_LINES: usize = 2;
pub const MAX_BLOCKS: usize = 1;
pub const MAX_LINE_CHARS: usize = 100;

const HISTORY_PHRASES: [&str; 8] = [
    "previously",
    "used to",
    "no longer",
    "was already",
    "originally",
    "formerly",
    "this change",
    "as requested",
];

pub struct Change {
    pub file: String,
    pub old: String,
    pub new: String,
}

struct Aggregate<'a> {
    file: &'a str,
    lines: usize,
    blocks: usize,
    marker: Option<&'a str>,
    too_long: bool,
}

pub fn evaluate(changes: &[Change]) -> Option<String> {
    let mut order: Vec<Aggregate<'_>> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    for change in changes {
        let Some(lang) = language_for(&change.file) else {
            continue;
        };
        let entry = match index.get(change.file.as_str()) {
            Some(found) => *found,
            None => {
                order.push(Aggregate {
                    file: change.file.as_str(),
                    lines: 0,
                    blocks: 0,
                    marker: None,
                    too_long: false,
                });
                let fresh = order.len().saturating_sub(1);
                index.insert(change.file.as_str(), fresh);
                fresh
            }
        };
        let Some(slot) = order.get_mut(entry) else {
            continue;
        };
        let mut pool: HashMap<&str, usize> = HashMap::new();
        for kind in scan(&change.old, lang) {
            if let LineKind::Comment(line) = kind {
                *pool.entry(line).or_insert(0) += 1;
            }
        }
        let mut running = false;
        for kind in scan(&change.new, lang) {
            match kind {
                LineKind::Comment(line) => {
                    let kept = match pool.get_mut(line) {
                        Some(count) if *count > 0 => {
                            *count -= 1;
                            true
                        }
                        _ => false,
                    };
                    if kept {
                        running = false;
                        continue;
                    }
                    if !running {
                        slot.blocks = slot.blocks.saturating_add(1);
                        running = true;
                    }
                    slot.lines = slot.lines.saturating_add(1);
                    if line.chars().count() > MAX_LINE_CHARS {
                        slot.too_long = true;
                    }
                    if slot.marker.is_none() {
                        slot.marker = history_marker(body(line));
                    }
                }
                LineKind::Other => running = false,
            }
        }
    }

    for aggregate in &order {
        if let Some(marker) = aggregate.marker {
            let detail = message(
                "comment_guard.detail.history",
                &[("file", aggregate.file), ("marker", marker)],
            );
            return Some(message("comment_guard.deny", &[("detail", detail.as_str())]));
        }
        if aggregate.too_long {
            let limit = MAX_LINE_CHARS.to_string();
            let detail = message(
                "comment_guard.detail.too_long",
                &[("file", aggregate.file), ("limit", limit.as_str())],
            );
            return Some(message("comment_guard.deny", &[("detail", detail.as_str())]));
        }
        if aggregate.lines > MAX_LINES || aggregate.blocks > MAX_BLOCKS {
            let lines = aggregate.lines.to_string();
            let blocks = aggregate.blocks.to_string();
            let max_lines = MAX_LINES.to_string();
            let detail = message(
                "comment_guard.detail.too_many",
                &[
                    ("file", aggregate.file),
                    ("lines", lines.as_str()),
                    ("blocks", blocks.as_str()),
                    ("max_lines", max_lines.as_str()),
                ],
            );
            return Some(message("comment_guard.deny", &[("detail", detail.as_str())]));
        }
    }
    None
}

fn is_word(c: char, underscore: bool) -> bool {
    c.is_alphanumeric() || (underscore && c == '_')
}

fn word_before(text: &str, at: usize, underscore: bool) -> bool {
    text.get(..at)
        .and_then(|head| head.chars().next_back())
        .is_some_and(|c| is_word(c, underscore))
}

fn word_after(text: &str, at: usize, underscore: bool) -> bool {
    text.get(at..)
        .and_then(|tail| tail.chars().next())
        .is_some_and(|c| is_word(c, underscore))
}

fn digit(byte: Option<&u8>) -> bool {
    matches!(byte, Some(value) if value.is_ascii_digit())
}

fn history_marker(text: &str) -> Option<&str> {
    if let Some(found) = find_date(text) {
        return Some(found);
    }
    if let Some(found) = find_decision(text) {
        return Some(found);
    }
    for phrase in HISTORY_PHRASES {
        if let Some(found) = find_phrase(text, phrase) {
            return Some(found);
        }
    }
    None
}

fn find_date(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while let Some(byte) = bytes.get(i) {
        if *byte == b'1' || *byte == b'2' {
            let end = i.saturating_add(10);
            if bytes.get(i..end).is_some_and(date_at) {
                if let Some(found) = text.get(i..end) {
                    return Some(found);
                }
            }
        }
        i = i.saturating_add(1);
    }
    None
}

fn date_at(slice: &[u8]) -> bool {
    let start = matches!(
        (slice.first().copied(), slice.get(1).copied()),
        (Some(b'1'), Some(b'9')) | (Some(b'2'), Some(b'0'))
    );
    start
        && digit(slice.get(2))
        && digit(slice.get(3))
        && slice.get(4).copied() == Some(b'-')
        && digit(slice.get(5))
        && digit(slice.get(6))
        && slice.get(7).copied() == Some(b'-')
        && digit(slice.get(8))
        && digit(slice.get(9))
}

fn find_decision(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    for (i, byte) in bytes.iter().enumerate() {
        if *byte != b'D' || word_before(text, i, true) {
            continue;
        }
        let mut end = i.saturating_add(1);
        while let Some(next) = bytes.get(end) {
            if next.is_ascii_digit() {
                end = end.saturating_add(1);
            } else {
                break;
            }
        }
        if end.saturating_sub(i).saturating_sub(1) < 2 || word_after(text, end, true) {
            continue;
        }
        if let Some(found) = text.get(i..end) {
            return Some(found);
        }
    }
    None
}

fn find_phrase<'a>(text: &'a str, phrase: &str) -> Option<&'a str> {
    let haystack = text.as_bytes();
    let needle = phrase.as_bytes();
    let last = haystack.len().checked_sub(needle.len())?;
    let mut i = 0usize;
    while i <= last {
        let end = i.saturating_add(needle.len());
        let window = haystack.get(i..end)?;
        if window.eq_ignore_ascii_case(needle)
            && !word_before(text, i, false)
            && !word_after(text, end, false)
        {
            return text.get(i..end);
        }
        i = i.saturating_add(1);
    }
    None
}
