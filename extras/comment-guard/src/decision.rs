use std::collections::HashMap;

use crate::comments::{body, scan, LineKind};
use crate::languages::{language_for, Language};
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
    pub baseline: Option<Vec<String>>,
    pub partial: bool,
    pub origin: Option<String>,
    pub carry: usize,
}

impl Change {
    pub fn whole(file: String, old: String, new: String) -> Change {
        Change {
            file,
            old,
            new,
            baseline: None,
            partial: false,
            origin: None,
            carry: 0,
        }
    }

    pub fn partial(file: String, old: String, new: String) -> Change {
        Change {
            file,
            old,
            new,
            baseline: None,
            partial: true,
            origin: None,
            carry: 0,
        }
    }
}

pub fn comment_lines(text: &str, lang: Language) -> Vec<String> {
    scan(text, lang)
        .filter_map(|kind| match kind {
            LineKind::Comment(line) | LineKind::Also(line) => Some(line.to_owned()),
            LineKind::Other => None,
        })
        .collect()
}

struct Aggregate<'a> {
    file: &'a str,
    lines: usize,
    blocks: usize,
    marker: Option<&'a str>,
    too_long: bool,
}

pub fn evaluate(changes: &[Change]) -> Option<String> {
    let detail = evaluate_detail(changes)?;
    Some(message("comment_guard.deny", &[("detail", detail.as_str())]))
}

pub fn evaluate_after(changes: &[Change]) -> Option<String> {
    let detail = evaluate_detail(changes)?;
    Some(message("comment_guard.after", &[("detail", detail.as_str())]))
}

struct Measure<'a> {
    net_lines: usize,
    blocks: usize,
    too_long: bool,
    marker: Option<&'a str>,
}

fn letters(line: &str) -> usize {
    body(line).chars().filter(|c| !c.is_whitespace()).count()
}

fn measure(change: &Change, lang: Language) -> Measure<'_> {
    let mut pool: HashMap<&str, usize> = HashMap::new();
    match &change.baseline {
        Some(lines) if !change.partial => {
            for line in lines {
                *pool.entry(line.as_str()).or_insert(0) += 1;
            }
        }
        _ => {
            for kind in scan(&change.old, lang) {
                if let LineKind::Comment(line) | LineKind::Also(line) = kind {
                    *pool.entry(line).or_insert(0) += 1;
                }
            }
        }
    }
    let mut running = false;
    let mut counted = false;
    let mut fresh_lines = 0usize;
    let mut fresh_blocks = 0usize;
    let mut fresh_long = 0usize;
    let mut fresh_letters = 0usize;
    let mut fresh_blank = 0usize;
    let mut fresh_markers: Vec<&str> = Vec::new();
    for kind in scan(&change.new, lang) {
        let (line, same_line) = match kind {
            LineKind::Comment(line) => (line, false),
            LineKind::Also(line) => (line, true),
            LineKind::Other => {
                running = false;
                counted = false;
                continue;
            }
        };
        if !same_line {
            counted = false;
        }
        let kept = match pool.get_mut(line) {
            Some(count) if *count > 0 => {
                *count -= 1;
                true
            }
            _ => false,
        };
        if kept {
            if !same_line {
                running = false;
            }
            continue;
        }
        if !counted {
            if !running {
                fresh_blocks = fresh_blocks.saturating_add(1);
                running = true;
            }
            fresh_lines = fresh_lines.saturating_add(1);
            if letters(line) == 0 {
                fresh_blank = fresh_blank.saturating_add(1);
            }
            counted = true;
        }
        if line.chars().count() > MAX_LINE_CHARS {
            fresh_long = fresh_long.saturating_add(1);
        }
        fresh_letters = fresh_letters.saturating_add(letters(line));
        if let Some(marker) = history_marker(body(line)) {
            fresh_markers.push(marker);
        }
    }
    let mut removed_total = 0usize;
    let mut removed_long = 0usize;
    let mut removed_letters = 0usize;
    let mut removed_markers: HashMap<String, usize> = HashMap::new();
    for (line, count) in &pool {
        if *count == 0 {
            continue;
        }
        removed_total = removed_total.saturating_add(*count);
        removed_letters = removed_letters.saturating_add(letters(line).saturating_mul(*count));
        if line.chars().count() > MAX_LINE_CHARS {
            removed_long = removed_long.saturating_add(*count);
        }
        if let Some(marker) = history_marker(body(line)) {
            let entry = removed_markers.entry(marker.to_ascii_lowercase()).or_insert(0);
            *entry = entry.saturating_add(*count);
        }
    }
    let lettered = fresh_lines.saturating_sub(fresh_blank);
    let mut net = lettered.saturating_sub(removed_total);
    if removed_total > 0 && fresh_letters <= removed_letters {
        net = 0;
    }
    net = net.saturating_add(fresh_blank);
    let mut marker = None;
    for found in fresh_markers {
        match removed_markers.get_mut(&found.to_ascii_lowercase()) {
            Some(count) if *count > 0 => *count -= 1,
            _ => {
                marker = Some(found);
                break;
            }
        }
    }
    Measure {
        net_lines: net.saturating_add(change.carry),
        blocks: fresh_blocks.min(net).saturating_add(usize::from(change.carry > 0)),
        too_long: fresh_long > removed_long,
        marker,
    }
}

pub fn net_lines(change: &Change) -> usize {
    let Some(lang) = language_for(&change.file) else {
        return 0;
    };
    let lang = if change.partial { lang.fragment() } else { lang };
    measure(change, lang).net_lines.saturating_sub(change.carry)
}

fn evaluate_detail(changes: &[Change]) -> Option<String> {
    let mut order: Vec<Aggregate<'_>> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    for change in changes {
        let Some(lang) = language_for(&change.file) else {
            continue;
        };
        let lang = if change.partial { lang.fragment() } else { lang };
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
        let measured = measure(change, lang);
        slot.lines = slot.lines.saturating_add(measured.net_lines);
        slot.blocks = slot.blocks.saturating_add(measured.blocks);
        if measured.too_long {
            slot.too_long = true;
        }
        if slot.marker.is_none() {
            slot.marker = measured.marker;
        }
    }

    for aggregate in &order {
        if let Some(marker) = aggregate.marker {
            let detail = message(
                "comment_guard.detail.history",
                &[("file", aggregate.file), ("marker", marker)],
            );
            return Some(detail);
        }
        if aggregate.too_long {
            let limit = MAX_LINE_CHARS.to_string();
            let detail = message(
                "comment_guard.detail.too_long",
                &[("file", aggregate.file), ("limit", limit.as_str())],
            );
            return Some(detail);
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
            return Some(detail);
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
            && !word_before(text, i, true)
            && !word_after(text, end, true)
        {
            return text.get(i..end);
        }
        i = i.saturating_add(1);
    }
    None
}
