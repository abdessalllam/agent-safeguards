use std::collections::{HashMap, HashSet};

use crate::comments::{body, protected, scan, LineKind};
use crate::languages::{language_for_text, Language, CLIKE, GO, RUST, SCRIPT, SHELL};
use crate::locale::message;

pub const MAX_LINES: usize = 2;
pub const MAX_BLOCKS: usize = 1;
pub const MAX_LINE_CHARS: usize = 100;
const REWRAP_FILL: usize = 24;

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

#[derive(Clone)]
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
    body(line).chars().filter(|c| c.is_alphanumeric()).count()
}

fn words(line: &str) -> impl Iterator<Item = String> + '_ {
    body(line)
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
}

fn reuses_words(fresh: &[&str], removed: &HashMap<&str, usize>) -> bool {
    let mut bank: HashMap<String, usize> = HashMap::new();
    for (line, count) in removed {
        if *count == 0 {
            continue;
        }
        for word in words(line) {
            let entry = bank.entry(word).or_insert(0);
            *entry = entry.saturating_add(*count);
        }
    }
    for line in fresh {
        for word in words(line) {
            match bank.get_mut(&word) {
                Some(left) if *left > 0 => *left -= 1,
                _ => return false,
            }
        }
    }
    true
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
    let mut fresh_text: Vec<&str> = Vec::new();
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
        fresh_text.push(line);
        if let Some(marker) = history_marker(body(line)) {
            fresh_markers.push(marker);
        }
    }
    let mut removed_total = 0usize;
    let mut removed_long = 0usize;
    let mut removed_markers: HashMap<String, usize> = HashMap::new();
    for (line, count) in &pool {
        if *count == 0 {
            continue;
        }
        removed_total = removed_total.saturating_add(*count);
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
    if lettered > removed_total && removed_total > 0 && reuses_words(&fresh_text, &pool) {
        let room = removed_total.max(fresh_letters.div_ceil(REWRAP_FILL));
        net = lettered.saturating_sub(room);
    }
    let spare = removed_total.saturating_sub(lettered);
    net = net.saturating_add(fresh_blank.saturating_sub(spare));
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

pub struct Trimmed {
    pub text: String,
    pub dropped: HashSet<usize>,
    pub removed: Vec<String>,
}

fn raw_string_open(line: &str) -> bool {
    let bytes = line.as_bytes();
    let ident = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let mut at = 0usize;
    while let Some(&byte) = bytes.get(at) {
        at = at.saturating_add(1);
        if byte != b'r' {
            continue;
        }
        let start = at.saturating_sub(1);
        let mut before = start.checked_sub(1).and_then(|index| bytes.get(index)).copied();
        if matches!(before, Some(b'b' | b'c')) {
            before = start.checked_sub(2).and_then(|index| bytes.get(index)).copied();
        }
        if before.is_some_and(ident) {
            continue;
        }
        let hashes = bytes.iter().skip(at).take_while(|byte| **byte == b'#').count();
        let quote = at.saturating_add(hashes);
        if bytes.get(quote) != Some(&b'"') {
            continue;
        }
        let closer = format!("\"{}", "#".repeat(hashes));
        match line.get(quote.saturating_add(1)..).and_then(|rest| rest.find(&closer)) {
            Some(found) => at = quote.saturating_add(1).saturating_add(found).saturating_add(closer.len()),
            None => return true,
        }
    }
    false
}

fn nested_template(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut at = 0usize;
    while let Some(found) = text.get(at..).and_then(|rest| rest.find("${")) {
        let start = at.saturating_add(found).saturating_add(2);
        let mut depth = 1usize;
        let mut closed = false;
        let mut quote: Option<u8> = None;
        let mut escaped = false;
        for byte in bytes.iter().skip(start).take(4096) {
            if let Some(open) = quote {
                if escaped {
                    escaped = false;
                } else if *byte == b'\\' {
                    escaped = true;
                } else if *byte == open {
                    quote = None;
                } else if *byte == b'\n' {
                    return true;
                }
                continue;
            }
            match byte {
                b'"' | b'\'' => quote = Some(*byte),
                b'{' => depth = depth.saturating_add(1),
                b'}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        closed = true;
                        break;
                    }
                }
                b'`' | b'/' => return true,
                _ => {}
            }
        }
        if !closed {
            return true;
        }
        at = start;
    }
    false
}

fn directive_shaped(line: &str) -> bool {
    let text = body(line);
    let word: String = text
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@' | '<' | '>' | '/'))
        .collect();
    !word.is_empty() && text.get(word.len()..).is_some_and(|rest| rest.trim_start().starts_with([':', '=']))
}

fn jsx_like(text: &str) -> bool {
    text.lines().any(|line| !line.trim_start().starts_with("//") && (line.contains("</") || line.contains("/>")))
}

fn risky(text: &str, lang: Language) -> bool {
    if !lang.trim
        || text.contains("\\\n")
        || text.contains("\\\r")
        || text.starts_with("__END__")
        || text.contains("\n__END__")
        || text.contains("__DATA__")
    {
        return true;
    }
    (lang == SHELL && text.contains("<<"))
        || (lang == RUST && text.lines().any(raw_string_open))
        || (lang == CLIKE && (text.contains("R\"") || text.contains("@\"")))
        || (lang == GO && text.contains("\"C\""))
        || (lang == SCRIPT && (nested_template(text) || jsx_like(text)))
}

pub fn trimmed(change: &Change) -> Option<Trimmed> {
    if change.partial {
        return None;
    }
    let lang = language_for_text(&change.file, &change.new)?;
    if risky(&change.new, lang) {
        return None;
    }
    let mut pool: HashMap<&str, usize> = HashMap::new();
    match &change.baseline {
        Some(lines) => {
            for line in lines {
                *pool.entry(line.as_str()).or_insert(0) += 1;
            }
        }
        None => {
            for kind in scan(&change.old, lang) {
                if let LineKind::Comment(line) | LineKind::Also(line) = kind {
                    *pool.entry(line).or_insert(0) += 1;
                }
            }
        }
    }
    let mut scanner = scan(&change.new, lang);
    let mut fresh: Vec<(usize, &str)> = Vec::new();
    while let Some(kind) = scanner.next() {
        let (line, same_line) = match kind {
            LineKind::Comment(line) => (line, false),
            LineKind::Also(line) => (line, true),
            LineKind::Other => continue,
        };
        let kept = match pool.get_mut(line) {
            Some(count) if *count > 0 => {
                *count -= 1;
                true
            }
            _ => false,
        };
        let guarded = protected(body(line)) || (scanner.line_index() < 3 && directive_shaped(line));
        if !kept && !same_line && scanner.standalone() && !guarded {
            fresh.push((scanner.line_index(), line));
        }
    }
    if scanner.uncertain() || fresh.is_empty() {
        return None;
    }
    let lines: Vec<&str> = change.new.split('\n').collect();
    for keep in [MAX_LINES, 1, 0] {
        let mut kept = 0usize;
        let mut dropped: HashSet<usize> = HashSet::new();
        for (index, line) in &fresh {
            let fine = history_marker(body(line)).is_none() && line.chars().count() <= MAX_LINE_CHARS;
            if kept < keep && fine {
                kept = kept.saturating_add(1);
            } else {
                dropped.insert(*index);
            }
        }
        if dropped.is_empty() {
            continue;
        }
        let text = lines
            .iter()
            .enumerate()
            .filter(|(index, _)| !dropped.contains(index))
            .map(|(_, line)| *line)
            .collect::<Vec<&str>>()
            .join("\n");
        let trial = Change { new: text.clone(), ..change.clone() };
        if evaluate(std::slice::from_ref(&trial)).is_none() {
            let mut order: Vec<&usize> = dropped.iter().collect();
            order.sort();
            let removed = order.into_iter().filter_map(|index| lines.get(*index)).map(|line| line.trim().to_owned()).collect();
            return Some(Trimmed { text, dropped, removed });
        }
    }
    None
}

pub fn net_lines(change: &Change) -> usize {
    let Some(lang) = language_for_text(&change.file, &change.new) else {
        return 0;
    };
    let lang = if change.partial { lang.fragment() } else { lang };
    measure(change, lang).net_lines.saturating_sub(change.carry)
}

fn evaluate_detail(changes: &[Change]) -> Option<String> {
    let mut order: Vec<Aggregate<'_>> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    for change in changes {
        let Some(lang) = language_for_text(&change.file, &change.new) else {
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
