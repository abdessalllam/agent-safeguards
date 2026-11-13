use std::collections::{HashMap, HashSet};

use crate::comments::{body, protected, scan, LineKind};
use crate::languages::{language_for_text, Language, CLIKE, GO, HTML, KOTLIN, PYTHON, RUST, SCRIPT, SHELL, SWIFT};
use crate::limits;
use crate::locale::message;

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

const LICENCE_PHRASES: [&str; 6] = [
    "\u{a9}",
    "licensed under",
    "licensed to",
    "all rights reserved",
    "permission is hereby granted",
    "redistribution and use in source",
];
const HEADER_LINES: usize = 40;

fn names_a_licence(line: &str) -> bool {
    let lower = line.to_lowercase();
    if LICENCE_PHRASES.iter().any(|phrase| lower.contains(phrase)) {
        return true;
    }
    lower.match_indices("copyright").any(|(at, word)| {
        let rest = lower.get(at.saturating_add(word.len())..).unwrap_or("").trim_start();
        ["(c)", "the ", "contributors"].iter().any(|start| rest.starts_with(start)) || rest.starts_with(|c: char| c.is_ascii_digit())
    })
}

fn licence_header(text: &str, lang: Language) -> Vec<String> {
    let mut header: Vec<String> = Vec::new();
    let mut scanner = scan(text, lang);
    while let Some(kind) = scanner.next() {
        match kind {
            LineKind::Comment(line) if !scanner.shares_line_with_code() => header.push(line.to_owned()),
            LineKind::Other if scanner.is_blank() && !header.is_empty() => break,
            LineKind::Other if !scanner.shares_line_with_code() => {}
            _ => break,
        }
        if header.len() >= HEADER_LINES {
            break;
        }
    }
    if header.iter().any(|line| names_a_licence(line)) {
        header
    } else {
        Vec::new()
    }
}

pub fn add_existing(change: &mut Change, lang: Language, lines: Vec<String>) -> bool {
    let mut merged = change.baseline.clone().unwrap_or_else(|| comment_lines(&change.old, lang));
    let mut held: HashMap<String, usize> = HashMap::new();
    for line in &merged {
        *held.entry(line.clone()).or_insert(0) += 1;
    }
    let mut grown = false;
    for line in lines {
        match held.get_mut(&line) {
            Some(count) if *count > 0 => *count -= 1,
            _ => {
                merged.push(line);
                grown = true;
            }
        }
    }
    if grown {
        change.baseline = Some(merged);
    }
    grown
}

pub fn widen_with_headers(changes: &mut [Change]) {
    for change in changes.iter_mut().filter(|change| !change.partial) {
        let Some(lang) = language_for_text(&change.file, &change.new) else {
            continue;
        };
        let header = licence_header(&change.new, lang);
        add_existing(change, lang, header);
    }
}

fn opens_scope(line: &str) -> bool {
    line.trim_end().ends_with([':', '{', '(', '['])
}

fn tidy_blanks(lines: &[&str], old: &str, gone: &mut HashSet<usize>, standing: &HashMap<usize, String>) {
    let old_lines: Vec<&str> = old.split('\n').collect();
    let prefix = if old.is_empty() {
        0
    } else {
        lines.iter().zip(&old_lines).take_while(|(new, before)| new == before).count()
    };
    let room = old_lines.len().min(lines.len()).saturating_sub(prefix);
    let suffix = lines
        .iter()
        .rev()
        .zip(old_lines.iter().rev())
        .take(room)
        .take_while(|(new, before)| new == before)
        .count();
    let editable = prefix..lines.len().saturating_sub(suffix);
    let blank = |index: usize| lines.get(index).is_some_and(|line| line.trim().is_empty()) && !standing.contains_key(&index);
    let mut kept: Vec<usize> = Vec::new();
    let mut added: Vec<usize> = Vec::new();
    let mut gap = false;
    for index in 0..lines.len() {
        if gone.contains(&index) {
            gap = true;
            continue;
        }
        if gap && blank(index) && editable.contains(&index) {
            let after_opener = |prev: usize| blank(prev) || opens_scope(lines.get(prev).copied().unwrap_or(""));
            if kept.last().copied().is_none_or(after_opener) {
                added.push(index);
                gap = false;
                continue;
            }
        }
        if gap && index.saturating_add(1) == lines.len() && blank(index) {
            if let Some(prev) = kept.last().copied().filter(|prev| blank(*prev) && editable.contains(prev)) {
                kept.pop();
                added.push(prev);
            }
        }
        gap = false;
        kept.push(index);
    }
    gone.extend(added);
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
    excess: usize,
    longest: usize,
    marker: Option<&'a str>,
    too_long: bool,
    first: Option<&'a str>,
    long: Option<&'a str>,
}

fn excerpt(line: &str) -> String {
    let text = line.trim();
    let shown: String = text.chars().take(60).collect();
    if text.chars().count() > 60 {
        format!("{shown}...")
    } else {
        shown
    }
}

pub fn evaluate(changes: &[Change]) -> Option<String> {
    let detail = evaluate_detail(changes)?;
    let max_lines = limits::current().lines.to_string();
    Some(message("comment_guard.deny", &[("detail", detail.as_str()), ("max_lines", max_lines.as_str())]))
}

pub fn evaluate_after(changes: &[Change]) -> Option<String> {
    let detail = evaluate_detail(changes)?;
    let max_lines = limits::current().lines.to_string();
    Some(message("comment_guard.after", &[("detail", detail.as_str()), ("max_lines", max_lines.as_str())]))
}

struct Measure<'a> {
    net_lines: usize,
    excess: usize,
    longest: usize,
    too_long: bool,
    marker: Option<&'a str>,
    first: Option<&'a str>,
    long: Option<&'a str>,
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
    let max_chars = limits::current().line_chars;
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
    let mut counted = false;
    let mut fresh_lines = 0usize;
    let mut run_fresh = 0usize;
    let mut run_doc = false;
    let mut runs: Vec<usize> = Vec::new();
    let mut fresh_long = 0usize;
    let mut first_fresh: Option<&str> = None;
    let mut first_long: Option<&str> = None;
    let mut fresh_letters = 0usize;
    let mut fresh_blank = 0usize;
    let mut fresh_text: Vec<&str> = Vec::new();
    let mut fresh_markers: Vec<&str> = Vec::new();
    let mut scanner = scan(&change.new, lang);
    while let Some(kind) = scanner.next() {
        let (line, same_line) = match kind {
            LineKind::Comment(line) => (line, false),
            LineKind::Also(line) => (line, true),
            LineKind::Other => {
                counted = false;
                if !scanner.is_blank() && run_fresh > 0 {
                    runs.push(run_fresh);
                    run_fresh = 0;
                }
                continue;
            }
        };
        let coded = scanner.shares_line_with_code();
        let doc = scanner.is_doc_line();
        if !same_line {
            counted = false;
            if coded || doc != run_doc {
                if run_fresh > 0 {
                    runs.push(run_fresh);
                    run_fresh = 0;
                }
                run_doc = doc && !coded;
            }
        }
        let kept = match pool.get_mut(line) {
            Some(count) if *count > 0 => {
                *count -= 1;
                true
            }
            _ => false,
        };
        if kept {
            continue;
        }
        if !counted {
            fresh_lines = fresh_lines.saturating_add(1);
            if !scanner.is_exempt_doc_line() && letters(line) > 0 {
                run_fresh = run_fresh.saturating_add(1);
            }
            if coded && run_fresh > 0 {
                runs.push(run_fresh);
                run_fresh = 0;
            }
            if letters(line) == 0 {
                fresh_blank = fresh_blank.saturating_add(1);
            }
            counted = true;
        }
        first_fresh.get_or_insert(line);
        if line.chars().count() > max_chars {
            fresh_long = fresh_long.saturating_add(1);
            first_long.get_or_insert(line);
        }
        fresh_letters = fresh_letters.saturating_add(letters(line));
        fresh_text.push(line);
        if let Some(marker) = history_marker(body(line)) {
            fresh_markers.push(marker);
        }
    }
    if run_fresh > 0 {
        runs.push(run_fresh);
    }
    let mut removed_total = 0usize;
    let mut removed_long = 0usize;
    let mut removed_markers: HashMap<String, usize> = HashMap::new();
    for (line, count) in &pool {
        if *count == 0 {
            continue;
        }
        removed_total = removed_total.saturating_add(*count);
        if line.chars().count() > max_chars {
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
    let limit = limits::current().lines;
    let over: usize = runs.iter().map(|run| run.saturating_sub(limit)).sum();
    let forgiven = fresh_lines.saturating_sub(net);
    Measure {
        net_lines: net,
        excess: over.saturating_sub(forgiven),
        longest: runs.iter().copied().max().unwrap_or(0),
        too_long: fresh_long > removed_long,
        marker,
        first: first_fresh,
        long: first_long,
    }
}

pub struct Trimmed {
    pub text: String,
    pub dropped: HashSet<usize>,
    pub swapped: HashMap<usize, String>,
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
        let mut previous = b' ';
        for (offset, byte) in bytes.iter().enumerate().skip(start).take(4096) {
            if let Some(open) = quote {
                if escaped {
                    escaped = false;
                } else if *byte == b'\\' {
                    escaped = true;
                } else if *byte == open {
                    quote = None;
                } else if matches!(*byte, b'\n' | b'`') {
                    return true;
                }
                continue;
            }
            match byte {
                b'"' | b'\'' => {
                    quote = Some(*byte);
                    previous = *byte;
                }
                b'{' => depth = depth.saturating_add(1),
                b'}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        closed = true;
                        break;
                    }
                }
                b'`' => return true,
                b'/' => {
                    let division = previous.is_ascii_alphanumeric() || matches!(previous, b'_' | b'$' | b')' | b']');
                    if !division || matches!(bytes.get(offset.saturating_add(1)), Some(b'/' | b'*')) {
                        return true;
                    }
                }
                _ => {}
            }
            if !byte.is_ascii_whitespace() {
                previous = *byte;
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

fn nested_triple(text: &str, opener: &str, inc: u8, dec: u8) -> bool {
    let bytes = text.as_bytes();
    let mut at = 0usize;
    while let Some(found) = text.get(at..).and_then(|rest| rest.find(opener)) {
        let start = at.saturating_add(found).saturating_add(opener.len());
        let mut depth = 1usize;
        let mut closed = false;
        for (offset, byte) in bytes.iter().enumerate().skip(start).take(4096) {
            if *byte == inc {
                depth = depth.saturating_add(1);
            } else if *byte == dec {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    closed = true;
                    break;
                }
            } else if matches!(bytes.get(offset..offset.saturating_add(3)), Some(b"\"\"\"")) {
                return true;
            }
        }
        if !closed {
            return true;
        }
        at = start;
    }
    false
}

fn fstring_triple(text: &str) -> bool {
    ["\"\"\"", "'''"].iter().any(|delim| {
        text.match_indices(delim).any(|(at, _)| {
            let head = text.get(..at).unwrap_or("");
            let run: String = head.chars().rev().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            run.len() <= 3 && run.chars().all(|c| "rRbBuUfFtT".contains(c)) && run.chars().any(|c| matches!(c, 'f' | 'F' | 't' | 'T'))
        })
    })
}

fn is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn has_f_prefix(bytes: &[u8], open: usize) -> bool {
    string_prefix(bytes, open).0
}

fn string_prefix(bytes: &[u8], open: usize) -> (bool, bool) {
    let mut start = open;
    while start > 0 && open.saturating_sub(start) < 2 {
        let Some(byte) = bytes.get(start.saturating_sub(1)) else {
            break;
        };
        if !matches!(byte, b'r' | b'R' | b'f' | b'F' | b't' | b'T') {
            break;
        }
        start = start.saturating_sub(1);
    }
    let prefix = bytes.get(start..open).unwrap_or(&[]);
    let bounded = start == 0 || bytes.get(start.saturating_sub(1)).is_some_and(|byte| !is_ident(*byte));
    let formatted = bounded && prefix.iter().any(|byte| matches!(byte, b'f' | b'F' | b't' | b'T'));
    (formatted, prefix.iter().any(|byte| matches!(byte, b'r' | b'R')))
}

fn interpolation_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut index = start;
    while let Some(&current) = bytes.get(index) {
        match current {
            b'\n' | b'\\' | b'#' => return None,
            b'\'' | b'"' => index = literal_end(bytes, index)?,
            b'(' | b'[' | b'{' => {
                depth = depth.saturating_add(1);
                index = index.saturating_add(1);
            }
            b')' | b']' => {
                depth = depth.checked_sub(1)?;
                index = index.saturating_add(1);
            }
            b'}' if depth == 0 => return Some(index.saturating_add(1)),
            b'}' => {
                depth = depth.saturating_sub(1);
                index = index.saturating_add(1);
            }
            b':' if depth == 0 => return spec_end(bytes, index.saturating_add(1)),
            _ => index = index.saturating_add(1),
        }
    }
    None
}

fn spec_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start;
    while let Some(&current) = bytes.get(index) {
        match current {
            b'\n' => return None,
            b'{' => index = interpolation_end(bytes, index.saturating_add(1))?,
            b'}' => return Some(index.saturating_add(1)),
            _ => index = index.saturating_add(1),
        }
    }
    None
}

fn literal_end(bytes: &[u8], open: usize) -> Option<usize> {
    let quote = *bytes.get(open)?;
    let after = open.saturating_add(1);
    if bytes.get(after) == Some(&quote) && bytes.get(after.saturating_add(1)) == Some(&quote) {
        return None;
    }
    let (formatted, raw) = string_prefix(bytes, open);
    let mut index = after;
    while let Some(&current) = bytes.get(index) {
        match current {
            b'\\' if formatted => {
                let next = bytes.get(index.saturating_add(1));
                let named = !raw && next == Some(&b'N') && bytes.get(index.saturating_add(2)) == Some(&b'{');
                if named {
                    let close = bytes.get(index..)?.iter().position(|byte| *byte == b'}')?;
                    index = index.saturating_add(close).saturating_add(1);
                } else if next == Some(&b'{') {
                    index = index.saturating_add(1);
                } else {
                    index = index.saturating_add(2);
                }
            }
            b'\\' => index = index.saturating_add(2),
            b'\n' => return None,
            _ if current == quote => return Some(index.saturating_add(1)),
            b'{' if formatted => {
                if bytes.get(index.saturating_add(1)) == Some(&b'{') {
                    index = index.saturating_add(2);
                } else {
                    index = interpolation_end(bytes, index.saturating_add(1))?;
                }
            }
            _ => index = index.saturating_add(1),
        }
    }
    None
}

fn first_quote_end(bytes: &[u8], open: usize) -> Option<usize> {
    let quote = *bytes.get(open)?;
    let mut index = open.saturating_add(1);
    while let Some(&current) = bytes.get(index) {
        match current {
            b'\\' => index = index.saturating_add(2),
            b'\n' => return None,
            _ if current == quote => return Some(index.saturating_add(1)),
            _ => index = index.saturating_add(1),
        }
    }
    None
}

fn fstring_misread(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.iter().enumerate().any(|(open, byte)| {
        matches!(byte, b'"' | b'\'') && has_f_prefix(bytes, open) && {
            let plain = first_quote_end(bytes, open);
            plain.is_some() && plain != literal_end(bytes, open)
        }
    })
}

fn header_key(head: &str) -> String {
    let code = head.split('#').next().unwrap_or("");
    let mut words = code.split_whitespace().peekable();
    if words.peek() == Some(&"async") {
        words.next();
    }
    if let Some(word) = words.next().filter(|word| matches!(*word, "def" | "class")) {
        let rest = words.next().unwrap_or("");
        let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        return format!("{word} {name}");
    }
    code.chars().filter(|c| !c.is_whitespace()).collect()
}

fn is_def_key(key: &str) -> bool {
    key.starts_with("def ") || key.starts_with("class ")
}

fn header_path(lines: &[&str], logical: &[usize], start: usize) -> String {
    let mut parts = vec![header_key(lines.get(start).map_or("", |line| line.trim()))];
    let mut indent = lines.get(start).map_or(0, |line| indent_of(line));
    for index in (0..start).rev() {
        if logical.get(index).copied() != Some(index) {
            continue;
        }
        let Some(line) = lines.get(index).filter(|line| code_line(line)) else {
            continue;
        };
        let key = header_key(line.trim());
        if indent_of(line) < indent {
            indent = indent_of(line);
            if is_def_key(&key) {
                parts.push(key);
            }
        }
    }
    parts.reverse();
    parts.join(">")
}

fn anchor_of(lines: &[&str], logical: &[usize], first: usize) -> String {
    let found = (0..first).rev().find(|index| lines.get(*index).is_some_and(|line| code_line(line)));
    let Some(index) = found else {
        return String::new();
    };
    let start = logical.get(index).copied().unwrap_or(index);
    header_path(lines, logical, start)
}

fn starts_with_quote(line: &str) -> bool {
    let bare = line.trim_start_matches(|c: char| c == '(' || c.is_whitespace());
    bare.trim_start_matches(|c: char| "rRuUbBfF".contains(c)).starts_with(['"', '\''])
}

fn has_inline_string(line: &str) -> bool {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut skip = false;
    for (at, ch) in line.char_indices() {
        if skip {
            skip = false;
            continue;
        }
        match (quote, ch) {
            (Some(_), '\\') => skip = true,
            (Some(open), _) if ch == open => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(ch),
            (None, '(' | '[' | '{') => depth = depth.saturating_add(1),
            (None, ')' | ']' | '}') => depth = depth.saturating_sub(1),
            (None, ':') if depth == 0 => {
                return starts_with_quote(line.get(at.saturating_add(1)..).unwrap_or("").trim_start());
            }
            (None, '#') => return false,
            _ => {}
        }
    }
    false
}

fn doc_anchors(old: &str, lang: Language) -> HashSet<String> {
    let lines: Vec<&str> = old.split('\n').collect();
    let mut logical: Vec<usize> = Vec::with_capacity(lines.len());
    let mut found = HashSet::new();
    let mut scanner = scan(old, lang);
    while scanner.next().is_some() {
        let index = scanner.line_index();
        while logical.len() <= index {
            let start = if scanner.starts_logical() { index } else { logical.last().copied().unwrap_or(0) };
            logical.push(start);
        }
        if scanner.doc_start() {
            found.insert(anchor_of(&lines, &logical, index));
        }
    }
    for (index, line) in lines.iter().enumerate() {
        if logical.get(index).copied() != Some(index) || !code_line(line) {
            continue;
        }
        if starts_with_quote(line.trim()) {
            found.insert(anchor_of(&lines, &logical, index));
        } else if is_def_key(&header_key(line.trim())) && has_inline_string(line) {
            found.insert(header_path(&lines, &logical, index));
        }
    }
    found
}

fn doc_text(line: &str) -> &str {
    let text = line.trim();
    let bare = text.trim_start_matches(|c: char| "rRuUbBfF".contains(c));
    let opened = ["\"\"\"", "'''"].iter().find_map(|delim| bare.strip_prefix(delim));
    let text = opened.unwrap_or(text);
    let closed = ["\"\"\"", "'''"].iter().find_map(|delim| text.strip_suffix(delim));
    closed.unwrap_or(text).trim()
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
        || text.to_ascii_lowercase().contains("local variables:")
    {
        return true;
    }
    (lang == SHELL && text.contains("<<"))
        || (lang == RUST && text.lines().any(raw_string_open))
        || (lang == CLIKE && (text.contains("R\"") || text.contains("@\"")))
        || (lang == GO && text.contains("\"C\""))
        || (lang == SWIFT && (text.contains("#\"") || nested_triple(text, "\\(", b'(', b')')))
        || (lang == KOTLIN && nested_triple(text, "${", b'{', b'}'))
        || (lang == PYTHON && (fstring_triple(text) || fstring_misread(text)))
        || (lang == SCRIPT && (nested_template(text) || jsx_like(text)))
}

fn still_open(opened: Option<usize>, closed: Option<usize>) -> bool {
    opened.is_some_and(|at| closed.is_none_or(|end| at > end))
}

const RAW_TEXT_TAGS: [&str; 5] = ["script", "style", "textarea", "title", "xmp"];

fn tag_boundary(rest: &str) -> bool {
    rest.chars().next().is_none_or(|next| next.is_ascii_whitespace() || next == '>' || next == '/')
}

fn raw_text_tag(rest: &str) -> Option<&'static str> {
    RAW_TEXT_TAGS.iter().copied().find(|tag| rest.strip_prefix(tag).is_some_and(tag_boundary))
}

// A `>` inside a quoted attribute value does not end the opening tag.
fn tag_end(rest: &str) -> Option<usize> {
    let mut quote = None;
    for (at, ch) in rest.char_indices() {
        match (quote, ch) {
            (None, '"' | '\'') => quote = Some(ch),
            (Some(open), _) if ch == open => quote = None,
            (None, '>') => return Some(at.saturating_add(1)),
            _ => {}
        }
    }
    None
}

fn closer_end(rest: &str, tag: &str) -> Option<usize> {
    let pattern = format!("</{tag}");
    rest.match_indices(&pattern)
        .find(|(at, _)| tag_boundary(rest.get(at.saturating_add(pattern.len())..).unwrap_or("")))
        .map(|(at, _)| at.saturating_add(pattern.len()))
}

// Walks the tags in order so a closer inside an opening tag's attribute is not a closer.
fn raw_text_open(before: &str) -> bool {
    let lower = before.to_ascii_lowercase();
    if still_open(lower.rfind("<![cdata["), lower.rfind("]]>")) {
        return true;
    }
    let mut rest = lower.as_str();
    while let Some(start) = rest.find('<') {
        rest = rest.get(start.saturating_add(1)..).unwrap_or("");
        let Some(tag) = raw_text_tag(rest) else { continue };
        let Some(opened) = rest.get(tag.len()..).and_then(tag_end) else { return true };
        rest = rest.get(tag.len().saturating_add(opened)..).unwrap_or("");
        match closer_end(rest, tag) {
            Some(end) => rest = rest.get(end..).unwrap_or(""),
            None => return true,
        }
    }
    false
}

// A plain `<!--` outside raw text is cut; scripts and template tags hold code.
fn html_cuttable(lines: &[&str], first: usize, last: usize) -> bool {
    let block = lines.get(first..=last).unwrap_or(&[]);
    block.first().is_some_and(|line| line.trim_start().starts_with("<!--"))
        && !block.iter().any(|line| ["{%", "{{", "<%", "<?", "${"].iter().any(|mark| line.contains(mark)))
        && lines.get(..first).is_some_and(|before| !raw_text_open(&before.join("\n")))
}

struct Piece {
    run: usize,
    first: usize,
    last: usize,
    shown: Vec<String>,
    cost: usize,
    fine: bool,
    docstring: bool,
}

struct OpenBlock {
    first: usize,
    shown: Vec<String>,
    fine: bool,
    fresh: bool,
    lettered: usize,
}

struct OpenDoc {
    first: usize,
    shown: Vec<String>,
    fine: bool,
    fresh: bool,
    statement: bool,
    exempt: bool,
    lettered: usize,
}

fn fits(line: &str) -> bool {
    history_marker(body(line)).is_none() && line.chars().count() <= limits::current().line_chars
}

fn code_line(line: &str) -> bool {
    let text = line.trim();
    !text.is_empty() && !text.starts_with('#')
}

fn indent_of(line: &str) -> usize {
    let mut column = 0usize;
    for ch in line.chars() {
        match ch {
            ' ' => column = column.saturating_add(1),
            '\t' => column = (column / 8).saturating_add(1).saturating_mul(8),
            '\x0c' => column = 0,
            _ => break,
        }
    }
    column
}

fn delimiter_only(line: &str) -> bool {
    let bare = line.trim_start_matches(|c: char| "rRuUbBfF".contains(c));
    bare == "\"\"\"" || bare == "'''"
}

fn opens_block(line: &str) -> bool {
    let code = line.trim_end();
    code.ends_with(':')
        || code
            .match_indices('#')
            .any(|(at, _)| line.get(..at).is_some_and(|head| head.trim_end().ends_with(':')))
}

// A docstring that is the only statement of its block cannot just be removed: the block
// would be empty. Over-reading a header here only adds a harmless `pass`.
fn needs_pass(
    lines: &[&str],
    logical: &[usize],
    gone: &HashSet<usize>,
    standing: &HashMap<usize, String>,
    piece: &Piece,
) -> bool {
    let mut head = None;
    for index in (0..piece.first).rev() {
        if standing.contains_key(&index) {
            return false;
        }
        if gone.contains(&index) {
            continue;
        }
        if lines.get(index).is_some_and(|line| code_line(line)) {
            head = Some(index);
            break;
        }
    }
    let Some(head) = head.filter(|index| lines.get(*index).is_some_and(|line| opens_block(line))) else {
        return false;
    };
    let opener = logical.get(head).copied().unwrap_or(head);
    let base = lines.get(opener).map_or(0, |line| indent_of(line));
    for index in piece.last.saturating_add(1)..lines.len() {
        if gone.contains(&index) {
            continue;
        }
        if let Some(line) = lines.get(index).filter(|line| code_line(line)) {
            return indent_of(line) <= base;
        }
    }
    true
}

pub fn trimmed(change: &Change) -> Option<Trimmed> {
    trimmed_with(change, true)
}

pub fn trimmed_with(change: &Change, docstrings: bool) -> Option<Trimmed> {
    if change.partial {
        return None;
    }
    let lang = language_for_text(&change.file, &change.new)?;
    if risky(&change.new, lang) {
        return None;
    }
    let mut pool: HashMap<&str, usize> = HashMap::new();
    if let Some(lines) = &change.baseline {
        for line in lines {
            *pool.entry(line.as_str()).or_insert(0) += 1;
        }
    }
    let mut carried: HashMap<&str, usize> = HashMap::new();
    for kind in scan(&change.old, lang) {
        if let LineKind::Comment(line) | LineKind::Also(line) = kind {
            *carried.entry(line).or_insert(0) += 1;
        }
    }
    for (line, count) in carried {
        let slot = pool.entry(line).or_insert(0);
        *slot = (*slot).max(count);
    }
    let anchors = if lang.docstring { doc_anchors(&change.old, lang) } else { HashSet::new() };
    let old_unclear = lang.docstring && (change.old.contains("\\\n") || change.old.contains("\\\r"));
    let lines: Vec<&str> = change.new.split('\n').collect();
    let mut logical: Vec<usize> = Vec::with_capacity(lines.len());
    let mut scanner = scan(&change.new, lang);
    let mut pieces: Vec<Piece> = Vec::new();
    let mut run_id = 0usize;
    let have_baseline = change.baseline.is_some() && !change.partial;
    let mut baseline_pool: HashMap<&str, usize> = HashMap::new();
    if have_baseline {
        for line in change.baseline.iter().flatten() {
            *baseline_pool.entry(line.as_str()).or_insert(0) += 1;
        }
    }
    let mut held: HashMap<usize, usize> = HashMap::new();
    let mut last_doc: Option<bool> = None;
    let mut block: Option<OpenBlock> = None;
    let mut open: Option<OpenDoc> = None;
    while let Some(kind) = scanner.next() {
        let index = scanner.line_index();
        while logical.len() <= index {
            let start = if scanner.starts_logical() { index } else { logical.last().copied().unwrap_or(0) };
            logical.push(start);
        }
        if scanner.doc_start() {
            open = Some(OpenDoc {
                first: index,
                shown: Vec::new(),
                fine: true,
                fresh: !anchors.contains(&anchor_of(&lines, &logical, index)),
                statement: scanner.at_statement(),
                exempt: scanner.is_exempt_doc_line(),
                lettered: 0,
            });
        }
        if scanner.block_start() {
            block = Some(OpenBlock {
                first: index,
                shown: Vec::new(),
                fine: true,
                fresh: true,
                lettered: 0,
            });
        }
        let found = match kind {
            LineKind::Comment(line) => Some((line, false)),
            LineKind::Also(line) => Some((line, true)),
            LineKind::Other => None,
        };
        if open.is_none() && ((found.is_none() && !scanner.is_blank()) || (found.is_some() && scanner.shares_line_with_code())) {
            run_id = run_id.saturating_add(1);
            last_doc = None;
        }
        if let (Some((_, false)), true, true) = (found, open.is_none() && block.is_none(), !scanner.shares_line_with_code()) {
            let now = scanner.is_doc_line();
            if last_doc.is_some_and(|before| before != now) {
                run_id = run_id.saturating_add(1);
            }
            last_doc = Some(now);
        }
        if found.is_none() {
            let raw = lines.get(index).map_or("", |line| line.trim());
            if let Some(doc) = open.as_mut().filter(|_| !raw.is_empty() && !delimiter_only(raw)) {
                doc.fresh = false;
            }
        }
        if let Some((line, same_line)) = found {
            let kept = match pool.get_mut(line) {
                Some(count) if *count > 0 => {
                    *count -= 1;
                    true
                }
                _ => false,
            };
            let from_baseline = match baseline_pool.get_mut(line) {
                Some(count) if *count > 0 => {
                    *count -= 1;
                    true
                }
                _ => false,
            };
            if kept && !from_baseline && have_baseline && open.is_none() && !same_line && !scanner.shares_line_with_code() {
                *held.entry(run_id).or_insert(0) += 1;
            }
            if let Some(doc) = open.as_mut() {
                let text = doc_text(line);
                doc.fresh &= !kept && !protected(body(line)) && !protected(text);
                doc.fine &= fits(line);
                doc.shown.push(line.trim().to_owned());
                if letters(line) > 0 {
                    doc.lettered = doc.lettered.saturating_add(1);
                }
            } else if let Some(unit) = block.as_mut() {
                let guarded = protected(body(line)) || (scanner.line_index() < 3 && directive_shaped(line));
                unit.fresh &= !kept && !guarded;
                unit.fine &= fits(line);
                unit.shown.push(line.trim().to_owned());
                if letters(line) > 0 {
                    unit.lettered = unit.lettered.saturating_add(1);
                }
            } else {
                let guarded = protected(body(line)) || (scanner.line_index() < 3 && directive_shaped(line));
                if !kept && !same_line && scanner.standalone() && !guarded && (lang != HTML || html_cuttable(&lines, index, index)) {
                    pieces.push(Piece {
                        run: run_id,
                        first: index,
                        last: index,
                        shown: vec![line.trim().to_owned()],
                        cost: usize::from(!scanner.is_exempt_doc_line() && letters(line) > 0),
                        fine: fits(line),
                        docstring: false,
                    });
                }
            }
        }
        if scanner.block_end() {
            if let Some(unit) = block.take() {
                if unit.fresh && scanner.block_pure() && !unit.shown.is_empty() && (lang != HTML || html_cuttable(&lines, unit.first, index)) {
                    run_id = run_id.saturating_add(1);
                    pieces.push(Piece {
                        run: run_id,
                        first: unit.first,
                        last: index,
                        cost: unit.lettered,
                        shown: unit.shown,
                        fine: unit.fine,
                        docstring: false,
                    });
                    run_id = run_id.saturating_add(1);
                    last_doc = None;
                }
            }
        }
        if scanner.doc_end() {
            if let Some(doc) = open.take() {
                if docstrings && doc.fresh && !old_unclear && doc.statement && scanner.doc_pure() && !doc.shown.is_empty() {
                    run_id = run_id.saturating_add(1);
                    pieces.push(Piece {
                        run: run_id,
                        first: doc.first,
                        last: index,
                        cost: if doc.exempt { 0 } else { doc.lettered },
                        shown: doc.shown,
                        fine: doc.fine,
                        docstring: true,
                    });
                    run_id = run_id.saturating_add(1);
                }
            }
        }
    }
    if scanner.uncertain() || pieces.is_empty() || limits::mode() == limits::Mode::Block {
        return None;
    }
    let limit = limits::current().lines;
    let mut cost_of: HashMap<usize, usize> = HashMap::new();
    let mut unfit: HashSet<usize> = HashSet::new();
    for piece in &pieces {
        *cost_of.entry(piece.run).or_insert(0) += piece.cost;
        if !piece.fine {
            unfit.insert(piece.run);
        }
    }
    let held_in = |run: usize| held.get(&run).copied().unwrap_or(0);
    let over_limit = |run: usize| cost_of.get(&run).copied().unwrap_or(0).saturating_add(held_in(run)) > limit || unfit.contains(&run);
    let mut plans: Vec<Vec<&Piece>> = Vec::new();
    if limits::mode() == limits::Mode::Trim {
        let mut kept: HashMap<usize, usize> = HashMap::new();
        let mut cut: Vec<&Piece> = Vec::new();
        for piece in &pieces {
            let used = kept.entry(piece.run).or_insert_with(|| held_in(piece.run));
            let room = if piece.cost == 0 { *used < limit } else { used.saturating_add(piece.cost) <= limit };
            if !over_limit(piece.run) || (piece.fine && room) {
                *used = used.saturating_add(piece.cost);
            } else {
                cut.push(piece);
            }
        }
        plans.push(cut);
    }
    plans.push(pieces.iter().filter(|piece| over_limit(piece.run)).collect());
    for cut in plans {
        if cut.is_empty() {
            continue;
        }
        let mut gone: HashSet<usize> = HashSet::new();
        for piece in &cut {
            gone.extend(piece.first..=piece.last);
        }
        let mut standing: HashMap<usize, String> = HashMap::new();
        for piece in cut.iter().filter(|piece| piece.docstring) {
            if needs_pass(&lines, &logical, &gone, &standing, piece) {
                let line = lines.get(piece.first)?;
                let pad: String = line.chars().take_while(|c| matches!(c, ' ' | '\t' | '\x0c')).collect();
                gone.remove(&piece.first);
                standing.insert(piece.first, format!("{pad}pass"));
            }
        }
        tidy_blanks(&lines, &change.old, &mut gone, &standing);
        let text = lines
            .iter()
            .enumerate()
            .filter(|(index, _)| !gone.contains(index))
            .map(|(index, line)| match standing.get(&index) {
                Some(stand_in) if line.ends_with('\r') => format!("{stand_in}\r"),
                Some(stand_in) => stand_in.clone(),
                None => (*line).to_owned(),
            })
            .collect::<Vec<String>>()
            .join("\n");
        let trial = Change { new: text.clone(), ..change.clone() };
        if evaluate(std::slice::from_ref(&trial)).is_none() {
            let removed = cut.iter().flat_map(|piece| piece.shown.iter().cloned()).collect();
            return Some(Trimmed { text, dropped: gone, swapped: standing, removed });
        }
    }
    None
}

pub fn net_lines(change: &Change) -> usize {
    let Some(lang) = language_for_text(&change.file, &change.new) else {
        return 0;
    };
    let lang = if change.partial { lang.fragment() } else { lang };
    measure(change, lang).net_lines
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
                    excess: 0,
                    longest: 0,
                    marker: None,
                    too_long: false,
                    first: None,
                    long: None,
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
        slot.excess = slot.excess.saturating_add(measured.excess);
        slot.longest = slot.longest.max(measured.longest);
        if measured.too_long {
            slot.too_long = true;
            slot.long = slot.long.or(measured.long);
        }
        slot.first = slot.first.or(measured.first);
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
            let limit = limits::current().line_chars.to_string();
            let detail = message(
                "comment_guard.detail.too_long",
                &[("file", aggregate.file), ("limit", limit.as_str()), ("line", excerpt(aggregate.long.unwrap_or("")).as_str())],
            );
            return Some(detail);
        }
        if aggregate.excess > 0 {
            let lines = aggregate.longest.to_string();
            let max_lines = limits::current().lines.to_string();
            let detail = message(
                "comment_guard.detail.too_many",
                &[
                    ("file", aggregate.file),
                    ("lines", lines.as_str()),
                    ("max_lines", max_lines.as_str()),
                    ("line", excerpt(aggregate.first.unwrap_or("")).as_str()),
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
