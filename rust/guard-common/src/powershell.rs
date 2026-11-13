use std::collections::{HashMap, HashSet};

use crate::shlex::quote;

const MAX_DEPTH: usize = 6;
const MAX_TOKENS: usize = 20_000;
const KEYWORDS: [&str; 17] = [
    "if", "elseif", "else", "while", "for", "foreach", "switch", "do", "until", "try", "catch", "finally", "begin",
    "process", "end", "foreach-object", "%",
];

#[derive(Clone, Debug, PartialEq)]
enum Part {
    Lit(String),
    Var(String),
    Sub(String),
}

#[derive(Clone, Debug, Default, PartialEq)]
struct Word {
    parts: Vec<Part>,
    quoted: bool,
    call: bool,
}

fn quote_glob(text: &str) -> String {
    if text == "~" {
        return "~".to_owned();
    }
    let (mut out, rest) = match text.strip_prefix("~/") {
        Some(rest) => ("~/".to_owned(), rest),
        None => (String::new(), text),
    };
    let mut chunk = String::new();
    for c in rest.chars() {
        if c == '*' || c == '?' {
            if !chunk.is_empty() {
                out.push_str(&quote(&chunk));
                chunk.clear();
            }
            out.push(c);
        } else {
            chunk.push(c);
        }
    }
    if !chunk.is_empty() {
        out.push_str(&quote(&chunk));
    }
    if out.is_empty() {
        "''".to_owned()
    } else {
        out
    }
}

fn strip_prefix_ignore_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        text.get(prefix.len()..)
    } else {
        None
    }
}

fn path_text(text: &str) -> String {
    let mut path = text;
    for prefix in ["Microsoft.PowerShell.Core\\FileSystem::", "FileSystem::"] {
        if let Some(rest) = strip_prefix_ignore_case(path, prefix) {
            path = rest;
        }
    }
    let unc;
    if let Some(rest) = path.strip_prefix("\\\\?\\UNC\\") {
        unc = format!("\\\\{rest}");
        path = &unc;
    } else if let Some(rest) = path.strip_prefix("\\\\?\\") {
        path = rest;
    }
    path.replace('\\', "/")
}

impl Word {
    fn lit(text: &str) -> Word {
        Word {
            parts: vec![Part::Lit(text.to_owned())],
            ..Word::default()
        }
    }

    fn literal(&self) -> Option<String> {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                Part::Lit(text) => out.push_str(text),
                _ => return None,
            }
        }
        Some(out)
    }

    fn text(&self) -> String {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                Part::Lit(text) => out.push_str(text),
                Part::Var(name) => {
                    out.push('$');
                    out.push_str(name);
                }
                Part::Sub(inner) => {
                    out.push_str("$(");
                    out.push_str(inner);
                    out.push(')');
                }
            }
        }
        out
    }

    fn emit_with(&self, path: bool) -> String {
        let parts: Vec<Part> = if path {
            self.parts
                .iter()
                .map(|part| match part {
                    Part::Lit(text) => Part::Lit(path_text(text)),
                    other => other.clone(),
                })
                .collect()
        } else {
            self.parts.clone()
        };
        let mut plain = String::new();
        for part in &parts {
            match part {
                Part::Lit(text) => plain.push_str(text),
                _ => {
                    plain.clear();
                    break;
                }
            }
        }
        if parts.iter().all(|part| matches!(part, Part::Lit(_))) {
            return if path { quote_glob(&plain) } else { quote(&plain) };
        }
        let mut out = String::from("\"");
        for part in &parts {
            match part {
                Part::Lit(text) => {
                    for c in text.chars() {
                        if matches!(c, '"' | '\\' | '$' | '`') {
                            out.push('\\');
                        }
                        out.push(c);
                    }
                }
                Part::Var(name) => {
                    out.push_str("${");
                    out.push_str(name);
                    out.push('}');
                }
                Part::Sub(inner) => {
                    out.push_str("$(");
                    out.push_str(inner);
                    out.push(')');
                }
            }
        }
        out.push('"');
        out
    }

    fn emit(&self) -> String {
        self.emit_with(false)
    }

    fn emit_path(&self) -> String {
        self.emit_with(true)
    }
}

enum Tok {
    Word(Word),
    Sep(&'static str),
    Redir(String),
}

fn is_single(c: char) -> bool {
    matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}')
}

fn is_double(c: char) -> bool {
    matches!(c, '"' | '\u{201C}' | '\u{201D}' | '\u{201E}')
}

struct Lexer {
    chars: Vec<char>,
    pos: usize,
    out: Vec<Tok>,
    start: bool,
    closers: Vec<char>,
    depth: usize,
}

impl Lexer {
    fn peek(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos.saturating_add(offset)).copied()
    }

    fn sep(&mut self, text: &'static str) {
        self.out.push(Tok::Sep(text));
        self.start = true;
    }

    fn run(mut self) -> Vec<Tok> {
        while let Some(c) = self.peek(0) {
            if self.out.len() > MAX_TOKENS {
                break;
            }
            match c {
                ' ' | '\t' | '\r' => self.pos += 1,
                '\n' => {
                    self.pos += 1;
                    self.sep("\n");
                }
                '`' if self.peek(1) == Some('\n') => self.pos += 2,
                '#' => self.skip_line(),
                '<' if self.peek(1) == Some('#') => self.skip_block_comment(),
                '<' => self.pos += 1,
                ';' => {
                    self.pos += 1;
                    self.sep(";");
                }
                '|' => {
                    if self.peek(1) == Some('|') {
                        self.pos += 2;
                        self.sep("||");
                    } else {
                        self.pos += 1;
                        self.sep("|");
                    }
                }
                '&' => {
                    if self.peek(1) == Some('&') {
                        self.pos += 2;
                        self.sep("&&");
                    } else if self.start {
                        self.pos += 1;
                    } else {
                        self.pos += 1;
                        self.sep(";");
                    }
                }
                '(' if self.start => {
                    self.closers.push(')');
                    self.pos += 1;
                }
                '{' if self.start => {
                    if matches!(self.out.last(), Some(Tok::Word(_))) {
                        self.sep(";");
                    }
                    self.closers.push('}');
                    self.pos += 1;
                }
                ')' | '}' if self.closers.last() == Some(&c) => {
                    self.closers.pop();
                    self.pos += 1;
                    if c == '}' {
                        self.sep(";");
                    } else {
                        self.start = true;
                    }
                }
                '>' => self.redirect(),
                '0'..='9' | '*' if self.peek(1) == Some('>') => self.redirect(),
                _ => {
                    let before = self.pos;
                    self.word();
                    if self.pos == before {
                        self.pos += 1;
                    }
                }
            }
        }
        self.out
    }

    fn skip_line(&mut self) {
        while self.peek(0).is_some_and(|c| c != '\n') {
            self.pos += 1;
        }
    }

    fn skip_block_comment(&mut self) {
        self.pos += 2;
        while let Some(c) = self.peek(0) {
            if c == '#' && self.peek(1) == Some('>') {
                self.pos += 2;
                return;
            }
            self.pos += 1;
        }
    }

    fn redirect(&mut self) {
        let mut text = String::new();
        if let Some(c) = self.peek(0) {
            if c != '>' {
                text.push(c);
                self.pos += 1;
            }
        }
        while self.peek(0) == Some('>') && text.matches('>').count() < 2 {
            text.push('>');
            self.pos += 1;
        }
        if self.peek(0) == Some('&') && self.peek(1).is_some_and(|d| d.is_ascii_digit()) {
            text.push('&');
            text.push(self.peek(1).unwrap_or('1'));
            self.pos += 2;
        }
        self.out.push(Tok::Redir(text));
    }

    fn balanced(&mut self, open: char, close: char) -> String {
        let mut inner = String::new();
        let mut level = 0usize;
        while let Some(c) = self.peek(0) {
            self.pos += 1;
            if c == open {
                level += 1;
                if level == 1 {
                    continue;
                }
            } else if c == close {
                level = level.saturating_sub(1);
                if level == 0 {
                    return inner;
                }
            } else if is_single(c) || is_double(c) {
                inner.push(c);
                while let Some(q) = self.peek(0) {
                    self.pos += 1;
                    inner.push(q);
                    if (is_single(c) && is_single(q)) || (is_double(c) && is_double(q)) {
                        break;
                    }
                }
                continue;
            } else if c == '`' {
                inner.push(c);
                if let Some(next) = self.peek(0) {
                    inner.push(next);
                    self.pos += 1;
                }
                continue;
            }
            inner.push(c);
        }
        inner
    }

    fn static_call(&mut self) -> Option<String> {
        let begin = self.pos;
        let mut at = begin;
        while let Some(c) = self.chars.get(at).copied() {
            at += 1;
            if c == ']' {
                break;
            }
            if c.is_whitespace() || at.saturating_sub(begin) > 120 {
                return None;
            }
        }
        if self.chars.get(at).copied() != Some(':') || self.chars.get(at.saturating_add(1)).copied() != Some(':') {
            return None;
        }
        at += 2;
        while self.chars.get(at).is_some_and(|c| c.is_alphanumeric() || *c == '_') {
            at += 1;
        }
        if self.chars.get(at).copied() != Some('(') {
            return None;
        }
        self.pos = at;
        self.balanced('(', ')');
        Some(self.chars.get(begin..self.pos).map(|slice| slice.iter().collect()).unwrap_or_default())
    }

    fn here_string(&mut self) -> Option<String> {
        let begin = self.pos;
        let quote_char = self.peek(1)?;
        self.pos += 2;
        while matches!(self.peek(0), Some(' ' | '\t' | '\r')) {
            self.pos += 1;
        }
        if self.peek(0) != Some('\n') {
            self.pos = begin;
            return None;
        }
        self.pos += 1;
        let mut text = String::new();
        let mut line_start = true;
        while let Some(c) = self.peek(0) {
            let closes = |next: Option<char>| match next {
                Some(q) => (is_single(quote_char) && is_single(q)) || (is_double(quote_char) && is_double(q)),
                None => false,
            };
            if line_start && closes(Some(c)) && self.peek(1) == Some('@') {
                self.pos += 2;
                if text.ends_with('\n') {
                    text.pop();
                }
                if text.ends_with('\r') {
                    text.pop();
                }
                return Some(text);
            }
            line_start = c == '\n';
            text.push(c);
            self.pos += 1;
        }
        Some(text)
    }

    fn expansion(&mut self, parts: &mut Vec<Part>, lit: &mut String) {
        self.pos += 1;
        match self.peek(0) {
            Some('(') => {
                let inner = self.balanced('(', ')');
                flush(parts, lit);
                parts.push(Part::Sub(convert(&inner, self.depth + 1)));
            }
            Some('{') => {
                self.pos += 1;
                let mut name = String::new();
                while let Some(c) = self.peek(0) {
                    self.pos += 1;
                    if c == '}' {
                        break;
                    }
                    name.push(c);
                }
                var(&name, parts, lit);
            }
            Some(c) if c.is_alphanumeric() || matches!(c, '_' | '?' | '$' | '^') => {
                let mut name = String::new();
                if matches!(c, '?' | '$' | '^') {
                    name.push(c);
                    self.pos += 1;
                } else {
                    while let Some(n) = self.peek(0) {
                        let scoped = n == ':' && self.peek(1).is_some_and(|x| x.is_alphanumeric() || x == '_');
                        if n.is_alphanumeric() || n == '_' || scoped {
                            name.push(n);
                            self.pos += 1;
                        } else {
                            break;
                        }
                    }
                }
                var(&name, parts, lit);
            }
            _ => lit.push('$'),
        }
    }

    fn single(&mut self, lit: &mut String) {
        while let Some(c) = self.peek(0) {
            if is_single(c) {
                if self.peek(1).is_some_and(is_single) {
                    lit.push('\'');
                    self.pos += 2;
                } else {
                    self.pos += 1;
                    return;
                }
            } else {
                lit.push(c);
                self.pos += 1;
            }
        }
    }

    fn double(&mut self, parts: &mut Vec<Part>, lit: &mut String) {
        while let Some(c) = self.peek(0) {
            if is_double(c) {
                if self.peek(1).is_some_and(is_double) {
                    lit.push('"');
                    self.pos += 2;
                } else {
                    self.pos += 1;
                    return;
                }
            } else if c == '`' {
                self.pos += 1;
                if let Some(next) = self.peek(0) {
                    self.pos += 1;
                    lit.push(match next {
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        '0' => '\0',
                        other => other,
                    });
                }
            } else if c == '$' {
                self.expansion(parts, lit);
            } else {
                lit.push(c);
                self.pos += 1;
            }
        }
    }

    fn word(&mut self) {
        let at_start = self.start;
        if self.peek(0) == Some('[') {
            if let Some(call) = self.static_call() {
                self.out.push(Tok::Word(Word {
                    parts: vec![Part::Lit(call)],
                    quoted: false,
                    call: true,
                }));
                self.start = false;
                return;
            }
        }
        if self.peek(0) == Some('@') && self.peek(1).is_some_and(|q| is_single(q) || is_double(q)) {
            if let Some(text) = self.here_string() {
                self.out.push(Tok::Word(Word {
                    parts: vec![Part::Lit(text)],
                    quoted: true,
                    call: false,
                }));
                self.start = false;
                return;
            }
        }
        let mut parts: Vec<Part> = Vec::new();
        let mut lit = String::new();
        let mut quoted = false;
        while let Some(c) = self.peek(0) {
            match c {
                ' ' | '\t' | '\r' | '\n' | ';' | '|' | '&' | '<' | '>' | ')' | '}' => break,
                '`' => {
                    self.pos += 1;
                    if let Some(next) = self.peek(0) {
                        self.pos += 1;
                        if next != '\n' {
                            lit.push(next);
                        }
                    }
                }
                '$' => self.expansion(&mut parts, &mut lit),
                '@' if self.peek(1) == Some('(') => {
                    self.pos += 1;
                    let inner = self.balanced('(', ')');
                    flush(&mut parts, &mut lit);
                    parts.push(Part::Sub(convert(&inner, self.depth + 1)));
                }
                '(' => {
                    let inner = self.balanced('(', ')');
                    flush(&mut parts, &mut lit);
                    parts.push(Part::Sub(convert(&inner, self.depth + 1)));
                }
                '{' => {
                    let inner = self.balanced('{', '}');
                    quoted = true;
                    lit.push('{');
                    lit.push_str(&inner);
                    lit.push('}');
                }
                _ if is_single(c) => {
                    quoted = true;
                    self.pos += 1;
                    self.single(&mut lit);
                }
                _ if is_double(c) => {
                    quoted = true;
                    self.pos += 1;
                    self.double(&mut parts, &mut lit);
                }
                _ => {
                    lit.push(c);
                    self.pos += 1;
                }
            }
        }
        flush(&mut parts, &mut lit);
        if parts.is_empty() {
            if !quoted {
                return;
            }
            parts.push(Part::Lit(String::new()));
        }
        let word = Word {
            parts,
            quoted,
            call: false,
        };
        if at_start && !quoted {
            if let Some(text) = word.literal() {
                if KEYWORDS.contains(&text.to_ascii_lowercase().as_str()) {
                    return;
                }
            }
        }
        self.out.push(Tok::Word(word));
        self.start = false;
    }
}

fn flush(parts: &mut Vec<Part>, lit: &mut String) {
    if !lit.is_empty() {
        parts.push(Part::Lit(std::mem::take(lit)));
    }
}

fn var(name: &str, parts: &mut Vec<Part>, lit: &mut String) {
    let mut plain = name;
    for scope in ["env:", "script:", "global:", "local:", "private:", "using:"] {
        if let Some(rest) = strip_prefix_ignore_case(plain, scope) {
            plain = rest;
        }
    }
    match plain.to_ascii_lowercase().as_str() {
        "null" => {}
        "true" => lit.push_str("true"),
        "false" => lit.push_str("false"),
        "" => lit.push('$'),
        "userprofile" | "home" => {
            flush(parts, lit);
            parts.push(Part::Var("HOME".to_owned()));
        }
        "appdata" | "localappdata" => {
            flush(parts, lit);
            parts.push(Part::Var("HOME".to_owned()));
            let folder = if plain.eq_ignore_ascii_case("appdata") { "Roaming" } else { "Local" };
            lit.push_str(&format!("/AppData/{folder}"));
        }
        _ => {
            flush(parts, lit);
            parts.push(Part::Var(plain.to_owned()));
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Stage {
    words: Vec<Word>,
    redirs: Vec<(String, Option<Word>)>,
    piped: bool,
}

enum Item {
    Stage(Stage),
    Sep(&'static str),
}

fn parse(tokens: Vec<Tok>) -> Vec<Item> {
    let mut items: Vec<Item> = Vec::new();
    let mut current = Stage::default();
    let mut pending: Option<usize> = None;
    let mut after_pipe = false;
    for token in tokens {
        if current.words.is_empty() && current.redirs.is_empty() && !matches!(token, Tok::Sep(_)) {
            current.piped = after_pipe;
        }
        match token {
            Tok::Word(word) => {
                if let Some(index) = pending.take() {
                    if let Some(redirect) = current.redirs.get_mut(index) {
                        redirect.1 = Some(word);
                    }
                } else {
                    current.words.push(word);
                }
            }
            Tok::Redir(op) => {
                let needs_target = !op.contains('&');
                current.redirs.push((op, None));
                pending = needs_target.then(|| current.redirs.len().saturating_sub(1));
            }
            Tok::Sep(text) => {
                pending = None;
                if !current.words.is_empty() || !current.redirs.is_empty() {
                    items.push(Item::Stage(std::mem::take(&mut current)));
                }
                items.push(Item::Sep(text));
                after_pipe = text == "|";
            }
        }
    }
    if !current.words.is_empty() || !current.redirs.is_empty() {
        items.push(Item::Stage(current));
    }
    items
}

struct Param {
    name: &'static str,
    aliases: &'static [&'static str],
    value: bool,
}

const fn param(name: &'static str, aliases: &'static [&'static str], value: bool) -> Param {
    Param { name, aliases, value }
}

#[derive(Default)]
struct Args {
    flags: HashSet<&'static str>,
    values: HashMap<&'static str, Vec<Word>>,
    positional: Vec<Word>,
    unknown: Vec<String>,
}

fn resolve<'a>(spec: &'a [Param], name: &str) -> Option<&'a Param> {
    let lower = name.to_ascii_lowercase();
    if let Some(found) = spec.iter().find(|p| p.name == lower || p.aliases.contains(&lower.as_str())) {
        return Some(found);
    }
    let hits: Vec<&Param> = spec.iter().filter(|p| p.name.starts_with(&lower)).collect();
    if hits.len() == 1 {
        hits.first().copied()
    } else {
        None
    }
}

fn parse_args(spec: &[Param], words: &[Word]) -> Args {
    let mut args = Args::default();
    let mut index = 0usize;
    while let Some(word) = words.get(index) {
        index += 1;
        let literal = if word.quoted { None } else { word.literal() };
        let body = literal
            .as_deref()
            .and_then(|text| text.strip_prefix('-'))
            .filter(|rest| rest.chars().next().is_some_and(|c| c.is_alphabetic()));
        let Some(body) = body else {
            args.positional.push(word.clone());
            continue;
        };
        let (name, inline) = match body.split_once(':') {
            Some((name, value)) => (name, Some(value)),
            None => (body, None),
        };
        match resolve(spec, name) {
            Some(found) if found.value => {
                let value = match inline {
                    Some(text) => Some(Word::lit(text)),
                    None => {
                        let next = words.get(index).cloned();
                        index += usize::from(next.is_some());
                        next
                    }
                };
                if let Some(value) = value {
                    args.values.entry(found.name).or_default().push(value);
                }
            }
            Some(found) => {
                if !matches!(inline.map(str::to_ascii_lowercase).as_deref(), Some("false" | "0")) {
                    args.flags.insert(found.name);
                }
            }
            None => args.unknown.push(name.to_ascii_lowercase()),
        }
    }
    args
}

fn split_commas(word: Word) -> Vec<Word> {
    match word.literal() {
        Some(text) if !word.quoted && text.contains(',') => text
            .split(',')
            .filter(|piece| !piece.is_empty())
            .map(Word::lit)
            .collect(),
        _ => vec![word],
    }
}

fn named(args: &Args, keys: &[&str]) -> Vec<Word> {
    let mut out = Vec::new();
    for key in keys {
        for word in args.values.get(key).into_iter().flatten() {
            out.extend(split_commas(word.clone()));
        }
    }
    out
}

fn cmd_flag(word: &Word) -> Option<char> {
    let text = word.literal()?;
    let rest = text.strip_prefix('/')?;
    let mut chars = rest.chars();
    let letter = chars.next().filter(char::is_ascii_alphabetic)?;
    match chars.next() {
        None | Some(':') => Some(letter.to_ascii_lowercase()),
        Some(_) => None,
    }
}

fn paths_text(words: &[Word]) -> String {
    words.iter().map(Word::emit_path).collect::<Vec<_>>().join(" ")
}

fn with_tail(head: &str, tail: &str) -> String {
    if tail.is_empty() {
        head.to_owned()
    } else {
        format!("{head} {tail}")
    }
}

fn flags_text(recurse: bool, force: bool) -> &'static str {
    match (recurse, force) {
        (true, true) => "-rf",
        (true, false) => "-r",
        (false, true) => "-f",
        (false, false) => "",
    }
}

fn env_query(name: &str) -> String {
    let name = name.trim_start_matches(['\\', '/']);
    if name.is_empty() {
        "env".to_owned()
    } else {
        format!("printenv {}", quote(name))
    }
}

fn env_target(words: &[Word]) -> Option<String> {
    let text = words.first()?.literal()?;
    strip_prefix_ignore_case(&text, "env:").map(env_query)
}

const REMOVE: [Param; 12] = [
    param("path", &[], true),
    param("literalpath", &["lp", "pspath"], true),
    param("recurse", &["r"], false),
    param("force", &[], false),
    param("include", &[], true),
    param("exclude", &[], true),
    param("filter", &[], true),
    param("whatif", &["wi"], false),
    param("confirm", &["cf"], false),
    param("stream", &[], true),
    param("credential", &[], true),
    param("usetransaction", &["usetx"], false),
];

fn remove(words: &[Word], piped: bool) -> String {
    let mut args = parse_args(&REMOVE, words);
    let mut recurse = args.flags.contains("recurse");
    let mut force = args.flags.contains("force");
    for unknown in &args.unknown {
        if !unknown.is_empty() && unknown.chars().all(|c| c == 'r' || c == 'f') {
            recurse |= unknown.contains('r');
            force |= unknown.contains('f');
        }
    }
    let mut targets = named(&args, &["path", "literalpath"]);
    for word in std::mem::take(&mut args.positional) {
        match cmd_flag(&word) {
            Some('s') => recurse = true,
            Some('f') => force = true,
            Some(_) => {}
            None => targets.extend(split_commas(word)),
        }
    }
    if args.flags.contains("whatif") {
        return "true".to_owned();
    }
    let verb = if targets.is_empty() && piped { "xargs rm" } else { "rm" };
    with_tail(&with_tail(verb, flags_text(recurse, force)), &paths_text(&targets))
}

const CONTENT: [Param; 17] = [
    param("path", &[], true),
    param("literalpath", &["lp", "pspath"], true),
    param("totalcount", &["head", "first"], true),
    param("tail", &["last"], true),
    param("raw", &[], false),
    param("encoding", &[], true),
    param("readcount", &[], true),
    param("wait", &[], false),
    param("delimiter", &[], true),
    param("stream", &[], true),
    param("filter", &[], true),
    param("include", &[], true),
    param("exclude", &[], true),
    param("force", &[], false),
    param("credential", &[], true),
    param("asbytestream", &[], false),
    param("usetransaction", &["usetx"], false),
];

fn read(words: &[Word], piped: bool) -> String {
    let args = parse_args(&CONTENT, words);
    let mut targets = named(&args, &["path", "literalpath"]);
    for word in &args.positional {
        if cmd_flag(word).is_none() {
            targets.extend(split_commas(word.clone()));
        }
    }
    if let Some(query) = env_target(&targets) {
        return query;
    }
    with_tail(if targets.is_empty() && piped { "xargs cat" } else { "cat" }, &paths_text(&targets))
}

const LIST: [Param; 16] = [
    param("path", &[], true),
    param("literalpath", &["lp", "pspath"], true),
    param("filter", &[], true),
    param("include", &[], true),
    param("exclude", &[], true),
    param("recurse", &["r"], false),
    param("force", &[], false),
    param("name", &["n"], false),
    param("file", &["af"], false),
    param("directory", &["ad"], false),
    param("depth", &[], true),
    param("hidden", &["ah"], false),
    param("readonly", &["ar"], false),
    param("system", &["as"], false),
    param("attributes", &[], true),
    param("followsymlink", &[], false),
];

fn list(words: &[Word]) -> String {
    let args = parse_args(&LIST, words);
    let mut targets = named(&args, &["path", "literalpath"]);
    for word in &args.positional {
        if cmd_flag(word).is_none() {
            targets.extend(split_commas(word.clone()));
        }
    }
    if let Some(query) = env_target(&targets) {
        return query;
    }
    if !args.flags.contains("recurse") {
        return with_tail("ls", &paths_text(&targets));
    }
    let start = if targets.is_empty() { ".".to_owned() } else { paths_text(&targets) };
    let mut out = format!("find {start}");
    if let Some(pattern) = named(&args, &["filter", "include"]).first().and_then(Word::literal) {
        out.push_str(&format!(" -name {}", quote(&pattern)));
    }
    out
}

const COPY: [Param; 11] = [
    param("path", &[], true),
    param("literalpath", &["lp", "pspath"], true),
    param("destination", &[], true),
    param("recurse", &["r"], false),
    param("force", &[], false),
    param("container", &[], false),
    param("passthru", &[], false),
    param("filter", &[], true),
    param("include", &[], true),
    param("exclude", &[], true),
    param("whatif", &["wi"], false),
];

fn transfer(words: &[Word], verb: &str) -> String {
    let args = parse_args(&COPY, words);
    if args.flags.contains("whatif") {
        return "true".to_owned();
    }
    let mut positional = args.positional.iter().filter(|word| cmd_flag(word).is_none()).cloned();
    let mut sources = named(&args, &["path", "literalpath"]);
    if sources.is_empty() {
        sources = positional.next().map(split_commas).unwrap_or_default();
    }
    let destination = named(&args, &["destination"]).into_iter().next().or_else(|| positional.next());
    let flags = if verb == "cp" {
        flags_text(args.flags.contains("recurse"), args.flags.contains("force"))
    } else if args.flags.contains("force") {
        "-f"
    } else {
        ""
    };
    let mut tail = paths_text(&sources);
    if let Some(destination) = destination {
        tail = with_tail(&tail, &destination.emit_path());
    }
    with_tail(&with_tail(verb, flags), &tail)
}

const SELECT: [Param; 14] = [
    param("pattern", &[], true),
    param("path", &[], true),
    param("literalpath", &["lp", "pspath"], true),
    param("simplematch", &[], false),
    param("casesensitive", &[], false),
    param("list", &[], false),
    param("quiet", &[], false),
    param("notmatch", &[], false),
    param("allmatches", &[], false),
    param("include", &[], true),
    param("exclude", &[], true),
    param("context", &[], true),
    param("encoding", &[], true),
    param("raw", &[], false),
];

fn search(words: &[Word]) -> String {
    let args = parse_args(&SELECT, words);
    let mut positional = args.positional.iter().cloned();
    let pattern = named(&args, &["pattern"]).into_iter().next().or_else(|| positional.next());
    let mut targets = named(&args, &["path", "literalpath"]);
    for word in positional {
        targets.extend(split_commas(word));
    }
    let head = with_tail("grep", &pattern.map(|word| word.emit()).unwrap_or_default());
    with_tail(&head, &paths_text(&targets))
}

fn change_directory(words: &[Word]) -> String {
    let args = parse_args(&[param("path", &[], true), param("literalpath", &["lp", "pspath"], true), param("passthru", &[], false)], words);
    let mut targets = named(&args, &["path", "literalpath"]);
    for word in &args.positional {
        if cmd_flag(word).is_none() {
            targets.push(word.clone());
        }
    }
    with_tail("cd", &paths_text(&targets))
}

fn name_of(word: &Word) -> String {
    let Some(text) = word.literal() else {
        return String::new();
    };
    let lower = text.to_ascii_lowercase();
    let base = lower.rsplit(['/', '\\']).next().unwrap_or("");
    for suffix in [".exe", ".cmd", ".bat", ".com"] {
        if let Some(stem) = base.strip_suffix(suffix) {
            return stem.to_owned();
        }
    }
    base.to_owned()
}

const B64: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn decode_utf16_base64(text: &str) -> Option<String> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut bits = 0u32;
    let mut count = 0u32;
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let value = u32::try_from(B64.find(c)?).ok()?;
        bits = (bits << 6) | value;
        count += 6;
        if count >= 8 {
            count -= 8;
            bytes.push(u8::try_from((bits >> count) & 0xFF).ok()?);
        }
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| match pair {
            [low, high] => u16::from_le_bytes([*low, *high]),
            _ => 0,
        })
        .collect();
    String::from_utf16(&units).ok()
}

fn nested(inner: &str, depth: usize) -> String {
    format!("bash -c {}", quote(&convert(inner, depth + 1)))
}

fn joined_text(words: &[Word]) -> String {
    words.iter().map(Word::text).collect::<Vec<_>>().join(" ")
}

fn powershell(words: &[Word], depth: usize) -> String {
    let mut index = 1usize;
    while let Some(word) = words.get(index) {
        index += 1;
        let text = word.literal().unwrap_or_default().to_ascii_lowercase();
        let Some(flag) = text.strip_prefix('-').or_else(|| text.strip_prefix('/')) else {
            return nested(&joined_text(words.get(index.saturating_sub(1)..).unwrap_or(&[])), depth);
        };
        let name = flag.split(':').next().unwrap_or("");
        let is = |full: &str| !name.is_empty() && full.starts_with(name);
        if name == "c" || (is("command") && name.len() > 1) {
            return nested(&joined_text(words.get(index..).unwrap_or(&[])), depth);
        }
        if is("encodedcommand") || name == "e" || name == "ec" {
            let value = words.get(index).map(Word::text).unwrap_or_default();
            return match decode_utf16_base64(&value) {
                Some(inner) => nested(&inner, depth),
                None => "eval \"$undecodable\"".to_owned(),
            };
        }
        if is("file") && name.starts_with('f') {
            let target = words.get(index).map(Word::emit_path).unwrap_or_default();
            return with_tail("bash", &target);
        }
        let takes_value = ["executionpolicy", "windowstyle", "outputformat", "inputformat", "configurationname", "version", "workingdirectory", "custompipename"]
            .iter()
            .any(|full| is(full))
            || name == "ep"
            || name == "wd";
        if takes_value {
            index += 1;
        }
    }
    "true".to_owned()
}

fn cmd_wrapper(words: &[Word], depth: usize) -> String {
    for (index, word) in words.iter().enumerate().skip(1) {
        let text = word.literal().unwrap_or_default().to_ascii_lowercase();
        if matches!(text.as_str(), "/c" | "/k" | "/r") {
            let rest = joined_text(words.get(index.saturating_add(1)..).unwrap_or(&[]));
            return format!("bash -c {}", quote(&cmd_convert(&rest, depth + 1)));
        }
    }
    "true".to_owned()
}

fn unquoted(raw: &str) -> Word {
    let text = raw.trim();
    let first = text.chars().next();
    if first.is_some_and(|c| is_single(c) || is_double(c)) {
        let inner = text.get(1..).unwrap_or("");
        let end = inner.rfind(|c: char| is_single(c) || is_double(c)).unwrap_or(inner.len());
        return Word::lit(inner.get(..end).unwrap_or(""));
    }
    match text.strip_prefix('$') {
        Some(name) if !name.is_empty() => Word {
            parts: vec![Part::Var(name.to_owned())],
            ..Word::default()
        },
        _ => Word::lit(text),
    }
}

fn static_call_text(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    let Some((kind, rest)) = lower.split_once("]::") else {
        return "true".to_owned();
    };
    let kind = kind.trim_start_matches('[').rsplit('.').next().unwrap_or("");
    let method = rest.split('(').next().unwrap_or("");
    let offset = raw.find('(').map_or(raw.len(), |at| at + 1);
    let inner = raw.get(offset..raw.len().saturating_sub(1)).unwrap_or("");
    let (first, second) = match inner.split_once(',') {
        Some((first, second)) => (first, second.trim().to_ascii_lowercase()),
        None => (inner, String::new()),
    };
    let target = unquoted(first);
    match (kind, method) {
        ("environment", "getenvironmentvariable") => env_query(&target.literal().unwrap_or_default()),
        ("environment", _) => "env".to_owned(),
        ("filesystem", "deletefile" | "deletedirectory") => {
            let recycle = lower.contains("sendtorecyclebin");
            let verb = match (recycle, method) {
                (true, _) => "trash",
                (false, "deletefile") => "rm -f",
                (false, _) => "rm -rf",
            };
            with_tail(verb, &target.emit_path())
        }
        ("file", "delete") => with_tail("rm -f", &target.emit_path()),
        ("directory", "delete") if matches!(second.as_str(), "$true" | "true" | "1") => with_tail("rm -rf", &target.emit_path()),
        ("directory", "delete") => with_tail("rmdir", &target.emit_path()),
        ("file", _) => with_tail("cat", &target.emit_path()),
        _ => "true".to_owned(),
    }
}

fn assignment(words: &[Word], depth: usize) -> Option<String> {
    let [first, equals, value @ ..] = words else {
        return None;
    };
    let [Part::Var(name)] = first.parts.as_slice() else {
        return None;
    };
    if equals.literal().as_deref() != Some("=") || value.is_empty() {
        return None;
    }
    if let [single] = value {
        if !single.call && single.parts.iter().all(|part| !matches!(part, Part::Sub(_))) {
            return Some(format!("{name}={}", single.emit_with(true)));
        }
    }
    Some(format!("{name}=$({})", dispatch(value, depth, false)))
}

fn dispatch(words: &[Word], depth: usize, piped: bool) -> String {
    let Some(first) = words.first() else {
        return String::new();
    };
    if first.call {
        return static_call_text(&first.text());
    }
    if let Some(done) = assignment(words, depth) {
        return done;
    }
    let rest = words.get(1..).unwrap_or(&[]);
    match name_of(first).as_str() {
        "remove-item" | "ri" | "rm" | "rmdir" | "rd" | "del" | "erase" => remove(rest, piped),
        "get-content" | "gc" | "cat" | "type" | "more" => read(rest, piped),
        "get-childitem" | "gci" | "dir" | "ls" => list(rest),
        "get-item" | "gi" => env_target(rest).unwrap_or_else(|| generic(words)),
        "copy-item" | "cpi" | "cp" | "copy" => transfer(rest, "cp"),
        "move-item" | "mi" | "mv" | "move" => transfer(rest, "mv"),
        "select-string" | "sls" => search(rest),
        "set-location" | "sl" | "cd" | "chdir" | "push-location" | "pushd" => change_directory(rest),
        "powershell" | "pwsh" | "powershell_ise" => powershell(words, depth),
        "cmd" => cmd_wrapper(words, depth),
        "invoke-expression" | "iex" => match rest.first().and_then(Word::literal) {
            Some(inner) => nested(&inner, depth),
            None => format!("eval {}", rest.iter().map(Word::emit).collect::<Vec<_>>().join(" ")),
        },
        _ => generic(words),
    }
}

fn generic(words: &[Word]) -> String {
    words.iter().map(Word::emit).collect::<Vec<_>>().join(" ")
}

fn stage_text(stage: &Stage, depth: usize) -> String {
    let mut words = stage.words.clone();
    if let [first, second, ..] = words.as_slice() {
        let header = matches!(first.parts.as_slice(), [Part::Var(_)]) && second.literal().is_some_and(|text| text.eq_ignore_ascii_case("in"));
        if header {
            words.drain(..2);
        }
    }
    if let [Word { parts, .. }] = words.as_slice() {
        if let [Part::Sub(inner)] = parts.as_slice() {
            return inner.clone();
        }
    }
    let mut out = dispatch(&words, depth, stage.piped);
    for (op, target) in &stage.redirs {
        out.push(' ');
        out.push_str(op);
        if let Some(target) = target {
            out.push(' ');
            out.push_str(&target.emit_path());
        }
    }
    out.trim().to_owned()
}

fn render(items: Vec<Item>, depth: usize) -> String {
    let mut out = String::new();
    let mut after_sep = true;
    for item in items {
        match item {
            Item::Stage(stage) => {
                let text = stage_text(&stage, depth);
                if text.is_empty() {
                    continue;
                }
                out.push_str(&text);
                after_sep = false;
            }
            Item::Sep(text) => {
                if after_sep {
                    continue;
                }
                out.push_str(match text {
                    "\n" => "\n",
                    "|" => " | ",
                    "&&" => " && ",
                    "||" => " || ",
                    _ => " ; ",
                });
                after_sep = true;
            }
        }
    }
    out.trim_end_matches([' ', ';', '\n']).to_owned()
}

fn cmd_items(line: &str) -> Vec<Item> {
    let mut items: Vec<Item> = Vec::new();
    let mut stage = Stage::default();
    let mut parts: Vec<Part> = Vec::new();
    let mut lit = String::new();
    let mut open = false;
    let mut quoted = false;
    let chars: Vec<char> = line.chars().collect();
    let mut at = 0usize;
    let finish = |stage: &mut Stage, parts: &mut Vec<Part>, lit: &mut String, open: &mut bool, quoted: bool| {
        flush(parts, lit);
        if *open {
            if parts.is_empty() {
                parts.push(Part::Lit(String::new()));
            }
            stage.words.push(Word {
                parts: std::mem::take(parts),
                quoted,
                call: false,
            });
            *open = false;
        }
    };
    while let Some(&c) = chars.get(at) {
        at += 1;
        if c == '"' {
            quoted = !quoted;
            open = true;
        } else if c == '^' && !quoted {
            if let Some(&next) = chars.get(at) {
                lit.push(next);
                open = true;
                at += 1;
            }
        } else if c == '%' && !quoted {
            let end = chars.get(at..).and_then(|rest| rest.iter().position(|x| *x == '%'));
            match end {
                Some(len) if len > 0 => {
                    let name: String = chars.get(at..at + len).map(|s| s.iter().collect()).unwrap_or_default();
                    var(&name, &mut parts, &mut lit);
                    open = true;
                    at += len + 1;
                }
                _ => {
                    lit.push(c);
                    open = true;
                }
            }
        } else if !quoted && c.is_whitespace() {
            finish(&mut stage, &mut parts, &mut lit, &mut open, false);
        } else if !quoted && matches!(c, '&' | '|') {
            finish(&mut stage, &mut parts, &mut lit, &mut open, false);
            let doubled = chars.get(at) == Some(&c);
            if doubled {
                at += 1;
            }
            if !stage.words.is_empty() {
                items.push(Item::Stage(std::mem::take(&mut stage)));
            }
            items.push(Item::Sep(match (c, doubled) {
                ('&', true) => "&&",
                ('|', true) => "||",
                ('|', false) => "|",
                _ => ";",
            }));
        } else {
            lit.push(c);
            open = true;
        }
    }
    finish(&mut stage, &mut parts, &mut lit, &mut open, false);
    if !stage.words.is_empty() {
        items.push(Item::Stage(stage));
    }
    items
}

fn cmd_convert(line: &str, depth: usize) -> String {
    if depth > MAX_DEPTH {
        return format!("eval {}", quote(line));
    }
    render(cmd_items(line), depth)
}

fn convert(command: &str, depth: usize) -> String {
    if depth > MAX_DEPTH {
        return format!("eval {}", quote(command));
    }
    let lexer = Lexer {
        chars: command.chars().collect(),
        pos: 0,
        out: Vec::new(),
        start: true,
        closers: Vec::new(),
        depth,
    };
    render(parse(lexer.run()), depth)
}

/// Rewrites a PowerShell or cmd command into the bash form the guards judge.
pub fn to_bash(command: &str) -> String {
    convert(command, 0)
}

/// True on Windows, or when `AGENT_SAFEGUARDS_SHELL=powershell` (to test elsewhere).
pub fn active() -> bool {
    cfg!(windows) || std::env::var("AGENT_SAFEGUARDS_SHELL").is_ok_and(|value| value.eq_ignore_ascii_case("powershell"))
}

pub fn for_guards(command: &str) -> String {
    if active() {
        to_bash(command)
    } else {
        command.to_owned()
    }
}

pub fn cwd_form(path: &str) -> String {
    if active() {
        path_text(path)
    } else {
        path.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::to_bash;

    fn check(cases: &[(&str, &str)]) {
        for (input, expected) in cases {
            assert_eq!(to_bash(input), *expected, "{input}");
        }
    }

    #[test]
    fn deletes_map_to_rm_with_the_flags_and_forward_slash_paths() {
        check(&[
            (r"Remove-Item -Recurse -Force C:\Users\me\proj", "rm -rf C:/Users/me/proj"),
            (r"ri -r -fo 'C:\Program Files\x'", "rm -rf 'C:/Program Files/x'"),
            (r"rm -rf C:\x", "rm -rf C:/x"),
            (r"Remove-Item -Path C:\a,C:\b -Recurse", "rm -r C:/a C:/b"),
            (r"Remove-Item -LiteralPath 'C:\a b'", "rm 'C:/a b'"),
            (r"del C:\x\*.log", "rm C:/x/*.log"),
            (r"Remove-Item C:\x\* -Recurse", "rm -r C:/x/*"),
            (r"Remove-Item C:\x -WhatIf", "true"),
            (r"Remove-Item ~\old -Recurse", "rm -r ~/old"),
            (r"RM -R C:\x", "rm -r C:/x"),
        ]);
    }

    #[test]
    fn cmd_forms_map_to_rm_and_rmdir_through_cmd_c() {
        check(&[
            (r#"cmd /c "rd /s /q C:\x""#, "bash -c 'rm -r C:/x'"),
            (r"cmd.exe /c del /f /q C:\x\a.txt", "bash -c 'rm -f C:/x/a.txt'"),
            (r"cmd /c rmdir C:\x", "bash -c 'rm C:/x'"),
            (r"cmd /c type %USERPROFILE%\.ssh\id_rsa", "bash -c 'cat \"${HOME}/.ssh/id_rsa\"'"),
        ]);
    }

    #[test]
    fn reads_map_to_cat_grep_find_and_env_queries() {
        check(&[
            (r"Get-Content C:\Users\me\.env", "cat C:/Users/me/.env"),
            (r"gc -Path .\secrets.txt -TotalCount 5", "cat ./secrets.txt"),
            (r"type C:\a.txt", "cat C:/a.txt"),
            (r"Select-String -Path C:\Users\me\.env -Pattern TOKEN", "grep TOKEN C:/Users/me/.env"),
            (r"sls TOKEN C:\x\*.env", "grep TOKEN C:/x/*.env"),
            (r"Get-ChildItem C:\Users\me -Recurse -Filter *.env", "find C:/Users/me -name '*.env'"),
            (r"dir env:", "env"),
            (r"Get-ChildItem Env:", "env"),
            (r"gi Env:GITHUB_TOKEN", "printenv GITHUB_TOKEN"),
            (r"Get-Content Env:\HOME", "printenv HOME"),
            (r"[System.IO.File]::ReadAllText('C:\x\.env')", "cat C:/x/.env"),
            (r"[Environment]::GetEnvironmentVariables()", "env"),
            (r"[Environment]::GetEnvironmentVariable('TOKEN')", "printenv TOKEN"),
        ]);
    }

    #[test]
    fn dotnet_deletes_and_copies_and_moves_map_to_the_unix_verbs() {
        check(&[
            (r"[System.IO.Directory]::Delete('C:\x', $true)", "rm -rf C:/x"),
            (r"[IO.Directory]::Delete('C:\x')", "rmdir C:/x"),
            (r"[IO.File]::Delete('C:\x\a')", "rm -f C:/x/a"),
            (r"[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile('C:\x\a','OnlyErrorDialogs','SendToRecycleBin')", "trash C:/x/a"),
            (r"[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory('C:\x','OnlyErrorDialogs','DeletePermanently')", "rm -rf C:/x"),
            (r"Copy-Item C:\a.txt C:\b.txt", "cp C:/a.txt C:/b.txt"),
            (r"cp -Recurse -Force -Path C:\a -Destination D:\b", "cp -rf C:/a D:/b"),
            (r"Move-Item C:\a C:\b -Force", "mv -f C:/a C:/b"),
            (r"copy C:\a.txt D:\ /y", "cp C:/a.txt D:/"),
        ]);
    }

    #[test]
    fn variables_pipelines_blocks_and_separators_keep_their_meaning() {
        check(&[
            (r"$p = 'C:\x'; Remove-Item $p -Recurse", "p=C:/x ; rm -r \"${p}\""),
            (r"Remove-Item $env:USERPROFILE\proj -Recurse", "rm -r \"${HOME}/proj\""),
            (r"Get-Content $env:APPDATA\npm\.npmrc", "cat \"${HOME}/AppData/Roaming/npm/.npmrc\""),
            (r"Get-ChildItem C:\x | ForEach-Object { Remove-Item $_.FullName -Force }", "ls C:/x | rm -f \"${_}.FullName\""),
            (r"if (Test-Path C:\x) { Remove-Item C:\x -Recurse }", "Test-Path 'C:\\x' ; rm -r C:/x"),
            (r"foreach ($f in (Get-ChildItem C:\x)) { Remove-Item $f }", "ls C:/x ; rm \"${f}\""),
            (r"$t = Get-Content C:\x\.env", "t=$(cat C:/x/.env)"),
            (r"Get-ChildItem C:\x -Recurse | Remove-Item -Force", "find C:/x | xargs rm -f"),
            (r"Get-ChildItem C:\x | Get-Content", "ls C:/x | xargs cat"),
            (r"Remove-Item $(Join-Path $HOME x) -Recurse", "rm -r \"$(Join-Path \"${HOME}\" x)\""),
            ("Remove-Item C:\\x `\n -Recurse", "rm -r C:/x"),
            ("Remove-Item C:\\a\nRemove-Item C:\\b", "rm C:/a\nrm C:/b"),
            (r"Remove-Item C:\a && Remove-Item C:\b", "rm C:/a && rm C:/b"),
            (r"echo hi > C:\x\out.txt", "echo hi > C:/x/out.txt"),
            (r"Remove-Item C:\x # -Recurse", "rm C:/x"),
            (r"Set-Location C:\proj; Remove-Item .\build -Recurse", "cd C:/proj ; rm -r ./build"),
        ]);
    }

    #[test]
    fn wrappers_and_quoting_tricks_are_unwrapped() {
        check(&[
            (r#"powershell -NoProfile -Command "Remove-Item 'C:\x' -Recurse""#, "bash -c 'rm -r C:/x'"),
            (r"pwsh -c Remove-Item C:\x", "bash -c 'rm C:/x'"),
            (r"powershell.exe -ExecutionPolicy Bypass -File C:\s.ps1", "bash C:/s.ps1"),
            (r#"iex "Remove-Item C:\x -Recurse""#, "bash -c 'rm -r C:/x'"),
            ("Remove-Item \u{2018}C:\\x y\u{2019} -Recurse", "rm -r 'C:/x y'"),
            (r#"Remove-Item "C:\x`ty" -Recurse"#, "rm -r 'C:/x\ty'"),
            (r"Remove-Item 'C:\it''s' -Recurse", "rm -r 'C:/it'\"'\"'s'"),
            (r"Remove-Item @'", "rm @"),
        ]);
        let encoded = "UgBlAG0AbwB2AGUALQBJAHQAZQBtACAAQwA6AFwAeAAgAC0AUgBlAGMAdQByAHMAZQA=";
        assert_eq!(to_bash(&format!("powershell -EncodedCommand {encoded}")), "bash -c 'rm -r C:/x'");
    }

    #[test]
    fn here_strings_and_odd_input_never_panic_and_stay_bounded() {
        let here = "Set-Content -Path C:\\a.txt -Value @'\nline # one\n'@\nRemove-Item C:\\b";
        assert_eq!(to_bash(here), "Set-Content -Path 'C:\\a.txt' -Value 'line # one'\nrm C:/b");
        for text in ["", "(", ")", "{", "}", "'", "\"", "`", "$(", "${", "@'", "@\"\n", "<#", "&&", "|", ">", "2>&1", "[", "[x]::", "$", "$$", "a`", "iex iex iex iex iex iex iex iex"] {
            let _ = to_bash(text);
        }
        let deep = "iex '".repeat(40);
        let _ = to_bash(&deep);
    }
}
