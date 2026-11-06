use std::sync::LazyLock;

use regex::Regex;

#[derive(Clone, Debug)]
enum ClassKind {
    Digit,
    Space,
    Word,
}

#[derive(Clone, Debug)]
enum SetItem {
    Char(char),
    Range(char, char),
    Class(ClassKind, bool),
}

#[derive(Clone, Debug)]
struct CharSet {
    negate: bool,
    items: Vec<SetItem>,
    ignore_case: bool,
}

#[derive(Clone, Debug)]
enum Node {
    Empty,
    Literal(char, bool),
    Any(bool),
    Set(CharSet),
    Seq(Vec<Node>),
    Alt(Vec<Node>),
    Repeat { node: Box<Node>, min: usize, max: usize, greedy: bool },
    Group { node: Box<Node>, index: Option<usize> },
    Look { node: Box<Node>, behind: bool, negate: bool, width: usize },
    Start(bool),
    End(bool),
    TextStart,
    TextEnd,
    Boundary(bool),
    Backref(usize, bool),
}

#[derive(Clone, Copy, Default)]
struct Flags {
    ignore_case: bool,
    multiline: bool,
    dotall: bool,
    verbose: bool,
}

pub struct PyRegex {
    root: Node,
    groups: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PyMatch {
    pub start: usize,
    pub end: usize,
    pub groups: Vec<Option<(usize, usize)>>,
}

const INFINITE: usize = usize::MAX;

static WORD_CLASS: LazyLock<Regex> = LazyLock::new(|| match Regex::new(r"\A[\p{L}\p{N}_]\z") {
    Ok(found) => found,
    Err(_) => std::process::abort(),
});
static SPACE_CLASS: LazyLock<Regex> = LazyLock::new(|| match Regex::new(r"\A[\s\x1c-\x1f]\z") {
    Ok(found) => found,
    Err(_) => std::process::abort(),
});
static DIGIT_CLASS: LazyLock<Regex> = LazyLock::new(|| match Regex::new(r"\A\p{Nd}\z") {
    Ok(found) => found,
    Err(_) => std::process::abort(),
});

fn is_word(character: char) -> bool {
    if character.is_ascii() {
        return character.is_ascii_alphanumeric() || character == '_';
    }
    WORD_CLASS.is_match(character.encode_utf8(&mut [0u8; 4]))
}

fn is_space(character: char) -> bool {
    if character.is_ascii() {
        return matches!(character, ' ' | '\t'..='\r' | '\u{1c}'..='\u{1f}');
    }
    SPACE_CLASS.is_match(character.encode_utf8(&mut [0u8; 4]))
}

fn is_digit(character: char) -> bool {
    if character.is_ascii() {
        return character.is_ascii_digit();
    }
    DIGIT_CLASS.is_match(character.encode_utf8(&mut [0u8; 4]))
}

fn class_has(kind: &ClassKind, negated: bool, character: char) -> bool {
    let inside = match kind {
        ClassKind::Digit => is_digit(character),
        ClassKind::Space => is_space(character),
        ClassKind::Word => is_word(character),
    };
    inside != negated
}

fn lower(character: char) -> char {
    if character == '\u{130}' {
        return 'i';
    }
    let mut mapped = character.to_lowercase();
    match (mapped.next(), mapped.next()) {
        (Some(single), None) => single,
        _ => character,
    }
}

fn upper(character: char) -> char {
    let mut mapped = character.to_uppercase();
    match (mapped.next(), mapped.next()) {
        (Some(single), None) => single,
        _ => character,
    }
}

const EQUIVALENT: &[&[u32]] = &[
    &[0x69, 0x131],
    &[0x73, 0x17f],
    &[0xb5, 0x3bc],
    &[0x345, 0x3b9, 0x1fbe],
    &[0x390, 0x1fd3],
    &[0x3b0, 0x1fe3],
    &[0x3b2, 0x3d0],
    &[0x3b5, 0x3f5],
    &[0x3b8, 0x3d1],
    &[0x3ba, 0x3f0],
    &[0x3c0, 0x3d6],
    &[0x3c1, 0x3f1],
    &[0x3c2, 0x3c3],
    &[0x3c6, 0x3d5],
    &[0x1e61, 0x1e9b],
    &[0xfb05, 0xfb06],
];

fn same_folded(left: char, right: char) -> bool {
    let (a, b) = (lower(left), lower(right));
    if a == b {
        return true;
    }
    EQUIVALENT
        .iter()
        .any(|group| group.contains(&(a as u32)) && group.contains(&(b as u32)))
}

static LOWER_SOURCES: LazyLock<std::collections::HashMap<char, Vec<char>>> = LazyLock::new(|| {
    let mut map: std::collections::HashMap<char, Vec<char>> = std::collections::HashMap::new();
    for code in 0..0x110000u32 {
        if let Some(character) = char::from_u32(code) {
            let mapped = lower(character);
            if mapped != character {
                map.entry(mapped).or_default().push(character);
            }
        }
    }
    map
});

fn group_of(lowered: char) -> Vec<char> {
    for group in EQUIVALENT {
        if group.contains(&(lowered as u32)) {
            return group.iter().filter_map(|code| char::from_u32(*code)).collect();
        }
    }
    vec![lowered]
}

fn sources_of(lowered: char) -> Vec<char> {
    let mut found = Vec::new();
    if lower(lowered) == lowered {
        found.push(lowered);
    }
    if lowered.is_ascii() {
        let upper_case = upper(lowered);
        if upper_case != lowered {
            found.push(upper_case);
        }
        match lowered {
            'i' => found.push('\u{130}'),
            'k' => found.push('\u{212a}'),
            _ => {}
        }
    } else if let Some(more) = LOWER_SOURCES.get(&lowered) {
        found.extend(more.iter().copied());
    }
    found
}

impl CharSet {
    fn plain_has(&self, character: char) -> bool {
        self.items.iter().any(|item| match item {
            SetItem::Char(single) => *single == character,
            SetItem::Range(low, high) => *low <= character && character <= *high,
            SetItem::Class(..) => false,
        })
    }

    fn classes_have(&self, character: char) -> bool {
        self.items.iter().any(|item| match item {
            SetItem::Class(kind, negated) => class_has(kind, *negated, character),
            _ => false,
        })
    }

    fn contains(&self, character: char) -> bool {
        let found = if self.ignore_case {
            let lowered = lower(character);
            self.classes_have(lowered)
                || group_of(lowered)
                    .into_iter()
                    .flat_map(sources_of)
                    .any(|candidate| self.plain_has(candidate))
        } else {
            self.plain_has(character) || self.classes_have(character)
        };
        found != self.negate
    }
}

struct Parser {
    chars: Vec<char>,
    index: usize,
    groups: usize,
    names: Vec<(String, usize)>,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.index).copied()
    }

    fn eat(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn parse_alternation(&mut self, flags: &mut Flags) -> Result<Node, String> {
        let mut branches = vec![self.parse_sequence(flags)?];
        while self.eat('|') {
            branches.push(self.parse_sequence(flags)?);
        }
        Ok(if branches.len() == 1 { branches.remove(0) } else { Node::Alt(branches) })
    }

    fn skip_verbose(&mut self, flags: &Flags) {
        if !flags.verbose {
            return;
        }
        while let Some(ch) = self.peek() {
            if ch.is_whitespace() {
                self.index += 1;
            } else if ch == '#' {
                while let Some(next) = self.peek() {
                    self.index += 1;
                    if next == '\n' {
                        break;
                    }
                }
            } else {
                break;
            }
        }
    }

    fn parse_sequence(&mut self, flags: &mut Flags) -> Result<Node, String> {
        let mut items = Vec::new();
        loop {
            self.skip_verbose(flags);
            match self.peek() {
                None | Some('|') | Some(')') => break,
                _ => {}
            }
            let atom = self.parse_atom(flags)?;
            self.skip_verbose(flags);
            let atom = self.parse_quantifier(atom)?;
            items.push(atom);
        }
        Ok(match items.len() {
            0 => Node::Empty,
            1 => items.remove(0),
            _ => Node::Seq(items),
        })
    }

    fn parse_quantifier(&mut self, atom: Node) -> Result<Node, String> {
        let mut node = atom;
        loop {
            let (min, max) = match self.peek() {
                Some('*') => {
                    self.index += 1;
                    (0, INFINITE)
                }
                Some('+') => {
                    self.index += 1;
                    (1, INFINITE)
                }
                Some('?') => {
                    self.index += 1;
                    (0, 1)
                }
                Some('{') => match self.try_braces() {
                    Some(bounds) => bounds,
                    None => return Ok(node),
                },
                _ => return Ok(node),
            };
            let greedy = !self.eat('?');
            if self.peek() == Some('+') {
                return Err("possessive quantifier".to_owned());
            }
            node = Node::Repeat { node: Box::new(node), min, max, greedy };
            if matches!(self.peek(), Some('*' | '+' | '?')) {
                return Err("multiple repeat".to_owned());
            }
        }
    }

    fn try_braces(&mut self) -> Option<(usize, usize)> {
        let start = self.index;
        self.index += 1;
        let read = |parser: &mut Parser| -> Option<usize> {
            let from = parser.index;
            while parser.peek().is_some_and(|ch| ch.is_ascii_digit()) {
                parser.index += 1;
            }
            let digits: String = parser.chars[from..parser.index].iter().collect();
            if digits.is_empty() { None } else { digits.parse::<usize>().ok() }
        };
        let low = read(self);
        let result = if self.eat(',') {
            let high = read(self);
            if self.eat('}') {
                Some((low.unwrap_or(0), high.unwrap_or(INFINITE)))
            } else {
                None
            }
        } else if self.eat('}') {
            low.map(|count| (count, count))
        } else {
            None
        };
        if result.is_none() {
            self.index = start;
        }
        result
    }

    fn parse_atom(&mut self, flags: &mut Flags) -> Result<Node, String> {
        let Some(ch) = self.peek() else { return Ok(Node::Empty) };
        self.index += 1;
        match ch {
            '.' => Ok(Node::Any(flags.dotall)),
            '^' => Ok(Node::Start(flags.multiline)),
            '$' => Ok(Node::End(flags.multiline)),
            '(' => self.parse_group(flags),
            '[' => self.parse_set(flags),
            '\\' => self.parse_escape(flags),
            '*' | '+' | '?' => Err("nothing to repeat".to_owned()),
            other => Ok(Node::Literal(other, flags.ignore_case)),
        }
    }

    fn parse_group(&mut self, flags: &mut Flags) -> Result<Node, String> {
        if self.eat('?') {
            let Some(kind) = self.peek() else { return Err("unexpected end".to_owned()) };
            self.index += 1;
            match kind {
                ':' => {
                    let mut inner = *flags;
                    let node = self.parse_alternation(&mut inner)?;
                    self.close()?;
                    return Ok(Node::Group { node: Box::new(node), index: None });
                }
                '#' => {
                    while let Some(next) = self.peek() {
                        self.index += 1;
                        if next == ')' {
                            return Ok(Node::Empty);
                        }
                    }
                    return Err("missing )".to_owned());
                }
                '=' | '!' => {
                    let mut inner = *flags;
                    let node = self.parse_alternation(&mut inner)?;
                    self.close()?;
                    return Ok(Node::Look { node: Box::new(node), behind: false, negate: kind == '!', width: 0 });
                }
                '<' => {
                    let direction = self.peek();
                    if direction == Some('=') || direction == Some('!') {
                        self.index += 1;
                        let mut inner = *flags;
                        let node = self.parse_alternation(&mut inner)?;
                        self.close()?;
                        let width = fixed_width(&node).ok_or_else(|| "look-behind requires fixed-width pattern".to_owned())?;
                        return Ok(Node::Look { node: Box::new(node), behind: true, negate: direction == Some('!'), width });
                    }
                    return Err("unknown extension".to_owned());
                }
                'P' => {
                    if self.eat('<') {
                        let mut name = String::new();
                        while let Some(next) = self.peek() {
                            self.index += 1;
                            if next == '>' {
                                break;
                            }
                            name.push(next);
                        }
                        self.groups += 1;
                        let index = self.groups;
                        self.names.push((name, index));
                        let mut inner = *flags;
                        let node = self.parse_alternation(&mut inner)?;
                        self.close()?;
                        return Ok(Node::Group { node: Box::new(node), index: Some(index) });
                    }
                    if self.eat('=') {
                        let mut name = String::new();
                        while let Some(next) = self.peek() {
                            self.index += 1;
                            if next == ')' {
                                break;
                            }
                            name.push(next);
                        }
                        let found = self.names.iter().find(|(known, _)| *known == name).map(|(_, index)| *index);
                        return found.map(|index| Node::Backref(index, flags.ignore_case)).ok_or_else(|| "unknown group name".to_owned());
                    }
                    return Err("unknown extension".to_owned());
                }
                _ => {
                    self.index -= 1;
                    return self.parse_flags(flags);
                }
            }
        }
        self.groups += 1;
        let index = self.groups;
        let mut inner = *flags;
        let node = self.parse_alternation(&mut inner)?;
        self.close()?;
        Ok(Node::Group { node: Box::new(node), index: Some(index) })
    }

    fn close(&mut self) -> Result<(), String> {
        if self.eat(')') { Ok(()) } else { Err("missing )".to_owned()) }
    }

    fn parse_flags(&mut self, flags: &mut Flags) -> Result<Node, String> {
        let mut enable = true;
        let mut updated = *flags;
        loop {
            let Some(ch) = self.peek() else { return Err("missing )".to_owned()) };
            self.index += 1;
            match ch {
                'i' => updated.ignore_case = enable,
                'm' => updated.multiline = enable,
                's' => updated.dotall = enable,
                'x' => updated.verbose = enable,
                'a' | 'u' | 'L' => {}
                '-' => enable = false,
                ')' => {
                    *flags = updated;
                    return Ok(Node::Empty);
                }
                ':' => {
                    let mut inner = updated;
                    let node = self.parse_alternation(&mut inner)?;
                    self.close()?;
                    return Ok(Node::Group { node: Box::new(node), index: None });
                }
                _ => return Err("unknown flag".to_owned()),
            }
        }
    }

    fn parse_escape(&mut self, flags: &Flags) -> Result<Node, String> {
        let Some(ch) = self.peek() else { return Err("bad escape (end of pattern)".to_owned()) };
        self.index += 1;
        let class = |kind: ClassKind, negated: bool| {
            Node::Set(CharSet { negate: false, items: vec![SetItem::Class(kind, negated)], ignore_case: false })
        };
        match ch {
            'd' => Ok(class(ClassKind::Digit, false)),
            'D' => Ok(class(ClassKind::Digit, true)),
            's' => Ok(class(ClassKind::Space, false)),
            'S' => Ok(class(ClassKind::Space, true)),
            'w' => Ok(class(ClassKind::Word, false)),
            'W' => Ok(class(ClassKind::Word, true)),
            'b' => Ok(Node::Boundary(false)),
            'B' => Ok(Node::Boundary(true)),
            'A' => Ok(Node::TextStart),
            'Z' => Ok(Node::TextEnd),
            '1'..='9' => {
                let mut number = ch.to_digit(10).unwrap_or(0) as usize;
                if let Some(next) = self.peek().and_then(|next| next.to_digit(10)) {
                    number = number * 10 + next as usize;
                    self.index += 1;
                }
                Ok(Node::Backref(number, flags.ignore_case))
            }
            other => {
                let literal = self.simple_escape(other)?;
                Ok(Node::Literal(literal, flags.ignore_case))
            }
        }
    }

    fn simple_escape(&mut self, ch: char) -> Result<char, String> {
        Ok(match ch {
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            'f' => '\u{c}',
            'v' => '\u{b}',
            'a' => '\u{7}',
            '0' => '\0',
            'x' => self.hex(2)?,
            'u' => self.hex(4)?,
            'U' => self.hex(8)?,
            other if other.is_ascii_alphanumeric() => return Err(format!("bad escape \\{other}")),
            other => other,
        })
    }

    fn hex(&mut self, count: usize) -> Result<char, String> {
        let mut value = 0u32;
        for _ in 0..count {
            let digit = self.peek().and_then(|ch| ch.to_digit(16)).ok_or_else(|| "incomplete escape".to_owned())?;
            self.index += 1;
            value = value * 16 + digit;
        }
        char::from_u32(value).ok_or_else(|| "bad code point".to_owned())
    }

    fn parse_set(&mut self, flags: &Flags) -> Result<Node, String> {
        let negate = self.eat('^');
        let mut items: Vec<SetItem> = Vec::new();
        let mut first = true;
        loop {
            let Some(ch) = self.peek() else { return Err("unterminated character set".to_owned()) };
            self.index += 1;
            if ch == ']' && !first {
                break;
            }
            first = false;
            let low = if ch == '\\' {
                match self.set_escape()? {
                    SetAtom::Item(item) => {
                        items.push(item);
                        continue;
                    }
                    SetAtom::Char(single) => single,
                }
            } else {
                ch
            };
            if self.peek() == Some('-') && self.chars.get(self.index + 1).is_some_and(|next| *next != ']') {
                self.index += 1;
                let Some(raw) = self.peek() else { return Err("unterminated character set".to_owned()) };
                self.index += 1;
                let high = if raw == '\\' {
                    match self.set_escape()? {
                        SetAtom::Char(single) => single,
                        SetAtom::Item(_) => return Err("bad character range".to_owned()),
                    }
                } else {
                    raw
                };
                if high < low {
                    return Err("bad character range".to_owned());
                }
                items.push(SetItem::Range(low, high));
            } else {
                items.push(SetItem::Char(low));
            }
        }
        Ok(Node::Set(CharSet { negate, items, ignore_case: flags.ignore_case }))
    }

    fn set_escape(&mut self) -> Result<SetAtom, String> {
        let Some(ch) = self.peek() else { return Err("bad escape (end of pattern)".to_owned()) };
        self.index += 1;
        Ok(match ch {
            'd' => SetAtom::Item(SetItem::Class(ClassKind::Digit, false)),
            'D' => SetAtom::Item(SetItem::Class(ClassKind::Digit, true)),
            's' => SetAtom::Item(SetItem::Class(ClassKind::Space, false)),
            'S' => SetAtom::Item(SetItem::Class(ClassKind::Space, true)),
            'w' => SetAtom::Item(SetItem::Class(ClassKind::Word, false)),
            'W' => SetAtom::Item(SetItem::Class(ClassKind::Word, true)),
            'b' => SetAtom::Char('\u{8}'),
            other => SetAtom::Char(self.simple_escape(other)?),
        })
    }
}

enum SetAtom {
    Item(SetItem),
    Char(char),
}

fn fixed_width(node: &Node) -> Option<usize> {
    match node {
        Node::Empty | Node::Start(_) | Node::End(_) | Node::TextStart | Node::TextEnd | Node::Boundary(_) | Node::Look { .. } => Some(0),
        Node::Literal(..) | Node::Any(_) | Node::Set(_) => Some(1),
        Node::Seq(items) => items.iter().map(fixed_width).sum(),
        Node::Alt(branches) => {
            let mut widths = branches.iter().map(fixed_width);
            let first = widths.next()??;
            widths.all(|width| width == Some(first)).then_some(first)
        }
        Node::Repeat { node, min, max, .. } => {
            if min == max {
                fixed_width(node).map(|width| width * min)
            } else {
                None
            }
        }
        Node::Group { node, .. } => fixed_width(node),
        Node::Backref(..) => None,
    }
}

struct State<'a> {
    text: &'a [char],
    captures: Vec<Option<(usize, usize)>>,
    start: usize,
    must_advance: bool,
}

type Continue<'t, 'a> = &'a mut dyn FnMut(&mut State<'t>, usize) -> bool;

impl PyRegex {
    pub fn new(source: &str) -> Result<PyRegex, String> {
        let mut parser = Parser { chars: source.chars().collect(), index: 0, groups: 0, names: Vec::new() };
        let mut flags = Flags::default();
        let root = parser.parse_alternation(&mut flags)?;
        if parser.index < parser.chars.len() {
            return Err("unbalanced parenthesis".to_owned());
        }
        Ok(PyRegex { root, groups: parser.groups })
    }

    fn single(&self, node: &Node, character: char) -> Option<bool> {
        match node {
            Node::Literal(expected, ignore_case) => Some(if *ignore_case { same_folded(*expected, character) } else { *expected == character }),
            Node::Any(dotall) => Some(*dotall || character != '\n'),
            Node::Set(set) => Some(set.contains(character)),
            _ => None,
        }
    }

    fn run<'t>(&self, node: &Node, state: &mut State<'t>, position: usize, next: Continue<'t, '_>) -> bool {
        match node {
            Node::Empty => next(state, position),
            Node::Literal(..) | Node::Any(_) | Node::Set(_) => match state.text.get(position) {
                Some(character) if self.single(node, *character) == Some(true) => next(state, position + 1),
                _ => false,
            },
            Node::Seq(items) => self.sequence(items, state, position, next),
            Node::Alt(branches) => {
                for branch in branches {
                    if self.run(branch, state, position, next) {
                        return true;
                    }
                }
                false
            }
            Node::Group { node, index } => match index {
                None => self.run(node, state, position, next),
                Some(number) => {
                    let number = *number;
                    let saved = state.captures[number];
                    let outcome = self.run(node, state, position, &mut |inner: &mut State<'t>, end: usize| {
                        let before = inner.captures[number];
                        inner.captures[number] = Some((position, end));
                        if next(inner, end) {
                            return true;
                        }
                        inner.captures[number] = before;
                        false
                    });
                    if !outcome {
                        state.captures[number] = saved;
                    }
                    outcome
                }
            },
            Node::Repeat { node, min, max, greedy } => {
                if matches!(**node, Node::Literal(..) | Node::Any(_) | Node::Set(_)) {
                    return self.repeat_single(node, *min, *max, *greedy, state, position, next);
                }
                self.repeat_general(node, *min, *max, *greedy, 0, state, position, next)
            }
            Node::Look { node, behind, negate, width } => {
                let saved = state.captures.clone();
                let matched = if *behind {
                    position >= *width && self.run(node, state, position - width, &mut |_: &mut State<'t>, end: usize| end == position)
                } else {
                    self.run(node, state, position, &mut |_: &mut State<'t>, _: usize| true)
                };
                if matched == *negate {
                    state.captures = saved;
                    return false;
                }
                if *negate {
                    state.captures = saved;
                    return next(state, position);
                }
                if next(state, position) {
                    return true;
                }
                state.captures = saved;
                false
            }
            Node::Start(multiline) => {
                if position == 0 || (*multiline && state.text.get(position - 1) == Some(&'\n')) {
                    next(state, position)
                } else {
                    false
                }
            }
            Node::End(multiline) => {
                let length = state.text.len();
                let at_end = position == length
                    || (position + 1 == length && state.text[position] == '\n')
                    || (*multiline && state.text[position] == '\n');
                if at_end { next(state, position) } else { false }
            }
            Node::TextStart => {
                if position == 0 { next(state, position) } else { false }
            }
            Node::TextEnd => {
                if position == state.text.len() { next(state, position) } else { false }
            }
            Node::Boundary(negated) => {
                if state.text.is_empty() {
                    return false;
                }
                let before = position > 0 && is_word(state.text[position - 1]);
                let after = position < state.text.len() && is_word(state.text[position]);
                if (before != after) != *negated { next(state, position) } else { false }
            }
            Node::Backref(number, ignore_case) => {
                let Some(Some((from, to))) = state.captures.get(*number).copied() else { return false };
                let length = to - from;
                if position + length > state.text.len() {
                    return false;
                }
                for offset in 0..length {
                    let (left, right) = (state.text[from + offset], state.text[position + offset]);
                    let same = if *ignore_case { lower(left) == lower(right) } else { left == right };
                    if !same {
                        return false;
                    }
                }
                next(state, position + length)
            }
        }
    }

    fn sequence<'t>(&self, items: &[Node], state: &mut State<'t>, position: usize, next: Continue<'t, '_>) -> bool {
        match items.split_first() {
            None => next(state, position),
            Some((head, tail)) => {
                if tail.is_empty() {
                    return self.run(head, state, position, next);
                }
                self.run(head, state, position, &mut |inner: &mut State<'t>, at: usize| self.sequence(tail, inner, at, next))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn repeat_single<'t>(&self, node: &Node, min: usize, max: usize, greedy: bool, state: &mut State<'t>, position: usize, next: Continue<'t, '_>) -> bool {
        let limit = if max == INFINITE { state.text.len() - position.min(state.text.len()) } else { max.min(state.text.len() - position.min(state.text.len())) };
        if greedy {
            let mut count = 0usize;
            while count < limit && self.single(node, state.text[position + count]) == Some(true) {
                count += 1;
            }
            if count < min {
                return false;
            }
            let mut take = count;
            loop {
                if next(state, position + take) {
                    return true;
                }
                if take == min {
                    return false;
                }
                take -= 1;
            }
        }
        let mut count = 0usize;
        while count < min {
            if count >= limit || self.single(node, state.text[position + count]) != Some(true) {
                return false;
            }
            count += 1;
        }
        loop {
            if next(state, position + count) {
                return true;
            }
            if count >= limit || self.single(node, state.text[position + count]) != Some(true) {
                return false;
            }
            count += 1;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn repeat_general<'t>(&self, node: &Node, min: usize, max: usize, greedy: bool, count: usize, state: &mut State<'t>, position: usize, next: Continue<'t, '_>) -> bool {
        if !greedy && count >= min && next(state, position) {
            return true;
        }
        if count < max {
            let advanced = self.run(node, state, position, &mut |inner: &mut State<'t>, at: usize| {
                if at == position {
                    if count + 1 >= min {
                        return next(inner, at);
                    }
                    return self.repeat_general(node, min, max, greedy, count + 1, inner, at, next);
                }
                self.repeat_general(node, min, max, greedy, count + 1, inner, at, next)
            });
            if advanced {
                return true;
            }
        }
        greedy && count >= min && next(state, position)
    }

    fn attempt<'t>(&self, text: &'t [char], start: usize, must_advance: bool) -> Option<PyMatch> {
        let mut state = State { text, captures: vec![None; self.groups + 1], start, must_advance };
        let mut end = 0usize;
        let found = self.run(&self.root, &mut state, start, &mut |inner: &mut State<'t>, at: usize| {
            if inner.must_advance && at == inner.start {
                return false;
            }
            end = at;
            true
        });
        found.then(|| PyMatch { start, end, groups: state.captures[1..].to_vec() })
    }

    /// Python `pattern.search(text, pos)` in code point indexes.
    pub fn search_chars(&self, text: &[char], from: usize, must_advance: bool) -> Option<PyMatch> {
        let mut start = from;
        while start <= text.len() {
            if let Some(found) = self.attempt(text, start, must_advance && start == from) {
                return Some(found);
            }
            start += 1;
        }
        None
    }

    pub fn match_chars(&self, text: &[char]) -> Option<PyMatch> {
        self.attempt(text, 0, false)
    }

    pub fn fullmatch_chars<'t>(&self, text: &'t [char]) -> Option<PyMatch> {
        let mut state = State { text, captures: vec![None; self.groups + 1], start: 0, must_advance: false };
        let mut end = 0usize;
        let length = text.len();
        let found = self.run(&self.root, &mut state, 0, &mut |_: &mut State<'t>, at: usize| {
            end = at;
            at == length
        });
        found.then(|| PyMatch { start: 0, end, groups: state.captures[1..].to_vec() })
    }

    pub fn find_iter_chars(&self, text: &[char]) -> Vec<PyMatch> {
        let mut found = Vec::new();
        let mut position = 0usize;
        let mut must_advance = false;
        while position <= text.len() {
            let Some(hit) = self.search_chars(text, position, must_advance) else { break };
            position = hit.end;
            must_advance = hit.end == hit.start;
            found.push(hit);
        }
        found
    }
}
