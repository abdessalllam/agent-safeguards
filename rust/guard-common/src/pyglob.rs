use std::fs;
use std::path::Path;

use crate::sys::{self, EmbeddedNul};

enum Token {
    Star,
    Any,
    Literal(char),
    Never,
    Set { negate: bool, ranges: Vec<(char, char)> },
}

/// Python `fnmatch.fnmatchcase`.
pub fn fnmatchcase(name: &str, pattern: &str) -> bool {
    let tokens = translate(pattern);
    let chars: Vec<char> = name.chars().collect();
    let (mut token, mut position) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while position < chars.len() {
        let single = tokens.get(token).filter(|item| !matches!(item, Token::Star));
        if single.is_some_and(|item| token_matches(item, chars[position])) {
            token += 1;
            position += 1;
        } else if matches!(tokens.get(token), Some(Token::Star)) {
            star = Some((token, position));
            token += 1;
        } else if let Some((star_token, mark)) = star {
            token = star_token + 1;
            star = Some((star_token, mark + 1));
            position = mark + 1;
        } else {
            return false;
        }
    }
    while matches!(tokens.get(token), Some(Token::Star)) {
        token += 1;
    }
    token == tokens.len()
}

fn token_matches(token: &Token, character: char) -> bool {
    match token {
        Token::Star | Token::Never => false,
        Token::Any => true,
        Token::Literal(expected) => *expected == character,
        Token::Set { negate, ranges } => {
            let inside = ranges.iter().any(|(low, high)| *low <= character && character <= *high);
            inside != *negate
        }
    }
}

fn translate(pattern: &str) -> Vec<Token> {
    let pat: Vec<char> = pattern.chars().collect();
    let length = pat.len();
    let mut tokens: Vec<Token> = Vec::new();
    let mut index = 0usize;
    while index < length {
        let character = pat[index];
        index += 1;
        match character {
            '*' => {
                if !matches!(tokens.last(), Some(Token::Star)) {
                    tokens.push(Token::Star);
                }
            }
            '?' => tokens.push(Token::Any),
            '[' => {
                let mut end = index;
                if end < length && pat[end] == '!' {
                    end += 1;
                }
                if end < length && pat[end] == ']' {
                    end += 1;
                }
                while end < length && pat[end] != ']' {
                    end += 1;
                }
                if end >= length {
                    tokens.push(Token::Literal('['));
                } else {
                    tokens.push(set_token(&pat, index, end));
                    index = end + 1;
                }
            }
            other => tokens.push(Token::Literal(other)),
        }
    }
    tokens
}

fn set_token(pat: &[char], start: usize, end: usize) -> Token {
    let stuff = &pat[start..end];
    let mut chunks: Vec<Vec<char>> = Vec::new();
    if !stuff.contains(&'-') {
        chunks.push(stuff.to_vec());
    } else {
        let mut begin = start;
        let mut cursor = if pat[start] == '!' { start + 2 } else { start + 1 };
        while let Some(found) = (cursor..end).find(|position| pat[*position] == '-') {
            chunks.push(pat[begin..found].to_vec());
            begin = found + 1;
            cursor = found + 3;
        }
        let tail = pat[begin..end].to_vec();
        if !tail.is_empty() {
            chunks.push(tail);
        } else if let Some(last) = chunks.last_mut() {
            last.push('-');
        }
        for position in (1..chunks.len()).rev() {
            let previous_last = chunks[position - 1].last().copied();
            let next_first = chunks[position].first().copied();
            if let (Some(low), Some(high)) = (previous_last, next_first) {
                if low > high {
                    let mut merged = chunks[position - 1].clone();
                    merged.pop();
                    merged.extend(chunks[position].iter().skip(1));
                    chunks[position - 1] = merged;
                    chunks.remove(position);
                }
            }
        }
    }
    let mut negate = false;
    let first_is_bang = chunks.first().and_then(|chunk| chunk.first()) == Some(&'!');
    if first_is_bang {
        if chunks.len() == 1 && chunks[0].len() == 1 {
            return Token::Any;
        }
        negate = true;
        chunks[0].remove(0);
    }
    if chunks.iter().all(Vec::is_empty) {
        return Token::Never;
    }
    let mut ranges: Vec<(char, char)> = Vec::new();
    let count = chunks.len();
    for (number, chunk) in chunks.iter().enumerate() {
        let from = usize::from(number > 0);
        let to = chunk.len().saturating_sub(usize::from(number + 1 < count));
        for item in chunk.iter().take(to).skip(from) {
            ranges.push((*item, *item));
        }
        if number + 1 < count {
            if let (Some(low), Some(high)) = (chunk.last(), chunks[number + 1].first()) {
                ranges.push((*low, *high));
            }
        }
    }
    Token::Set { negate, ranges }
}

pub fn expanduser(path: &str) -> Result<String, EmbeddedNul> {
    if !path.starts_with('~') {
        return Ok(path.to_owned());
    }
    let end = path[1..].find('/').map_or(path.len(), |offset| offset + 1);
    let home = if end == 1 {
        match std::env::var("HOME") {
            Ok(value) => value,
            Err(_) => match sys::passwd_home(sys::getuid()) {
                Some(value) => value,
                None => return Ok(path.to_owned()),
            },
        }
    } else {
        match sys::passwd_home_by_name(&path[1..end])? {
            Some(value) => value,
            None => return Ok(path.to_owned()),
        }
    };
    let joined = format!("{}{}", home.trim_end_matches('/'), &path[end..]);
    Ok(if joined.is_empty() { "/".to_owned() } else { joined })
}

fn has_magic(text: &str) -> bool {
    text.contains(['*', '?', '['])
}

fn split(path: &str) -> (String, String) {
    let cut = path.rfind('/').map_or(0, |position| position + 1);
    let (head, tail) = path.split_at(cut);
    let head = if !head.is_empty() && head.chars().any(|ch| ch != '/') {
        head.trim_end_matches('/')
    } else {
        head
    };
    (head.to_owned(), tail.to_owned())
}

fn join(base: &str, name: &str) -> String {
    if name.starts_with('/') {
        name.to_owned()
    } else if base.is_empty() || base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

fn glob_join(directory: &str, name: &str) -> String {
    if directory.is_empty() || name.is_empty() {
        if directory.is_empty() { name.to_owned() } else { directory.to_owned() }
    } else {
        join(directory, name)
    }
}

fn lexists(path: &str) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn is_directory(path: &str) -> bool {
    Path::new(path).is_dir()
}

fn list_directory(directory: &str, only_directories: bool) -> Result<Vec<String>, EmbeddedNul> {
    let target = if directory.is_empty() { "." } else { directory };
    if target.contains('\0') {
        return Err(EmbeddedNul);
    }
    let Ok(entries) = fs::read_dir(target) else {
        return Ok(Vec::new());
    };
    let mut names = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if only_directories {
            let is_folder = match entry.file_type() {
                Ok(kind) if kind.is_dir() => true,
                Ok(kind) if kind.is_symlink() => {
                    fs::metadata(entry.path()).is_ok_and(|meta| meta.is_dir())
                }
                _ => false,
            };
            if !is_folder {
                continue;
            }
        }
        names.push(name);
    }
    Ok(names)
}

fn glob_names_matching(
    directory: &str,
    pattern: &str,
    only_directories: bool,
) -> Result<Vec<String>, EmbeddedNul> {
    let mut names = list_directory(directory, only_directories)?;
    if !pattern.starts_with('.') {
        names.retain(|name| !name.starts_with('.'));
    }
    names.retain(|name| fnmatchcase(name, pattern));
    Ok(names)
}

fn glob_literal(directory: &str, name: &str) -> Vec<String> {
    let found = if name.is_empty() {
        is_directory(directory)
    } else {
        lexists(&glob_join(directory, name))
    };
    if found { vec![name.to_owned()] } else { Vec::new() }
}

type Emit<'a> = &'a mut dyn FnMut(String) -> bool;

pub fn iglob(pathname: &str, limit: usize) -> Result<Vec<String>, EmbeddedNul> {
    let mut found: Vec<String> = Vec::new();
    if limit == 0 {
        return Ok(found);
    }
    iglob_into(pathname, false, &mut |item: String| {
        found.push(item);
        found.len() < limit
    })?;
    Ok(found)
}

fn iglob_into(pathname: &str, only_directories: bool, emit: Emit) -> Result<bool, EmbeddedNul> {
    let (dirname, basename) = split(pathname);
    if !has_magic(pathname) {
        let present = if basename.is_empty() { is_directory(&dirname) } else { lexists(pathname) };
        return Ok(if present { emit(pathname.to_owned()) } else { true });
    }
    if dirname.is_empty() {
        for name in glob_names_matching("", &basename, only_directories)? {
            if !emit(name) {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    let magic_basename = has_magic(&basename);
    let inside = |directory: &str, emit: Emit| -> Result<bool, EmbeddedNul> {
        let names = if magic_basename {
            glob_names_matching(directory, &basename, only_directories)?
        } else {
            glob_literal(directory, &basename)
        };
        for name in names {
            if !emit(join(directory, &name)) {
                return Ok(false);
            }
        }
        Ok(true)
    };
    if dirname != pathname && has_magic(&dirname) {
        let mut failure: Option<EmbeddedNul> = None;
        let finished = iglob_into(&dirname, true, &mut |directory: String| {
            match inside(&directory, &mut *emit) {
                Ok(keep_going) => keep_going,
                Err(error) => {
                    failure = Some(error);
                    false
                }
            }
        })?;
        return match failure {
            Some(error) => Err(error),
            None => Ok(finished),
        };
    }
    inside(&dirname, emit)
}
