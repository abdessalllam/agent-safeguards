use std::collections::HashSet;

use crate::keys::{self, LineRead};
use crate::startup_values::{self, Scan};

const MAX_NESTING: usize = 6;

pub struct Limits {
    pub files: usize,
    pub bytes: usize,
}

pub const STANDARD: Limits = Limits { files: 500, bytes: 8 * 1024 * 1024 };

type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

fn lookup(name: &str, home: &str, vars: &[(String, String)], env: Env) -> Option<String> {
    if name == "HOME" {
        return Some(home.to_owned());
    }
    vars.iter()
        .rev()
        .find(|(known, _)| known == name)
        .map(|(_, value)| value.clone())
        .or_else(|| env(name))
}

fn name_end(chars: &[char], from: usize) -> usize {
    let mut at = from;
    while chars.get(at).is_some_and(|ch| ch.is_ascii_alphanumeric() || *ch == '_') {
        at = at.saturating_add(1);
    }
    at
}

// The closing brace of the `${` that starts at `open`, nested braces counted.
fn closing_brace(chars: &[char], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (at, ch) in chars.iter().enumerate().skip(open.saturating_add(1)) {
        match ch {
            '{' => depth = depth.saturating_add(1),
            '}' if depth == 0 => return Some(at),
            '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    None
}

struct Scope<'a> {
    home: &'a str,
    vars: &'a [(String, String)],
    env: Env<'a>,
}

impl Scope<'_> {
    fn value_of(&self, name: &str, depth: usize) -> Option<String> {
        let found = lookup(name, self.home, self.vars, self.env)?;
        self.expand(&found, depth.saturating_add(1))
    }

    // `${NAME}` and its default forms (`-`, `:-`, `=`, `:=`); other forms are not followed.
    fn braced(&self, inner: &[char], depth: usize) -> Option<String> {
        let end = name_end(inner, 0);
        let name: String = inner.get(..end)?.iter().collect();
        if name.is_empty() {
            return None;
        }
        let rest: String = inner.get(end..)?.iter().collect();
        if rest.is_empty() {
            return self.value_of(&name, depth);
        }
        let (colon, default) = match rest.strip_prefix(':') {
            Some(after) => (true, after),
            None => (false, rest.as_str()),
        };
        let default = default.strip_prefix('-').or_else(|| default.strip_prefix('='))?;
        match self.value_of(&name, depth) {
            Some(set) if !(colon && set.is_empty()) => Some(set),
            _ => self.expand(default, depth.saturating_add(1)),
        }
    }

    // Glob characters stay in the text; the caller matches them against the folder.
    fn expand(&self, text: &str, depth: usize) -> Option<String> {
        if depth > MAX_NESTING {
            return None;
        }
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::new();
        let mut at = 0usize;
        if chars.first() == Some(&'~') {
            if !matches!(chars.get(1), None | Some('/')) {
                return None;
            }
            out.push_str(self.home);
            at = 1;
        }
        while let Some(&ch) = chars.get(at) {
            match ch {
                '$' if chars.get(at.saturating_add(1)) == Some(&'{') => {
                    let close = closing_brace(&chars, at.saturating_add(1))?;
                    let inner = chars.get(at.saturating_add(2)..close)?;
                    out.push_str(&self.braced(inner, depth)?);
                    at = close.saturating_add(1);
                }
                '$' => {
                    let end = name_end(&chars, at.saturating_add(1));
                    let name: String = chars.get(at.saturating_add(1)..end)?.iter().collect();
                    if name.is_empty() || name.starts_with(|first: char| first.is_ascii_digit()) {
                        return None;
                    }
                    out.push_str(&self.value_of(&name, depth)?);
                    at = end;
                }
                '`' | '{' | '\0' => return None,
                _ => {
                    out.push(ch);
                    at = at.saturating_add(1);
                }
            }
        }
        Some(out)
    }
}

// The path a `source` operand names, or nothing when the text does not fix it.
fn resolve(raw: &str, scope: &Scope) -> Option<String> {
    let expanded = scope.expand(raw, 0)?;
    if expanded.is_empty() {
        return None;
    }
    Some(if expanded.starts_with('/') {
        expanded
    } else {
        format!("{}/{expanded}", scope.home)
    })
}

// `text` with `$name` and `${name}` swapped for `word`; nothing if `name` is unused.
fn substitute(text: &str, name: &str, word: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut used = false;
    let mut at = 0usize;
    while let Some(&ch) = chars.get(at) {
        let mut next = at.saturating_add(1);
        let reference = if ch != '$' {
            None
        } else if chars.get(next) == Some(&'{') {
            closing_brace(&chars, next).and_then(|close| {
                let inner: String = chars.get(next.saturating_add(1)..close)?.iter().collect();
                next = close.saturating_add(1);
                Some(inner)
            })
        } else {
            let end = name_end(&chars, next);
            let found: String = chars.get(next..end)?.iter().collect();
            next = end;
            Some(found)
        };
        match reference {
            Some(found) if found == name => {
                out.push_str(word);
                used = true;
            }
            _ => out.extend(chars.get(at..next).unwrap_or_default()),
        }
        at = next;
    }
    used.then_some(out)
}

// The operand with every loop variable it uses replaced by each word of its loop.
fn loop_texts(raw: &str, loops: &[(String, Vec<String>)], cap: usize) -> Option<Vec<String>> {
    let mut grouped: Vec<(&str, Vec<&String>)> = Vec::new();
    for (name, words) in loops {
        match grouped.iter_mut().find(|(known, _)| *known == name.as_str()) {
            Some((_, merged)) => merged.extend(words),
            None => grouped.push((name.as_str(), words.iter().collect())),
        }
    }
    let mut texts = vec![raw.to_owned()];
    for (name, words) in grouped {
        let mut next: Vec<String> = Vec::new();
        for text in &texts {
            let replaced: Vec<String> = words.iter().filter_map(|word| substitute(text, name, word)).collect();
            if replaced.is_empty() {
                next.push(text.clone());
            } else {
                next.extend(replaced);
            }
        }
        next.sort();
        next.dedup();
        if next.len() > cap {
            return None;
        }
        texts = next;
    }
    Some(texts)
}

enum Token {
    Star,
    Any,
    Literal(char),
    Class { ranges: Vec<(char, char)>, negate: bool },
}

impl Token {
    fn accepts(&self, ch: char) -> bool {
        match self {
            Token::Star => false,
            Token::Any => true,
            Token::Literal(wanted) => *wanted == ch,
            Token::Class { ranges, negate } => ranges.iter().any(|(low, high)| *low <= ch && ch <= *high) != *negate,
        }
    }
}

fn tokens(pattern: &str) -> Vec<Token> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out: Vec<Token> = Vec::new();
    let mut at = 0usize;
    while let Some(&ch) = chars.get(at) {
        at = at.saturating_add(1);
        match ch {
            '*' if matches!(out.last(), Some(Token::Star)) => {}
            '*' => out.push(Token::Star),
            '?' => out.push(Token::Any),
            '[' => {
                let negate = matches!(chars.get(at), Some('!' | '^'));
                let start = at.saturating_add(usize::from(negate));
                let close = chars
                    .iter()
                    .enumerate()
                    .skip(start.saturating_add(1))
                    .find(|(_, member)| **member == ']')
                    .map(|(place, _)| place);
                let Some(close) = close else {
                    out.push(Token::Literal('['));
                    continue;
                };
                let set: Vec<char> = chars.get(start..close).unwrap_or_default().to_vec();
                let mut ranges: Vec<(char, char)> = Vec::new();
                let mut index = 0usize;
                while let Some(&low) = set.get(index) {
                    let dash = set.get(index.saturating_add(1)) == Some(&'-');
                    match set.get(index.saturating_add(2)) {
                        Some(&high) if dash => {
                            ranges.push((low, high));
                            index = index.saturating_add(3);
                        }
                        _ => {
                            ranges.push((low, low));
                            index = index.saturating_add(1);
                        }
                    }
                }
                out.push(Token::Class { ranges, negate });
                at = close.saturating_add(1);
            }
            other => out.push(Token::Literal(other)),
        }
    }
    out
}

fn glob_matches(pattern: &[Token], name: &[char]) -> bool {
    let (mut at_pattern, mut at_name) = (0usize, 0usize);
    let mut resume: Option<(usize, usize)> = None;
    while at_name < name.len() {
        let current = name.get(at_name).copied().unwrap_or_default();
        match pattern.get(at_pattern) {
            Some(Token::Star) => {
                resume = Some((at_pattern, at_name));
                at_pattern = at_pattern.saturating_add(1);
            }
            Some(token) if token.accepts(current) => {
                at_pattern = at_pattern.saturating_add(1);
                at_name = at_name.saturating_add(1);
            }
            _ => {
                let Some((star, from)) = resume else {
                    return false;
                };
                resume = Some((star, from.saturating_add(1)));
                at_pattern = star.saturating_add(1);
                at_name = from.saturating_add(1);
            }
        }
    }
    pattern.iter().skip(at_pattern).all(|token| matches!(token, Token::Star))
}

fn has_glob(text: &str) -> bool {
    text.contains(['*', '?', '['])
}

// Every existing path a pattern matches; names that start with a dot match only a dot.
fn expand_glob(path: &str, cap: usize) -> Option<Vec<String>> {
    if !has_glob(path) {
        return Some(vec![path.to_owned()]);
    }
    let mut bases = vec![String::new()];
    for part in path.split('/').filter(|part| !part.is_empty()) {
        let mut next: Vec<String> = Vec::new();
        for base in &bases {
            if !has_glob(part) {
                next.push(format!("{base}/{part}"));
                continue;
            }
            let Ok(entries) = std::fs::read_dir(if base.is_empty() { "/" } else { base.as_str() }) else {
                continue;
            };
            let pattern = tokens(part);
            let mut names: Vec<String> = entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| !name.starts_with('.') || part.starts_with('.'))
                .filter(|name| glob_matches(&pattern, &name.chars().collect::<Vec<char>>()))
                .collect();
            names.sort();
            next.extend(names.into_iter().map(|name| format!("{base}/{name}")));
        }
        if next.len() > cap {
            return None;
        }
        bases = next;
    }
    Some(bases)
}

fn canonical(path: &str) -> String {
    std::fs::canonicalize(path).map_or_else(|_| path.to_owned(), |found| found.to_string_lossy().into_owned())
}

// Reads every file the scanned text sources, and the files those source. False when a
// limit stopped it.
pub fn follow(home: &str, scan: &mut Scan, read: &[String], max_chars: usize, limits: &Limits, env: Env) -> bool {
    let mut visited: HashSet<String> = read.iter().map(|path| canonical(path)).collect();
    let mut handled = 0usize;
    let mut waiting: Vec<String> = Vec::new();
    let mut files = 0usize;
    let mut bytes = 0usize;
    loop {
        let mut todo = std::mem::take(&mut waiting);
        todo.extend(scan.sources.iter().skip(handled).cloned());
        handled = scan.sources.len();
        let known = (scan.sources.len(), scan.vars.len(), scan.loops.len());
        for raw in todo {
            let Some(texts) = loop_texts(&raw, &scan.loops, limits.files) else {
                return false;
            };
            let mut fixed = false;
            for text in texts {
                let path = {
                    let scope = Scope { home, vars: &scan.vars, env };
                    resolve(&text, &scope)
                };
                let Some(path) = path else {
                    continue;
                };
                fixed = true;
                let Some(found) = expand_glob(&path, limits.files) else {
                    return false;
                };
                for file in found {
                    if !std::fs::metadata(&file).is_ok_and(|meta| meta.is_file()) || !visited.insert(canonical(&file)) {
                        continue;
                    }
                    files = files.saturating_add(1);
                    if files > limits.files {
                        return false;
                    }
                    let Ok((content, how)) = keys::read_text(&file, max_chars) else {
                        continue;
                    };
                    bytes = bytes.saturating_add(content.len());
                    if matches!(how, LineRead::Truncated) || bytes > limits.bytes {
                        return false;
                    }
                    startup_values::scan_text(&content, scan);
                }
            }
            if !fixed {
                waiting.push(raw);
            }
        }
        if (scan.sources.len(), scan.vars.len(), scan.loops.len()) == known {
            return true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{expand_glob, follow, glob_matches, loop_texts, resolve, tokens, Limits, Scope};
    use crate::startup_values::{scan_text, Scan};

    fn none(_: &str) -> Option<String> {
        None
    }

    fn at(text: &str, vars: &[(&str, &str)]) -> Option<String> {
        let vars: Vec<(String, String)> = vars.iter().map(|(a, b)| ((*a).to_owned(), (*b).to_owned())).collect();
        resolve(text, &Scope { home: "/h", vars: &vars, env: &none })
    }

    #[test]
    fn home_tilde_and_plain_paths_resolve() {
        assert_eq!(at("~/.secrets", &[]).as_deref(), Some("/h/.secrets"));
        assert_eq!(at("$HOME/.secrets", &[]).as_deref(), Some("/h/.secrets"));
        assert_eq!(at("${HOME}/a/b", &[]).as_deref(), Some("/h/a/b"));
        assert_eq!(at("/etc/profile.d/x.sh", &[]).as_deref(), Some("/etc/profile.d/x.sh"));
        assert_eq!(at("env.sh", &[]).as_deref(), Some("/h/env.sh"));
        assert_eq!(at("./env.sh", &[]).as_deref(), Some("/h/./env.sh"));
        assert_eq!(at("~/.d/*.sh", &[]).as_deref(), Some("/h/.d/*.sh"));
    }

    #[test]
    fn variables_defaults_and_chains_resolve() {
        let vars = [("ZSH", "$HOME/.oh-my-zsh"), ("DIR", "$ZSH/custom")];
        assert_eq!(at("$ZSH/oh-my-zsh.sh", &vars).as_deref(), Some("/h/.oh-my-zsh/oh-my-zsh.sh"));
        assert_eq!(at("${DIR}/x.zsh", &vars).as_deref(), Some("/h/.oh-my-zsh/custom/x.zsh"));
        assert_eq!(at("${XDG:-$HOME/.config}/app/env", &[]).as_deref(), Some("/h/.config/app/env"));
        assert_eq!(at("${XDG:-$HOME/.config}/app/env", &[("XDG", "/x")]).as_deref(), Some("/x/app/env"));
        assert_eq!(at("${XDG:-/d}/e", &[("XDG", "")]).as_deref(), Some("/d/e"));
        assert_eq!(at("${XDG-/d}/e", &[("XDG", "")]).as_deref(), Some("/e"));
        assert_eq!(at("${XDG:=${HOME}/c}/e", &[]).as_deref(), Some("/h/c/e"));
    }

    #[test]
    fn paths_the_text_does_not_fix_are_not_resolved() {
        for raw in ["$UNSET/x", "${UNSET}/x", "$(pwd)/x", "`pwd`/x", "~other/x", "/a/{b,c}", "$1/x", "$", "${#HOME}", "${HOME:2}", "${HOME/h/x}", ""] {
            assert_eq!(at(raw, &[]), None, "{raw}");
        }
        assert_eq!(at("$A", &[("A", "$B"), ("B", "$A")]), None);
    }

    fn loops(list: &[(&str, &[&str])]) -> Vec<(String, Vec<String>)> {
        list.iter()
            .map(|(name, words)| ((*name).to_owned(), words.iter().map(|word| (*word).to_owned()).collect()))
            .collect()
    }

    #[test]
    fn loop_variables_are_replaced_by_each_word_of_their_loop() {
        let one = loops(&[("f", &["~/.a/x.sh", "$HOME/.b"])]);
        assert_eq!(loop_texts("$f", &one, 10), Some(vec!["$HOME/.b".to_owned(), "~/.a/x.sh".to_owned()]));
        assert_eq!(loop_texts("${f}/env", &one, 10), Some(vec!["$HOME/.b/env".to_owned(), "~/.a/x.sh/env".to_owned()]));
        assert_eq!(loop_texts("$fo/x", &one, 10), Some(vec!["$fo/x".to_owned()]));
        assert_eq!(loop_texts("~/.plain", &one, 10), Some(vec!["~/.plain".to_owned()]));
        let two = loops(&[("a", &["1", "2"]), ("b", &["x", "y"])]);
        assert_eq!(loop_texts("$a$b", &two, 10).map(|texts| texts.len()), Some(4));
        assert_eq!(loop_texts("$a$b", &two, 3), None);
        let reused = loops(&[("f", &["one"]), ("f", &["two"])]);
        assert_eq!(loop_texts("${f}", &reused, 10), Some(vec!["one".to_owned(), "two".to_owned()]));
    }

    fn matches(pattern: &str, name: &str) -> bool {
        glob_matches(&tokens(pattern), &name.chars().collect::<Vec<char>>())
    }

    #[test]
    fn glob_patterns_match_like_the_shell() {
        assert!(matches("*.sh", "a.sh") && matches("*", "anything") && matches("a*b*c", "aXXbYYc"));
        assert!(!matches("*.sh", "a.zsh") && !matches("a*b", "acd") && !matches("?", ""));
        assert!(matches("f?.env", "f1.env") && !matches("f?.env", "f12.env"));
        assert!(matches("[abc]x", "bx") && !matches("[abc]x", "dx") && matches("[a-c]x", "bx"));
        assert!(matches("[!a-c]x", "dx") && !matches("[!a-c]x", "bx") && matches("[^a]x", "bx"));
        assert!(matches("a[", "a[") && matches("*a*a*a*a*a*a*b", "aaaaaaaaaaaaaaaaaaaab"));
    }

    fn folder(name: &str) -> String {
        let home = std::env::temp_dir().join(format!("sourced-unit-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&home).expect("folder");
        guard_common::sys::realpath(&home.to_string_lossy())
    }

    #[test]
    fn globs_list_matching_files_and_folders_and_skip_dot_names() {
        let home = folder("glob");
        for file in ["d/a.sh", "d/b.sh", "d/c.txt", "d/.hidden.sh", "e/x/one.env", "e/y/two.env", "e/y/three.txt"] {
            let path = format!("{home}/{file}");
            std::fs::create_dir_all(std::path::Path::new(&path).parent().expect("parent")).expect("folders");
            std::fs::write(path, "x").expect("file");
        }
        assert_eq!(expand_glob(&format!("{home}/d/*.sh"), 10), Some(vec![format!("{home}/d/a.sh"), format!("{home}/d/b.sh")]));
        assert_eq!(expand_glob(&format!("{home}/d/.*.sh"), 10), Some(vec![format!("{home}/d/.hidden.sh")]));
        assert_eq!(expand_glob(&format!("{home}/e/*/*.env"), 10), Some(vec![format!("{home}/e/x/one.env"), format!("{home}/e/y/two.env")]));
        assert_eq!(expand_glob(&format!("{home}/none/*"), 10), Some(Vec::new()));
        assert_eq!(expand_glob(&format!("{home}/d/*"), 1), None);
        assert_eq!(expand_glob("/plain/path", 1), Some(vec!["/plain/path".to_owned()]));
        let _ = std::fs::remove_dir_all(&home);
    }

    fn followed(name: &str, rc: &str, files: &[(&str, &str)], max_chars: usize, limits: &Limits) -> (bool, Vec<String>) {
        let home = folder(name);
        for (file, text) in files {
            let path = format!("{home}/{file}");
            std::fs::create_dir_all(std::path::Path::new(&path).parent().expect("parent")).expect("folders");
            std::fs::write(path, text).expect("file");
        }
        let mut scan = Scan::default();
        scan_text(rc, &mut scan);
        let complete = follow(&home, &mut scan, &[], max_chars, limits, &none);
        let _ = std::fs::remove_dir_all(&home);
        (complete, scan.values.into_iter().map(|(_, value)| value).collect())
    }

    const ROOMY: Limits = Limits { files: 10, bytes: 10_000 };

    #[test]
    fn nested_files_are_read_once_each_and_their_values_collected() {
        let files = [("a", "export X=firstvalue1\nsource ~/b\n"), ("b", "export Y=secondvalue2\nsource ~/a\n")];
        let (complete, values) = followed("nest", "source ~/a\nsource ~/a\n", &files, 4096, &ROOMY);
        assert!(complete);
        assert_eq!(values.iter().filter(|value| value.as_str() == "firstvalue1").count(), 1);
        assert!(values.iter().any(|value| value == "secondvalue2"));
    }

    #[test]
    fn globs_and_loop_variables_are_followed() {
        let files = [("d/a.sh", "export A=globvalue-a\n"), ("d/b.sh", "export B=globvalue-b\n"), ("c/one", "export C=loopvalue-c\n")];
        let rc = "for f in ~/d/*.sh; do source \"$f\"; done\nfor n in one two; do [ -r ~/c/$n ] && . ~/c/$n; done\n";
        let (complete, values) = followed("loops", rc, &files, 4096, &ROOMY);
        assert!(complete);
        for wanted in ["globvalue-a", "globvalue-b", "loopvalue-c"] {
            assert!(values.iter().any(|value| value == wanted), "{wanted}");
        }
        assert!(!followed("glob-cap", "source ~/d/*.sh\n", &files, 4096, &Limits { files: 1, bytes: 10_000 }).0);
    }

    #[test]
    fn a_sourced_file_is_protected_completely_even_when_it_defines_functions() {
        let program = "f() { :; }\nPROMPT_PART='|MERGING'\nWORDS='some option text here'\nPLAIN=hunter2x\n";
        let (_, values) = followed("program", "source ~/p\n", &[("p", program)], 4096, &ROOMY);
        for wanted in ["|MERGING", "some option text here", "hunter2x"] {
            assert!(values.iter().any(|value| value == wanted), "{wanted}");
        }
    }

    #[test]
    fn too_many_files_too_many_bytes_or_a_truncated_file_stop_the_reading() {
        let files = [("a", "# aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"), ("b", "# b\n"), ("c", "# c\n")];
        let rc = "source ~/a\nsource ~/b\nsource ~/c\n";
        assert!(followed("count-ok", rc, &files, 4096, &Limits { files: 3, bytes: 10_000 }).0);
        assert!(!followed("count", rc, &files, 4096, &Limits { files: 2, bytes: 10_000 }).0);
        let total: usize = files.iter().map(|(_, text)| text.len()).sum();
        assert!(followed("bytes-ok", rc, &files, 4096, &Limits { files: 10, bytes: total }).0);
        assert!(!followed("bytes", rc, &files, 4096, &Limits { files: 10, bytes: total - 1 }).0);
        assert!(!followed("lines", "source ~/a\n", &[("a", "aaaaaaaaaaaaaaa\nbbbb\n")], 10, &ROOMY).0);
    }
}
