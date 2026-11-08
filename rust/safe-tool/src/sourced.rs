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
                '`' | '*' | '?' | '[' | '{' | '\0' => return None,
                _ => {
                    out.push(ch);
                    at = at.saturating_add(1);
                }
            }
        }
        Some(out)
    }
}

// The file a `source` operand names, or nothing when the text does not fix it.
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
        let known = (scan.sources.len(), scan.vars.len());
        for raw in todo {
            let path = {
                let scope = Scope { home, vars: &scan.vars, env };
                resolve(&raw, &scope)
            };
            let Some(path) = path else {
                waiting.push(raw);
                continue;
            };
            if !std::fs::metadata(&path).is_ok_and(|found| found.is_file()) || !visited.insert(canonical(&path)) {
                continue;
            }
            files = files.saturating_add(1);
            if files > limits.files {
                return false;
            }
            let Ok((text, how)) = keys::read_text(&path, max_chars) else {
                continue;
            };
            bytes = bytes.saturating_add(text.len());
            if matches!(how, LineRead::Truncated) || bytes > limits.bytes {
                return false;
            }
            startup_values::scan_text(&text, scan);
        }
        if (scan.sources.len(), scan.vars.len()) == known {
            return true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{follow, resolve, Limits, Scope};
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

    fn followed(name: &str, rc: &str, files: &[(&str, &str)], max_chars: usize, limits: &Limits) -> (bool, Vec<String>) {
        let home = std::env::temp_dir().join(format!("sourced-unit-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&home).expect("folder");
        let home = guard_common::sys::realpath(&home.to_string_lossy());
        for (file, text) in files {
            std::fs::write(format!("{home}/{file}"), text).expect("file");
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

    #[test]
    fn paths_the_text_does_not_fix_are_not_resolved() {
        for raw in ["$UNSET/x", "${UNSET}/x", "$(pwd)/x", "`pwd`/x", "~other/x", "/a/*.sh", "/a/?.sh", "/a/{b,c}", "$1/x", "$", "${#HOME}", "${HOME:2}", "${HOME/h/x}", ""] {
            assert_eq!(at(raw, &[]), None, "{raw}");
        }
        assert_eq!(at("$A", &[("A", "$B"), ("B", "$A")]), None);
    }
}
