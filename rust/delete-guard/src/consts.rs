use std::collections::{HashSet, BTreeSet};
use std::sync::LazyLock;

use regex::{Captures, Regex};
use serde_json::{json, Value};

pub use crate::budget::HOOK_BUDGET_SECONDS;

pub const TOOL_NAME: &str = "delete-guard";
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_TRASH_SCAN: usize = 20000;
pub const MAX_MATCHES: usize = 20000;
pub const MATCH_MARK: &str = "\u{e000}match\u{e001}";
pub const GLOB_VISITS: usize = 200000;
pub const MAX_SCRIPT_BYTES: usize = 256 * 1024;
pub const MAX_SCRIPT_DEPTH: usize = 3;

const QUICK_SCAN_SRC: &str = r"\b(rm|rmtree|removedirs|rmSync|rmdirSync|remove_dir_all|rm_rf|find|xargs|trash|gio|diskutil|dd|mkfs|newfs|shred|srm|rsync|clean|unlink|rmdir|mv)\b|\b(?:mkfs|newfs)[._]|\b(?:ktrash|kioclient)\d*\b|\b(?:hadoop|hdfs|osascript|powershell|pwsh|cmd\.exe)\b|(?i:clear-recyclebin)";
const ERASE_TOOL_SRC: &str = r"(?:mkfs|newfs|shred|srm)(?:[._].*)?";
const TRASH_FOLDER_SRC: &str = r"(?i:\.Trash(?:es|-\d+)?|\$Recycle\.Bin|#recycle|@Recycle|files_trashbin)|RECYCLER|RECYCLED|Recycled|\.recycle|\.FilesByGoogleTrash|\.trashed-.+";
const TRASH_URI_SRC: &str = r"(?i)trash:";
const TRASH_EMPTY_TOOL_SRC: &str = r"trash-(?:empty|rm)\d*";
const KDE_TRASH_TOOL_SRC: &str = r"ktrash\d*";
const KIO_TOOL_SRC: &str = r"kioclient\d*";
const TRASH_FILE_NAME_SRC: &str = r"\.trashed-.+";
const LOCATION_SCHEME_SRC: &str = r"(?i)[a-z][a-z0-9+.-]*:/";
const FIND_NEWER_PREDICATE_SRC: &str = r"-newer[aBcmt][aBcmt]";
const FINDER_TEXT_SRC: &str = r"(?i)(?:trash|\bempty\b)";
const WINDOWS_TEXT_SRC: &str = r"(?i)recycle";
const REMOTE_UNSAFE_PATH_SRC: &str = r#"[$`\\*?\[\]{}!;&|<>()'"\s\x00-\x1f]"#;
const REMOTE_UNSAFE_AFTER_QUOTES_SRC: &str = r#"[$`\\;&|<>'"\s\x00-\x1f]"#;
const REMOTE_COMMAND_PATTERN_SRC: &str = r"ssh[_-].+";
const VETTED_MENTION_SRC: &str = r#"delete-guard["']?[\s\x1c-\x1f]+(?:check-remote|remote-preflight)"#;
const QUOTED_TILDE_SRC: &str = r#"(?:^|[\s\x1c-\x1f;&|(])(?:(?:['"]+|\\)~|~['"\\])"#;
const FUNCTION_HEADER_SRC: &str = r"(?:function[ \t]+)?[A-Za-z_][\p{L}\p{N}_.:-]*[ \t]*(?:\([ \t]*\)[ \t]*)?\{?";
const TEXT_HEREDOC_OWNER_SRC: &str = r#"[ \t]*cat\b[^|;&<(`$\"'\\\n]*"#;
const TEXT_HEREDOC_TAIL_SRC: &str = r#"[|`]|\$\(|[<>]\("#;
const SHELL_SHEBANG_SRC: &str = r"#![\s\x1c-\x1f]*[^\s\x1c-\x1f]*(?:/env[\s\x1c-\x1f]+)?(?:ba|z|da|k)?sh\b";
const DISKUTIL_ERASE_SRC: &str = r"(?i)^(erase|zero|secureerase|partitiondisk|reformat|deletevolume|deletecontainer|apfs)";
const INLINE_SIMPLE_SRC: &str = r"rmtree|removedirs|rmSync|rmdirSync|remove_dir_all|rm_rf|rm[\s\x1c-\x1f]+-[a-zA-Z]*[rR]";
const SCRIPT_HINT_SRC: &str = r#"/|\.sh\b|(?:^|[\s\x1c-\x1f;&|(])[\\'"]?(?:source|\.|bash|sh|zsh|dash|ksh|fish|ssh|mosh|exec|env|timeout|sudo|nice|nohup|time|command|xargs|ssh[_-][\p{L}\p{N}_-]+)[\\'"]?(?:([\s\x1c-\x1f;&|)])|\z)"#;

pub static QUICK_SCAN: LazyLock<Regex> = LazyLock::new(|| compile(QUICK_SCAN_SRC));
pub static ERASE_TOOL: LazyLock<Regex> = LazyLock::new(|| compile(ERASE_TOOL_SRC));
pub static TRASH_FOLDER: LazyLock<Regex> = LazyLock::new(|| compile(TRASH_FOLDER_SRC));
pub static TRASH_URI: LazyLock<Regex> = LazyLock::new(|| compile(TRASH_URI_SRC));
pub static TRASH_EMPTY_TOOL: LazyLock<Regex> = LazyLock::new(|| compile(TRASH_EMPTY_TOOL_SRC));
pub static KDE_TRASH_TOOL: LazyLock<Regex> = LazyLock::new(|| compile(KDE_TRASH_TOOL_SRC));
pub static KIO_TOOL: LazyLock<Regex> = LazyLock::new(|| compile(KIO_TOOL_SRC));
pub static TRASH_FILE_NAME: LazyLock<Regex> = LazyLock::new(|| compile(TRASH_FILE_NAME_SRC));
pub static LOCATION_SCHEME: LazyLock<Regex> = LazyLock::new(|| compile(LOCATION_SCHEME_SRC));
pub static FIND_NEWER_PREDICATE: LazyLock<Regex> = LazyLock::new(|| compile(FIND_NEWER_PREDICATE_SRC));
pub static FINDER_TEXT: LazyLock<Regex> = LazyLock::new(|| compile(FINDER_TEXT_SRC));
pub static WINDOWS_TEXT: LazyLock<Regex> = LazyLock::new(|| compile(WINDOWS_TEXT_SRC));
pub static REMOTE_UNSAFE_PATH: LazyLock<Regex> = LazyLock::new(|| compile(REMOTE_UNSAFE_PATH_SRC));
pub static REMOTE_UNSAFE_AFTER_QUOTES: LazyLock<Regex> = LazyLock::new(|| compile(REMOTE_UNSAFE_AFTER_QUOTES_SRC));
pub static REMOTE_COMMAND_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(REMOTE_COMMAND_PATTERN_SRC));
pub static VETTED_MENTION: LazyLock<Regex> = LazyLock::new(|| compile(VETTED_MENTION_SRC));
pub static QUOTED_TILDE: LazyLock<Regex> = LazyLock::new(|| compile(QUOTED_TILDE_SRC));
pub static FUNCTION_HEADER: LazyLock<Regex> = LazyLock::new(|| compile(FUNCTION_HEADER_SRC));
pub static TEXT_HEREDOC_OWNER: LazyLock<Regex> = LazyLock::new(|| compile(TEXT_HEREDOC_OWNER_SRC));
pub static TEXT_HEREDOC_TAIL: LazyLock<Regex> = LazyLock::new(|| compile(TEXT_HEREDOC_TAIL_SRC));
pub static SHELL_SHEBANG: LazyLock<Regex> = LazyLock::new(|| compile(SHELL_SHEBANG_SRC));
pub static DISKUTIL_ERASE: LazyLock<Regex> = LazyLock::new(|| compile(DISKUTIL_ERASE_SRC));

static QUICK_SCAN_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(QUICK_SCAN_SRC));
static ERASE_TOOL_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(ERASE_TOOL_SRC));
static TRASH_FOLDER_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(TRASH_FOLDER_SRC));
static TRASH_URI_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(TRASH_URI_SRC));
static TRASH_EMPTY_TOOL_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(TRASH_EMPTY_TOOL_SRC));
static KDE_TRASH_TOOL_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(KDE_TRASH_TOOL_SRC));
static KIO_TOOL_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(KIO_TOOL_SRC));
static TRASH_FILE_NAME_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(TRASH_FILE_NAME_SRC));
static LOCATION_SCHEME_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(LOCATION_SCHEME_SRC));
static FIND_NEWER_PREDICATE_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(FIND_NEWER_PREDICATE_SRC));
static FINDER_TEXT_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(FINDER_TEXT_SRC));
static WINDOWS_TEXT_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(WINDOWS_TEXT_SRC));
static REMOTE_UNSAFE_PATH_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(REMOTE_UNSAFE_PATH_SRC));
static REMOTE_UNSAFE_AFTER_QUOTES_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(REMOTE_UNSAFE_AFTER_QUOTES_SRC));
static REMOTE_COMMAND_PATTERN_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(REMOTE_COMMAND_PATTERN_SRC));
static VETTED_MENTION_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(VETTED_MENTION_SRC));
static QUOTED_TILDE_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(QUOTED_TILDE_SRC));
static FUNCTION_HEADER_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(FUNCTION_HEADER_SRC));
static TEXT_HEREDOC_OWNER_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(TEXT_HEREDOC_OWNER_SRC));
static TEXT_HEREDOC_TAIL_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(TEXT_HEREDOC_TAIL_SRC));
static SHELL_SHEBANG_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(SHELL_SHEBANG_SRC));
static DISKUTIL_ERASE_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(DISKUTIL_ERASE_SRC));
static INLINE_SIMPLE: LazyLock<Regex> = LazyLock::new(|| compile(INLINE_SIMPLE_SRC));
static INLINE_SIMPLE_FULL: LazyLock<Regex> = LazyLock::new(|| compile_full(INLINE_SIMPLE_SRC));
static SCRIPT_HINT_RE: LazyLock<Regex> = LazyLock::new(|| compile(SCRIPT_HINT_SRC));
static TRASH_HOME_SLASH: LazyLock<Regex> = LazyLock::new(|| compile(r"(?:\A|/)\.local/share/Trash/"));
static TRASH_HOME_END: LazyLock<Regex> = LazyLock::new(|| compile(r"(?:\A|/)\.local/share/Trash"));

fn compile(pattern: &str) -> Regex {
    match Regex::new(pattern) {
        Ok(regex) => regex,
        Err(error) => panic!("regex failed to compile: {error}"),
    }
}

fn compile_full(pattern: &str) -> Regex {
    compile(&format!(r"\A(?:{pattern})\z"))
}

fn char_span(text: &str, start_byte: usize, end_byte: usize) -> (usize, usize) {
    let start = match text.get(..start_byte) {
        Some(prefix) => prefix.chars().count(),
        None => 0,
    };
    let end = match text.get(..end_byte) {
        Some(prefix) => prefix.chars().count(),
        None => start,
    };
    (start, end)
}

fn search_span(regex: &Regex, text: &str) -> Option<(usize, usize)> {
    regex.find(text).map(|found| char_span(text, found.start(), found.end()))
}

fn match_span(regex: &Regex, text: &str) -> Option<(usize, usize)> {
    let found = regex.find(text)?;
    if found.start() != 0 {
        return None;
    }
    Some(char_span(text, found.start(), found.end()))
}

fn full_span(regex: &Regex, text: &str) -> Option<(usize, usize)> {
    let found = regex.find(text)?;
    if found.start() == 0 && found.end() == text.len() {
        Some(char_span(text, 0, found.end()))
    } else {
        None
    }
}

fn py_space(ch: char) -> bool {
    ch.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&ch)
}

fn py_word(ch: char) -> bool {
    ch == '_' || ch.is_alphanumeric()
}

fn next_byte(text: &str, index: usize) -> usize {
    match text.get(index..) {
        Some(rest) => match rest.chars().next() {
            Some(ch) => index.saturating_add(ch.len_utf8()),
            None => index,
        },
        None => index,
    }
}

fn prev_char(text: &str, index: usize) -> Option<char> {
    text.get(..index)?.chars().next_back()
}

fn skip_space(text: &str, mut index: usize) -> usize {
    while let Some(ch) = text.get(index..).and_then(|rest| rest.chars().next()) {
        if !py_space(ch) {
            break;
        }
        index = index.saturating_add(ch.len_utf8());
    }
    index
}

fn advance_chars(text: &str, start: usize, count: usize) -> usize {
    let Some(rest) = text.get(start..) else {
        return start;
    };
    let mut seen = 0usize;
    for (offset, _) in rest.char_indices() {
        if seen == count {
            return start.saturating_add(offset);
        }
        seen = seen.saturating_add(1);
    }
    text.len()
}

fn boundary_before_word(text: &str, index: usize) -> bool {
    let Some(current) = text.get(index..).and_then(|rest| rest.chars().next()) else {
        return false;
    };
    if !py_word(current) {
        return false;
    }
    match prev_char(text, index) {
        None => true,
        Some(ch) => !py_word(ch),
    }
}

fn boundary_after_word(text: &str, index: usize) -> bool {
    match text.get(index..).and_then(|rest| rest.chars().next()) {
        None => true,
        Some(ch) => !py_word(ch),
    }
}

fn forbidden_after(text: &str, start: usize) -> bool {
    let index = skip_space(text, start);
    for word in ["false", "0", "null", "undefined"] {
        let Some(rest) = text.get(index..) else {
            continue;
        };
        if rest.starts_with(word) && boundary_after_word(text, index.saturating_add(word.len())) {
            return true;
        }
    }
    false
}

fn rm_call_at(text: &str, start: usize) -> Option<usize> {
    let rest = text.get(start..)?;
    if !rest.starts_with(".rm") {
        return None;
    }
    let mut index = start.saturating_add(3);
    index = skip_space(text, index);
    let after_space = text.get(index..)?;
    if !after_space.starts_with('(') {
        return None;
    }
    let body = index.saturating_add(1);
    let limit = advance_chars(text, body, 1500);
    let mut scan = body;
    while scan <= limit && scan < text.len() {
        if text.get(scan..).is_some_and(|piece| piece.starts_with("recursive"))
            && scan <= limit
            && boundary_before_word(text, scan)
        {
            let after_word = scan.saturating_add("recursive".len());
            let colon = skip_space(text, after_word);
            if text.get(colon..).is_some_and(|piece| piece.starts_with(':')) {
                let end = colon.saturating_add(1);
                if !forbidden_after(text, end) {
                    return Some(end);
                }
            }
        }
        let stepped = next_byte(text, scan);
        if stepped == scan {
            break;
        }
        scan = stepped;
    }
    None
}

fn inline_raw(text: &str, anchored: bool) -> Option<(usize, usize)> {
    let simple = INLINE_SIMPLE.find(text).map(|found| (found.start(), found.end()));
    let mut custom = None;
    if anchored {
        if let Some(end) = rm_call_at(text, 0) {
            custom = Some((0usize, end));
        }
    } else {
        let mut index = 0usize;
        while index < text.len() {
            if let Some(end) = rm_call_at(text, index) {
                custom = Some((index, end));
                break;
            }
            let stepped = next_byte(text, index);
            if stepped == index {
                break;
            }
            index = stepped;
        }
    }
    let chosen = match (simple, custom) {
        (Some(left), Some(right)) => {
            if anchored {
                match (left.0 == 0, right.0 == 0) {
                    (true, _) => Some(left),
                    (false, true) => Some(right),
                    (false, false) => None,
                }
            } else if left.0 <= right.0 {
                Some(left)
            } else {
                Some(right)
            }
        }
        (Some(left), None) => {
            if anchored && left.0 != 0 {
                None
            } else {
                Some(left)
            }
        }
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }?;
    Some(char_span(text, chosen.0, chosen.1))
}

pub fn inline_recursive_delete_search(text: &str) -> Option<(usize, usize)> {
    inline_raw(text, false)
}

pub fn inline_recursive_delete_match(text: &str) -> Option<(usize, usize)> {
    inline_raw(text, true)
}

pub fn inline_recursive_delete_fullmatch(text: &str) -> Option<(usize, usize)> {
    if INLINE_SIMPLE_FULL.is_match(text) {
        return Some((0, text.chars().count()));
    }
    let end = rm_call_at(text, 0)?;
    if end == text.len() {
        Some((0, text.chars().count()))
    } else {
        None
    }
}

fn trash_home_bytes(text: &str) -> Option<(usize, usize)> {
    let slash = TRASH_HOME_SLASH.find(text).map(|found| (found.start(), found.end()));
    let mut ended = None;
    for found in TRASH_HOME_END.find_iter(text) {
        let rest = text.get(found.end()..).unwrap_or("");
        if rest.is_empty() || rest == "\n" {
            ended = Some((found.start(), found.end()));
            break;
        }
    }
    match (slash, ended) {
        (Some(left), Some(right)) => Some(if left.0 <= right.0 { left } else { right }),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

pub fn trash_home_folder_search(text: &str) -> Option<(usize, usize)> {
    trash_home_bytes(text).map(|(start, end)| char_span(text, start, end))
}

pub fn trash_home_folder_match(text: &str) -> Option<(usize, usize)> {
    let (start, end) = trash_home_bytes(text)?;
    if start != 0 {
        return None;
    }
    Some(char_span(text, start, end))
}

pub fn trash_home_folder_fullmatch(text: &str) -> Option<(usize, usize)> {
    let (start, end) = trash_home_bytes(text)?;
    if start == 0 && end == text.len() {
        Some(char_span(text, start, end))
    } else {
        None
    }
}

fn script_hint_from(text: &str, found: &Captures<'_>) -> Option<(usize, usize)> {
    let whole = found.get(0)?;
    let end_byte = match found.get(1) {
        Some(group) => group.start(),
        None => whole.end(),
    };
    Some(char_span(text, whole.start(), end_byte))
}

pub fn script_hint_search(text: &str) -> Option<(usize, usize)> {
    script_hint_from(text, &SCRIPT_HINT_RE.captures(text)?)
}

pub fn script_hint_match(text: &str) -> Option<(usize, usize)> {
    let found = SCRIPT_HINT_RE.captures(text)?;
    let whole = found.get(0)?;
    if whole.start() != 0 {
        return None;
    }
    script_hint_from(text, &found)
}

pub fn script_hint_fullmatch(text: &str) -> Option<(usize, usize)> {
    let span = script_hint_match(text)?;
    if span.0 == 0 && span.1 == text.chars().count() {
        Some(span)
    } else {
        None
    }
}

pub fn git_path() -> Option<&'static str> {
    static CACHE: LazyLock<Option<String>> = LazyLock::new(|| guard_common::env::find_executable("git"));
    CACHE.as_deref()
}

pub fn temp_roots() -> &'static [String] {
    static CACHE: LazyLock<Vec<String>> = LazyLock::new(|| {
        let mut paths = Vec::new();
        for path in ["/tmp", "/private/tmp", "/var/tmp", "/var/folders", "/private/var/folders"] {
            paths.push(guard_common::sys::realpath(path));
        }
        let tmpdir = match std::env::var_os("TMPDIR") {
            Some(value) => value.to_string_lossy().into_owned(),
            None => "/tmp".to_string(),
        };
        paths.push(guard_common::sys::realpath(&tmpdir));
        paths
    });
    CACHE.as_slice()
}

pub fn etc_paths() -> &'static [String] {
    static CACHE: LazyLock<Vec<String>> = LazyLock::new(|| vec!["/etc".to_string(), guard_common::sys::realpath("/etc")]);
    CACHE.as_slice()
}

pub fn system_root_paths() -> &'static [String] {
    static CACHE: LazyLock<Vec<String>> = LazyLock::new(|| {
        let mut paths = BTreeSet::new();
        for path in SYSTEM_ROOTS {
            paths.insert((*path).to_string());
            paths.insert(guard_common::sys::realpath(path));
        }
        paths.into_iter().collect()
    });
    CACHE.as_slice()
}

pub fn in_system_root_path(path: &str) -> bool {
    static CACHE: LazyLock<HashSet<String>> = LazyLock::new(|| system_root_paths().iter().cloned().collect());
    CACHE.contains(path)
}
pub static DEFAULT_REMOTE_ROOTS: &[&str] = &[
    "~/ci",
    "/tmp",
];

pub static MOUNT_PARENTS: &[&str] = &[
    "/Volumes",
    "/mnt",
    "/media",
];

pub static RM_LONG_OPTIONS: &[&str] = &[
    "dir",
    "force",
    "help",
    "interactive",
    "no-preserve-root",
    "one-file-system",
    "preserve-root",
    "recursive",
    "verbose",
    "version",
];

pub static SYSTEM_PROGRAM_FOLDERS: &[&str] = &[
    "/bin/",
    "/sbin/",
    "/usr/",
    "/opt/",
    "/Library/",
    "/System/",
    "/Applications/",
];

pub static SYSTEM_ROOTS: &[&str] = &[
    "/",
    "/Applications",
    "/Library",
    "/System",
    "/Users",
    "/Volumes",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/home",
    "/lib",
    "/lib32",
    "/lib64",
    "/media",
    "/mnt",
    "/opt",
    "/private",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/snap",
    "/srv",
    "/sys",
    "/usr",
    "/var",
];

pub static BASH_SINGLE_DASH_LONG: &[&str] = &[
    "-debugger",
    "-dump-po-strings",
    "-dump-strings",
    "-help",
    "-init-file",
    "-login",
    "-noediting",
    "-nolineediting",
    "-noprofile",
    "-norc",
    "-posix",
    "-pretty-print",
    "-rcfile",
    "-restricted",
    "-verbose",
    "-version",
];

pub static FIND_EXEC_PREDICATES: &[&str] = &[
    "-exec",
    "-execdir",
    "-ok",
    "-okdir",
];

pub static FIND_GLOBAL_OPTIONS: &[&str] = &[
    "-E",
    "-H",
    "-L",
    "-P",
    "-X",
    "-d",
    "-s",
    "-x",
];

pub static FIND_VALUE_PREDICATES: &[&str] = &[
    "-Bnewer",
    "-D",
    "-O",
    "-amin",
    "-anewer",
    "-atime",
    "-cmin",
    "-cnewer",
    "-context",
    "-ctime",
    "-files0-from",
    "-flags",
    "-fls",
    "-fprint",
    "-fprint0",
    "-fprintf",
    "-fstype",
    "-gid",
    "-group",
    "-ilname",
    "-iname",
    "-inum",
    "-ipath",
    "-iregex",
    "-iwholename",
    "-links",
    "-lname",
    "-maxdepth",
    "-mindepth",
    "-mmin",
    "-mtime",
    "-name",
    "-newer",
    "-path",
    "-perm",
    "-printf",
    "-regex",
    "-regextype",
    "-samefile",
    "-size",
    "-type",
    "-uid",
    "-used",
    "-user",
    "-wholename",
    "-xattrname",
    "-xtype",
];

pub static GIO_DELETE_VERBS: &[&str] = &[
    "remove",
    "rm",
    "trash",
];

pub static HADOOP_PURGE_OPTIONS: &[&str] = &[
    "-expunge",
    "-skipTrash",
];

pub static HOOK_EVENTS: &[&str] = &[
    "PostToolUse",
    "PreToolUse",
    "SessionStart",
];

pub static INTERPRETERS: &[&str] = &[
    "bun",
    "deno",
    "node",
    "osascript",
    "perl",
    "python",
    "python3",
    "ruby",
    "swift",
];

pub static KIO_COMMANDS: &[&str] = &[
    "cat",
    "copy",
    "cp",
    "del",
    "delete",
    "exec",
    "ls",
    "move",
    "mv",
    "openProperties",
    "properties",
    "remove",
    "rm",
];

pub static KIO_REMOVE_VERBS: &[&str] = &[
    "del",
    "delete",
    "remove",
    "rm",
];

pub static MOSH_LONG_FLAGS: &[&str] = &[
    "--help",
    "--local",
    "--no-init",
    "--no-ssh-pty",
    "--predict-overwrite",
    "--verbose",
    "--version",
];

pub static MOSH_LONG_VALUES: &[&str] = &[
    "--bind-server",
    "--client",
    "--experimental-remote-ip",
    "--family",
    "--port",
    "--predict",
    "--server",
    "--ssh",
];

pub static REMOTE_COMMAND_NAMES: &[&str] = &[
    "mosh",
    "ssh",
];

pub static REMOTE_HOME_PARENTS: &[&str] = &[
    "/Users",
    "/home",
];

pub static REMOTE_TRASH_SYSTEM_TREES: &[&str] = &[
    "/Applications",
    "/Library",
    "/System",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/proc",
    "/run",
    "/sbin",
    "/snap",
    "/sys",
    "/usr",
];

pub static RSYNC_VALUE_OPTIONS: &[&str] = &[
    "--address",
    "--backup-dir",
    "--block-size",
    "--bwlimit",
    "--cc",
    "--checksum-choice",
    "--checksum-seed",
    "--chmod",
    "--chown",
    "--compare-dest",
    "--contimeout",
    "--copy-as",
    "--copy-dest",
    "--debug",
    "--early-input",
    "--exclude",
    "--exclude-from",
    "--files-from",
    "--filter",
    "--groupmap",
    "--iconv",
    "--include",
    "--include-from",
    "--info",
    "--link-dest",
    "--log-file",
    "--log-file-format",
    "--max-alloc",
    "--max-size",
    "--min-size",
    "--modify-window",
    "--only-write-batch",
    "--out-format",
    "--outbuf",
    "--partial-dir",
    "--password-file",
    "--port",
    "--protocol",
    "--read-batch",
    "--remote-option",
    "--rsh",
    "--rsync-path",
    "--sockopts",
    "--stop-after",
    "--stop-at",
    "--suffix",
    "--temp-dir",
    "--timeout",
    "--usermap",
    "--write-batch",
];

pub static SHELLS: &[&str] = &[
    "bash",
    "dash",
    "fish",
    "sh",
    "zsh",
];

pub static SHELL_LONG_WITH_VALUE: &[&str] = &[
    "--command",
    "--emulate",
    "--init-command",
    "--init-file",
    "--rcfile",
    "-init-file",
    "-rcfile",
];

pub static TRASH_TOOLS: &[&str] = &[
    "gvfs-trash",
    "trash",
    "trash-put",
];

pub static TRASH_VALUE_OPTIONS: &[&str] = &[
    "--trash-dir",
];

pub static VETTED_COMMANDS: &[&str] = &[
    "check-remote",
    "remote-preflight",
];

pub static WINDOWS_SHELLS: &[&str] = &[
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
];

pub static XARGS_DELETERS: &[&str] = &[
    "gvfs-rm",
    "rm",
    "rmdir",
    "shred",
    "srm",
    "unlink",
];

pub static MOSH_FLAG_LETTERS: &[&str] = &["4", "6", "a", "n"];

pub static MOSH_VALUE_LETTERS: &[&str] = &["p"];

pub static RELAXED_CHARACTERS: &[&str] = &["!", "(", ")", "*", "?", "[", "]", "{", "}"];

pub static RSYNC_VALUE_LETTERS: &[&str] = &["@", "B", "M", "T", "e", "f"];

pub static SSH_FLAG_LETTERS: &[&str] = &["4", "6", "A", "C", "G", "K", "M", "N", "T", "V", "X", "Y", "a", "f", "g", "k", "n", "q", "s", "t", "v", "x", "y"];

pub static SSH_VALUE_LETTERS: &[&str] = &["B", "D", "E", "F", "I", "J", "L", "O", "P", "Q", "R", "S", "W", "b", "c", "e", "i", "l", "m", "o", "p", "w"];

pub static XARGS_SHORT_VALUES: &[&str] = &["E", "I", "J", "L", "P", "R", "S", "a", "d", "n", "s"];

pub static POSIX_CLASSES: &[(&str, &str)] = &[
    ("alnum", "a-zA-Z0-9\\x80-\\U0010ffff"),
    ("alpha", "a-zA-Z\\x80-\\U0010ffff"),
    ("blank", " \\t\\x80-\\U0010ffff"),
    ("cntrl", "\\x00-\\x1f\\x7f-\\U0010ffff"),
    ("digit", "0-9"),
    ("graph", "!-~\\x80-\\U0010ffff"),
    ("lower", "a-z\\x80-\\U0010ffff"),
    ("print", " -~\\x80-\\U0010ffff"),
    ("punct", "!-/:-@\\[-`{-~\\x80-\\U0010ffff"),
    ("space", " \\t\\n\\r\\f\\v\\x80-\\U0010ffff"),
    ("upper", "A-Z\\x80-\\U0010ffff"),
    ("word", "a-zA-Z0-9_\\x80-\\U0010ffff"),
    ("xdigit", "0-9A-Fa-f"),
];

pub static POSIX_CLASSES_ASCII: &[(&str, &str)] = &[
    ("alnum", "a-zA-Z0-9"),
    ("alpha", "a-zA-Z"),
    ("blank", " \\t"),
    ("cntrl", "\\x00-\\x1f\\x7f"),
    ("digit", "0-9"),
    ("graph", "!-~"),
    ("lower", "a-z"),
    ("print", " -~"),
    ("punct", "!-/:-@\\[-`{-~"),
    ("space", " \\t\\n\\r\\f\\v"),
    ("upper", "A-Z"),
    ("word", "a-zA-Z0-9_"),
    ("xdigit", "0-9A-Fa-f"),
];

pub static STDIN_OPERATORS: &[&str] = &[
    "<>",
    "<",
];

pub static XARGS_LONG_OPTIONS: &[(&str, &str)] = &[
    ("arg-file", "required"),
    ("delimiter", "required"),
    ("max-args", "required"),
    ("max-chars", "required"),
    ("max-procs", "required"),
    ("process-slot-var", "required"),
    ("eof", "optional"),
    ("replace", "optional"),
    ("max-lines", "optional"),
    ("null", "none"),
    ("no-run-if-empty", "none"),
    ("interactive", "none"),
    ("open-tty", "none"),
    ("verbose", "none"),
    ("exit", "none"),
    ("show-limits", "none"),
    ("help", "none"),
    ("version", "none"),
];

pub fn in_system_roots(path: &str) -> bool {
    SYSTEM_ROOTS.contains(&path)
}

pub fn in_find_value_predicates(word: &str) -> bool {
    static SET: LazyLock<HashSet<&str>> = LazyLock::new(|| FIND_VALUE_PREDICATES.iter().copied().collect());
    SET.contains(word)
}

pub fn in_bash_single_dash_long(word: &str) -> bool {
    static SET: LazyLock<HashSet<&str>> = LazyLock::new(|| BASH_SINGLE_DASH_LONG.iter().copied().collect());
    SET.contains(word)
}

pub fn posix_class(name: &str) -> Option<&'static str> {
    POSIX_CLASSES.iter().find(|(key, _)| *key == name).map(|(_, value)| *value)
}

pub fn posix_class_ascii(name: &str) -> Option<&'static str> {
    POSIX_CLASSES_ASCII.iter().find(|(key, _)| *key == name).map(|(_, value)| *value)
}

pub fn xargs_long_option(name: &str) -> Option<&'static str> {
    XARGS_LONG_OPTIONS.iter().find(|(key, _)| *key == name).map(|(_, value)| *value)
}

fn sorted_strings(values: &[&str]) -> Value {
    let mut owned: Vec<&str> = values.to_vec();
    owned.sort_unstable();
    json!(owned)
}

fn sorted_pairs(values: &[(&str, &str)]) -> Value {
    let mut owned = values.to_vec();
    owned.sort_unstable();
    json!(owned)
}

fn sorted_owned(values: &[String]) -> Value {
    let mut owned = values.to_vec();
    owned.sort_unstable();
    json!(owned)
}

pub fn constant_value(name: &str) -> Option<Value> {
    let value = match name {
        "TOOL_NAME" => json!(TOOL_NAME),
        "GIT_PATH" => match git_path() {
            Some(path) => json!(path),
            None => Value::Null,
        },
        "MAX_INPUT_BYTES" => json!(MAX_INPUT_BYTES),
        "MAX_TRASH_SCAN" => json!(MAX_TRASH_SCAN),
        "MAX_MATCHES" => json!(MAX_MATCHES),
        "MATCH_MARK" => json!(MATCH_MARK),
        "GLOB_VISITS" => json!(GLOB_VISITS),
        "HOOK_BUDGET_SECONDS" => json!(HOOK_BUDGET_SECONDS),
        "MAX_SCRIPT_BYTES" => json!(MAX_SCRIPT_BYTES),
        "MAX_SCRIPT_DEPTH" => json!(MAX_SCRIPT_DEPTH),
        "BASH_SINGLE_DASH_LONG" => sorted_strings(BASH_SINGLE_DASH_LONG),
        "DEFAULT_REMOTE_ROOTS" => sorted_strings(DEFAULT_REMOTE_ROOTS),
        "ETC_PATHS" => sorted_owned(etc_paths()),
        "FIND_EXEC_PREDICATES" => sorted_strings(FIND_EXEC_PREDICATES),
        "FIND_GLOBAL_OPTIONS" => sorted_strings(FIND_GLOBAL_OPTIONS),
        "FIND_VALUE_PREDICATES" => sorted_strings(FIND_VALUE_PREDICATES),
        "GIO_DELETE_VERBS" => sorted_strings(GIO_DELETE_VERBS),
        "HADOOP_PURGE_OPTIONS" => sorted_strings(HADOOP_PURGE_OPTIONS),
        "HOOK_EVENTS" => sorted_strings(HOOK_EVENTS),
        "INTERPRETERS" => sorted_strings(INTERPRETERS),
        "KIO_COMMANDS" => sorted_strings(KIO_COMMANDS),
        "KIO_REMOVE_VERBS" => sorted_strings(KIO_REMOVE_VERBS),
        "MOSH_FLAG_LETTERS" => sorted_strings(MOSH_FLAG_LETTERS),
        "MOSH_LONG_FLAGS" => sorted_strings(MOSH_LONG_FLAGS),
        "MOSH_LONG_VALUES" => sorted_strings(MOSH_LONG_VALUES),
        "MOSH_VALUE_LETTERS" => sorted_strings(MOSH_VALUE_LETTERS),
        "MOUNT_PARENTS" => sorted_strings(MOUNT_PARENTS),
        "POSIX_CLASSES" => sorted_pairs(POSIX_CLASSES),
        "POSIX_CLASSES_ASCII" => sorted_pairs(POSIX_CLASSES_ASCII),
        "RELAXED_CHARACTERS" => sorted_strings(RELAXED_CHARACTERS),
        "REMOTE_COMMAND_NAMES" => sorted_strings(REMOTE_COMMAND_NAMES),
        "REMOTE_HOME_PARENTS" => sorted_strings(REMOTE_HOME_PARENTS),
        "REMOTE_TRASH_SYSTEM_TREES" => sorted_strings(REMOTE_TRASH_SYSTEM_TREES),
        "RM_LONG_OPTIONS" => sorted_strings(RM_LONG_OPTIONS),
        "RSYNC_VALUE_LETTERS" => sorted_strings(RSYNC_VALUE_LETTERS),
        "RSYNC_VALUE_OPTIONS" => sorted_strings(RSYNC_VALUE_OPTIONS),
        "SHELLS" => sorted_strings(SHELLS),
        "SHELL_LONG_WITH_VALUE" => sorted_strings(SHELL_LONG_WITH_VALUE),
        "SSH_FLAG_LETTERS" => sorted_strings(SSH_FLAG_LETTERS),
        "SSH_VALUE_LETTERS" => sorted_strings(SSH_VALUE_LETTERS),
        "STDIN_OPERATORS" => sorted_strings(STDIN_OPERATORS),
        "SYSTEM_PROGRAM_FOLDERS" => sorted_strings(SYSTEM_PROGRAM_FOLDERS),
        "SYSTEM_ROOTS" => sorted_strings(SYSTEM_ROOTS),
        "SYSTEM_ROOT_PATHS" => sorted_owned(system_root_paths()),
        "TEMP_ROOTS" => sorted_owned(temp_roots()),
        "TRASH_TOOLS" => sorted_strings(TRASH_TOOLS),
        "TRASH_VALUE_OPTIONS" => sorted_strings(TRASH_VALUE_OPTIONS),
        "VETTED_COMMANDS" => sorted_strings(VETTED_COMMANDS),
        "WINDOWS_SHELLS" => sorted_strings(WINDOWS_SHELLS),
        "XARGS_DELETERS" => sorted_strings(XARGS_DELETERS),
        "XARGS_LONG_OPTIONS" => sorted_pairs(XARGS_LONG_OPTIONS),
        "XARGS_SHORT_VALUES" => sorted_strings(XARGS_SHORT_VALUES),
        _ => return None,
    };
    Some(value)
}

pub fn replay_regex(name: &str, method: &str, text: &str) -> Option<Option<(usize, usize)>> {
    let found = match (name, method) {
        ("QUICK_SCAN", "search") => search_span(&QUICK_SCAN, text),
        ("QUICK_SCAN", "match") => match_span(&QUICK_SCAN, text),
        ("QUICK_SCAN", "fullmatch") => full_span(&QUICK_SCAN_FULL, text),
        ("ERASE_TOOL", "search") => search_span(&ERASE_TOOL, text),
        ("ERASE_TOOL", "match") => match_span(&ERASE_TOOL, text),
        ("ERASE_TOOL", "fullmatch") => full_span(&ERASE_TOOL_FULL, text),
        ("TRASH_FOLDER", "search") => search_span(&TRASH_FOLDER, text),
        ("TRASH_FOLDER", "match") => match_span(&TRASH_FOLDER, text),
        ("TRASH_FOLDER", "fullmatch") => full_span(&TRASH_FOLDER_FULL, text),
        ("TRASH_URI", "search") => search_span(&TRASH_URI, text),
        ("TRASH_URI", "match") => match_span(&TRASH_URI, text),
        ("TRASH_URI", "fullmatch") => full_span(&TRASH_URI_FULL, text),
        ("TRASH_EMPTY_TOOL", "search") => search_span(&TRASH_EMPTY_TOOL, text),
        ("TRASH_EMPTY_TOOL", "match") => match_span(&TRASH_EMPTY_TOOL, text),
        ("TRASH_EMPTY_TOOL", "fullmatch") => full_span(&TRASH_EMPTY_TOOL_FULL, text),
        ("KDE_TRASH_TOOL", "search") => search_span(&KDE_TRASH_TOOL, text),
        ("KDE_TRASH_TOOL", "match") => match_span(&KDE_TRASH_TOOL, text),
        ("KDE_TRASH_TOOL", "fullmatch") => full_span(&KDE_TRASH_TOOL_FULL, text),
        ("KIO_TOOL", "search") => search_span(&KIO_TOOL, text),
        ("KIO_TOOL", "match") => match_span(&KIO_TOOL, text),
        ("KIO_TOOL", "fullmatch") => full_span(&KIO_TOOL_FULL, text),
        ("TRASH_FILE_NAME", "search") => search_span(&TRASH_FILE_NAME, text),
        ("TRASH_FILE_NAME", "match") => match_span(&TRASH_FILE_NAME, text),
        ("TRASH_FILE_NAME", "fullmatch") => full_span(&TRASH_FILE_NAME_FULL, text),
        ("LOCATION_SCHEME", "search") => search_span(&LOCATION_SCHEME, text),
        ("LOCATION_SCHEME", "match") => match_span(&LOCATION_SCHEME, text),
        ("LOCATION_SCHEME", "fullmatch") => full_span(&LOCATION_SCHEME_FULL, text),
        ("FIND_NEWER_PREDICATE", "search") => search_span(&FIND_NEWER_PREDICATE, text),
        ("FIND_NEWER_PREDICATE", "match") => match_span(&FIND_NEWER_PREDICATE, text),
        ("FIND_NEWER_PREDICATE", "fullmatch") => full_span(&FIND_NEWER_PREDICATE_FULL, text),
        ("FINDER_TEXT", "search") => search_span(&FINDER_TEXT, text),
        ("FINDER_TEXT", "match") => match_span(&FINDER_TEXT, text),
        ("FINDER_TEXT", "fullmatch") => full_span(&FINDER_TEXT_FULL, text),
        ("WINDOWS_TEXT", "search") => search_span(&WINDOWS_TEXT, text),
        ("WINDOWS_TEXT", "match") => match_span(&WINDOWS_TEXT, text),
        ("WINDOWS_TEXT", "fullmatch") => full_span(&WINDOWS_TEXT_FULL, text),
        ("REMOTE_UNSAFE_PATH", "search") => search_span(&REMOTE_UNSAFE_PATH, text),
        ("REMOTE_UNSAFE_PATH", "match") => match_span(&REMOTE_UNSAFE_PATH, text),
        ("REMOTE_UNSAFE_PATH", "fullmatch") => full_span(&REMOTE_UNSAFE_PATH_FULL, text),
        ("REMOTE_UNSAFE_AFTER_QUOTES", "search") => search_span(&REMOTE_UNSAFE_AFTER_QUOTES, text),
        ("REMOTE_UNSAFE_AFTER_QUOTES", "match") => match_span(&REMOTE_UNSAFE_AFTER_QUOTES, text),
        ("REMOTE_UNSAFE_AFTER_QUOTES", "fullmatch") => full_span(&REMOTE_UNSAFE_AFTER_QUOTES_FULL, text),
        ("REMOTE_COMMAND_PATTERN", "search") => search_span(&REMOTE_COMMAND_PATTERN, text),
        ("REMOTE_COMMAND_PATTERN", "match") => match_span(&REMOTE_COMMAND_PATTERN, text),
        ("REMOTE_COMMAND_PATTERN", "fullmatch") => full_span(&REMOTE_COMMAND_PATTERN_FULL, text),
        ("VETTED_MENTION", "search") => search_span(&VETTED_MENTION, text),
        ("VETTED_MENTION", "match") => match_span(&VETTED_MENTION, text),
        ("VETTED_MENTION", "fullmatch") => full_span(&VETTED_MENTION_FULL, text),
        ("QUOTED_TILDE", "search") => search_span(&QUOTED_TILDE, text),
        ("QUOTED_TILDE", "match") => match_span(&QUOTED_TILDE, text),
        ("QUOTED_TILDE", "fullmatch") => full_span(&QUOTED_TILDE_FULL, text),
        ("FUNCTION_HEADER", "search") => search_span(&FUNCTION_HEADER, text),
        ("FUNCTION_HEADER", "match") => match_span(&FUNCTION_HEADER, text),
        ("FUNCTION_HEADER", "fullmatch") => full_span(&FUNCTION_HEADER_FULL, text),
        ("TEXT_HEREDOC_OWNER", "search") => search_span(&TEXT_HEREDOC_OWNER, text),
        ("TEXT_HEREDOC_OWNER", "match") => match_span(&TEXT_HEREDOC_OWNER, text),
        ("TEXT_HEREDOC_OWNER", "fullmatch") => full_span(&TEXT_HEREDOC_OWNER_FULL, text),
        ("TEXT_HEREDOC_TAIL", "search") => search_span(&TEXT_HEREDOC_TAIL, text),
        ("TEXT_HEREDOC_TAIL", "match") => match_span(&TEXT_HEREDOC_TAIL, text),
        ("TEXT_HEREDOC_TAIL", "fullmatch") => full_span(&TEXT_HEREDOC_TAIL_FULL, text),
        ("SHELL_SHEBANG", "search") => search_span(&SHELL_SHEBANG, text),
        ("SHELL_SHEBANG", "match") => match_span(&SHELL_SHEBANG, text),
        ("SHELL_SHEBANG", "fullmatch") => full_span(&SHELL_SHEBANG_FULL, text),
        ("DISKUTIL_ERASE", "search") => search_span(&DISKUTIL_ERASE, text),
        ("DISKUTIL_ERASE", "match") => match_span(&DISKUTIL_ERASE, text),
        ("DISKUTIL_ERASE", "fullmatch") => full_span(&DISKUTIL_ERASE_FULL, text),
        ("INLINE_RECURSIVE_DELETE", "search") => inline_recursive_delete_search(text),
        ("INLINE_RECURSIVE_DELETE", "match") => inline_recursive_delete_match(text),
        ("INLINE_RECURSIVE_DELETE", "fullmatch") => inline_recursive_delete_fullmatch(text),
        ("TRASH_HOME_FOLDER", "search") => trash_home_folder_search(text),
        ("TRASH_HOME_FOLDER", "match") => trash_home_folder_match(text),
        ("TRASH_HOME_FOLDER", "fullmatch") => trash_home_folder_fullmatch(text),
        ("SCRIPT_HINT", "search") => script_hint_search(text),
        ("SCRIPT_HINT", "match") => script_hint_match(text),
        ("SCRIPT_HINT", "fullmatch") => script_hint_fullmatch(text),
        _ => return None,
    };
    Some(found)
}

#[cfg(test)]
mod tests {
    use super::{
        inline_recursive_delete_fullmatch, inline_recursive_delete_search, script_hint_fullmatch, script_hint_search,
        trash_home_folder_fullmatch, trash_home_folder_match, trash_home_folder_search, DISKUTIL_ERASE, FINDER_TEXT,
        TRASH_FOLDER,
    };

    #[test]
    fn inline_lookahead_rejects_false_and_keeps_a_later_true() {
        assert!(inline_recursive_delete_search("fs.rm(recursive: false)").is_none());
        assert_eq!(inline_recursive_delete_search(".rm(recursive: false, recursive: true)"), Some((0, 32)));
        assert!(inline_recursive_delete_fullmatch("rm -rf").is_none());
        assert_eq!(inline_recursive_delete_search("rm -rf"), Some((0, 5)));
    }

    #[test]
    fn script_hint_does_not_consume_the_trailing_delimiter() {
        assert_eq!(script_hint_search(" ssh "), Some((0, 4)));
        assert!(script_hint_fullmatch(" ssh ").is_none());
        assert_eq!(script_hint_fullmatch(" ssh"), Some((0, 4)));
        assert_eq!(script_hint_search("a/.sh"), Some((1, 2)));
        assert!(script_hint_search("ssh").is_some());
    }

    #[test]
    fn trash_home_dollar_allows_one_trailing_newline_on_search_only() {
        assert_eq!(trash_home_folder_search(".local/share/Trash\n"), Some((0, 18)));
        assert_eq!(trash_home_folder_match(".local/share/Trash\n"), Some((0, 18)));
        assert!(trash_home_folder_fullmatch(".local/share/Trash\n").is_none());
        assert!(trash_home_folder_search(".local/share/Trash\n\n").is_none());
        assert_eq!(trash_home_folder_fullmatch(".local/share/Trash"), Some((0, 18)));
    }

    #[test]
    fn diskutil_and_finder_case_follow_python() {
        assert_eq!(super::match_span(&DISKUTIL_ERASE, "EraseDisk"), Some((0, 5)));
        assert!(super::full_span(&super::DISKUTIL_ERASE_FULL, "apfs").is_some());
        assert!(FINDER_TEXT.is_match("EMPTY"));
        assert!(TRASH_FOLDER.is_match(".trash"));
        assert!(!TRASH_FOLDER.is_match("recycler"));
    }
}
