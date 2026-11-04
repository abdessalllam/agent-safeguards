#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Language {
    pub hash: bool,
    pub slash: bool,
    pub dash: bool,
    pub php: bool,
}

pub const HASH: Language = Language { hash: true, slash: false, dash: false, php: false };
pub const SLASH: Language = Language { hash: false, slash: true, dash: false, php: false };
pub const DASH: Language = Language { hash: false, slash: false, dash: true, php: false };
pub const PHP: Language = Language { hash: true, slash: true, dash: false, php: true };

const HASH_EXTS: &[&str] = &[
    "py", "pyi", "rb", "sh", "bash", "zsh", "fish", "pl", "pm", "r", "ex", "exs", "nim", "cr",
];

const SLASH_EXTS: &[&str] = &[
    "rs", "go", "js", "jsx", "mjs", "cjs", "ts", "tsx", "java", "kt", "kts", "swift", "c", "h", "cc",
    "cpp", "cxx", "hpp", "hh", "cs", "dart", "scala", "groovy", "gradle", "m", "mm", "zig", "proto",
    "sol",
];

const DASH_EXTS: &[&str] = &["lua", "sql", "hs", "elm"];

pub fn language_for(path: &str) -> Option<Language> {
    let name = path.rsplit_once('/').map_or(path, |(_, tail)| tail);
    let name = name.rsplit_once('\\').map_or(name, |(_, tail)| tail);
    let (_, ext) = name.rsplit_once('.')?;
    if ext.is_empty() {
        return None;
    }
    if ext.eq_ignore_ascii_case("php") {
        return Some(PHP);
    }
    if HASH_EXTS.iter().any(|known| ext.eq_ignore_ascii_case(known)) {
        return Some(HASH);
    }
    if SLASH_EXTS.iter().any(|known| ext.eq_ignore_ascii_case(known)) {
        return Some(SLASH);
    }
    if DASH_EXTS.iter().any(|known| ext.eq_ignore_ascii_case(known)) {
        return Some(DASH);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{language_for, PHP, SLASH};

    #[test]
    fn picks_by_extension_ignoring_case_and_folders() {
        assert_eq!(language_for("a/b/C.RS"), Some(SLASH));
        assert_eq!(language_for("x.php"), Some(PHP));
        assert!(language_for("README").is_none());
        assert!(language_for("notes.md").is_none());
        assert!(language_for("a.py.txt").is_none());
        assert!(language_for("dir.py/file").is_none());
        assert!(language_for("win\\path\\x.lua").is_some());
    }
}
