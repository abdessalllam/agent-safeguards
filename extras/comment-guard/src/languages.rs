#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Language {
    pub line: &'static [&'static str],
    pub block: &'static [(&'static str, &'static str)],
    pub column_zero: &'static [(&'static str, &'static str)],
    pub pod: bool,
    pub quotes: &'static str,
    pub triple: &'static [&'static str],
    pub backtick: bool,
    pub docstring: bool,
    pub doc_attributes: bool,
    pub lifetimes: bool,
    pub php: bool,
    pub hash_after_space: bool,
    pub dash_symbols: bool,
    pub nested: bool,
    pub regex: bool,
}

const C_BLOCKS: &[(&str, &str)] = &[("/*", "*/")];
const TEXT_BLOCKS: &[&str] = &["\"\"\""];
const BOTH_BLOCKS: &[&str] = &["\"\"\"", "'''"];

const BASE: Language = Language {
    line: &[],
    block: &[],
    column_zero: &[],
    pod: false,
    quotes: "\"'",
    triple: &[],
    backtick: false,
    docstring: false,
    doc_attributes: false,
    lifetimes: false,
    php: false,
    hash_after_space: false,
    dash_symbols: false,
    nested: false,
    regex: false,
};

pub const HASH: Language = Language { line: &["#"], ..BASE };
pub const SHELL: Language = Language { line: &["#"], hash_after_space: true, ..BASE };
pub const PYTHON: Language = Language { line: &["#"], triple: BOTH_BLOCKS, docstring: true, ..BASE };
pub const RUBY: Language = Language { line: &["#"], column_zero: &[("=begin", "=end")], ..BASE };
pub const PERL: Language = Language { line: &["#"], pod: true, hash_after_space: true, ..BASE };
pub const ELIXIR: Language = Language { line: &["#"], triple: BOTH_BLOCKS, doc_attributes: true, ..BASE };
pub const NIM: Language = Language { line: &["#"], block: &[("#[", "]#")], quotes: "\"", ..BASE };

pub const SLASH: Language = Language { line: &["//"], block: C_BLOCKS, ..BASE };
pub const SCRIPT: Language = Language { line: &["//"], block: C_BLOCKS, backtick: true, regex: true, ..BASE };
pub const GO: Language = Language { line: &["//"], block: C_BLOCKS, backtick: true, ..BASE };
pub const RUST: Language = Language {
    line: &["//"],
    block: C_BLOCKS,
    quotes: "\"",
    lifetimes: true,
    nested: true,
    ..BASE
};
pub const TEXT: Language = Language { line: &["//"], block: C_BLOCKS, triple: TEXT_BLOCKS, ..BASE };
pub const SWIFT: Language = Language {
    line: &["//"],
    block: C_BLOCKS,
    quotes: "\"",
    triple: TEXT_BLOCKS,
    nested: true,
    ..BASE
};
pub const GROOVY: Language = Language { line: &["//"], block: C_BLOCKS, triple: BOTH_BLOCKS, ..BASE };
pub const PHP: Language = Language { line: &["#", "//"], block: C_BLOCKS, php: true, ..BASE };

pub const LUA: Language = Language {
    line: &["--"],
    block: &[("--[[", "]]"), ("--[=[", "]=]")],
    ..BASE
};
pub const SQL: Language = Language { line: &["--"], block: &[("/*", "*/")], quotes: "\"'`", ..BASE };
pub const HASKELL: Language = Language {
    line: &["--"],
    block: &[("{-", "-}")],
    quotes: "\"",
    dash_symbols: true,
    nested: true,
    ..BASE
};

const HTML_BLOCKS: &[(&str, &str)] = &[("<!--", "-->"), ("/*", "*/")];
pub const HTML: Language = Language { line: &["//"], block: HTML_BLOCKS, ..BASE };
pub const COMPONENT: Language = Language {
    line: &["//"],
    block: HTML_BLOCKS,
    backtick: true,
    regex: true,
    ..BASE
};
pub const CSS: Language = Language { block: &[("/*", "*/")], ..BASE };
pub const SCSS: Language = Language { line: &["//"], block: &[("/*", "*/")], ..BASE };

const TABLE: &[(&str, Language)] = &[
    ("sh", SHELL),
    ("bash", SHELL),
    ("zsh", SHELL),
    ("fish", SHELL),
    ("r", HASH),
    ("cr", HASH),
    ("py", PYTHON),
    ("pyi", PYTHON),
    ("rb", RUBY),
    ("pl", PERL),
    ("pm", PERL),
    ("ex", ELIXIR),
    ("exs", ELIXIR),
    ("nim", NIM),
    ("rs", RUST),
    ("go", GO),
    ("js", SCRIPT),
    ("jsx", SCRIPT),
    ("mjs", SCRIPT),
    ("cjs", SCRIPT),
    ("ts", SCRIPT),
    ("tsx", SCRIPT),
    ("java", TEXT),
    ("kt", TEXT),
    ("kts", TEXT),
    ("scala", TEXT),
    ("swift", SWIFT),
    ("dart", GROOVY),
    ("groovy", GROOVY),
    ("gradle", GROOVY),
    ("c", SLASH),
    ("h", SLASH),
    ("cc", SLASH),
    ("cpp", SLASH),
    ("cxx", SLASH),
    ("hpp", SLASH),
    ("hh", SLASH),
    ("cs", SLASH),
    ("m", SLASH),
    ("mm", SLASH),
    ("zig", SLASH),
    ("proto", SLASH),
    ("sol", SLASH),
    ("php", PHP),
    ("lua", LUA),
    ("sql", SQL),
    ("hs", HASKELL),
    ("elm", HASKELL),
    ("html", HTML),
    ("htm", HTML),
    ("xhtml", HTML),
    ("vue", COMPONENT),
    ("svelte", COMPONENT),
    ("astro", COMPONENT),
    ("css", CSS),
    ("scss", SCSS),
    ("sass", SCSS),
    ("less", SCSS),
];

impl Language {
    pub fn fragment(self) -> Language {
        Language {
            column_zero: &[],
            pod: false,
            triple: &[],
            backtick: false,
            docstring: false,
            doc_attributes: false,
            ..self
        }
    }
}

pub fn language_for(path: &str) -> Option<Language> {
    let name = path.rsplit_once('/').map_or(path, |(_, tail)| tail);
    let name = name.rsplit_once('\\').map_or(name, |(_, tail)| tail);
    let (_, ext) = name.rsplit_once('.')?;
    if ext.is_empty() {
        return None;
    }
    TABLE
        .iter()
        .find(|(known, _)| ext.eq_ignore_ascii_case(known))
        .map(|(_, language)| *language)
}

#[cfg(test)]
mod tests {
    use super::{language_for, PHP, SLASH};

    #[test]
    fn picks_by_extension_ignoring_case_and_folders() {
        assert_eq!(language_for("a/b/C.c"), Some(SLASH));
        assert_eq!(language_for("x.php"), Some(PHP));
        assert!(language_for("README").is_none());
        assert!(language_for("notes.md").is_none());
        assert!(language_for("a.py.txt").is_none());
        assert!(language_for("dir.py/file").is_none());
        assert!(language_for("win\\path\\x.lua").is_some());
    }

    #[test]
    fn markup_and_style_files_are_checked_but_data_files_are_not() {
        for name in ["a.html", "a.HTM", "a.css", "a.scss", "a.less", "a.vue", "a.svelte"] {
            assert!(language_for(name).is_some(), "{name}");
        }
        for name in ["a.yaml", "a.yml", "a.toml", "a.json", "a.md", "a.xml", "a.ini", "a.lock"] {
            assert!(language_for(name).is_none(), "{name}");
        }
    }
}
