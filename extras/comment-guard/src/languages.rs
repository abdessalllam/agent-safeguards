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
    pub rem: bool,
    pub comment_strings: bool,
    pub indent_block: bool,
    pub dollar_directive: bool,
    pub sentinel: bool,
    pub long_bracket: Option<&'static str>,
    pub escape: char,
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
    rem: false,
    comment_strings: false,
    indent_block: false,
    dollar_directive: false,
    sentinel: false,
    long_bracket: None,
    escape: '\\',
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

pub const LUA: Language = Language { line: &["--"], long_bracket: Some("--"), ..BASE };
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

pub const POWERSHELL: Language = Language { line: &["#"], block: &[("<#", "#>")], escape: '`', ..BASE };
pub const MAKE: Language = Language { line: &["#"], ..BASE };
pub const HCL: Language = Language { line: &["#", "//"], block: C_BLOCKS, quotes: "\"", ..BASE };
pub const CMAKE: Language = Language { line: &["#"], long_bracket: Some("#"), hash_after_space: true, ..BASE };
pub const BATCH: Language = Language { rem: true, ..BASE };
pub const BASIC: Language = Language { line: &["'"], quotes: "\"", rem: true, ..BASE };
pub const LISP: Language = Language { line: &[";"], block: &[("#|", "|#")], quotes: "\"", nested: true, ..BASE };
pub const SEMICOLON: Language = Language { line: &[";"], ..BASE };
pub const PERCENT: Language = Language { line: &["%"], quotes: "\"'", ..BASE };
pub const OCAML: Language = Language { block: &[("(*", "*)")], quotes: "\"", nested: true, comment_strings: true, ..BASE };
pub const FSHARP: Language =
    Language { line: &["//"], block: &[("(*", "*)")], quotes: "\"", nested: true, comment_strings: true, ..BASE };
pub const PASCAL: Language =
    Language { line: &["//"], block: &[("(*", "*)"), ("{", "}")], quotes: "'", dollar_directive: true, ..BASE };
pub const DASHES: Language = Language { line: &["--"], quotes: "\"", ..BASE };
pub const FORTRAN: Language = Language { line: &["!"], sentinel: true, ..BASE };
pub const NIX: Language = Language { line: &["#"], block: C_BLOCKS, quotes: "\"", ..BASE };
pub const JULIA: Language = Language { line: &["#"], block: &[("#=", "=#")], nested: true, ..BASE };
pub const ERB: Language = Language { block: &[("<!--", "-->"), ("<%#", "%>"), ("/*", "*/")], ..BASE };
pub const JINJA: Language = Language { block: &[("<!--", "-->"), ("{#", "#}"), ("/*", "*/")], ..BASE };
pub const HANDLEBARS: Language = Language { block: &[("<!--", "-->"), ("{{!--", "--}}"), ("{{!", "}}")], ..BASE };
pub const RAZOR: Language = Language { block: &[("<!--", "-->"), ("@*", "*@"), ("/*", "*/")], ..BASE };
pub const PUG: Language = Language { line: &["//"], indent_block: true, ..BASE };
pub const LEAN: Language = Language { line: &["--"], block: &[("/-", "-/")], quotes: "\"", nested: true, ..BASE };
pub const IDRIS: Language = Language { line: &["--", "|||"], block: &[("{-", "-}")], quotes: "\"", nested: true, ..BASE };
pub const DLANG: Language = Language { line: &["//"], block: &[("/*", "*/"), ("/+", "+/")], nested: true, ..BASE };
pub const JSONNET: Language = Language { line: &["#", "//"], block: C_BLOCKS, quotes: "\"'", ..BASE };

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
    ("svg", HTML),
    ("ipynb", PYTHON),
    ("ps1", POWERSHELL),
    ("psm1", POWERSHELL),
    ("psd1", POWERSHELL),
    ("tf", HCL),
    ("tfvars", HCL),
    ("hcl", HCL),
    ("nomad", HCL),
    ("thrift", JSONNET),
    ("jsonnet", JSONNET),
    ("libsonnet", JSONNET),
    ("mk", MAKE),
    ("mak", MAKE),
    ("make", MAKE),
    ("dockerfile", SHELL),
    ("containerfile", SHELL),
    ("just", SHELL),
    ("bats", SHELL),
    ("ksh", SHELL),
    ("csh", SHELL),
    ("tcsh", SHELL),
    ("ash", SHELL),
    ("command", SHELL),
    ("cmake", CMAKE),
    ("nix", NIX),
    ("jl", JULIA),
    ("tcl", HASH),
    ("awk", HASH),
    ("graphql", HASH),
    ("gql", HASH),
    ("capnp", HASH),
    ("rego", HASH),
    ("mojo", HASH),
    ("bat", BATCH),
    ("cmd", BATCH),
    ("vb", BASIC),
    ("vbs", BASIC),
    ("bas", BASIC),
    ("clj", LISP),
    ("cljs", LISP),
    ("cljc", LISP),
    ("lisp", LISP),
    ("lsp", LISP),
    ("el", LISP),
    ("scm", LISP),
    ("rkt", LISP),
    ("asm", SEMICOLON),
    ("nasm", SEMICOLON),
    ("erl", PERCENT),
    ("hrl", PERCENT),
    ("ml", OCAML),
    ("mli", OCAML),
    ("fs", FSHARP),
    ("fsi", FSHARP),
    ("fsx", FSHARP),
    ("pas", PASCAL),
    ("dpr", PASCAL),
    ("adb", DASHES),
    ("ads", DASHES),
    ("vhd", DASHES),
    ("vhdl", DASHES),
    ("purs", HASKELL),
    ("idr", IDRIS),
    ("agda", HASKELL),
    ("lean", LEAN),
    ("dhall", HASKELL),
    ("f90", FORTRAN),
    ("f95", FORTRAN),
    ("f03", FORTRAN),
    ("f08", FORTRAN),
    ("bzl", PYTHON),
    ("bazel", PYTHON),
    ("star", PYTHON),
    ("pyw", PYTHON),
    ("pyx", PYTHON),
    ("pxd", PYTHON),
    ("rake", RUBY),
    ("gemspec", RUBY),
    ("ru", RUBY),
    ("podspec", RUBY),
    ("mts", SCRIPT),
    ("cts", SCRIPT),
    ("prisma", SLASH),
    ("bicep", SLASH),
    ("cue", SLASH),
    ("move", SLASH),
    ("cairo", SLASH),
    ("odin", SLASH),
    ("gleam", SLASH),
    ("hx", SLASH),
    ("vala", SLASH),
    ("v", SLASH),
    ("sv", SLASH),
    ("svh", SLASH),
    ("d", DLANG),
    ("cu", SLASH),
    ("cuh", SLASH),
    ("cl", SLASH),
    ("glsl", SLASH),
    ("vert", SLASH),
    ("frag", SLASH),
    ("wgsl", SLASH),
    ("hlsl", SLASH),
    ("metal", SLASH),
    ("ino", SLASH),
    ("erb", ERB),
    ("ejs", ERB),
    ("j2", JINJA),
    ("jinja", JINJA),
    ("jinja2", JINJA),
    ("twig", JINJA),
    ("njk", JINJA),
    ("hbs", HANDLEBARS),
    ("handlebars", HANDLEBARS),
    ("mustache", HANDLEBARS),
    ("cshtml", RAZOR),
    ("razor", RAZOR),
    ("pug", PUG),
    ("jade", PUG),
];

const NAMES: &[(&str, Language)] = &[
    ("makefile", MAKE),
    ("gnumakefile", MAKE),
    ("bsdmakefile", MAKE),
    ("dockerfile", SHELL),
    ("containerfile", SHELL),
    ("justfile", SHELL),
    ("earthfile", SHELL),
    ("pkgbuild", SHELL),
    ("apkbuild", SHELL),
    (".bashrc", SHELL),
    (".bash_profile", SHELL),
    (".bash_login", SHELL),
    (".bash_logout", SHELL),
    (".profile", SHELL),
    (".zshrc", SHELL),
    (".zshenv", SHELL),
    (".zprofile", SHELL),
    (".zlogin", SHELL),
    (".zlogout", SHELL),
    (".kshrc", SHELL),
    (".envrc", SHELL),
    ("jenkinsfile", GROOVY),
    ("vagrantfile", RUBY),
    ("rakefile", RUBY),
    ("gemfile", RUBY),
    ("podfile", RUBY),
    ("brewfile", RUBY),
    ("guardfile", RUBY),
    ("capfile", RUBY),
    ("fastfile", RUBY),
    ("appfile", RUBY),
    ("dangerfile", RUBY),
    ("berksfile", RUBY),
    ("puppetfile", RUBY),
    ("thorfile", RUBY),
    ("cmakelists.txt", CMAKE),
    ("build", PYTHON),
    ("workspace", PYTHON),
    ("tiltfile", PYTHON),
    ("sconstruct", PYTHON),
    ("sconscript", PYTHON),
];

const INTERPRETERS: &[(&str, Language)] = &[
    ("sh", SHELL),
    ("bash", SHELL),
    ("zsh", SHELL),
    ("dash", SHELL),
    ("ash", SHELL),
    ("ksh", SHELL),
    ("fish", SHELL),
    ("csh", SHELL),
    ("tcsh", SHELL),
    ("make", SHELL),
    ("python", PYTHON),
    ("pypy", PYTHON),
    ("ruby", RUBY),
    ("perl", PERL),
    ("node", SCRIPT),
    ("nodejs", SCRIPT),
    ("deno", SCRIPT),
    ("bun", SCRIPT),
    ("tsx", SCRIPT),
    ("php", PHP),
    ("lua", LUA),
    ("luajit", LUA),
    ("rscript", HASH),
    ("tclsh", HASH),
    ("wish", HASH),
    ("expect", HASH),
    ("awk", HASH),
    ("gawk", HASH),
    ("mawk", HASH),
    ("julia", JULIA),
    ("groovy", GROOVY),
    ("pwsh", POWERSHELL),
    ("powershell", POWERSHELL),
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

fn file_name(path: &str) -> &str {
    let name = path.rsplit_once('/').map_or(path, |(_, tail)| tail);
    name.rsplit_once('\\').map_or(name, |(_, tail)| tail)
}

pub fn language_for(path: &str) -> Option<Language> {
    let name = file_name(path);
    let lower = name.to_ascii_lowercase();
    if let Some((_, language)) = NAMES.iter().find(|(known, _)| lower == *known) {
        return Some(*language);
    }
    if lower.starts_with("dockerfile.") || lower.starts_with("containerfile.") {
        return Some(SHELL);
    }
    let (_, ext) = name.rsplit_once('.')?;
    if ext.is_empty() {
        return None;
    }
    TABLE
        .iter()
        .find(|(known, _)| ext.eq_ignore_ascii_case(known))
        .map(|(_, language)| *language)
}

fn interpreter_language(first_line: &str) -> Option<Language> {
    let mut words = first_line.strip_prefix("#!")?.split_whitespace();
    let program = words.next()?;
    let mut name = program.rsplit('/').next().unwrap_or(program);
    if name == "env" {
        name = words.find(|word| !word.starts_with('-') && !word.contains('='))?;
        name = name.rsplit('/').next().unwrap_or(name);
    }
    let name = name.to_ascii_lowercase();
    let name = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    INTERPRETERS
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, language)| *language)
}

pub fn language_for_text(path: &str, text: &str) -> Option<Language> {
    if let Some(language) = language_for(path) {
        return Some(language);
    }
    if file_name(path).contains('.') {
        return None;
    }
    interpreter_language(text.trim_start_matches('\u{feff}').lines().next().unwrap_or(""))
}

pub fn language_for_file(path: &str) -> Option<Language> {
    if let Some(language) = language_for(path) {
        return Some(language);
    }
    if file_name(path).contains('.') {
        return None;
    }
    let mut head = [0u8; 160];
    let length = std::io::Read::read(&mut std::fs::File::open(path).ok()?, &mut head).ok()?;
    let text = String::from_utf8_lossy(head.get(..length)?).into_owned();
    interpreter_language(text.trim_start_matches('\u{feff}').lines().next().unwrap_or(""))
}

#[cfg(test)]
mod tests {
    use super::{language_for, language_for_text, PHP, SLASH};

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
        for name in ["a.html", "a.HTM", "a.css", "a.scss", "a.less", "a.vue", "a.svelte", "a.svg"] {
            assert!(language_for(name).is_some(), "{name}");
        }
        for name in ["a.yaml", "a.yml", "a.toml", "a.json", "a.md", "a.xml", "a.ini", "a.lock", "a.txt", "a.cfg"] {
            assert!(language_for(name).is_none(), "{name}");
        }
    }

    #[test]
    fn build_files_are_known_by_their_whole_name() {
        for name in ["Makefile", "sub/GNUmakefile", "Dockerfile", "Dockerfile.dev", "a.dockerfile", "CMakeLists.txt"] {
            assert!(language_for(name).is_some(), "{name}");
        }
        for name in ["Jenkinsfile", "Vagrantfile", "Gemfile", "Rakefile", ".zshrc", ".envrc", "BUILD", "justfile"] {
            assert!(language_for(name).is_some(), "{name}");
        }
        for name in ["notes", "LICENSE", "NOTICE", "Procfile", "Gemfile.lock", "CMakeLists.cmake.in", "x.txt"] {
            assert!(language_for(name).is_none(), "{name}");
        }
    }

    #[test]
    fn a_file_without_extension_is_judged_by_its_first_line() {
        let python = language_for_text("bin/tool", "#!/usr/bin/env python3\nx = 1\n");
        assert_eq!(python.map(|l| l.docstring), Some(true));
        assert!(language_for_text("bin/tool", "#!/bin/bash\n").is_some());
        assert!(language_for_text("bin/tool", "#!/usr/bin/env -S node --flag\n").is_some());
        assert!(language_for_text("bin/tool", "#!/usr/bin/python3.11\n").is_some());
        assert!(language_for_text("bin/tool", "#!/usr/bin/pwsh\n").is_some());
        assert!(language_for_text("bin/tool", "\u{feff}#!/bin/sh\n").is_some());
        assert!(language_for_text("bin/tool", "# plain notes\n").is_none());
        assert!(language_for_text("bin/tool", "#!/usr/bin/cat\n").is_none());
        assert!(language_for_text("bin/tool", "").is_none());
        assert!(language_for_text("notes.txt", "#!/bin/sh\n").is_none());
        assert!(language_for_text("notes.md", "#!/bin/sh\n").is_none());
    }
}
