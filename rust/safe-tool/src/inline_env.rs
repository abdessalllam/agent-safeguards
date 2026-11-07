use std::sync::LazyLock;

use regex::Regex;

fn gate(source: &str) -> Regex {
    Regex::new(source).unwrap_or_else(|_| std::process::abort())
}

static PYTHON: LazyLock<Regex> = LazyLock::new(|| gate(r"\b(?:python[0-9.]*|pypy[0-9.]*)\b"));
static PYTHON_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    gate(r"from\s+os\s+import\s*(?:\*|\([^)]*\benvironb?\b[^)]*\)|[\w \t,]*\benvironb?\b)")
});
static PYTHON_IMPORT_LIST: LazyLock<Regex> =
    LazyLock::new(|| gate(r"from\s+os\s+import\s*(?:\([^)]*\)|[\w \t,*]+)"));
static NODE: LazyLock<Regex> = LazyLock::new(|| gate(r"\b(?:node(?:js)?|bun|deno)\b"));
static NODE_BRACKET: LazyLock<Regex> =
    LazyLock::new(|| gate(r#"\[\s*\\?["'`](\w+)\\?["'`]\s*\]"#));
static RUBY: LazyLock<Regex> = LazyLock::new(|| gate(r"\bruby[0-9.]*\b"));
static PERL: LazyLock<Regex> = LazyLock::new(|| gate(r"\bperl[0-9.]*\b"));
static PHP: LazyLock<Regex> = LazyLock::new(|| gate(r"\bphp[0-9.]*\b"));
static NAMED_ARGUMENT: LazyLock<Regex> = LazyLock::new(|| gate(r"\A[A-Za-z_]\w*\s*:"));
static AWK: LazyLock<Regex> = LazyLock::new(|| gate(r"\b[gmn]?awk\b"));
static AROUND_DOT: LazyLock<Regex> = LazyLock::new(|| gate(r"\s*\.\s*"));
static BEFORE_PAREN: LazyLock<Regex> = LazyLock::new(|| gate(r"\s+\("));
static FOR_LOOP: LazyLock<Regex> = LazyLock::new(|| gate(r"(?:\b|\\[nrt])for[\s(]"));
static FOR_BEFORE: LazyLock<Regex> = LazyLock::new(|| gate(r"(?:\b|\\[nrt])for\s*\z"));

const OBJECT_METHODS: [&str; 6] =
    ["valueOf", "toString", "toLocaleString", "toJSON", "constructor", "__proto__"];

// Spaces around a dot or before a bracket do not change what the code reads.
fn normalized(text: &str) -> String {
    let dotted = AROUND_DOT.replace_all(text, ".");
    BEFORE_PAREN.replace_all(&dotted, "(").into_owned()
}

fn name_char(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

// A name is used on its own, not through one key, when nothing in `allowed` follows it.
fn whole_use(text: &str, name: &str, allowed: &dyn Fn(&str) -> bool, membership: bool) -> bool {
    text.match_indices(name).any(|(at, _)| {
        let before = text.get(..at).unwrap_or("");
        let after = text.get(at.saturating_add(name.len())..).unwrap_or("");
        if before.chars().last().is_some_and(name_char)
            || after.chars().next().is_some_and(name_char)
        {
            return false;
        }
        if allowed(after.trim_start()) {
            return false;
        }
        !(membership && is_membership_test(before))
    })
}

fn unclosed_paren(text: &str) -> Option<usize> {
    let mut open: Vec<usize> = Vec::new();
    for (place, ch) in text.char_indices() {
        match ch {
            '(' => open.push(place),
            ')' => {
                open.pop();
            }
            _ => {}
        }
    }
    open.last().copied()
}

// `'X' in os.environ` asks about one name; `for k in os.environ` walks every value.
fn is_membership_test(before: &str) -> bool {
    let Some(head) = before.trim_end().strip_suffix("in") else {
        return false;
    };
    if !head.ends_with(char::is_whitespace) {
        return false;
    }
    let current = head.rsplit(';').next().unwrap_or("");
    if unclosed_paren(current).is_some_and(|open| FOR_BEFORE.is_match(current.get(..open).unwrap_or(""))) {
        return false;
    }
    let mut lines: Vec<&str> = current.split('\n').collect();
    let mut statement = lines.pop().unwrap_or("").to_owned();
    while let Some(previous) = lines.pop() {
        if !previous.trim_end().ends_with('\\') {
            break;
        }
        statement = format!("{previous}\n{statement}");
    }
    !FOR_LOOP.is_match(&statement)
}

fn starts_with_any(rest: &str, starts: &[&str]) -> bool {
    starts.iter().any(|start| rest.starts_with(start))
}

fn python(text: &str) -> bool {
    let allowed = |rest: &str| {
        starts_with_any(rest, &["[", ".get(", ".pop(", ".setdefault(", ".update(", ".__contains__("])
    };
    whole_use(text, "os.environ", &allowed, true)
        || whole_use(text, "os.environb", &allowed, true)
        || (PYTHON_IMPORT.is_match(text) && {
            let code = PYTHON_IMPORT_LIST.replace_all(text, " ");
            whole_use(&code, "environ", &allowed, true) || whole_use(&code, "environb", &allowed, true)
        })
}

fn node(text: &str) -> bool {
    let text = NODE_BRACKET.replace_all(text, ".$1");
    let allowed = |rest: &str| {
        rest.starts_with('[')
            || rest.strip_prefix('.').is_some_and(|after| {
                let name: String = after
                    .chars()
                    .take_while(|ch| ch.is_alphanumeric() || matches!(ch, '_' | '$'))
                    .collect();
                let tail = after.get(name.len()..).unwrap_or("").trim_start();
                let called = tail.starts_with('(') || tail.starts_with("?.(");
                name.chars()
                    .next()
                    .is_some_and(|ch| ch.is_ascii_alphabetic() || matches!(ch, '_' | '$'))
                    && !(called && OBJECT_METHODS.contains(&name.as_str()))
            })
    };
    whole_use(&text, "process.env", &allowed, true)
        || whole_use(&text, "Bun.env", &allowed, true)
        || text.contains("Deno.env.toObject")
}

fn ruby(text: &str) -> bool {
    let allowed = |rest: &str| {
        starts_with_any(
            rest,
            &["[", "=", ".fetch(", ".key?(", ".has_key?(", ".include?(", ".member?(", ".delete(", ".dig("],
        )
    };
    whole_use(text, "ENV", &allowed, false)
}

fn perl(text: &str) -> bool {
    ["%ENV", "%main::ENV", "%::ENV", "%main'ENV"]
        .iter()
        .any(|name| text.contains(name))
}

// getenv names one variable when its first argument is a text or a variable.
fn names_one_variable(arguments: &str) -> bool {
    let mut rest = arguments.trim_start();
    while let Some(inner) = rest.strip_prefix('(') {
        rest = inner.trim_start();
    }
    if let Some(found) = NAMED_ARGUMENT.find(rest) {
        if !rest.get(found.end()..).is_some_and(|tail| tail.starts_with(':')) {
            rest = rest.get(found.end()..).unwrap_or("").trim_start();
        }
    }
    matches!(rest.chars().next(), Some('\'' | '"' | '$'))
}

fn php(text: &str) -> bool {
    let indexed = |rest: &str| rest.starts_with('[');
    let lowered = text.to_lowercase();
    let all_variables = lowered.match_indices("getenv(").any(|(at, found)| {
        lowered
            .get(at.saturating_add(found.len())..)
            .is_some_and(|rest| !names_one_variable(rest))
    });
    whole_use(text, "$_ENV", &indexed, false)
        || whole_use(text, "$_SERVER", &indexed, false)
        || all_variables
        || lowered.contains("phpinfo(")
        || lowered.contains("get_defined_vars(")
}

fn awk(text: &str) -> bool {
    whole_use(text, "ENVIRON", &|rest: &str| rest.starts_with('['), false)
}

// Inline interpreter code that reads the whole environment prints every value at once.
pub fn dumps_environment(command: &str) -> bool {
    let text = normalized(command);
    (PYTHON.is_match(command) && python(&text))
        || (NODE.is_match(command) && node(&text))
        || (RUBY.is_match(command) && ruby(&text))
        || (PERL.is_match(command) && perl(&text))
        || (PHP.is_match(command) && php(&text))
        || (AWK.is_match(command) && awk(&text))
}

#[cfg(test)]
mod tests {
    use super::dumps_environment;

    #[test]
    fn code_that_reads_the_whole_environment_is_refused() {
        let refused = [
            r#"python3 -c "import os; print(os.environ)""#,
            r#"python3 -c "import os; print(dict(os.environ))""#,
            r#"python3 -c 'import os; [print(k, v) for k, v in os.environ.items()]'"#,
            r#"python -c "import os; print(os.environb)""#,
            r#"python3 -c "import os; [print(k) for k in os.environ]""#,
            r#"python3 -c "import os\nfor k in os.environ: print(k, os.environ[k])""#,
            "python3 -c 'import os; print([os.environ[k] for\tk in os.environ])'",
            "python3 -c 'import os\nfor k \\\n in os.environ: print(os.environ[k])'",
            r#"python3 -c "from os import environ; print(environ)""#,
            r#"python3 -c "from os import *; print(dict(environ))""#,
            r#"python3 -c 'from os import environb; print(dict(environb))'"#,
            r"python3 -c $'from os import environ\nprint(dict(environ))'",
            "python3 -c 'from os import (\n environ\n)\nprint(dict(environ))'",
            r#"python3 -c 'import os; print(dict(os . environ))'"#,
            "python3 - <<'PY'\nimport os\nprint(os.environ)\nPY",
            r#"node -e "console.log(process.env)""#,
            r#"node -e "console.log(process . env)""#,
            r#"node -e "console.log(process.env.valueOf())""#,
            r#"node -e "console.log(process.env.valueOf?.())""#,
            r#"node -e "console.log(process[\"env\"])""#,
            r#"node -e 'console.log(process["env"])'"#,
            r#"node -e 'console.log(process.env["valueOf"]())'"#,
            "node -e 'for (const k\n in process.env) console.log(process.env[k])'",
            r#"node -e "console.log(JSON.stringify(process.env))""#,
            r#"node -e "Object.entries(process.env).forEach(console.log)""#,
            r#"node -e "for (const k in process.env) console.log(k, process.env[k])""#,
            r#"bun -e "console.log(Bun.env)""#,
            r#"deno eval "console.log(Deno.env.toObject())""#,
            "ruby -e 'p ENV'",
            "ruby -e 'puts ENV.to_h'",
            "perl -e 'print %ENV'",
            "perl -e 'print %main::ENV'",
            "perl -e \"print %main'ENV\"",
            "perl -e 'for (keys %ENV) { print }'",
            "php -r 'print_r($_ENV);'",
            "php -r 'var_dump(getenv());'",
            "php -r 'var_dump(getenv ());'",
            "php -r 'var_dump(GETENV());'",
            "php -r 'var_dump(getenv(null));'",
            "php -r 'var_dump(getenv(name: null));'",
            "php -r 'var_dump(getenv(null, true));'",
            "php -r 'phpinfo();'",
            "awk 'BEGIN { for (k in ENVIRON) print k, ENVIRON[k] }'",
        ];
        for command in refused {
            assert!(dumps_environment(command), "{command}");
        }
    }

    #[test]
    fn reading_one_named_variable_is_allowed() {
        let allowed = [
            r#"python3 -c "import os; print(len(os.environ['HOME']))""#,
            r#"python3 -c "import os; print(os.environ.get('X', 'd'))""#,
            r#"python3 -c 'import os; print(os.environ.get ("HOME"))'"#,
            r#"python3 -c 'import os; print(os.environ["env"])'"#,
            r#"python3 -c "import os; print('X' in os.environ)""#,
            r#"python3 -c "import os; print(os.getenv('HOME'))""#,
            r#"python3 -c 'from os import environ; print(environ["FIXTURE_NAME"])'"#,
            r#"node -e "console.log(process.env.HOME.length)""#,
            r#"node -e "console.log(process.env['X'])""#,
            r#"node -e "console.log(process.env.constructor)""#,
            r#"node -e "console.log('X' in process.env)""#,
            r#"ruby -e 'puts ENV["HOME"].size'"#,
            r#"ruby -e 'puts ENV["env"]'"#,
            r#"ruby -e 'puts ENV.fetch("HOME").size'"#,
            r#"ruby -e 'puts ENV.fetch ("HOME")'"#,
            "perl -e 'print length $ENV{HOME}'",
            r#"php -r 'echo strlen(getenv("HOME"));'"#,
            r#"php -r 'echo getenv($name);'"#,
            r#"php -r 'echo getenv(name: "FIXTURE_NAME");'"#,
            r#"php -r 'echo getenv(("FIXTURE_NAME"));'"#,
            r#"php -r 'echo getenv(name: "FIXTURE_NAME", local_only: true);'"#,
            r#"awk 'BEGIN { print length(ENVIRON["HOME"]) }'"#,
        ];
        for command in allowed {
            assert!(!dumps_environment(command), "{command}");
        }
    }

    #[test]
    fn text_that_is_not_interpreter_code_is_left_alone() {
        let left = [
            r#"grep -rn "os.environ" src/"#,
            "echo process.env",
            "ENV=production ./run.sh",
            "ENV=production ruby app.rb",
            "cat notes.txt",
            "git log --oneline",
        ];
        for command in left {
            assert!(!dumps_environment(command), "{command}");
        }
    }
}
