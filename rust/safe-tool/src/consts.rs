use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::sync::LazyLock;

use regex::{Captures, Regex};
use serde_json::{json, Map, Number, Value};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub start: usize,
    pub end: usize,
    pub groups: Vec<Option<String>>,
}

fn compile(pattern: &str) -> Regex {
    match guard_common::pyre::new(pattern) {
        Ok(compiled) => compiled,
        Err(error) => panic!("constant pattern failed to compile: {error}"),
    }
}

thread_local! {
    static PS_TARGET_CELL: RefCell<String> = RefCell::new(String::from(if cfg!(target_os = "macos") { "darwin" } else { "linux" }));
    static STARTUP_RULES_CELL: Cell<bool> = const { Cell::new(true) };
}

pub fn ps_target() -> String {
    if let Some(value) = guard_common::overrides::list("_PS_TARGET").and_then(|items| items.into_iter().next()) {
        return value;
    }
    PS_TARGET_CELL.with(|cell| cell.borrow().clone())
}

pub fn rtk_path() -> Option<String> {
    match guard_common::overrides::nullable_string("RTK_PATH") {
        Some(value) => value,
        None => RTK_PATH.clone(),
    }
}

pub fn hook_budget_seconds() -> f64 {
    guard_common::overrides::number("HOOK_BUDGET_SECONDS").unwrap_or(HOOK_BUDGET_SECONDS)
}

pub fn set_ps_target(value: &str) {
    PS_TARGET_CELL.with(|cell| *cell.borrow_mut() = value.to_owned());
}

pub fn startup_rules() -> bool {
    STARTUP_RULES_CELL.with(Cell::get)
}

pub fn set_startup_rules(value: bool) {
    STARTUP_RULES_CELL.with(|cell| cell.set(value));
}

pub static SELF_PATH: LazyLock<String> = LazyLock::new(|| match std::env::current_exe() {
    Ok(path) => guard_common::sys::realpath(path.to_string_lossy().as_ref()),
    Err(_) => String::new(),
});

pub static GIT_PATH: LazyLock<Option<String>> = LazyLock::new(|| guard_common::env::find_executable("git"));
pub static RTK_PATH: LazyLock<Option<String>> = LazyLock::new(|| guard_common::env::find_executable("rtk"));
pub static CODERABBIT_PATH: LazyLock<Option<String>> = LazyLock::new(|| guard_common::env::find_executable("coderabbit"));

pub const TOOL_NAME: &str = "safe-tool";
pub const MAX_OUTPUT_BYTES: usize = 1048576;
pub const STATUS_TIMEOUT_SECONDS: usize = 20;
pub const GIT_TIMEOUT_SECONDS: usize = 300;
pub const RTK_REWRITE_TIMEOUT_SECONDS: usize = 2;
const OBJECT_ID_PATTERN_SRC: &str = "^[0-9a-f]{40}(?:[0-9a-f]{24})?$";
pub static OBJECT_ID_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(OBJECT_ID_PATTERN_SRC));

const ATTRIBUTION_PATTERN_SRC: &str = "(?im)(?im)^\\s*(?:co-authored-by|generated-by)\\s*:";
pub static ATTRIBUTION_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(ATTRIBUTION_PATTERN_SRC));

const EMAIL_PATTERN_SRC: &str = "\\b[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,})\\b";
pub static EMAIL_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(EMAIL_PATTERN_SRC));

const NON_EMAIL_IDENTITY_FIELD_PATTERN_SRC: &str = "(?i)(?i)(?:user(?:name)?|display[_ -]?name|name|account(?:[_ -]?id)?|org(?:anization)?|tenant(?:[_ -]?id)?)\\s*(?:[\\\"']\\s*)?[:=]\\s*[\\\"']?[^\\s,}\\]]+";
pub static NON_EMAIL_IDENTITY_FIELD_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(NON_EMAIL_IDENTITY_FIELD_PATTERN_SRC));

pub static HOOK_EVENTS: &[&str] = &["PostToolUse", "PreToolUse", "SessionStart"];
pub const HOOK_BUDGET_SECONDS: f64 = 3.0;
const PROXY_PREFIX_SRC: &str = "\\brtk\\s+proxy\\b";
pub static PROXY_PREFIX: LazyLock<Regex> = LazyLock::new(|| compile(PROXY_PREFIX_SRC));

const EVENT_PATTERN_SRC: &str = "\"hook_event_name\"\\s*:\\s*\"(PreToolUse|PostToolUse|SessionStart)\"";
pub static EVENT_PATTERN: LazyLock<regex::bytes::Regex> = LazyLock::new(|| match regex::bytes::Regex::new(EVENT_PATTERN_SRC) {
    Ok(compiled) => compiled,
    Err(error) => panic!("constant pattern failed to compile: {error}"),
});

pub const EVENT_SEARCH_BYTES: usize = 65536;
pub static RESERVED_EMAIL_DOMAINS: &[&str] = &["example.com", "example.net", "example.org", "example.test", "localhost"];
pub static RESERVED_EMAIL_SUFFIXES: &[&str] = &[".example.com", ".example.net", ".example.org", ".example", ".test", ".invalid", ".localhost", ".local"];
pub static FIXTURE_EMAIL_DOMAINS: &[&str] = &["company.com", "corp.com", "domain.com", "test.com", "yourcompany.com", "yourdomain.com"];
pub static SHARED_EMAIL_LOCALS: &[&str] = &["abuse", "admin", "contact", "do-not-reply", "donotreply", "git", "hello", "help", "hg", "info", "legal", "mailer-daemon", "no-reply", "noreply", "notifications", "postmaster", "privacy", "sales", "security", "ssh", "support", "team", "webmaster"];
static SHARED_EMAIL_LOCALS_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| SHARED_EMAIL_LOCALS.iter().copied().collect());
pub fn in_shared_email_locals(word: &str) -> bool {
    SHARED_EMAIL_LOCALS_SET.contains(word)
}

pub static SHELL_PUNCTUATION: &[&str] = &["\n", "&", "(", ")", ";", "|"];
pub static CLI_GLOBAL_VALUE_OPTIONS: &[(&str, &[&str])] = &[("aws", &["--ca-bundle", "--cli-binary-format", "--cli-connect-timeout", "--cli-input-json", "--cli-input-yaml", "--cli-read-timeout", "--color", "--endpoint-url", "--output", "--profile", "--query", "--region"]), ("az", &["--output", "--query", "--subscription", "--tenant", "-o"]), ("gcloud", &["--access-token-file", "--account", "--billing-project", "--configuration", "--flags-file", "--format", "--impersonate-service-account", "--project", "--trace-token", "--user-output-enabled", "--verbosity"]), ("gh", &["--hostname", "--repo", "-r"]), ("kubectl", &["--as", "--as-group", "--as-uid", "--cache-dir", "--certificate-authority", "--client-certificate", "--client-key", "--cluster", "--context", "--kubeconfig", "--log-flush-frequency", "--namespace", "--profile", "--profile-output", "--request-timeout", "--server", "--tls-server-name", "--user", "--v", "-n", "-s", "-v"])];
pub static SAFE_PROXY_COMMANDS: &[&str] = &["awk", "cat", "cmp", "diff", "du", "find", "git", "grep", "head", "ls", "nl", "rg", "sed", "sort", "stat", "tail", "uniq", "wc"];
static SAFE_PROXY_COMMANDS_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| SAFE_PROXY_COMMANDS.iter().copied().collect());
pub fn in_safe_proxy_commands(word: &str) -> bool {
    SAFE_PROXY_COMMANDS_SET.contains(word)
}

pub static DIRECT_IDENTITY_COMMANDS: &[&str] = &["env", "finger", "groups", "logname", "printenv", "users", "whoami"];
pub static DEFINITION_PRINTERS: &[&str] = &["alias", "declare", "export", "fc", "functions", "history", "local", "readonly", "set", "type", "typeset", "whence", "where"];
static DEFINITION_PRINTERS_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| DEFINITION_PRINTERS.iter().copied().collect());
pub fn in_definition_printers(word: &str) -> bool {
    DEFINITION_PRINTERS_SET.contains(word)
}

const DEFINITION_OUTPUT_PATTERN_SRC: &str = "alias [^\\s=]+=| is an alias for | is aliased to |: aliased to | is a shell function\\b|(?m:^\\S+ \\(\\) ?\\{?[ \\t]*$)";
pub static DEFINITION_OUTPUT_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(DEFINITION_OUTPUT_PATTERN_SRC));

const DEFINITION_PARAMETER_PATTERN_SRC: &str = "\\$\\{?[(@~^=%#a-z)]*(?:aliases|galiases|saliases|functions|dis_aliases|dis_functions|bash_aliases)\\b";
pub static DEFINITION_PARAMETER_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(DEFINITION_PARAMETER_PATTERN_SRC));

const SHELL_COMMAND_OPTION_SRC: &str = "-[A-Za-z]*c[A-Za-z]*";
pub static SHELL_COMMAND_OPTION: LazyLock<Regex> = LazyLock::new(|| compile(SHELL_COMMAND_OPTION_SRC));
pub static SHELL_COMMAND_OPTION_FULL: LazyLock<Regex> = LazyLock::new(|| compile(&format!(r"\A(?:{SHELL_COMMAND_OPTION_SRC})\z")));

pub const STARTUP_RC_NAMES: &str = "zshrc|zshenv|zprofile|zlogin|zlogout|bashrc|bash_profile|bash_login|bash_logout|bash_aliases|profile|login|logout|kshrc|cshrc|tcshrc";
pub const STARTUP_HISTORY_NAMES: &str = "zsh_history|bash_history|sh_history|history|zhistory|python_history|psql_history|mysql_history|sqlite_history|node_repl_history|irb_history|rediscli_history|dbshell|viminfo|lesshst|Rhistory";
pub static STARTUP_FOLDER_PATHS: &[&str] = &["zsh", "zprezto/runcoms", "oh-my-zsh/custom", "config/fish", "config/zsh", "config/bash"];
pub static STARTUP_HISTORY_FOLDER_PATHS: &[&str] = &["zsh_sessions", "bash_sessions", "local/share/fish", "local/state/zsh", "local/share/zsh", "cache/zsh", "local/share/atuin"];
pub const STARTUP_FOLDERS: &str = "zsh|zprezto/runcoms|oh-my-zsh/custom|config/fish|config/zsh|config/bash";
pub const STARTUP_HISTORY_FOLDERS: &str = "zsh_sessions|bash_sessions|local/share/fish|local/state/zsh|local/share/zsh|cache/zsh|local/share/atuin";
pub const STARTUP_SYSTEM_FILES: &str = "(?:/private)?/etc/(?:zshrc|zprofile|zshenv|zlogin|zlogout|profile|bashrc|bash\\.bashrc|environment)(?![A-Za-z0-9_])|(?:/private)?/etc/(?:zsh|bash|profile\\.d)/";
pub const STARTUP_SOURCEABLE: &str = "\\.(?:zshrc|zshenv|zprofile|zlogin|zlogout|bashrc|bash_profile|bash_login|bash_logout|bash_aliases|profile|login|logout|kshrc|cshrc|tcshrc)(?![A-Za-z0-9_])|\\.(?:zsh|zprezto/runcoms|oh-my-zsh/custom|config/fish|config/zsh|config/bash)/|(?:/private)?/etc/(?:zshrc|zprofile|zshenv|zlogin|zlogout|profile|bashrc|bash\\.bashrc|environment)(?![A-Za-z0-9_])|(?:/private)?/etc/(?:zsh|bash|profile\\.d)/";
pub const STARTUP_NAME_END: &str = "(?=/|[\\s\\\"';&|()<>`]|$)";
pub const STARTUP_HISTORY: &str = "\\.(?:zsh_history|bash_history|sh_history|history|zhistory|python_history|psql_history|mysql_history|sqlite_history|node_repl_history|irb_history|rediscli_history|dbshell|viminfo|lesshst|Rhistory)(?![A-Za-z0-9_])|\\.(?:zsh_sessions|bash_sessions|local/share/fish|local/state/zsh|local/share/zsh|cache/zsh|local/share/atuin)(?=/|[\\s\\\"';&|()<>`]|$)";
pub const STARTUP_NAME: &str = "\\.(?:zshrc|zshenv|zprofile|zlogin|zlogout|bashrc|bash_profile|bash_login|bash_logout|bash_aliases|profile|login|logout|kshrc|cshrc|tcshrc)(?![A-Za-z0-9_])|\\.(?:zsh|zprezto/runcoms|oh-my-zsh/custom|config/fish|config/zsh|config/bash)/|(?:/private)?/etc/(?:zshrc|zprofile|zshenv|zlogin|zlogout|profile|bashrc|bash\\.bashrc|environment)(?![A-Za-z0-9_])|(?:/private)?/etc/(?:zsh|bash|profile\\.d)/|\\.(?:zsh|zprezto/runcoms|oh-my-zsh/custom|config/fish|config/zsh|config/bash)(?=/|[\\s\\\"';&|()<>`]|$)|\\.(?:zsh_history|bash_history|sh_history|history|zhistory|python_history|psql_history|mysql_history|sqlite_history|node_repl_history|irb_history|rediscli_history|dbshell|viminfo|lesshst|Rhistory)(?![A-Za-z0-9_])|\\.(?:zsh_sessions|bash_sessions|local/share/fish|local/state/zsh|local/share/zsh|cache/zsh|local/share/atuin)(?=/|[\\s\\\"';&|()<>`]|$)";
pub const STARTUP_BOUNDARY: &str = "(?:^|[\\s\\\"'=:(<>|;&/{`])";
pub static STARTUP_SAMPLE_NAMES: &[&str] = &[".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout", ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".bash_aliases", ".profile", ".login", ".logout", ".kshrc", ".cshrc", ".tcshrc", ".zsh_history", ".bash_history", ".sh_history", ".history", ".zhistory", ".python_history", ".psql_history", ".mysql_history", ".sqlite_history", ".node_repl_history", ".irb_history", ".rediscli_history", ".dbshell", ".viminfo", ".lesshst", ".rhistory"];
const GLOB_SYNTAX_PATTERN_SRC: &str = "\\*|\\?|\\[[^\\]]{1,64}\\]|\\{[^{}]*,[^{}]*\\}|\\{[^{}]{1,16}\\.\\.[^{}]{1,16}\\}";
pub static GLOB_SYNTAX_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(GLOB_SYNTAX_PATTERN_SRC));

const DOTGLOB_PATTERN_SRC: &str = "(?i)dotglob|globdots|GLOBIGNORE|\\(D\\)";
pub static DOTGLOB_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(DOTGLOB_PATTERN_SRC));

const FIND_NAME_PATTERN_SRC: &str = "-(?:i?name|i?path|i?wholename)[ \\t]+(?:'([^']*)'|\\\"([^\\\"]*)\\\"|([^\\s;&|()<>`]+))";
pub static FIND_NAME_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(FIND_NAME_PATTERN_SRC));

const FIND_ROOTS_SRC: &str = "\\bfind[ \\t]+((?:[^\\s;&|()<>`!-][^\\s;&|()<>`]*[ \\t]+){0,50})";
pub static FIND_ROOTS: LazyLock<Regex> = LazyLock::new(|| compile(FIND_ROOTS_SRC));

const PIPELINE_WORD_PATTERN_SRC: &str = "\\b(?:xargs|while|for|eval|exec|parallel)\\b|-exec|-ok(?:dir)?\\b";
pub static PIPELINE_WORD_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(PIPELINE_WORD_PATTERN_SRC));

const HISTORY_VARIABLE_PATTERN_SRC: &str = "(?i)\\$\\{?histfile\\b";
pub static HISTORY_VARIABLE_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(HISTORY_VARIABLE_PATTERN_SRC));

const PROCESS_ENVIRONMENT_PATTERN_SRC: &str = "/proc/\\S{0,80}environ";
pub static PROCESS_ENVIRONMENT_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(PROCESS_ENVIRONMENT_PATTERN_SRC));

pub static HEREDOC_DATA_COMMANDS: &[&str] = &["cat", "diff", "gh", "grep", "jq", "tee"];
pub const MAX_HEREDOC_LINE_CHARS: usize = 4096;
const SYSTEM_COMMAND_PATH_SRC: &str = "(?:/usr/bin/|/bin/|/usr/local/bin/|/opt/[a-z]+/bin/)?[a-z]+";
pub static SYSTEM_COMMAND_PATH: LazyLock<Regex> = LazyLock::new(|| compile(SYSTEM_COMMAND_PATH_SRC));
pub static SYSTEM_COMMAND_PATH_FULL: LazyLock<Regex> = LazyLock::new(|| compile(&format!(r"\A(?:{SYSTEM_COMMAND_PATH_SRC})\z")));

const JQ_PROGRAM_FILE_SRC: &str = "-[A-Za-z]*f[A-Za-z]*|--from-file|--run[a-z-]*";
pub static JQ_PROGRAM_FILE: LazyLock<Regex> = LazyLock::new(|| compile(JQ_PROGRAM_FILE_SRC));
pub static JQ_PROGRAM_FILE_FULL: LazyLock<Regex> = LazyLock::new(|| compile(&format!(r"\A(?:{JQ_PROGRAM_FILE_SRC})\z")));

pub static HEREDOC_ARGUMENT_COMMANDS: &[(&str, &[&str])] = &[("gh", &["issue", "pr", "release"])];
pub static GH_TEXT_OPTIONS: &[&str] = &["--body", "--notes", "--title", "-b", "-n", "-t"];
pub const REMOTE_MAX_CHARS: usize = 4096;
pub static REMOTE_READ_COMMANDS: &[&str] = &["cat", "column", "cut", "date", "df", "docker", "du", "egrep", "fgrep", "file", "find", "free", "grep", "head", "journalctl", "jq", "ls", "nl", "pm2", "ps", "sort", "stat", "systemctl", "tac", "tail", "tr", "uniq", "uptime", "wc", "zcat", "zgrep"];
static REMOTE_READ_COMMANDS_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| REMOTE_READ_COMMANDS.iter().copied().collect());
pub fn in_remote_read_commands(word: &str) -> bool {
    REMOTE_READ_COMMANDS_SET.contains(word)
}

pub static REMOTE_FORBIDDEN_OPTIONS: &[(&str, &[&str])] = &[("find", &["-delete", "-exec", "-execdir", "-fls", "-fprint", "-fprint0", "-fprintf", "-ok", "-okdir"])];
pub static REMOTE_FORBIDDEN_LONG: &[(&str, &[&str])] = &[("date", &["--set"]), ("file", &["--compile", "--uncompress", "--uncompress-noreport"]), ("free", &["--seconds"]), ("journalctl", &["--flush", "--follow", "--relinquish-var", "--rotate", "--setup-keys", "--smart-relinquish-var", "--sync", "--update-catalog", "--vacuum-files", "--vacuum-size", "--vacuum-time", "--cursor-file", "--machine"]), ("systemctl", &["--host", "--machine"]), ("sort", &["--compress-program", "--output"]), ("tail", &["--follow"])];
pub static REMOTE_FORBIDDEN_LETTERS: &[(&str, &str)] = &[("date", "s"), ("file", "CzZ"), ("free", "s"), ("journalctl", "fM"), ("sort", "o"), ("systemctl", "HM"), ("tail", "fF")];
pub static REMOTE_EXACT_LONG: &[(&str, &[&str])] = &[("journalctl", &["--cursor"])];
pub static REMOTE_VALUE_LETTERS: &[(&str, &str)] = &[("date", "dfrsI"), ("file", "fmeFP"), ("free", "cs"), ("journalctl", "DMutpcSUnogF"), ("sort", "tTkSo"), ("systemctl", "HMPnopst"), ("tail", "ncs")];
pub static REMOTE_ATTACHED_LETTERS: &[(&str, &str)] = &[("date", "I")];
pub static REMOTE_FLAG_LONG: &[(&str, &[&str])] = &[("date", &["--debug", "--help", "--iso-8601", "--rfc-2822", "--rfc-822", "--rfc-email", "--universal", "--utc", "--version"]), ("file", &["--apple", "--brief", "--dereference", "--extension", "--help", "--keep-going", "--mime", "--mime-encoding", "--mime-type", "--no-dereference", "--no-pad", "--preserve-date", "--raw", "--special-files", "--uncompress", "--version"]), ("free", &["--bytes", "--committed", "--gibi", "--giga", "--help", "--human", "--kibi", "--kilo", "--lohi", "--mebi", "--mega", "--pebi", "--peta", "--si", "--tebi", "--tera", "--total", "--version", "--wide"]), ("journalctl", &["--all", "--catalog", "--disk-usage", "--dmesg", "--full", "--header", "--help", "--list-boots", "--list-catalog", "--merge", "--no-full", "--no-hostname", "--no-pager", "--quiet", "--reverse", "--show-cursor", "--system", "--user", "--utc", "--verify", "--version"]), ("sort", &["--check", "--debug", "--dictionary-order", "--general-numeric-sort", "--help", "--human-numeric-sort", "--ignore-case", "--ignore-leading-blanks", "--ignore-nonprinting", "--merge", "--month-sort", "--numeric-sort", "--random-sort", "--reverse", "--stable", "--unique", "--version", "--version-sort", "--zero-terminated"]), ("systemctl", &["--all", "--failed", "--full", "--help", "--no-ask-password", "--no-legend", "--no-pager", "--no-warn", "--plain", "--quiet", "--recursive", "--show-types", "--system", "--user", "--value", "--version"]), ("tail", &["--help", "--quiet", "--silent", "--verbose", "--version", "--zero-terminated"])];
pub static DOCKER_STATS_VALUE_OPTIONS: &[&str] = &["--format"];
pub static BOOLEAN_TRUE: &[&str] = &["1", "T", "TRUE", "True", "t", "true"];
pub static BOOLEAN_FALSE: &[&str] = &["0", "F", "FALSE", "False", "f", "false"];
pub static PS_PROFILES: &[(&str, &[char], &[char])] = &[("linux", &['C', 'G', 'O', 'U', 'g', 'o', 'p', 'q', 's', 't', 'u'], &['N', 'O', 'U', 'o', 'p', 'q', 't']),("darwin", &['G', 'O', 'U', 'g', 'o', 'p', 't', 'u'], &['G', 'O', 'U', 'g', 'o', 'p', 't', 'u']),];
pub fn ps_profile(name: &str) -> Option<(&'static [char], &'static [char])> {
    PS_PROFILES.iter().find(|(key, _, _)| *key == name).map(|(_, unix, bsd)| (*unix, *bsd))
}

pub static PS_LONG_VALUE_OPTIONS: &[&str] = &["--Group", "--User", "--cols", "--columns", "--date-format", "--format", "--group", "--lines", "--pid", "--ppid", "--quick-pid", "--rows", "--sid", "--sort", "--tty", "--user", "--width"];
static PS_LONG_VALUE_OPTIONS_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| PS_LONG_VALUE_OPTIONS.iter().copied().collect());
pub fn in_ps_long_value_options(word: &str) -> bool {
    PS_LONG_VALUE_OPTIONS_SET.contains(word)
}

pub static DOCKER_VALUE_LETTERS: &[&str] = &["H", "c", "l"];
pub static DOCKER_VALUE_OPTIONS: &[&str] = &["--config", "--context", "--host", "--log-level", "--tlscacert", "--tlscert", "--tlskey"];
pub static COMPOSE_VALUE_LETTERS: &[&str] = &["f", "p"];
pub static COMPOSE_VALUE_OPTIONS: &[&str] = &["--ansi", "--env-file", "--file", "--parallel", "--profile", "--progress", "--project-directory", "--project-name"];
pub static SYSTEMCTL_VALUE_LETTERS: &[&str] = &["H", "M", "P", "n", "o", "p", "s", "t"];
pub static SYSTEMCTL_VALUE_OPTIONS: &[&str] = &["--host", "--lines", "--machine", "--output", "--property", "--signal", "--state", "--type"];
pub static DATE_VALUE_LETTERS: &[&str] = &["d", "f", "r"];
pub static DATE_VALUE_OPTIONS: &[&str] = &["--date", "--file", "--reference"];
pub static UNIQ_VALUE_LETTERS: &[&str] = &["f", "s", "w"];
pub static UNIQ_VALUE_OPTIONS: &[&str] = &["--check-chars", "--skip-chars", "--skip-fields"];
pub static REMOTE_SUBCOMMANDS: &[(&str, &[&str])] = &[("docker", &["compose", "images", "logs", "ps", "stats", "version"]), ("pm2", &["list", "logs", "ls", "status"]), ("systemctl", &["is-active", "is-enabled", "is-failed", "list-timers", "list-unit-files", "list-units", "status"])];
pub static REMOTE_COMPOSE_SUBCOMMANDS: &[&str] = &["logs", "ps"];
const REDACT_USER_HOST_SRC: &str = "[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\\.[A-Za-z0-9-]{1,63})*";
pub static REDACT_USER_HOST: LazyLock<Regex> = LazyLock::new(|| compile(REDACT_USER_HOST_SRC));

pub const MAX_GLOB_WORDS: usize = 20;
pub const MAX_GLOB_WORD_CHARS: usize = 512;
const SECRET_VARIABLE_PATTERN_SRC: &str = "(?i)\\$\\{?[#!]?[A-Za-z0-9_]*(?:key|token|secret|pass|credential|auth)[A-Za-z0-9_]*";
pub static SECRET_VARIABLE_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(SECRET_VARIABLE_PATTERN_SRC));

pub static PRINTING_COMMANDS: &[&str] = &["echo", "print", "printf"];
pub static PLAIN_UTILITIES: &[&str] = &["[", "awk", "basename", "cat", "cd", "chmod", "cmp", "column", "comm", "cp", "cut", "df", "diff", "dirname", "du", "egrep", "expand", "false", "fgrep", "file", "find", "fmt", "fold", "gmake", "grep", "gunzip", "gzip", "head", "hexdump", "install", "join", "just", "less", "link", "ln", "ls", "make", "mkdir", "mktemp", "more", "mv", "nl", "od", "paste", "pr", "pwd", "readlink", "realpath", "rev", "rg", "rm", "rmdir", "sed", "sort", "split", "stat", "strings", "tac", "tail", "tar", "tee", "test", "touch", "tr", "true", "unexpand", "uniq", "unlink", "unzip", "wc", "zip"];
static PLAIN_UTILITIES_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| PLAIN_UTILITIES.iter().copied().collect());
pub fn in_plain_utilities(word: &str) -> bool {
    PLAIN_UTILITIES_SET.contains(word)
}

pub static CREDENTIAL_COMMANDS: &[&str] = &["bw", "gopass", "keyctl", "pass", "secret-tool"];
pub static ENVIRONMENT_SERVICE_ACTIONS: &[&str] = &["dumpstate", "export", "getenv", "print", "print-cache", "print-disabled", "procinfo"];
pub const STARTUP_KEYWORDS: &str = "(?:(?:if|then|elif|else|do|while|until|time|!)[ \\t]+)*";
pub const STARTUP_COMMAND_POSITION: &str = "(?:^|[;&|({\\n`])[ \\t]*(?:(?:if|then|elif|else|do|while|until|time|!)[ \\t]+)*";
pub const STARTUP_QUOTED_POSITION: &str = "(?:^|[;&|({\\n`]|\\x01)[ \\t]*(?:(?:if|then|elif|else|do|while|until|time|!)[ \\t]+)*";
const METADATA_STARTUP_PATTERN_SRC: &str = "(?i)(?:^|[;&|({\\n`])[ \\t]*(?:(?:if|then|elif|else|do|while|until|time|!)[ \\t]+)*(?:rtk[ \\t]+(?:proxy[ \\t]+)?)?(?:/usr/bin/|/bin/|/usr/local/bin/|/opt/[a-z]+/bin/)?(?:ls|stat|test|\\[\\[?)[ \\t]+[^;&|()<>`\\n]*";
pub static METADATA_STARTUP_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(METADATA_STARTUP_PATTERN_SRC));

const HAS_KEY_STARTUP_PATTERN_SRC: &str = "(?i)(?:^|[;&|({\\n`])[ \\t]*(?:(?:if|then|elif|else|do|while|until|time|!)[ \\t]+)*(?:safe-tool|~/\\.local/bin/safe-tool|\\$\\{?HOME\\}?/\\.local/bin/safe-tool)[ \\t]+has-key\\b[^;&|()<>`\\n]*";
pub static HAS_KEY_STARTUP_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(HAS_KEY_STARTUP_PATTERN_SRC));

const TRACE_OPTION_SRC: &str = "-[A-Za-z]*[vx][A-Za-z]*|--(?:verbose|xtrace)";
pub static TRACE_OPTION: LazyLock<Regex> = LazyLock::new(|| compile(TRACE_OPTION_SRC));
pub static TRACE_OPTION_FULL: LazyLock<Regex> = LazyLock::new(|| compile(&format!(r"\A(?:{TRACE_OPTION_SRC})\z")));

pub static TRACE_OPTION_NAMES: &[&str] = &["sourcetrace", "verbose", "xtrace"];
pub static TRACE_COMMANDS: &[&str] = &["ash", "bash", "dash", "ksh", "ksh93", "mksh", "set", "setopt", "sh", "shopt", "yash", "zsh"];
static TRACE_COMMANDS_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| TRACE_COMMANDS.iter().copied().collect());
pub fn in_trace_commands(word: &str) -> bool {
    TRACE_COMMANDS_SET.contains(word)
}

const TRACE_ENVIRONMENT_PATTERN_SRC: &str = "\\b(?:SHELLOPTS|BASHOPTS|BASH_XTRACEFD)=|\\btrap\\b[^\\n;]*\\bDEBUG\\b|\\bset[ \\t]+[-+]\\w*T|\\bfunctrace\\b";
pub static TRACE_ENVIRONMENT_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(TRACE_ENVIRONMENT_PATTERN_SRC));

const SHADOWING_PATTERN_SRC: &str = "\\(\\)[ \\t]*\\{|\\bfunction\\b|\\balias\\b|\\bunalias\\b";
pub static SHADOWING_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(SHADOWING_PATTERN_SRC));

const JQ_PROGRAM_SRC: &str = "(?P<head>\\b(?:jq|gojq|yq)\\b(?:[ \\t]+-[A-Za-z]+)*[ \\t]+)(?:'[^']*'|\\\"[^\\\"$`\\\\]*\\\")";
pub static JQ_PROGRAM: LazyLock<Regex> = LazyLock::new(|| compile(JQ_PROGRAM_SRC));

const HERE_STRING_SECRET_SRC: &str = "(?i)<<<[ \\t]*[\\\"']?\\$\\{?[#!]?[A-Za-z0-9_]*(?:key|token|secret|pass|credential|auth)";
pub static HERE_STRING_SECRET: LazyLock<Regex> = LazyLock::new(|| compile(HERE_STRING_SECRET_SRC));

const HEREDOC_EXPANSION_SRC: &str = "`|\\$[({\\['\\\"\\\\]|\\\\\\n";
pub static HEREDOC_EXPANSION: LazyLock<Regex> = LazyLock::new(|| compile(HEREDOC_EXPANSION_SRC));

pub static COMPOUND_WORDS: &[&str] = &["!", "case", "coproc", "do", "done", "elif", "else", "esac", "fi", "for", "function", "if", "select", "then", "until", "while", "{", "}"];
static COMPOUND_WORDS_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| COMPOUND_WORDS.iter().copied().collect());
pub fn in_compound_words(word: &str) -> bool {
    COMPOUND_WORDS_SET.contains(word)
}

pub static STARTUP_KEY_FILES: &[&str] = &[".zshrc", ".zshenv", ".zprofile", ".bashrc", ".bash_profile", ".profile"];
const KEY_NAME_PATTERN_SRC: &str = "[A-Za-z_][A-Za-z0-9_]*";
pub static KEY_NAME_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(KEY_NAME_PATTERN_SRC));
pub static KEY_NAME_PATTERN_FULL: LazyLock<Regex> = LazyLock::new(|| compile(&format!(r"\A(?:{KEY_NAME_PATTERN_SRC})\z")));

const KEY_ASSIGNMENT_PATTERN_SRC: &str = "[ \\t]*(?:(?:export|readonly|declare|typeset)[ \\t]+(?:-[A-Za-z]+[ \\t]+)*)?([A-Za-z_][A-Za-z0-9_]*)=(.*)";
pub static KEY_ASSIGNMENT_PATTERN: LazyLock<Regex> = LazyLock::new(|| compile(KEY_ASSIGNMENT_PATTERN_SRC));

pub const MAX_KEY_NAMES: usize = 50;
pub const MAX_STARTUP_FILE_LINES: usize = 20000;
pub const MAX_STARTUP_LINE_CHARS: usize = 65536;
const ADDRESS_LOOKUP_COMMAND_SRC: &str = "(?i)(?i)ifconfig\\.(?:me|co)|icanhazip|ipinfo\\.io|ipify|checkip\\.|ident\\.me|myexternalip|ip-api\\.com|ipecho|wtfismyip|whatismyip";
pub static ADDRESS_LOOKUP_COMMAND: LazyLock<Regex> = LazyLock::new(|| compile(ADDRESS_LOOKUP_COMMAND_SRC));

pub static SENSITIVE_FLAGS: &[&str] = &["--api-key", "--client-secret", "--credential", "--credentials", "--password", "--private-key", "--secret", "--show-token", "--token"];
static SENSITIVE_FLAGS_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| SENSITIVE_FLAGS.iter().copied().collect());
pub fn in_sensitive_flags(word: &str) -> bool {
    SENSITIVE_FLAGS_SET.contains(word)
}

pub static SENSITIVE_PATH_FRAGMENTS: &[&str] = &["/.aws/credentials", "/.config/gh/hosts.yml", "/.config/git/config", "/.docker/config.json", "/.git/config", "/.git/objects/", "/.gnupg/", "/.kube/config", "/.netrc", "/.npmrc", "/.pypirc", "/.ssh/", "/.gitconfig"];
pub const TEMPLATE_SUFFIX: &str = "(?!\\.(?:example|sample|template|dist)(?![A-Za-z0-9_-]))";
pub static SAFE_CONFIG_KEYS: &[&str] = &["commit.gpgsign", "core.autocrlf", "core.bare", "core.eol", "core.filemode", "core.hookspath", "core.ignorecase", "core.logallrefupdates", "core.longpaths", "core.precomposeunicode", "core.repositoryformatversion", "core.sparsecheckout", "core.symlinks", "core.untrackedcache", "extensions.worktreeconfig", "fetch.prune", "init.defaultbranch", "merge.ff", "pull.ff", "pull.rebase", "push.autosetupremote", "push.default", "rebase.autostash", "status.showuntrackedfiles", "tag.gpgsign"];
static SAFE_CONFIG_KEYS_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| SAFE_CONFIG_KEYS.iter().copied().collect());
pub fn in_safe_config_keys(word: &str) -> bool {
    SAFE_CONFIG_KEYS_SET.contains(word)
}

pub static SAFE_CONFIG_WORDS: &[&str] = &["autosetupremote", "defaultbranch", "hookspath", "logallrefupdates", "precomposeunicode", "repositoryformatversion", "showuntrackedfiles", "sparsecheckout", "untrackedcache", "worktreeconfig"];
static SAFE_CONFIG_WORDS_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| SAFE_CONFIG_WORDS.iter().copied().collect());
pub fn in_safe_config_words(word: &str) -> bool {
    SAFE_CONFIG_WORDS_SET.contains(word)
}

pub static CONFIG_SCOPES: &[&str] = &["--global", "--local", "--system", "--worktree"];
const CONFIG_ENVIRONMENT_SRC: &str = "git_(?:config|dir|common_dir|work_tree|index_file|object_directory|alternate_object_directories|namespace)";
pub static CONFIG_ENVIRONMENT: LazyLock<Regex> = LazyLock::new(|| compile(CONFIG_ENVIRONMENT_SRC));

pub static SEPARATORS_AFTER_QUIET: &[&str] = &["", "\n", "&", "&&", ";", "||"];
const UNRESOLVED_WORD_SRC: &str = "[$`*?{}\\\\]";
pub static UNRESOLVED_WORD: LazyLock<Regex> = LazyLock::new(|| compile(UNRESOLVED_WORD_SRC));

const GREP_ENVIRONMENT_SRC: &str = "grep_(?:options|color)";
pub static GREP_ENVIRONMENT: LazyLock<Regex> = LazyLock::new(|| compile(GREP_ENVIRONMENT_SRC));

pub static NEIGHBOR_COMMANDS: &[&str] = &["[", "basename", "cat", "cd", "cmp", "cut", "df", "diff", "dirname", "du", "echo", "egrep", "false", "fgrep", "file", "git", "grep", "head", "ls", "pwd", "readlink", "realpath", "rg", "sort", "stat", "tail", "test", "tr", "true", "uniq", "wc"];
static NEIGHBOR_COMMANDS_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| NEIGHBOR_COMMANDS.iter().copied().collect());
pub fn in_neighbor_commands(word: &str) -> bool {
    NEIGHBOR_COMMANDS_SET.contains(word)
}

pub static GIT_CONFIG_FRAGMENTS: &[&str] = &["/.config/git/config", "/.git/config", "/.gitconfig"];
pub static METADATA_COMMANDS: &[&str] = &["[", "[[", "ls", "stat", "test", "wc"];
pub static GREP_COMMANDS: &[&str] = &["egrep", "fgrep", "grep", "rg"];
pub static GREP_COUNTING_FLAGS: &[&str] = &["L", "c", "l", "q"];
pub static GREP_VALUE_FLAGS: &[&str] = &["A", "B", "C", "D", "d", "e", "f", "m"];
pub static GREP_PLAIN_FLAGS: &[&str] = &["E", "F", "G", "H", "I", "a", "h", "i", "n", "s", "w"];
static GREP_PLAIN_FLAGS_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| GREP_PLAIN_FLAGS.iter().copied().collect());
pub fn in_grep_plain_flags(word: &str) -> bool {
    GREP_PLAIN_FLAGS_SET.contains(word)
}

pub static GREP_COUNTING_OPTIONS: &[&str] = &["--count", "--files-with-matches", "--files-without-match", "--quiet", "--silent"];
pub static GREP_PLAIN_OPTIONS: &[&str] = &["--ignore-case", "--line-number", "--no-filename", "--no-messages", "--with-filename", "--word-regexp"];
pub const SECRET_FILE_EXEMPT: &str = "(?!(?:\\.[a-z0-9_-]{1,64}){0,8}\\.(?:pub|example|sample|template|dist)(?![^\\s\\\"'|;&<>()=:/]))";
pub const SECRET_FILE_NAME: &str = "\\.pgpass|\\.my\\.cnf|\\.git-credentials|\\.vault-token|\\.dev\\.vars|\\.envrc|id_(?:rsa|dsa|ecdsa|ed25519)(?:_[a-z0-9]+)?|credentials\\.json|secrets?\\.(?:json|ya?ml|toml)|service[-_]account[^\\s\\\"'|;&<>()=:/]{0,256}\\.json|kubeconfig|terraform\\.tfstate(?:\\.backup)?|[^\\s\\\"'|;&<>()=:/]{0,256}\\.(?:pem|key|p12|pfx|jks|keystore|p8|tfstate|tfvars)";
pub static GENERIC_PRIVATE_SUBCOMMANDS: &[&str] = &["account", "auth", "credential", "credentials", "identity", "org", "organization", "profile", "user"];
static GENERIC_PRIVATE_SUBCOMMANDS_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| GENERIC_PRIVATE_SUBCOMMANDS.iter().copied().collect());
pub fn in_generic_private_subcommands(word: &str) -> bool {
    GENERIC_PRIVATE_SUBCOMMANDS_SET.contains(word)
}

pub static GENERIC_PRIVATE_ACTIONS: &[&str] = &["current", "get", "list", "login", "logout", "org", "show", "status", "switch", "whoami"];
static GENERIC_PRIVATE_ACTIONS_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| GENERIC_PRIVATE_ACTIONS.iter().copied().collect());
pub fn in_generic_private_actions(word: &str) -> bool {
    GENERIC_PRIVATE_ACTIONS_SET.contains(word)
}

pub static SAFE_LOG_PLACEHOLDERS: &[&str] = &["D", "H", "P", "S", "T", "d", "e", "f", "h", "m", "n", "p", "s", "t"];
static SAFE_LOG_PLACEHOLDERS_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| SAFE_LOG_PLACEHOLDERS.iter().copied().collect());
pub fn in_safe_log_placeholders(word: &str) -> bool {
    SAFE_LOG_PLACEHOLDERS_SET.contains(word)
}

pub static SAFE_LOG_DATE_LETTERS: &[(&str, &str)] = &[("a", "dDiIstr"), ("c", "dDiIstr"), ("g", "Dds")];
pub static SAFE_PRETTY_NAMES: &[&str] = &["oneline", "reference"];
pub static SAFE_FOR_EACH_REF_FIELDS: &[&str] = &["HEAD", "ahead-behind", "align", "authordate", "color", "committerdate", "creatordate", "deltabase", "describe", "else", "end", "flag", "head", "if", "numparent", "object", "objectname", "objectsize", "objecttype", "parent", "push", "refname", "rest", "subject", "symref", "tag", "taggerdate", "then", "tree", "type", "upstream", "worktreepath"];
static SAFE_FOR_EACH_REF_FIELDS_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| SAFE_FOR_EACH_REF_FIELDS.iter().copied().collect());
pub fn in_safe_for_each_ref_fields(word: &str) -> bool {
    SAFE_FOR_EACH_REF_FIELDS_SET.contains(word)
}

pub static SAFE_ENV_KEYS: &[&str] = &["SSH_AUTH_SOCK", "TERM"];
pub static DEFAULT_LOCAL_ONLY: &[&str] = &["CLAUDE.local.md"];
const LOCAL_ONLY_ENTRY_SRC: &str = "[A-Za-z0-9._][A-Za-z0-9._/-]*";
pub static LOCAL_ONLY_ENTRY: LazyLock<Regex> = LazyLock::new(|| compile(LOCAL_ONLY_ENTRY_SRC));
pub static LOCAL_ONLY_ENTRY_FULL: LazyLock<Regex> = LazyLock::new(|| compile(&format!(r"\A(?:{LOCAL_ONLY_ENTRY_SRC})\z")));

static HIST_CORE: LazyLock<Regex> = LazyLock::new(|| compile("(?i)(?:^|[\\s\\\"'=:(<>|;&/{`])(?:\\.(?P<name>zsh_history|bash_history|sh_history|history|zhistory|python_history|psql_history|mysql_history|sqlite_history|node_repl_history|irb_history|rediscli_history|dbshell|viminfo|lesshst|Rhistory)|\\.(?P<folder>zsh_sessions|bash_sessions|local/share/fish|local/state/zsh|local/share/zsh|cache/zsh|local/share/atuin))"));
static HIST_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A(?:(?i)(?:^|[\\s\\\"'=:(<>|;&/{`])(?:\\.(?P<name>zsh_history|bash_history|sh_history|history|zhistory|python_history|psql_history|mysql_history|sqlite_history|node_repl_history|irb_history|rediscli_history|dbshell|viminfo|lesshst|Rhistory)|\\.(?P<folder>zsh_sessions|bash_sessions|local/share/fish|local/state/zsh|local/share/zsh|cache/zsh|local/share/atuin)))\\z"));
static FILE_CORE: LazyLock<Regex> = LazyLock::new(|| compile("(?i)(?:^|[\\s\\\"'=:(<>|;&/{`])(?:\\.(?P<rc>zshrc|zshenv|zprofile|zlogin|zlogout|bashrc|bash_profile|bash_login|bash_logout|bash_aliases|profile|login|logout|kshrc|cshrc|tcshrc)(?P<rc_end>[^A-Za-z0-9_]|$)|\\.(?P<folder>zsh|zprezto/runcoms|oh-my-zsh/custom|config/fish|config/zsh|config/bash)/|(?P<system>(?:/private)?/etc/(?:zshrc|zprofile|zshenv|zlogin|zlogout|profile|bashrc|bash\\.bashrc|environment)|(?:/private)?/etc/(?:zsh|bash|profile\\.d)/)|\\.(?P<folder2>zsh|zprezto/runcoms|oh-my-zsh/custom|config/fish|config/zsh|config/bash)(?P<f2_end>/|[\\s\\\"';&|()<>`]|$)|\\.(?P<hname>zsh_history|bash_history|sh_history|history|zhistory|python_history|psql_history|mysql_history|sqlite_history|node_repl_history|irb_history|rediscli_history|dbshell|viminfo|lesshst|Rhistory)(?P<hn_end>[^A-Za-z0-9_]|$)|\\.(?P<hfolder>zsh_sessions|bash_sessions|local/share/fish|local/state/zsh|local/share/zsh|cache/zsh|local/share/atuin)(?P<hf_end>/|[\\s\\\"';&|()<>`]|$))"));
static FILE_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A(?:(?i)(?:^|[\\s\\\"'=:(<>|;&/{`])(?:\\.(?P<rc>zshrc|zshenv|zprofile|zlogin|zlogout|bashrc|bash_profile|bash_login|bash_logout|bash_aliases|profile|login|logout|kshrc|cshrc|tcshrc)(?P<rc_end>[^A-Za-z0-9_]|$)|\\.(?P<folder>zsh|zprezto/runcoms|oh-my-zsh/custom|config/fish|config/zsh|config/bash)/|(?P<system>(?:/private)?/etc/(?:zshrc|zprofile|zshenv|zlogin|zlogout|profile|bashrc|bash\\.bashrc|environment)|(?:/private)?/etc/(?:zsh|bash|profile\\.d)/)|\\.(?P<folder2>zsh|zprezto/runcoms|oh-my-zsh/custom|config/fish|config/zsh|config/bash)(?P<f2_end>/|[\\s\\\"';&|()<>`]|$)|\\.(?P<hname>zsh_history|bash_history|sh_history|history|zhistory|python_history|psql_history|mysql_history|sqlite_history|node_repl_history|irb_history|rediscli_history|dbshell|viminfo|lesshst|Rhistory)(?P<hn_end>[^A-Za-z0-9_]|$)|\\.(?P<hfolder>zsh_sessions|bash_sessions|local/share/fish|local/state/zsh|local/share/zsh|cache/zsh|local/share/atuin)(?P<hf_end>/|[\\s\\\"';&|()<>`]|$)))\\z"));
static BLOB_CORE: LazyLock<Regex> = LazyLock::new(|| compile("[A-Za-z0-9_./~^@+-]{0,200}:[^\\s/]\\S{0,499}"));
static BLOB_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A(?:[A-Za-z0-9_./~^@+-]{0,200}:[^\\s/]\\S{0,499})\\z"));
static PIPE_CORE: LazyLock<Regex> = LazyLock::new(|| compile("\\||`|\\$\\(|[<>]\\("));
static PIPE_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A(?:\\||`|\\$\\(|[<>]\\()\\z"));
static HERE_CORE: LazyLock<Regex> = LazyLock::new(|| compile("<<-?[ \\t]*\\w"));
static HERE_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A(?:<<-?[ \\t]*\\w)\\z"));
static UN_A: LazyLock<Regex> = LazyLock::new(|| compile("-i?regex\\b"));
static UN_B: LazyLock<Regex> = LazyLock::new(|| compile("[ \\t](?:-not|-or|-o|!)"));
static UN_A_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A-i?regex\\b\\z"));
static UN_B_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A[ \\t](?:-not|-or|-o|!)\\z"));
static JQ_CORE: LazyLock<Regex> = LazyLock::new(|| compile("(?:\\$ENV|env|strenv)\\b"));
static JQ_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A(?:(?:\\$ENV|env|strenv)\\b)\\z"));
static REMOTE_CORE: LazyLock<Regex> = LazyLock::new(|| compile("(?i)/etc/(?:shadow|gshadow|sudoers|ssh/ssh_host|ssl/private)|/root(?:/|\\b)|~root|/proc/|\\.ssh(?:/|\\b)|\\.git-credentials|\\.docker/config|\\.kube/|\\.aws/|\\.gnupg|/\\.config/"));
static REMOTE_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A(?:(?i)/etc/(?:shadow|gshadow|sudoers|ssh/ssh_host|ssl/private)|/root(?:/|\\b)|~root|/proc/|\\.ssh(?:/|\\b)|\\.git-credentials|\\.docker/config|\\.kube/|\\.aws/|\\.gnupg|/\\.config/)\\z"));
static URL_CORE: LazyLock<Regex> = LazyLock::new(|| compile("(?i)[a-z][a-z0-9+.-]*://[^\\s\\\"'<>`]+"));
static URL_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A(?:(?i)[a-z][a-z0-9+.-]*://[^\\s\\\"'<>`]+)\\z"));
static BARE_CORE: LazyLock<Regex> = LazyLock::new(|| compile("(\\d{1,3}(?:\\.\\d{1,3}){3})"));
static BARE_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A(\\d{1,3}(?:\\.\\d{1,3}){3})\\z"));
static EMU_CORE: LazyLock<Regex> = LazyLock::new(|| compile("10\\.0\\.(?:2\\.\\d{1,3}|3\\.2)"));
static EMU_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A(?:10\\.0\\.(?:2\\.\\d{1,3}|3\\.2))\\z"));
static PRIV4_CORE: LazyLock<Regex> = LazyLock::new(|| compile("(?:10(?:\\.\\d{1,3}){3}|192\\.168(?:\\.\\d{1,3}){2}|172\\.(?:1[6-9]|2\\d|3[01])(?:\\.\\d{1,3}){2}|169\\.254(?:\\.\\d{1,3}){2}|100\\.(?:6[4-9]|[7-9]\\d|1[01]\\d|12[0-7])(?:\\.\\d{1,3}){2})"));
static PRIV4_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A(?:(?:10(?:\\.\\d{1,3}){3}|192\\.168(?:\\.\\d{1,3}){2}|172\\.(?:1[6-9]|2\\d|3[01])(?:\\.\\d{1,3}){2}|169\\.254(?:\\.\\d{1,3}){2}|100\\.(?:6[4-9]|[7-9]\\d|1[01]\\d|12[0-7])(?:\\.\\d{1,3}){2}))\\z"));
static IPV4_WITH: LazyLock<Regex> = LazyLock::new(|| compile("(\\d{1,3}(?:\\.\\d{1,3}){3})(?::\\d{1,5})?"));
static IPV4_SHORT: LazyLock<Regex> = LazyLock::new(|| compile("(\\d{1,3}(?:\\.\\d{1,3}){3})"));
static IPV4_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A(\\d{1,3}(?:\\.\\d{1,3}){3})(?::\\d{1,5})?\\z"));
static LABEL_CORE: LazyLock<Regex> = LazyLock::new(|| compile("(?i)\\b(?:inet|ipv4 address(?: for [^\\s:]{1,32})?|ip address(?:es)?|public ip|external ip|server ip|remote ip)\\b(?:[ \\t]{0,16}[:=][ \\t]{0,16}|[ \\t]{1,16})(\\d{1,3}(?:\\.\\d{1,3}){3})"));
static LABEL_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A(?:(?i)\\b(?:inet|ipv4 address(?: for [^\\s:]{1,32})?|ip address(?:es)?|public ip|external ip|server ip|remote ip)\\b(?:[ \\t]{0,16}[:=][ \\t]{0,16}|[ \\t]{1,16})(\\d{1,3}(?:\\.\\d{1,3}){3}))\\z"));
static SENSITIVE_CORE: LazyLock<Regex> = LazyLock::new(|| compile("(?:^|[\\s\\\"'=:(<>|;&/])(?:\\.pgpass|\\.my\\.cnf|\\.git-credentials|\\.vault-token|\\.dev\\.vars|\\.envrc|id_(?:rsa|dsa|ecdsa|ed25519)(?:_[a-z0-9]+)?|credentials\\.json|secrets?\\.(?:json|ya?ml|toml)|service[-_]account[^\\s\\\"'|;&<>()=:/]{0,256}\\.json|kubeconfig|terraform\\.tfstate(?:\\.backup)?|[^\\s\\\"'|;&<>()=:/]{0,256}\\.(?:pem|key|p12|pfx|jks|keystore|p8|tfstate|tfvars))"));
static SENSITIVE_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A(?:(?:^|[\\s\\\"'=:(<>|;&/])(?:\\.pgpass|\\.my\\.cnf|\\.git-credentials|\\.vault-token|\\.dev\\.vars|\\.envrc|id_(?:rsa|dsa|ecdsa|ed25519)(?:_[a-z0-9]+)?|credentials\\.json|secrets?\\.(?:json|ya?ml|toml)|service[-_]account[^\\s\\\"'|;&<>()=:/]{0,256}\\.json|kubeconfig|terraform\\.tfstate(?:\\.backup)?|[^\\s\\\"'|;&<>()=:/]{0,256}\\.(?:pem|key|p12|pfx|jks|keystore|p8|tfstate|tfvars)))\\z"));
static GIT_CORE: LazyLock<Regex> = LazyLock::new(|| compile("/\\.config/git/config|/\\.git/config|/\\.gitconfig|(?:^|[\\s\\\"'=:(<>|;&/])\\.config/git/config|(?:^|[\\s\\\"'=:(<>|;&/])\\.git/config|(?:^|[\\s\\\"'=:(<>|;&/])\\.gitconfig"));
static GIT_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A(?:/\\.config/git/config|/\\.git/config|/\\.gitconfig|(?:^|[\\s\\\"'=:(<>|;&/])\\.config/git/config|(?:^|[\\s\\\"'=:(<>|;&/])\\.git/config|(?:^|[\\s\\\"'=:(<>|;&/])\\.gitconfig)\\z"));
static PATH_CORE: LazyLock<Regex> = LazyLock::new(|| compile("/\\.aws/credentials|/\\.config/gh/hosts\\.yml|/\\.config/git/config|/\\.docker/config\\.json|/\\.git/config|/\\.git/objects/|/\\.gnupg/|/\\.kube/config|/\\.netrc|/\\.npmrc|/\\.pypirc|/\\.ssh/|/\\.gitconfig|(?:^|[\\s\\\"'=:(<>|;&])\\.aws/credentials|(?:^|[\\s\\\"'=:(<>|;&])\\.config/gh/hosts\\.yml|(?:^|[\\s\\\"'=:(<>|;&])\\.config/git/config|(?:^|[\\s\\\"'=:(<>|;&])\\.docker/config\\.json|(?:^|[\\s\\\"'=:(<>|;&])\\.git/config|(?:^|[\\s\\\"'=:(<>|;&])\\.git/objects/|(?:^|[\\s\\\"'=:(<>|;&])\\.gnupg/|(?:^|[\\s\\\"'=:(<>|;&])\\.kube/config|(?:^|[\\s\\\"'=:(<>|;&])\\.netrc|(?:^|[\\s\\\"'=:(<>|;&])\\.npmrc|(?:^|[\\s\\\"'=:(<>|;&])\\.pypirc|(?:^|[\\s\\\"'=:(<>|;&])\\.ssh/|(?:^|[\\s\\\"'=:(<>|;&])\\.gitconfig"));
static PATH_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A(?:/\\.aws/credentials|/\\.config/gh/hosts\\.yml|/\\.config/git/config|/\\.docker/config\\.json|/\\.git/config|/\\.git/objects/|/\\.gnupg/|/\\.kube/config|/\\.netrc|/\\.npmrc|/\\.pypirc|/\\.ssh/|/\\.gitconfig|(?:^|[\\s\\\"'=:(<>|;&])\\.aws/credentials|(?:^|[\\s\\\"'=:(<>|;&])\\.config/gh/hosts\\.yml|(?:^|[\\s\\\"'=:(<>|;&])\\.config/git/config|(?:^|[\\s\\\"'=:(<>|;&])\\.docker/config\\.json|(?:^|[\\s\\\"'=:(<>|;&])\\.git/config|(?:^|[\\s\\\"'=:(<>|;&])\\.git/objects/|(?:^|[\\s\\\"'=:(<>|;&])\\.gnupg/|(?:^|[\\s\\\"'=:(<>|;&])\\.kube/config|(?:^|[\\s\\\"'=:(<>|;&])\\.netrc|(?:^|[\\s\\\"'=:(<>|;&])\\.npmrc|(?:^|[\\s\\\"'=:(<>|;&])\\.pypirc|(?:^|[\\s\\\"'=:(<>|;&])\\.ssh/|(?:^|[\\s\\\"'=:(<>|;&])\\.gitconfig)\\z"));
static IPV6_CORE: LazyLock<Regex> = LazyLock::new(|| compile("((?:[0-9A-Fa-f]{0,4}:){2,7}(?:\\d{1,3}(?:\\.\\d{1,3}){3}|[0-9A-Fa-f]{0,4})(?:%[A-Za-z0-9_.-]{1,32})?)(?:$|[^\\w:.]|\\.(?:$|[^\\w]))"));
static IPV6_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A(?:(?:[0-9A-Fa-f]{0,4}:){2,7}(?:\\d{1,3}(?:\\.\\d{1,3}){3}|[0-9A-Fa-f]{0,4})(?:%[A-Za-z0-9_.-]{1,32})?)\\z"));
static PRIV6_CORE: LazyLock<Regex> = LazyLock::new(|| compile("(?i)((?:fe80|f[cd][0-9a-f]{2}|[23][0-9a-f]{3})(?:(?::[0-9a-f]{1,4}){7}|(?::[0-9a-f]{1,4}){0,6}::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,5})?|(?::[0-9a-f]{1,4}){5}:\\d{1,3}(?:\\.\\d{1,3}){3}|(?::[0-9a-f]{1,4}){0,4}::(?:[0-9a-f]{1,4}:){0,3}\\d{1,3}(?:\\.\\d{1,3}){3}))(?:$|[^\\w:])"));
static PRIV6_FULL: LazyLock<Regex> = LazyLock::new(|| compile("(?i)\\A(?:(?:fe80|f[cd][0-9a-f]{2}|[23][0-9a-f]{3})(?:(?::[0-9a-f]{1,4}){7}|(?::[0-9a-f]{1,4}){0,6}::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,5})?|(?::[0-9a-f]{1,4}){5}:\\d{1,3}(?:\\.\\d{1,3}){3}|(?::[0-9a-f]{1,4}){0,4}::(?:[0-9a-f]{1,4}:){0,3}\\d{1,3}(?:\\.\\d{1,3}){3}))\\z"));
static USER_BRACKET: LazyLock<Regex> = LazyLock::new(|| compile("[A-Za-z0-9._%+-]{1,64}@\\[((?:[0-9A-Fa-f]{0,4}:){2,7}(?:\\d{1,3}(?:\\.\\d{1,3}){3}|[0-9A-Fa-f]{0,4})(?:%[A-Za-z0-9_.-]{1,32})?)\\]"));
static USER_PLAIN: LazyLock<Regex> = LazyLock::new(|| compile("[A-Za-z0-9._%+-]{1,64}@((?:[0-9A-Fa-f]{0,4}:){2,7}(?:\\d{1,3}(?:\\.\\d{1,3}){3}|[0-9A-Fa-f]{0,4})(?:%[A-Za-z0-9_.-]{1,32})?)(?:$|[^\\w:.]|\\.(?:$|[^\\w]))"));
static USER_BRACKET_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A[A-Za-z0-9._%+-]{1,64}@\\[((?:[0-9A-Fa-f]{0,4}:){2,7}(?:\\d{1,3}(?:\\.\\d{1,3}){3}|[0-9A-Fa-f]{0,4})(?:%[A-Za-z0-9_.-]{1,32})?)\\]\\z"));
static USER_PLAIN_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A[A-Za-z0-9._%+-]{1,64}@((?:[0-9A-Fa-f]{0,4}:){2,7}(?:\\d{1,3}(?:\\.\\d{1,3}){3}|[0-9A-Fa-f]{0,4})(?:%[A-Za-z0-9_.-]{1,32})?)\\z"));
static LOGIN_CORE: LazyLock<Regex> = LazyLock::new(|| compile("Welcome to (?:Ubuntu|Debian|Fedora|CentOS|Amazon Linux|Alpine|Red Hat|Rocky|AlmaLinux|openSUSE|Arch|FreeBSD|Raspbian)\\b|System information as of |\\bIPv[46] address for [^\\s:]{1,32}:|Last login: [^\\n]{0,80} from \\S|Warning: Permanently added |The authenticity of host |\\bConnection to \\S{1,255} closed|\\bConnection (?:reset|closed) by (?:(?:invalid|authenticating) user \\S{1,64} )?\\S{1,255} port \\d{1,5}|\\bDisconnected from (?:(?:invalid|authenticating) user \\S{1,64} )?\\S{1,255} port \\d{1,5}|\\bReceived disconnect from \\S{1,255} port \\d{1,5}|\\bUnable to negotiate with \\S|\\bConnecting to \\S{1,255} \\[|ssh: (?:connect to host|Could not resolve hostname) \\S|REMOTE HOST IDENTIFICATION HAS CHANGED|\\bOffending [A-Za-z0-9-]{1,16} key in \\S|\\bThe fingerprint for the [A-Za-z0-9-]{1,16} key sent by the remote host|\\bAdd correct host key in \\S|(?i:\\bhost key for \\S{1,255} (?:has changed|was revoked|is marked as revoked))|REVOKED HOST KEY DETECTED|differs from the key for the IP address|\\bNo [A-Za-z0-9-]{1,16} host key is known for \\S|known by the following other names/addresses|\\bConnection timed out during banner exchange|\\bConnection to \\S{1,255} port \\d{1,5}\\b|(?m:^# \\S{1,255}:\\d{1,5} SSH-\\d)|(?m:^Connected to [A-Za-z0-9-]{1,63}(?:\\.[A-Za-z0-9-]{1,63}){1,10}\\.[ \\t]*$)|\\bfailed to connect to \\S{1,255} \\(|\\bcould not get canonical name for \\S|\\bMOSH CONNECT \\d{1,5} \\S"));
static LOGIN_FULL: LazyLock<Regex> = LazyLock::new(|| compile("\\A(?:Welcome to (?:Ubuntu|Debian|Fedora|CentOS|Amazon Linux|Alpine|Red Hat|Rocky|AlmaLinux|openSUSE|Arch|FreeBSD|Raspbian)\\b|System information as of |\\bIPv[46] address for [^\\s:]{1,32}:|Last login: [^\\n]{0,80} from \\S|Warning: Permanently added |The authenticity of host |\\bConnection to \\S{1,255} closed|\\bConnection (?:reset|closed) by (?:(?:invalid|authenticating) user \\S{1,64} )?\\S{1,255} port \\d{1,5}|\\bDisconnected from (?:(?:invalid|authenticating) user \\S{1,64} )?\\S{1,255} port \\d{1,5}|\\bReceived disconnect from \\S{1,255} port \\d{1,5}|\\bUnable to negotiate with \\S|\\bConnecting to \\S{1,255} \\[|ssh: (?:connect to host|Could not resolve hostname) \\S|REMOTE HOST IDENTIFICATION HAS CHANGED|\\bOffending [A-Za-z0-9-]{1,16} key in \\S|\\bThe fingerprint for the [A-Za-z0-9-]{1,16} key sent by the remote host|\\bAdd correct host key in \\S|(?i:\\bhost key for \\S{1,255} (?:has changed|was revoked|is marked as revoked))|REVOKED HOST KEY DETECTED|differs from the key for the IP address|\\bNo [A-Za-z0-9-]{1,16} host key is known for \\S|known by the following other names/addresses|\\bConnection timed out during banner exchange|\\bConnection to \\S{1,255} port \\d{1,5}\\b|(?m:^# \\S{1,255}:\\d{1,5} SSH-\\d)|(?m:^Connected to [A-Za-z0-9-]{1,63}(?:\\.[A-Za-z0-9-]{1,63}){1,10}\\.[ \\t]*$)|\\bfailed to connect to \\S{1,255} \\(|\\bcould not get canonical name for \\S|\\bMOSH CONNECT \\d{1,5} \\S)\\z"));

fn next_pos(text: &str, pos: usize) -> usize {
    match text.get(pos..) {
        Some(rest) => match rest.chars().next() {
            Some(ch) => pos.saturating_add(ch.len_utf8()),
            None => text.len(),
        },
        None => text.len(),
    }
}

fn prev_char(text: &str, index: usize) -> Option<char> {
    text.get(..index)?.chars().next_back()
}

fn char_at(text: &str, index: usize) -> Option<char> {
    text.get(index..)?.chars().next()
}

fn class_has(class: &regex::Regex, ch: char) -> bool {
    let mut buf = [0u8; 4];
    class.is_match(ch.encode_utf8(&mut buf))
}

fn prefix_has(class: &regex::Regex, text: &str, index: usize) -> bool {
    match text.get(index..) {
        Some(rest) => class.is_match(rest),
        None => false,
    }
}

static WORD_DOT: LazyLock<regex::Regex> = LazyLock::new(|| compile(r"\A[\w.]\z"));
static WORD_DOT_DASH: LazyLock<regex::Regex> = LazyLock::new(|| compile(r"\A[\w.-]\z"));
static WORD_COLON_DOT: LazyLock<regex::Regex> = LazyLock::new(|| compile(r"\A[\w:.]\z"));
static WORD_COLON: LazyLock<regex::Regex> = LazyLock::new(|| compile(r"\A[\w:]\z"));
static SCHEME_CHAR: LazyLock<regex::Regex> = LazyLock::new(|| compile(r"(?i)\A[a-z0-9+.-]\z"));
static NAME_END_CHAR: LazyLock<regex::Regex> = LazyLock::new(|| compile(r#"\A[\s\"';&|()<>`]\z"#));
static WS_COLON: LazyLock<regex::Regex> = LazyLock::new(|| compile(r"\A\s*:"));
static IPV4_TAIL: LazyLock<regex::Regex> = LazyLock::new(|| compile(r"\A(?:\w|\.\w)"));
static PRIV4_TAIL: LazyLock<regex::Regex> = LazyLock::new(|| compile(r"\A(?:\w|\.\d)"));
static SUFFIX_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| compile(r"\A\.(?:example|sample|template|dist)(?:\z|[^A-Za-z0-9_-])"));
static EXEMPT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    compile(
        r#"\A(?:\.[a-z0-9_-]{1,64}){0,8}\.(?:pub|example|sample|template|dist)(?:\z|[\s"'|;&<>()=:/])"#,
    )
});
static LOGIN_HOST: LazyLock<regex::Regex> =
    LazyLock::new(|| compile(r"Connection to (\S{1,255}) port \d{1,5}\b"));
static LOGIN_CONNECTED: LazyLock<regex::Regex> = LazyLock::new(|| {
    compile(r"(?m)^Connected to ([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,10})\.[ \t]*$")
});
static LOGIN_FORBIDDEN: LazyLock<regex::Regex> =
    LazyLock::new(|| compile(r"\Alocalhost\b|127\.|\[?::1\b"));
static LOGIN_FORBIDDEN_SHORT: LazyLock<regex::Regex> =
    LazyLock::new(|| compile(r"\Alocalhost\b|127\."));
static DOC_PREFIX: LazyLock<regex::Regex> = LazyLock::new(|| compile(r"(?i)\A2001:0?db8:"));

fn ascii_word(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn ascii_file_tail(ch: char) -> bool {
    ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-'
}

fn empty_groups() -> Vec<Option<String>> {
    Vec::new()
}

fn one_group(caps: &Captures<'_>, index: usize) -> Vec<Option<String>> {
    vec![caps.get(index).map(|item| item.as_str().to_owned())]
}

struct Hit {
    start: usize,
    end: usize,
    groups: Vec<Option<String>>,
}

fn into_found(hit: Hit) -> Found {
    Found {
        start: hit.start,
        end: hit.end,
        groups: hit.groups,
    }
}

fn scan(
    text: &str,
    re: &regex::Regex,
    accept: impl Fn(&str, &Captures<'_>) -> bool,
    logical: impl Fn(&Captures<'_>) -> Option<(usize, usize)>,
    groups: impl Fn(&Captures<'_>) -> Vec<Option<String>>,
) -> Vec<Found> {
    let mut found = Vec::new();
    let mut pos = 0usize;
    let length = text.len();
    while pos <= length {
        let Some(caps) = re.captures_at(text, pos) else {
            break;
        };
        let Some(whole) = caps.get(0) else {
            break;
        };
        if accept(text, &caps) {
            if let Some((start, end)) = logical(&caps) {
                found.push(into_found(Hit {
                    start,
                    end,
                    groups: groups(&caps),
                }));
                let nxt = if end > pos { end } else { next_pos(text, pos) };
                if nxt == pos {
                    break;
                }
                pos = nxt;
                continue;
            }
        }
        let nxt = next_pos(text, whole.start());
        if nxt <= pos {
            break;
        }
        pos = nxt;
    }
    found
}

fn whole_span(caps: &Captures<'_>) -> Option<(usize, usize)> {
    caps.get(0).map(|item| (item.start(), item.end()))
}

fn search_of(mut hits: Vec<Found>) -> Option<Found> {
    if hits.is_empty() {
        None
    } else {
        Some(hits.remove(0))
    }
}

fn match_of(hits: Vec<Found>) -> Option<Found> {
    let first = search_of(hits)?;
    if first.start == 0 {
        Some(first)
    } else {
        None
    }
}

fn name_end_ok(text: &str, end: usize) -> bool {
    match char_at(text, end) {
        None => true,
        Some('/') => true,
        Some(ch) => class_has(&NAME_END_CHAR, ch),
    }
}

fn alnum_boundary(text: &str, end: usize) -> bool {
    match char_at(text, end) {
        None => true,
        Some(ch) => !ascii_word(ch),
    }
}

fn accept_hist(text: &str, caps: &Captures<'_>) -> bool {
    if caps.name("name").is_some() {
        alnum_boundary(text, caps.get(0).map(|item| item.end()).unwrap_or(0))
    } else {
        name_end_ok(text, caps.get(0).map(|item| item.end()).unwrap_or(0))
    }
}

fn file_span(caps: &Captures<'_>) -> Option<(usize, usize)> {
    let whole = caps.get(0)?;
    let mut end = whole.end();
    for name in ["rc_end", "hn_end", "f2_end", "hf_end"] {
        if let Some(extra) = caps.name(name) {
            if extra.start() != extra.end() {
                end = extra.start();
            }
        }
    }
    Some((whole.start(), end))
}

fn accept_file(text: &str, caps: &Captures<'_>) -> bool {
    if caps.name("system").is_none() {
        return true;
    }
    let end = caps.get(0).map(|item| item.end()).unwrap_or(0);
    let whole = caps.get(0).map(|item| item.as_str()).unwrap_or("");
    if whole.ends_with('/') {
        return true;
    }
    alnum_boundary(text, end)
}

fn accept_pipe(text: &str, caps: &Captures<'_>) -> bool {
    let Some(whole) = caps.get(0) else {
        return false;
    };
    if whole.as_str() != "|" {
        return true;
    }
    let prev_ok = !matches!(prev_char(text, whole.start()), Some('|'));
    let next_ok = !matches!(char_at(text, whole.end()), Some('|'));
    prev_ok && next_ok
}

fn accept_here(text: &str, caps: &Captures<'_>) -> bool {
    let Some(whole) = caps.get(0) else {
        return false;
    };
    !matches!(prev_char(text, whole.start()), Some('<'))
}

fn accept_jq(text: &str, caps: &Captures<'_>) -> bool {
    let Some(whole) = caps.get(0) else {
        return false;
    };
    if let Some(prev) = prev_char(text, whole.start()) {
        if prev == '"' || class_has(&WORD_DOT, prev) {
            return false;
        }
    }
    !prefix_has(&WS_COLON, text, whole.end())
}

fn accept_remote(text: &str, caps: &Captures<'_>) -> bool {
    let Some(whole) = caps.get(0) else {
        return false;
    };
    if whole.as_str().to_lowercase().ends_with("~root") {
        if let Some(ch) = char_at(text, whole.end()) {
            if class_has(&WORD_DOT_DASH, ch) {
                return false;
            }
        }
    }
    true
}

fn accept_url(text: &str, caps: &Captures<'_>) -> bool {
    let Some(whole) = caps.get(0) else {
        return false;
    };
    match prev_char(text, whole.start()) {
        None => true,
        Some(ch) => !class_has(&SCHEME_CHAR, ch),
    }
}

fn prev_word_dot(text: &str, start: usize) -> bool {
    match prev_char(text, start) {
        Some(ch) => class_has(&WORD_DOT, ch),
        None => false,
    }
}

fn accept_bare(text: &str, caps: &Captures<'_>) -> bool {
    let Some(whole) = caps.get(0) else {
        return false;
    };
    if prev_word_dot(text, whole.start()) {
        return false;
    }
    match char_at(text, whole.end()) {
        Some(ch) => !class_has(&WORD_DOT, ch),
        None => true,
    }
}

fn accept_emu(text: &str, caps: &Captures<'_>) -> bool {
    let Some(whole) = caps.get(0) else {
        return false;
    };
    if prev_word_dot(text, whole.start()) {
        return false;
    }
    !prefix_has(&PRIV4_TAIL, text, whole.end())
}

fn accept_priv4(text: &str, caps: &Captures<'_>) -> bool {
    accept_emu(text, caps)
}

fn accept_label(text: &str, caps: &Captures<'_>) -> bool {
    let Some(whole) = caps.get(0) else {
        return false;
    };
    match char_at(text, whole.end()) {
        Some(ch) => !class_has(&WORD_DOT, ch),
        None => true,
    }
}

fn accept_sensitive(text: &str, caps: &Captures<'_>) -> bool {
    let Some(whole) = caps.get(0) else {
        return false;
    };
    if let Some(ch) = char_at(text, whole.end()) {
        if ascii_file_tail(ch) {
            return false;
        }
    }
    !prefix_has(&EXEMPT_RE, text, whole.end())
}

fn accept_suffix(text: &str, caps: &Captures<'_>) -> bool {
    let Some(whole) = caps.get(0) else {
        return false;
    };
    whole.as_str().ends_with('/') || !prefix_has(&SUFFIX_RE, text, whole.end())
}

fn accept_ipv6(text: &str, caps: &Captures<'_>) -> bool {
    let Some(body) = caps.get(1) else {
        return false;
    };
    match prev_char(text, body.start()) {
        Some(ch) => !class_has(&WORD_COLON_DOT, ch),
        None => true,
    }
}

fn accept_priv6(text: &str, caps: &Captures<'_>) -> bool {
    let Some(body) = caps.get(1) else {
        return false;
    };
    if DOC_PREFIX.is_match(body.as_str()) {
        return false;
    }
    match prev_char(text, body.start()) {
        Some(ch) => !class_has(&WORD_COLON, ch),
        None => true,
    }
}

fn body_span(caps: &Captures<'_>) -> Option<(usize, usize)> {
    caps.get(1).map(|item| (item.start(), item.end()))
}

fn accept_login(text: &str, caps: &Captures<'_>) -> bool {
    let _ = text;
    let Some(whole) = caps.get(0) else {
        return false;
    };
    let chunk = whole.as_str();
    if let Some(host) = LOGIN_HOST.captures(chunk) {
        if let Some(name) = host.get(1) {
            if LOGIN_FORBIDDEN.is_match(name.as_str()) {
                return false;
            }
        }
    }
    if let Some(host) = LOGIN_CONNECTED.captures(chunk) {
        if let Some(name) = host.get(1) {
            if LOGIN_FORBIDDEN_SHORT.is_match(name.as_str()) {
                return false;
            }
        }
    }
    true
}

fn find_un(text: &str) -> Vec<Found> {
    let mut found = Vec::new();
    let mut pos = 0usize;
    while pos <= text.len() {
        let left = UN_A.captures_at(text, pos);
        let right = UN_B.captures_at(text, pos);
        let left_at = left.as_ref().and_then(|caps| caps.get(0)).map(|item| item.start());
        let right_at = right.as_ref().and_then(|caps| caps.get(0)).map(|item| item.start());
        let prefer_left = match (left_at, right_at) {
            (Some(lhs), Some(rhs)) => lhs <= rhs,
            (Some(_), None) => true,
            _ => false,
        };
        if left.is_none() && right.is_none() {
            break;
        }
        if prefer_left {
            let Some(caps) = left else { break };
            let Some(whole) = caps.get(0) else { break };
            let start = whole.start();
            let end = whole.end();
            found.push(Found {
                start,
                end,
                groups: empty_groups(),
            });
            let nxt = if end > pos { end } else { next_pos(text, pos) };
            if nxt == pos {
                break;
            }
            pos = nxt;
            continue;
        }
        let Some(caps) = right else { break };
        let Some(whole) = caps.get(0) else { break };
        let start = whole.start();
        let end = whole.end();
        let ok = match char_at(text, end) {
            None => true,
            Some(' ' | '\t') => true,
            Some('\n') => end == text.len().saturating_sub(1),
            Some(_) => false,
        };
        if ok {
            found.push(Found {
                start,
                end,
                groups: empty_groups(),
            });
            let nxt = if end > pos { end } else { next_pos(text, pos) };
            if nxt == pos {
                break;
            }
            pos = nxt;
        } else {
            let nxt = next_pos(text, start);
            if nxt <= pos {
                break;
            }
            pos = nxt;
        }
    }
    found
}

fn find_ipv4(text: &str) -> Vec<Found> {
    let mut found = Vec::new();
    let mut pos = 0usize;
    while pos <= text.len() {
        let Some(caps) = IPV4_WITH.captures_at(text, pos) else {
            break;
        };
        let Some(whole) = caps.get(0) else {
            break;
        };
        let start = whole.start();
        let mut chosen: Option<(usize, usize, Option<String>)> = None;
        if !prev_word_dot(text, start) {
            if !prefix_has(&IPV4_TAIL, text, whole.end()) {
                chosen = Some((
                    start,
                    whole.end(),
                    caps.get(1).map(|item| item.as_str().to_owned()),
                ));
            } else if let Some(short) = IPV4_SHORT.captures_at(text, start) {
                if let Some(body) = short.get(0) {
                    if body.start() == start && !prefix_has(&IPV4_TAIL, text, body.end()) {
                        chosen = Some((
                            start,
                            body.end(),
                            short.get(1).or_else(|| short.get(0)).map(|item| item.as_str().to_owned()),
                        ));
                    }
                }
            }
        }
        if let Some((start, end, ip)) = chosen {
            found.push(Found {
                start,
                end,
                groups: vec![ip],
            });
            let nxt = if end > pos { end } else { next_pos(text, pos) };
            if nxt == pos {
                break;
            }
            pos = nxt;
        } else {
            let nxt = next_pos(text, start);
            if nxt <= pos {
                break;
            }
            pos = nxt;
        }
    }
    found
}

fn find_user(text: &str) -> Vec<Found> {
    let mut found = Vec::new();
    let mut pos = 0usize;
    while pos <= text.len() {
        let left = USER_BRACKET.captures_at(text, pos);
        let right = USER_PLAIN.captures_at(text, pos);
        let left_at = left.as_ref().and_then(|caps| caps.get(0)).map(|item| item.start());
        let right_at = right.as_ref().and_then(|caps| caps.get(0)).map(|item| item.start());
        let prefer_left = match (left_at, right_at) {
            (Some(lhs), Some(rhs)) => lhs <= rhs,
            (Some(_), None) => true,
            _ => false,
        };
        if left.is_none() && right.is_none() {
            break;
        }
        if prefer_left {
            let Some(caps) = left else { break };
            let Some(whole) = caps.get(0) else { break };
            let end = whole.end();
            found.push(Found {
                start: whole.start(),
                end,
                groups: vec![Some("[".to_owned()), caps.get(1).map(|item| item.as_str().to_owned())],
            });
            let nxt = if end > pos { end } else { next_pos(text, pos) };
            if nxt == pos {
                break;
            }
            pos = nxt;
        } else {
            let Some(caps) = right else { break };
            let Some(whole) = caps.get(0) else { break };
            let Some(body) = caps.get(1) else { break };
            let end = body.end();
            found.push(Found {
                start: whole.start(),
                end,
                groups: vec![None, Some(body.as_str().to_owned())],
            });
            let nxt = if end > pos { end } else { next_pos(text, pos) };
            if nxt == pos {
                break;
            }
            pos = nxt;
        }
    }
    found
}

fn find_hist(text: &str) -> Vec<Found> {
    scan(text, &HIST_CORE, accept_hist, whole_span, |_| empty_groups())
}

fn find_file(text: &str) -> Vec<Found> {
    scan(text, &FILE_CORE, accept_file, file_span, |_| empty_groups())
}


static SOURCE_ENGINE_SRC: &str = r#"(?i)(?:^|[;&|({\n`]|\x01)[ \t]*(?:(?:if|then|elif|else|do|while|until|time|!)[ \t]+)*(?:source|\.)[ \t]+[\x01\"']?[^\s\"';&|()<>`]*(?:\.(?:zshrc|zshenv|zprofile|zlogin|zlogout|bashrc|bash_profile|bash_login|bash_logout|bash_aliases|profile|login|logout|kshrc|cshrc|tcshrc)(?![A-Za-z0-9_])|\.(?:zsh|zprezto/runcoms|oh-my-zsh/custom|config/fish|config/zsh|config/bash)/|(?:/private)?/etc/(?:zshrc|zprofile|zshenv|zlogin|zlogout|profile|bashrc|bash\.bashrc|environment)(?![A-Za-z0-9_])|(?:/private)?/etc/(?:zsh|bash|profile\.d)/)[^\s\"';&|()<>`]*[\"']?"#;

static SOURCE_ENGINE: LazyLock<guard_common::pyengine::PyRegex> = LazyLock::new(|| {
    guard_common::pyengine::PyRegex::new(SOURCE_ENGINE_SRC).unwrap_or_else(|_| std::process::abort())
});

fn engine_found(text: &str, hit: &guard_common::pyengine::PyMatch, chars: &[usize]) -> Found {
    let bytes = |index: usize| chars.get(index).copied().unwrap_or(text.len());
    Found {
        start: bytes(hit.start),
        end: bytes(hit.end),
        groups: hit
            .groups
            .iter()
            .map(|group| group.map(|(from, to)| text[bytes(from)..bytes(to)].to_owned()))
            .collect(),
    }
}

fn char_starts(text: &str) -> Vec<usize> {
    text.char_indices().map(|(index, _)| index).chain(std::iter::once(text.len())).collect()
}

fn engine_find(engine: &guard_common::pyengine::PyRegex, text: &str) -> Vec<Found> {
    let chars: Vec<char> = text.chars().collect();
    let starts = char_starts(text);
    engine.find_iter_chars(&chars).iter().map(|hit| engine_found(text, hit, &starts)).collect()
}

fn engine_full(engine: &guard_common::pyengine::PyRegex, text: &str) -> Option<Found> {
    let chars: Vec<char> = text.chars().collect();
    let starts = char_starts(text);
    engine.fullmatch_chars(&chars).map(|hit| engine_found(text, &hit, &starts))
}

fn find_source(text: &str) -> Vec<Found> {
    engine_find(&SOURCE_ENGINE, text)
}

fn find_blob(text: &str) -> Vec<Found> {
    scan(text, &BLOB_CORE, |_, _| true, whole_span, |_| empty_groups())
}

fn find_pipe(text: &str) -> Vec<Found> {
    scan(text, &PIPE_CORE, accept_pipe, whole_span, |_| empty_groups())
}

fn find_here(text: &str) -> Vec<Found> {
    scan(text, &HERE_CORE, accept_here, whole_span, |_| empty_groups())
}

fn find_jq(text: &str) -> Vec<Found> {
    scan(text, &JQ_CORE, accept_jq, whole_span, |_| empty_groups())
}

fn find_remote(text: &str) -> Vec<Found> {
    scan(text, &REMOTE_CORE, accept_remote, whole_span, |_| empty_groups())
}

fn find_url(text: &str) -> Vec<Found> {
    scan(text, &URL_CORE, accept_url, whole_span, |_| empty_groups())
}

fn find_bare(text: &str) -> Vec<Found> {
    scan(text, &BARE_CORE, accept_bare, whole_span, |caps| one_group(caps, 1))
}

fn find_emu(text: &str) -> Vec<Found> {
    scan(text, &EMU_CORE, accept_emu, whole_span, |_| empty_groups())
}

fn find_priv4(text: &str) -> Vec<Found> {
    scan(text, &PRIV4_CORE, accept_priv4, whole_span, |_| empty_groups())
}

fn find_label(text: &str) -> Vec<Found> {
    scan(text, &LABEL_CORE, accept_label, whole_span, |caps| one_group(caps, 1))
}

const SECRET_FILE_ALTERNATIVES: [(&str, usize); 13] = [
    (r"\.pgpass", 16),
    (r"\.my\.cnf", 16),
    (r"\.git-credentials", 32),
    (r"\.vault-token", 32),
    (r"\.dev\.vars", 16),
    (r"\.envrc", 16),
    (r"id_(?:rsa|dsa|ecdsa|ed25519)(?:_[a-z0-9]+)?", 4096),
    (r"credentials\.json", 32),
    (r"secrets?\.(?:json|ya?ml|toml)", 32),
    (r#"service[-_]account[^\s"'|;&<>()=:/]{0,256}\.json"#, 320),
    (r"kubeconfig", 16),
    (r"terraform\.tfstate(?:\.backup)?", 32),
    (r#"[^\s"'|;&<>()=:/]{0,256}\.(?:pem|key|p12|pfx|jks|keystore|p8|tfstate|tfvars)"#, 320),
];

static SECRET_FILE_NAMES: LazyLock<Vec<(Regex, usize)>> = LazyLock::new(|| {
    SECRET_FILE_ALTERNATIVES
        .iter()
        .map(|(source, reach)| (compile(&format!(r"\A(?:{source})\z")), *reach))
        .collect()
});

static SECRET_FILE_PREFIX: LazyLock<Regex> = LazyLock::new(|| compile(r#"\A[\s"'=:(<>|;&/]"#));

fn accept_sensitive_end(text: &str, end: usize) -> bool {
    if let Some(ch) = char_at(text, end) {
        if ascii_file_tail(ch) {
            return false;
        }
    }
    !prefix_has(&EXEMPT_RE, text, end)
}

fn sensitive_end(text: &str, start: usize, first_end: usize) -> Option<usize> {
    if accept_sensitive_end(text, first_end) {
        return Some(first_end);
    }
    let mut name_starts = Vec::new();
    if start == 0 {
        name_starts.push(0usize);
    }
    if let Some(ch) = char_at(text, start) {
        if SECRET_FILE_PREFIX.is_match(ch.encode_utf8(&mut [0u8; 4])) {
            name_starts.push(start.saturating_add(ch.len_utf8()));
        }
    }
    for name_start in name_starts {
        for (alternative, reach) in SECRET_FILE_NAMES.iter() {
            let mut end = name_start.saturating_add(*reach).min(text.len());
            while end > name_start {
                if text.is_char_boundary(end)
                    && alternative.is_match(&text[name_start..end])
                    && accept_sensitive_end(text, end)
                {
                    return Some(end);
                }
                end -= 1;
            }
        }
    }
    None
}

fn find_sensitive(text: &str) -> Vec<Found> {
    let mut found = Vec::new();
    let mut pos = 0usize;
    while pos <= text.len() {
        let Some(whole) = SENSITIVE_CORE.find_at(text, pos) else {
            break;
        };
        if let Some(end) = sensitive_end(text, whole.start(), whole.end()) {
            found.push(Found {
                start: whole.start(),
                end,
                groups: empty_groups(),
            });
            let next = if end > pos { end } else { next_pos(text, pos) };
            if next == pos {
                break;
            }
            pos = next;
            continue;
        }
        let next = next_pos(text, whole.start());
        if next <= pos {
            break;
        }
        pos = next;
    }
    found
}

fn find_git(text: &str) -> Vec<Found> {
    scan(text, &GIT_CORE, accept_suffix, whole_span, |_| empty_groups())
}

fn find_path(text: &str) -> Vec<Found> {
    scan(text, &PATH_CORE, accept_suffix, whole_span, |_| empty_groups())
}

fn find_ipv6(text: &str) -> Vec<Found> {
    scan(text, &IPV6_CORE, accept_ipv6, body_span, |_| empty_groups())
}

fn find_priv6(text: &str) -> Vec<Found> {
    scan(text, &PRIV6_CORE, accept_priv6, body_span, |_| empty_groups())
}

fn find_login(text: &str) -> Vec<Found> {
    scan(text, &LOGIN_CORE, accept_login, whole_span, |_| empty_groups())
}

fn full_simple(re: &regex::Regex, text: &str, accept: impl Fn(&str, &Captures<'_>) -> bool) -> Option<Found> {
    let caps = re.captures(text)?;
    let whole = caps.get(0)?;
    if whole.start() != 0 || whole.end() != text.len() || !accept(text, &caps) {
        return None;
    }
    Some(Found {
        start: 0,
        end: text.len(),
        groups: empty_groups(),
    })
}

fn full_groups(
    re: &regex::Regex,
    text: &str,
    accept: impl Fn(&str, &Captures<'_>) -> bool,
    groups: impl Fn(&Captures<'_>) -> Vec<Option<String>>,
) -> Option<Found> {
    let caps = re.captures(text)?;
    let whole = caps.get(0)?;
    if whole.start() != 0 || whole.end() != text.len() || !accept(text, &caps) {
        return None;
    }
    Some(Found {
        start: 0,
        end: text.len(),
        groups: groups(&caps),
    })
}

macro_rules! expose {
    ($search:ident, $matchf:ident, $full:ident, $iter:ident, $all:path, $fullfn:path) => {
        pub fn $search(text: &str) -> Option<Found> {
            search_of($all(text))
        }
        pub fn $matchf(text: &str) -> Option<Found> {
            match_of($all(text))
        }
        pub fn $full(text: &str) -> Option<Found> {
            $fullfn(text)
        }
        pub fn $iter(text: &str) -> Vec<Found> {
            $all(text)
        }
    };
}

fn full_hist(text: &str) -> Option<Found> {
    full_simple(&HIST_FULL, text, accept_hist)
}
fn full_file(text: &str) -> Option<Found> {
    let caps = FILE_FULL.captures(text)?;
    if !accept_file(text, &caps) {
        return None;
    }
    let (start, end) = file_span(&caps)?;
    if start == 0 && end == text.len() {
        Some(Found {
            start,
            end,
            groups: empty_groups(),
        })
    } else {
        None
    }
}
fn full_source(text: &str) -> Option<Found> {
    engine_full(&SOURCE_ENGINE, text)
}
fn full_blob(text: &str) -> Option<Found> {
    full_simple(&BLOB_FULL, text, |_, _| true)
}
fn full_pipe(text: &str) -> Option<Found> {
    full_simple(&PIPE_FULL, text, accept_pipe)
}
fn full_here(text: &str) -> Option<Found> {
    full_simple(&HERE_FULL, text, accept_here)
}
fn full_jq(text: &str) -> Option<Found> {
    full_simple(&JQ_FULL, text, accept_jq)
}
fn full_remote(text: &str) -> Option<Found> {
    full_simple(&REMOTE_FULL, text, accept_remote)
}
fn full_url(text: &str) -> Option<Found> {
    full_simple(&URL_FULL, text, accept_url)
}
fn full_bare(text: &str) -> Option<Found> {
    full_groups(&BARE_FULL, text, accept_bare, |caps| one_group(caps, 1))
}
fn full_emu(text: &str) -> Option<Found> {
    full_simple(&EMU_FULL, text, accept_emu)
}
fn full_priv4(text: &str) -> Option<Found> {
    full_simple(&PRIV4_FULL, text, accept_priv4)
}
fn full_label(text: &str) -> Option<Found> {
    full_groups(&LABEL_FULL, text, accept_label, |caps| one_group(caps, 1))
}
fn full_sensitive(text: &str) -> Option<Found> {
    full_simple(&SENSITIVE_FULL, text, accept_sensitive)
}
fn full_git(text: &str) -> Option<Found> {
    full_simple(&GIT_FULL, text, accept_suffix)
}
fn full_path(text: &str) -> Option<Found> {
    full_simple(&PATH_FULL, text, accept_suffix)
}
fn full_ipv6(text: &str) -> Option<Found> {
    full_simple(&IPV6_FULL, text, |_, _| true)
}
fn full_priv6(text: &str) -> Option<Found> {
    full_simple(&PRIV6_FULL, text, |text, caps| {
        let _ = text;
        match caps.get(1) {
            Some(body) => !DOC_PREFIX.is_match(body.as_str()),
            None => !DOC_PREFIX.is_match(caps.get(0).map(|item| item.as_str()).unwrap_or("")),
        }
    })
}
fn full_login(text: &str) -> Option<Found> {
    full_simple(&LOGIN_FULL, text, accept_login)
}
fn full_un(text: &str) -> Option<Found> {
    if UN_A_FULL.is_match(text) || UN_B_FULL.is_match(text) {
        Some(Found {
            start: 0,
            end: text.len(),
            groups: empty_groups(),
        })
    } else {
        None
    }
}
fn full_ipv4(text: &str) -> Option<Found> {
    let caps = IPV4_FULL.captures(text)?;
    Some(Found {
        start: 0,
        end: text.len(),
        groups: one_group(&caps, 1),
    })
}
fn full_user(text: &str) -> Option<Found> {
    if let Some(caps) = USER_BRACKET_FULL.captures(text) {
        return Some(Found {
            start: 0,
            end: text.len(),
            groups: vec![Some("[".to_owned()), caps.get(1).map(|item| item.as_str().to_owned())],
        });
    }
    if let Some(caps) = USER_PLAIN_FULL.captures(text) {
        return Some(Found {
            start: 0,
            end: text.len(),
            groups: vec![None, caps.get(1).map(|item| item.as_str().to_owned())],
        });
    }
    None
}

expose!(startup_history_pattern_search, startup_history_pattern_match, startup_history_pattern_fullmatch, startup_history_pattern_finditer, find_hist, full_hist);
expose!(startup_file_pattern_search, startup_file_pattern_match, startup_file_pattern_fullmatch, startup_file_pattern_finditer, find_file, full_file);
expose!(source_startup_pattern_search, source_startup_pattern_match, source_startup_pattern_fullmatch, source_startup_pattern_finditer, find_source, full_source);
expose!(git_blob_spec_search, git_blob_spec_match, git_blob_spec_fullmatch, git_blob_spec_finditer, find_blob, full_blob);
expose!(pipeline_operator_pattern_search, pipeline_operator_pattern_match, pipeline_operator_pattern_fullmatch, pipeline_operator_pattern_finditer, find_pipe, full_pipe);
expose!(heredoc_start_search, heredoc_start_match, heredoc_start_fullmatch, heredoc_start_finditer, find_here, full_here);
expose!(jq_environment_search, jq_environment_match, jq_environment_fullmatch, jq_environment_finditer, find_jq, full_jq);
expose!(remote_secret_paths_search, remote_secret_paths_match, remote_secret_paths_fullmatch, remote_secret_paths_finditer, find_remote, full_remote);
expose!(redact_url_search, redact_url_match, redact_url_fullmatch, redact_url_finditer, find_url, full_url);
expose!(bare_address_search, bare_address_match, bare_address_fullmatch, bare_address_finditer, find_bare, full_bare);
expose!(emulator_address_search, emulator_address_match, emulator_address_fullmatch, emulator_address_finditer, find_emu, full_emu);
expose!(private_address_v4_search, private_address_v4_match, private_address_v4_fullmatch, private_address_v4_finditer, find_priv4, full_priv4);
expose!(labelled_address_search, labelled_address_match, labelled_address_fullmatch, labelled_address_finditer, find_label, full_label);
expose!(sensitive_file_pattern_search, sensitive_file_pattern_match, sensitive_file_pattern_fullmatch, sensitive_file_pattern_finditer, find_sensitive, full_sensitive);
expose!(git_config_path_pattern_search, git_config_path_pattern_match, git_config_path_pattern_fullmatch, git_config_path_pattern_finditer, find_git, full_git);
expose!(sensitive_path_pattern_search, sensitive_path_pattern_match, sensitive_path_pattern_fullmatch, sensitive_path_pattern_finditer, find_path, full_path);
expose!(redact_ipv6_search, redact_ipv6_match, redact_ipv6_fullmatch, redact_ipv6_finditer, find_ipv6, full_ipv6);
expose!(private_address_v6_search, private_address_v6_match, private_address_v6_fullmatch, private_address_v6_finditer, find_priv6, full_priv6);
expose!(login_banner_pattern_search, login_banner_pattern_match, login_banner_pattern_fullmatch, login_banner_pattern_finditer, find_login, full_login);
expose!(find_uncheckable_search, find_uncheckable_match, find_uncheckable_fullmatch, find_uncheckable_finditer, find_un, full_un);
expose!(redact_ipv4_search, redact_ipv4_match, redact_ipv4_fullmatch, redact_ipv4_finditer, find_ipv4, full_ipv4);
expose!(redact_user_ipv6_search, redact_user_ipv6_match, redact_user_ipv6_fullmatch, redact_user_ipv6_finditer, find_user, full_user);

fn substitute(text: &str, hits: &[Found], replacement: &str) -> String {
    let mut out = String::new();
    let mut cursor = 0usize;
    for hit in hits {
        if hit.start < cursor {
            continue;
        }
        if let Some(prefix) = text.get(cursor..hit.start) {
            out.push_str(prefix);
        }
        out.push_str(replacement);
        cursor = hit.end;
    }
    if let Some(rest) = text.get(cursor..) {
        out.push_str(rest);
    }
    out
}

pub fn emulator_address_sub(text: &str, replacement: &str) -> String {
    substitute(text, &find_emu(text), replacement)
}

pub fn redact_url_sub(text: &str, replacement: &str) -> String {
    substitute(text, &find_url(text), replacement)
}

pub fn redact_ipv4_sub_with(text: &str, replacer: impl Fn(&Found) -> String) -> String {
    let hits = find_ipv4(text);
    let mut out = String::new();
    let mut cursor = 0usize;
    for hit in &hits {
        if hit.start < cursor {
            continue;
        }
        if let Some(prefix) = text.get(cursor..hit.start) {
            out.push_str(prefix);
        }
        out.push_str(&replacer(hit));
        cursor = hit.end;
    }
    if let Some(rest) = text.get(cursor..) {
        out.push_str(rest);
    }
    out
}

pub fn redact_ipv6_sub_with(text: &str, replacer: impl Fn(&Found) -> String) -> String {
    let hits = find_ipv6(text);
    let mut out = String::new();
    let mut cursor = 0usize;
    for hit in &hits {
        if let Some(prefix) = text.get(cursor..hit.start) {
            out.push_str(prefix);
        }
        out.push_str(&replacer(hit));
        cursor = hit.end;
    }
    if let Some(rest) = text.get(cursor..) {
        out.push_str(rest);
    }
    out
}

pub fn redact_user_ipv6_sub_with(text: &str, replacer: impl Fn(&Found) -> String) -> String {
    let hits = find_user(text);
    let mut out = String::new();
    let mut cursor = 0usize;
    for hit in &hits {
        if let Some(prefix) = text.get(cursor..hit.start) {
            out.push_str(prefix);
        }
        out.push_str(&replacer(hit));
        cursor = hit.end;
    }
    if let Some(rest) = text.get(cursor..) {
        out.push_str(rest);
    }
    out
}

fn found_json(hit: &Found) -> Value {
    let mut groups = Vec::new();
    for group in &hit.groups {
        match group {
            Some(text) => groups.push(Value::String(text.clone())),
            None => groups.push(Value::Null),
        }
    }
    let mut object = Map::new();
    object.insert(
        "span".to_owned(),
        Value::Array(vec![
            Value::Number(Number::from(hit.start)),
            Value::Number(Number::from(hit.end)),
        ]),
    );
    object.insert("groups".to_owned(), Value::Array(groups));
    Value::Object(object)
}

fn option_json(hit: Option<Found>) -> Value {
    match hit {
        Some(hit) => found_json(&hit),
        None => Value::Null,
    }
}

fn many_json(hits: Vec<Found>) -> Value {
    Value::Array(hits.iter().map(found_json).collect())
}

pub fn replay_look(function: &str, text: &str) -> Option<Value> {
    let (name, method) = function.rsplit_once('.')?;
    let value = match (name, method) {
        ("STARTUP_HISTORY_PATTERN", "search") => option_json(startup_history_pattern_search(text)),
        ("STARTUP_HISTORY_PATTERN", "match") => option_json(startup_history_pattern_match(text)),
        ("STARTUP_HISTORY_PATTERN", "fullmatch") => option_json(startup_history_pattern_fullmatch(text)),
        ("STARTUP_HISTORY_PATTERN", "finditer") => many_json(startup_history_pattern_finditer(text)),
        ("STARTUP_FILE_PATTERN", "search") => option_json(startup_file_pattern_search(text)),
        ("STARTUP_FILE_PATTERN", "match") => option_json(startup_file_pattern_match(text)),
        ("STARTUP_FILE_PATTERN", "fullmatch") => option_json(startup_file_pattern_fullmatch(text)),
        ("STARTUP_FILE_PATTERN", "finditer") => many_json(startup_file_pattern_finditer(text)),
        ("SOURCE_STARTUP_PATTERN", "search") => option_json(source_startup_pattern_search(text)),
        ("SOURCE_STARTUP_PATTERN", "match") => option_json(source_startup_pattern_match(text)),
        ("SOURCE_STARTUP_PATTERN", "fullmatch") => option_json(source_startup_pattern_fullmatch(text)),
        ("SOURCE_STARTUP_PATTERN", "finditer") => many_json(source_startup_pattern_finditer(text)),
        ("GIT_BLOB_SPEC", "search") => option_json(git_blob_spec_search(text)),
        ("GIT_BLOB_SPEC", "match") => option_json(git_blob_spec_match(text)),
        ("GIT_BLOB_SPEC", "fullmatch") => option_json(git_blob_spec_fullmatch(text)),
        ("GIT_BLOB_SPEC", "finditer") => many_json(git_blob_spec_finditer(text)),
        ("PIPELINE_OPERATOR_PATTERN", "search") => option_json(pipeline_operator_pattern_search(text)),
        ("PIPELINE_OPERATOR_PATTERN", "match") => option_json(pipeline_operator_pattern_match(text)),
        ("PIPELINE_OPERATOR_PATTERN", "fullmatch") => option_json(pipeline_operator_pattern_fullmatch(text)),
        ("PIPELINE_OPERATOR_PATTERN", "finditer") => many_json(pipeline_operator_pattern_finditer(text)),
        ("HEREDOC_START", "search") => option_json(heredoc_start_search(text)),
        ("HEREDOC_START", "match") => option_json(heredoc_start_match(text)),
        ("HEREDOC_START", "fullmatch") => option_json(heredoc_start_fullmatch(text)),
        ("HEREDOC_START", "finditer") => many_json(heredoc_start_finditer(text)),
        ("JQ_ENVIRONMENT", "search") => option_json(jq_environment_search(text)),
        ("JQ_ENVIRONMENT", "match") => option_json(jq_environment_match(text)),
        ("JQ_ENVIRONMENT", "fullmatch") => option_json(jq_environment_fullmatch(text)),
        ("JQ_ENVIRONMENT", "finditer") => many_json(jq_environment_finditer(text)),
        ("REMOTE_SECRET_PATHS", "search") => option_json(remote_secret_paths_search(text)),
        ("REMOTE_SECRET_PATHS", "match") => option_json(remote_secret_paths_match(text)),
        ("REMOTE_SECRET_PATHS", "fullmatch") => option_json(remote_secret_paths_fullmatch(text)),
        ("REMOTE_SECRET_PATHS", "finditer") => many_json(remote_secret_paths_finditer(text)),
        ("REDACT_URL", "search") => option_json(redact_url_search(text)),
        ("REDACT_URL", "match") => option_json(redact_url_match(text)),
        ("REDACT_URL", "fullmatch") => option_json(redact_url_fullmatch(text)),
        ("REDACT_URL", "finditer") => many_json(redact_url_finditer(text)),
        ("BARE_ADDRESS", "search") => option_json(bare_address_search(text)),
        ("BARE_ADDRESS", "match") => option_json(bare_address_match(text)),
        ("BARE_ADDRESS", "fullmatch") => option_json(bare_address_fullmatch(text)),
        ("BARE_ADDRESS", "finditer") => many_json(bare_address_finditer(text)),
        ("EMULATOR_ADDRESS", "search") => option_json(emulator_address_search(text)),
        ("EMULATOR_ADDRESS", "match") => option_json(emulator_address_match(text)),
        ("EMULATOR_ADDRESS", "fullmatch") => option_json(emulator_address_fullmatch(text)),
        ("EMULATOR_ADDRESS", "finditer") => many_json(emulator_address_finditer(text)),
        ("PRIVATE_ADDRESS_V4", "search") => option_json(private_address_v4_search(text)),
        ("PRIVATE_ADDRESS_V4", "match") => option_json(private_address_v4_match(text)),
        ("PRIVATE_ADDRESS_V4", "fullmatch") => option_json(private_address_v4_fullmatch(text)),
        ("PRIVATE_ADDRESS_V4", "finditer") => many_json(private_address_v4_finditer(text)),
        ("LABELLED_ADDRESS", "search") => option_json(labelled_address_search(text)),
        ("LABELLED_ADDRESS", "match") => option_json(labelled_address_match(text)),
        ("LABELLED_ADDRESS", "fullmatch") => option_json(labelled_address_fullmatch(text)),
        ("LABELLED_ADDRESS", "finditer") => many_json(labelled_address_finditer(text)),
        ("SENSITIVE_FILE_PATTERN", "search") => option_json(sensitive_file_pattern_search(text)),
        ("SENSITIVE_FILE_PATTERN", "match") => option_json(sensitive_file_pattern_match(text)),
        ("SENSITIVE_FILE_PATTERN", "fullmatch") => option_json(sensitive_file_pattern_fullmatch(text)),
        ("SENSITIVE_FILE_PATTERN", "finditer") => many_json(sensitive_file_pattern_finditer(text)),
        ("GIT_CONFIG_PATH_PATTERN", "search") => option_json(git_config_path_pattern_search(text)),
        ("GIT_CONFIG_PATH_PATTERN", "match") => option_json(git_config_path_pattern_match(text)),
        ("GIT_CONFIG_PATH_PATTERN", "fullmatch") => option_json(git_config_path_pattern_fullmatch(text)),
        ("GIT_CONFIG_PATH_PATTERN", "finditer") => many_json(git_config_path_pattern_finditer(text)),
        ("SENSITIVE_PATH_PATTERN", "search") => option_json(sensitive_path_pattern_search(text)),
        ("SENSITIVE_PATH_PATTERN", "match") => option_json(sensitive_path_pattern_match(text)),
        ("SENSITIVE_PATH_PATTERN", "fullmatch") => option_json(sensitive_path_pattern_fullmatch(text)),
        ("SENSITIVE_PATH_PATTERN", "finditer") => many_json(sensitive_path_pattern_finditer(text)),
        ("REDACT_IPV6", "search") => option_json(redact_ipv6_search(text)),
        ("REDACT_IPV6", "match") => option_json(redact_ipv6_match(text)),
        ("REDACT_IPV6", "fullmatch") => option_json(redact_ipv6_fullmatch(text)),
        ("REDACT_IPV6", "finditer") => many_json(redact_ipv6_finditer(text)),
        ("PRIVATE_ADDRESS_V6", "search") => option_json(private_address_v6_search(text)),
        ("PRIVATE_ADDRESS_V6", "match") => option_json(private_address_v6_match(text)),
        ("PRIVATE_ADDRESS_V6", "fullmatch") => option_json(private_address_v6_fullmatch(text)),
        ("PRIVATE_ADDRESS_V6", "finditer") => many_json(private_address_v6_finditer(text)),
        ("LOGIN_BANNER_PATTERN", "search") => option_json(login_banner_pattern_search(text)),
        ("LOGIN_BANNER_PATTERN", "match") => option_json(login_banner_pattern_match(text)),
        ("LOGIN_BANNER_PATTERN", "fullmatch") => option_json(login_banner_pattern_fullmatch(text)),
        ("LOGIN_BANNER_PATTERN", "finditer") => many_json(login_banner_pattern_finditer(text)),
        ("FIND_UNCHECKABLE", "search") => option_json(find_uncheckable_search(text)),
        ("FIND_UNCHECKABLE", "match") => option_json(find_uncheckable_match(text)),
        ("FIND_UNCHECKABLE", "fullmatch") => option_json(find_uncheckable_fullmatch(text)),
        ("FIND_UNCHECKABLE", "finditer") => many_json(find_uncheckable_finditer(text)),
        ("REDACT_IPV4", "search") => option_json(redact_ipv4_search(text)),
        ("REDACT_IPV4", "match") => option_json(redact_ipv4_match(text)),
        ("REDACT_IPV4", "fullmatch") => option_json(redact_ipv4_fullmatch(text)),
        ("REDACT_IPV4", "finditer") => many_json(redact_ipv4_finditer(text)),
        ("REDACT_USER_IPV6", "search") => option_json(redact_user_ipv6_search(text)),
        ("REDACT_USER_IPV6", "match") => option_json(redact_user_ipv6_match(text)),
        ("REDACT_USER_IPV6", "fullmatch") => option_json(redact_user_ipv6_fullmatch(text)),
        ("REDACT_USER_IPV6", "finditer") => many_json(redact_user_ipv6_finditer(text)),
        _ => return None,
    };
    Some(value)
}

fn plain_regex(name: &str) -> Option<&'static Regex> {
    match name {
        "OBJECT_ID_PATTERN" => Some(&OBJECT_ID_PATTERN),
        "ATTRIBUTION_PATTERN" => Some(&ATTRIBUTION_PATTERN),
        "EMAIL_PATTERN" => Some(&EMAIL_PATTERN),
        "NON_EMAIL_IDENTITY_FIELD_PATTERN" => Some(&NON_EMAIL_IDENTITY_FIELD_PATTERN),
        "PROXY_PREFIX" => Some(&PROXY_PREFIX),
        "DEFINITION_OUTPUT_PATTERN" => Some(&DEFINITION_OUTPUT_PATTERN),
        "DEFINITION_PARAMETER_PATTERN" => Some(&DEFINITION_PARAMETER_PATTERN),
        "SHELL_COMMAND_OPTION" => Some(&SHELL_COMMAND_OPTION),
        "GLOB_SYNTAX_PATTERN" => Some(&GLOB_SYNTAX_PATTERN),
        "DOTGLOB_PATTERN" => Some(&DOTGLOB_PATTERN),
        "FIND_NAME_PATTERN" => Some(&FIND_NAME_PATTERN),
        "FIND_ROOTS" => Some(&FIND_ROOTS),
        "PIPELINE_WORD_PATTERN" => Some(&PIPELINE_WORD_PATTERN),
        "HISTORY_VARIABLE_PATTERN" => Some(&HISTORY_VARIABLE_PATTERN),
        "PROCESS_ENVIRONMENT_PATTERN" => Some(&PROCESS_ENVIRONMENT_PATTERN),
        "SYSTEM_COMMAND_PATH" => Some(&SYSTEM_COMMAND_PATH),
        "JQ_PROGRAM_FILE" => Some(&JQ_PROGRAM_FILE),
        "REDACT_USER_HOST" => Some(&REDACT_USER_HOST),
        "SECRET_VARIABLE_PATTERN" => Some(&SECRET_VARIABLE_PATTERN),
        "METADATA_STARTUP_PATTERN" => Some(&METADATA_STARTUP_PATTERN),
        "HAS_KEY_STARTUP_PATTERN" => Some(&HAS_KEY_STARTUP_PATTERN),
        "TRACE_OPTION" => Some(&TRACE_OPTION),
        "TRACE_ENVIRONMENT_PATTERN" => Some(&TRACE_ENVIRONMENT_PATTERN),
        "SHADOWING_PATTERN" => Some(&SHADOWING_PATTERN),
        "JQ_PROGRAM" => Some(&JQ_PROGRAM),
        "HERE_STRING_SECRET" => Some(&HERE_STRING_SECRET),
        "HEREDOC_EXPANSION" => Some(&HEREDOC_EXPANSION),
        "KEY_NAME_PATTERN" => Some(&KEY_NAME_PATTERN),
        "KEY_ASSIGNMENT_PATTERN" => Some(&KEY_ASSIGNMENT_PATTERN),
        "ADDRESS_LOOKUP_COMMAND" => Some(&ADDRESS_LOOKUP_COMMAND),
        "CONFIG_ENVIRONMENT" => Some(&CONFIG_ENVIRONMENT),
        "UNRESOLVED_WORD" => Some(&UNRESOLVED_WORD),
        "GREP_ENVIRONMENT" => Some(&GREP_ENVIRONMENT),
        "LOCAL_ONLY_ENTRY" => Some(&LOCAL_ONLY_ENTRY),
        _ => None,
    }
}

fn plain_source(name: &str) -> Option<&'static str> {
    match name {
        "OBJECT_ID_PATTERN" => Some(OBJECT_ID_PATTERN_SRC),
        "ATTRIBUTION_PATTERN" => Some(ATTRIBUTION_PATTERN_SRC),
        "EMAIL_PATTERN" => Some(EMAIL_PATTERN_SRC),
        "NON_EMAIL_IDENTITY_FIELD_PATTERN" => Some(NON_EMAIL_IDENTITY_FIELD_PATTERN_SRC),
        "PROXY_PREFIX" => Some(PROXY_PREFIX_SRC),
        "DEFINITION_OUTPUT_PATTERN" => Some(DEFINITION_OUTPUT_PATTERN_SRC),
        "DEFINITION_PARAMETER_PATTERN" => Some(DEFINITION_PARAMETER_PATTERN_SRC),
        "SHELL_COMMAND_OPTION" => Some(SHELL_COMMAND_OPTION_SRC),
        "GLOB_SYNTAX_PATTERN" => Some(GLOB_SYNTAX_PATTERN_SRC),
        "DOTGLOB_PATTERN" => Some(DOTGLOB_PATTERN_SRC),
        "FIND_NAME_PATTERN" => Some(FIND_NAME_PATTERN_SRC),
        "FIND_ROOTS" => Some(FIND_ROOTS_SRC),
        "PIPELINE_WORD_PATTERN" => Some(PIPELINE_WORD_PATTERN_SRC),
        "HISTORY_VARIABLE_PATTERN" => Some(HISTORY_VARIABLE_PATTERN_SRC),
        "PROCESS_ENVIRONMENT_PATTERN" => Some(PROCESS_ENVIRONMENT_PATTERN_SRC),
        "SYSTEM_COMMAND_PATH" => Some(SYSTEM_COMMAND_PATH_SRC),
        "JQ_PROGRAM_FILE" => Some(JQ_PROGRAM_FILE_SRC),
        "REDACT_USER_HOST" => Some(REDACT_USER_HOST_SRC),
        "SECRET_VARIABLE_PATTERN" => Some(SECRET_VARIABLE_PATTERN_SRC),
        "METADATA_STARTUP_PATTERN" => Some(METADATA_STARTUP_PATTERN_SRC),
        "HAS_KEY_STARTUP_PATTERN" => Some(HAS_KEY_STARTUP_PATTERN_SRC),
        "TRACE_OPTION" => Some(TRACE_OPTION_SRC),
        "TRACE_ENVIRONMENT_PATTERN" => Some(TRACE_ENVIRONMENT_PATTERN_SRC),
        "SHADOWING_PATTERN" => Some(SHADOWING_PATTERN_SRC),
        "JQ_PROGRAM" => Some(JQ_PROGRAM_SRC),
        "HERE_STRING_SECRET" => Some(HERE_STRING_SECRET_SRC),
        "HEREDOC_EXPANSION" => Some(HEREDOC_EXPANSION_SRC),
        "KEY_NAME_PATTERN" => Some(KEY_NAME_PATTERN_SRC),
        "KEY_ASSIGNMENT_PATTERN" => Some(KEY_ASSIGNMENT_PATTERN_SRC),
        "ADDRESS_LOOKUP_COMMAND" => Some(ADDRESS_LOOKUP_COMMAND_SRC),
        "CONFIG_ENVIRONMENT" => Some(CONFIG_ENVIRONMENT_SRC),
        "UNRESOLVED_WORD" => Some(UNRESOLVED_WORD_SRC),
        "GREP_ENVIRONMENT" => Some(GREP_ENVIRONMENT_SRC),
        "LOCAL_ONLY_ENTRY" => Some(LOCAL_ONLY_ENTRY_SRC),
        _ => None,
    }
}

fn bytes_regex(name: &str) -> Option<&'static regex::bytes::Regex> {
    match name {
        "EVENT_PATTERN" => Some(&EVENT_PATTERN),
        _ => None,
    }
}

fn bytes_source(name: &str) -> Option<&'static str> {
    match name {
        "EVENT_PATTERN" => Some(EVENT_PATTERN_SRC),
        _ => None,
    }
}

fn sorted_value(items: &[&str]) -> Value {
    let mut copy: Vec<&str> = items.to_vec();
    copy.sort_unstable();
    Value::Array(copy.into_iter().map(|item| Value::String(item.to_owned())).collect())
}

fn ordered_value(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|item| Value::String((*item).to_owned())).collect())
}

fn constant_value(name: &str) -> Option<Value> {
    Some(match name {
        "TOOL_NAME" => Value::String(TOOL_NAME.to_owned()),
        "MAX_OUTPUT_BYTES" => Value::Number(Number::from(MAX_OUTPUT_BYTES as u64)),
        "STATUS_TIMEOUT_SECONDS" => Value::Number(Number::from(STATUS_TIMEOUT_SECONDS as u64)),
        "GIT_TIMEOUT_SECONDS" => Value::Number(Number::from(GIT_TIMEOUT_SECONDS as u64)),
        "RTK_REWRITE_TIMEOUT_SECONDS" => Value::Number(Number::from(RTK_REWRITE_TIMEOUT_SECONDS as u64)),
        "HOOK_EVENTS" => sorted_value(HOOK_EVENTS),
        "HOOK_BUDGET_SECONDS" => json!(HOOK_BUDGET_SECONDS),
        "EVENT_SEARCH_BYTES" => Value::Number(Number::from(EVENT_SEARCH_BYTES as u64)),
        "RESERVED_EMAIL_DOMAINS" => sorted_value(RESERVED_EMAIL_DOMAINS),
        "RESERVED_EMAIL_SUFFIXES" => ordered_value(RESERVED_EMAIL_SUFFIXES),
        "FIXTURE_EMAIL_DOMAINS" => sorted_value(FIXTURE_EMAIL_DOMAINS),
        "SHARED_EMAIL_LOCALS" => sorted_value(SHARED_EMAIL_LOCALS),
        "SHELL_PUNCTUATION" => sorted_value(SHELL_PUNCTUATION),
        "CLI_GLOBAL_VALUE_OPTIONS" => dict_value_cli_global_value_options(),
        "SAFE_PROXY_COMMANDS" => sorted_value(SAFE_PROXY_COMMANDS),
        "DIRECT_IDENTITY_COMMANDS" => sorted_value(DIRECT_IDENTITY_COMMANDS),
        "DEFINITION_PRINTERS" => sorted_value(DEFINITION_PRINTERS),
        "STARTUP_RC_NAMES" => Value::String(STARTUP_RC_NAMES.to_owned()),
        "STARTUP_HISTORY_NAMES" => Value::String(STARTUP_HISTORY_NAMES.to_owned()),
        "STARTUP_FOLDER_PATHS" => ordered_value(STARTUP_FOLDER_PATHS),
        "STARTUP_HISTORY_FOLDER_PATHS" => ordered_value(STARTUP_HISTORY_FOLDER_PATHS),
        "STARTUP_FOLDERS" => Value::String(STARTUP_FOLDERS.to_owned()),
        "STARTUP_HISTORY_FOLDERS" => Value::String(STARTUP_HISTORY_FOLDERS.to_owned()),
        "STARTUP_SYSTEM_FILES" => Value::String(STARTUP_SYSTEM_FILES.to_owned()),
        "STARTUP_SOURCEABLE" => Value::String(STARTUP_SOURCEABLE.to_owned()),
        "STARTUP_NAME_END" => Value::String(STARTUP_NAME_END.to_owned()),
        "STARTUP_HISTORY" => Value::String(STARTUP_HISTORY.to_owned()),
        "STARTUP_NAME" => Value::String(STARTUP_NAME.to_owned()),
        "STARTUP_BOUNDARY" => Value::String(STARTUP_BOUNDARY.to_owned()),
        "STARTUP_SAMPLE_NAMES" => ordered_value(STARTUP_SAMPLE_NAMES),
        "HEREDOC_DATA_COMMANDS" => sorted_value(HEREDOC_DATA_COMMANDS),
        "MAX_HEREDOC_LINE_CHARS" => Value::Number(Number::from(MAX_HEREDOC_LINE_CHARS as u64)),
        "HEREDOC_ARGUMENT_COMMANDS" => dict_value_heredoc_argument_commands(),
        "GH_TEXT_OPTIONS" => sorted_value(GH_TEXT_OPTIONS),
        "REMOTE_MAX_CHARS" => Value::Number(Number::from(REMOTE_MAX_CHARS as u64)),
        "REMOTE_READ_COMMANDS" => sorted_value(REMOTE_READ_COMMANDS),
        "REMOTE_FORBIDDEN_OPTIONS" => dict_value_remote_forbidden_options(),
        "REMOTE_FORBIDDEN_LONG" => dict_value_remote_forbidden_long(),
        "REMOTE_FORBIDDEN_LETTERS" => dict_value_remote_forbidden_letters(),
        "REMOTE_EXACT_LONG" => dict_value_remote_exact_long(),
        "REMOTE_VALUE_LETTERS" => dict_value_remote_value_letters(),
        "REMOTE_ATTACHED_LETTERS" => dict_value_remote_attached_letters(),
        "REMOTE_FLAG_LONG" => dict_value_remote_flag_long(),
        "DOCKER_STATS_VALUE_OPTIONS" => sorted_value(DOCKER_STATS_VALUE_OPTIONS),
        "BOOLEAN_TRUE" => sorted_value(BOOLEAN_TRUE),
        "BOOLEAN_FALSE" => sorted_value(BOOLEAN_FALSE),
        "PS_PROFILES" => dict_value_ps_profiles(),
        "PS_LONG_VALUE_OPTIONS" => sorted_value(PS_LONG_VALUE_OPTIONS),
        "DOCKER_VALUE_LETTERS" => sorted_value(DOCKER_VALUE_LETTERS),
        "DOCKER_VALUE_OPTIONS" => sorted_value(DOCKER_VALUE_OPTIONS),
        "COMPOSE_VALUE_LETTERS" => sorted_value(COMPOSE_VALUE_LETTERS),
        "COMPOSE_VALUE_OPTIONS" => sorted_value(COMPOSE_VALUE_OPTIONS),
        "SYSTEMCTL_VALUE_LETTERS" => sorted_value(SYSTEMCTL_VALUE_LETTERS),
        "SYSTEMCTL_VALUE_OPTIONS" => sorted_value(SYSTEMCTL_VALUE_OPTIONS),
        "DATE_VALUE_LETTERS" => sorted_value(DATE_VALUE_LETTERS),
        "DATE_VALUE_OPTIONS" => sorted_value(DATE_VALUE_OPTIONS),
        "UNIQ_VALUE_LETTERS" => sorted_value(UNIQ_VALUE_LETTERS),
        "UNIQ_VALUE_OPTIONS" => sorted_value(UNIQ_VALUE_OPTIONS),
        "REMOTE_SUBCOMMANDS" => dict_value_remote_subcommands(),
        "REMOTE_COMPOSE_SUBCOMMANDS" => sorted_value(REMOTE_COMPOSE_SUBCOMMANDS),
        "MAX_GLOB_WORDS" => Value::Number(Number::from(MAX_GLOB_WORDS as u64)),
        "MAX_GLOB_WORD_CHARS" => Value::Number(Number::from(MAX_GLOB_WORD_CHARS as u64)),
        "PRINTING_COMMANDS" => sorted_value(PRINTING_COMMANDS),
        "PLAIN_UTILITIES" => sorted_value(PLAIN_UTILITIES),
        "CREDENTIAL_COMMANDS" => sorted_value(CREDENTIAL_COMMANDS),
        "ENVIRONMENT_SERVICE_ACTIONS" => sorted_value(ENVIRONMENT_SERVICE_ACTIONS),
        "STARTUP_KEYWORDS" => Value::String(STARTUP_KEYWORDS.to_owned()),
        "STARTUP_COMMAND_POSITION" => Value::String(STARTUP_COMMAND_POSITION.to_owned()),
        "STARTUP_QUOTED_POSITION" => Value::String(STARTUP_QUOTED_POSITION.to_owned()),
        "TRACE_OPTION_NAMES" => sorted_value(TRACE_OPTION_NAMES),
        "TRACE_COMMANDS" => sorted_value(TRACE_COMMANDS),
        "COMPOUND_WORDS" => sorted_value(COMPOUND_WORDS),
        "STARTUP_KEY_FILES" => ordered_value(STARTUP_KEY_FILES),
        "MAX_KEY_NAMES" => Value::Number(Number::from(MAX_KEY_NAMES as u64)),
        "MAX_STARTUP_FILE_LINES" => Value::Number(Number::from(MAX_STARTUP_FILE_LINES as u64)),
        "MAX_STARTUP_LINE_CHARS" => Value::Number(Number::from(MAX_STARTUP_LINE_CHARS as u64)),
        "SENSITIVE_FLAGS" => sorted_value(SENSITIVE_FLAGS),
        "SENSITIVE_PATH_FRAGMENTS" => ordered_value(SENSITIVE_PATH_FRAGMENTS),
        "TEMPLATE_SUFFIX" => Value::String(TEMPLATE_SUFFIX.to_owned()),
        "SAFE_CONFIG_KEYS" => sorted_value(SAFE_CONFIG_KEYS),
        "SAFE_CONFIG_WORDS" => sorted_value(SAFE_CONFIG_WORDS),
        "CONFIG_SCOPES" => sorted_value(CONFIG_SCOPES),
        "SEPARATORS_AFTER_QUIET" => sorted_value(SEPARATORS_AFTER_QUIET),
        "NEIGHBOR_COMMANDS" => sorted_value(NEIGHBOR_COMMANDS),
        "GIT_CONFIG_FRAGMENTS" => ordered_value(GIT_CONFIG_FRAGMENTS),
        "METADATA_COMMANDS" => sorted_value(METADATA_COMMANDS),
        "GREP_COMMANDS" => sorted_value(GREP_COMMANDS),
        "GREP_COUNTING_FLAGS" => sorted_value(GREP_COUNTING_FLAGS),
        "GREP_VALUE_FLAGS" => sorted_value(GREP_VALUE_FLAGS),
        "GREP_PLAIN_FLAGS" => sorted_value(GREP_PLAIN_FLAGS),
        "GREP_COUNTING_OPTIONS" => sorted_value(GREP_COUNTING_OPTIONS),
        "GREP_PLAIN_OPTIONS" => sorted_value(GREP_PLAIN_OPTIONS),
        "SECRET_FILE_EXEMPT" => Value::String(SECRET_FILE_EXEMPT.to_owned()),
        "SECRET_FILE_NAME" => Value::String(SECRET_FILE_NAME.to_owned()),
        "GENERIC_PRIVATE_SUBCOMMANDS" => sorted_value(GENERIC_PRIVATE_SUBCOMMANDS),
        "GENERIC_PRIVATE_ACTIONS" => sorted_value(GENERIC_PRIVATE_ACTIONS),
        "SAFE_LOG_PLACEHOLDERS" => sorted_value(SAFE_LOG_PLACEHOLDERS),
        "SAFE_LOG_DATE_LETTERS" => dict_value_safe_log_date_letters(),
        "SAFE_PRETTY_NAMES" => sorted_value(SAFE_PRETTY_NAMES),
        "SAFE_FOR_EACH_REF_FIELDS" => sorted_value(SAFE_FOR_EACH_REF_FIELDS),
        "SAFE_ENV_KEYS" => ordered_value(SAFE_ENV_KEYS),
        "DEFAULT_LOCAL_ONLY" => ordered_value(DEFAULT_LOCAL_ONLY),
        _ => return None,
    })
}

fn dict_value_cli_global_value_options() -> Value {
    Value::Array(CLI_GLOBAL_VALUE_OPTIONS.iter().map(|(key, items)| {
        let mut copy: Vec<&str> = items.to_vec();
        copy.sort_unstable();
        json!([key, copy])
    }).collect())
}

fn dict_value_heredoc_argument_commands() -> Value {
    Value::Array(HEREDOC_ARGUMENT_COMMANDS.iter().map(|(key, items)| {
        let mut copy: Vec<&str> = items.to_vec();
        copy.sort_unstable();
        json!([key, copy])
    }).collect())
}

fn dict_value_remote_forbidden_options() -> Value {
    Value::Array(REMOTE_FORBIDDEN_OPTIONS.iter().map(|(key, items)| {
        let mut copy: Vec<&str> = items.to_vec();
        copy.sort_unstable();
        json!([key, copy])
    }).collect())
}

fn dict_value_remote_forbidden_long() -> Value {
    Value::Array(REMOTE_FORBIDDEN_LONG.iter().map(|(key, items)| {
        json!([key, items])
    }).collect())
}

fn dict_value_remote_forbidden_letters() -> Value {
    Value::Array(REMOTE_FORBIDDEN_LETTERS.iter().map(|(key, item)| json!([key, item])).collect())
}

fn dict_value_remote_exact_long() -> Value {
    Value::Array(REMOTE_EXACT_LONG.iter().map(|(key, items)| {
        let mut copy: Vec<&str> = items.to_vec();
        copy.sort_unstable();
        json!([key, copy])
    }).collect())
}

fn dict_value_remote_value_letters() -> Value {
    Value::Array(REMOTE_VALUE_LETTERS.iter().map(|(key, item)| json!([key, item])).collect())
}

fn dict_value_remote_attached_letters() -> Value {
    Value::Array(REMOTE_ATTACHED_LETTERS.iter().map(|(key, item)| json!([key, item])).collect())
}

fn dict_value_remote_flag_long() -> Value {
    Value::Array(REMOTE_FLAG_LONG.iter().map(|(key, items)| {
        let mut copy: Vec<&str> = items.to_vec();
        copy.sort_unstable();
        json!([key, copy])
    }).collect())
}

fn dict_value_ps_profiles() -> Value {
    let mut rows = Vec::new();
    for (key, unix, bsd) in PS_PROFILES {
        let mut left: Vec<String> = unix.iter().map(|ch| ch.to_string()).collect();
        let mut right: Vec<String> = bsd.iter().map(|ch| ch.to_string()).collect();
        left.sort();
        right.sort();
        rows.push(json!([key, left, right]));
    }
    Value::Array(rows)
}

fn dict_value_remote_subcommands() -> Value {
    Value::Array(REMOTE_SUBCOMMANDS.iter().map(|(key, items)| {
        let mut copy: Vec<&str> = items.to_vec();
        copy.sort_unstable();
        json!([key, copy])
    }).collect())
}

fn dict_value_safe_log_date_letters() -> Value {
    Value::Array(SAFE_LOG_DATE_LETTERS.iter().map(|(key, item)| json!([key, item])).collect())
}


fn groups_of(caps: &regex::Captures<'_>) -> Vec<Option<String>> {
    let mut groups = Vec::new();
    let mut index = 1usize;
    while index < caps.len() {
        groups.push(caps.get(index).map(|item| item.as_str().to_owned()));
        index = index.saturating_add(1);
    }
    groups
}

fn found_from(caps: &regex::Captures<'_>) -> Value {
    let Some(whole) = caps.get(0) else {
        return Value::Null;
    };
    let hit = Found { start: whole.start(), end: whole.end(), groups: groups_of(caps) };
    found_json(&hit)
}

fn bytes_found(caps: &regex::bytes::Captures<'_>) -> Value {
    let Some(whole) = caps.get(0) else {
        return Value::Null;
    };
    let mut groups = Vec::new();
    let mut index = 1usize;
    while index < caps.len() {
        groups.push(match caps.get(index) {
            Some(item) => match std::str::from_utf8(item.as_bytes()) {
                Ok(text) => Some(text.to_owned()),
                Err(_) => None,
            },
            None => None,
        });
        index = index.saturating_add(1);
    }
    found_json(&Found { start: whole.start(), end: whole.end(), groups })
}

static PLAIN_FULL: LazyLock<std::collections::HashMap<String, Regex>> = LazyLock::new(|| {
    let mut map = std::collections::HashMap::new();
    let names = [
        "OBJECT_ID_PATTERN", "ATTRIBUTION_PATTERN", "EMAIL_PATTERN", "NON_EMAIL_IDENTITY_FIELD_PATTERN", "PROXY_PREFIX", "DEFINITION_OUTPUT_PATTERN", "DEFINITION_PARAMETER_PATTERN", "SHELL_COMMAND_OPTION", "GLOB_SYNTAX_PATTERN", "DOTGLOB_PATTERN", "FIND_NAME_PATTERN", "FIND_ROOTS", "PIPELINE_WORD_PATTERN", "HISTORY_VARIABLE_PATTERN", "PROCESS_ENVIRONMENT_PATTERN", "SYSTEM_COMMAND_PATH", "JQ_PROGRAM_FILE", "REDACT_USER_HOST", "SECRET_VARIABLE_PATTERN", "METADATA_STARTUP_PATTERN", "HAS_KEY_STARTUP_PATTERN", "TRACE_OPTION", "TRACE_ENVIRONMENT_PATTERN", "SHADOWING_PATTERN", "JQ_PROGRAM", "HERE_STRING_SECRET", "HEREDOC_EXPANSION", "KEY_NAME_PATTERN", "KEY_ASSIGNMENT_PATTERN", "ADDRESS_LOOKUP_COMMAND", "CONFIG_ENVIRONMENT", "UNRESOLVED_WORD", "GREP_ENVIRONMENT", "LOCAL_ONLY_ENTRY"
    ];
    for name in names {
        let Some(source) = plain_source(name) else { continue; };
        let wrapped = format!("\\A(?:{source})\\z");
        map.insert((*name).to_owned(), compile(&wrapped));
    }
    map
});

fn case_value(search: Value, matched: Value, full: Value, found: Value) -> Value {
    json!({"search": search, "match": matched, "fullmatch": full, "finditer": found})
}

fn python_captures<'a>(re: &'a Regex, text: &'a str) -> Option<regex::Captures<'a>> {
    if let Some(caps) = re.captures(text) {
        return Some(caps);
    }
    // Python `$` also matches before one trailing newline. The regex crate does not.
    match text.strip_suffix('\n') {
        Some(stripped) => re.captures(stripped),
        None => None,
    }
}

fn python_iter(re: &Regex, text: &str) -> Vec<Value> {
    let mut rows: Vec<Value> = re.captures_iter(text).map(|caps| found_from(&caps)).collect();
    if let Some(stripped) = text.strip_suffix('\n') {
        for caps in re.captures_iter(stripped) {
            let row = found_from(&caps);
            if !rows.iter().any(|item| item == &row) {
                rows.push(row);
            }
        }
    }
    rows
}

pub fn replay(function: &str, args: &[Value]) -> Value {
    if let Some(value) = constant_value(function) {
        return value;
    }
    let text = args.first().and_then(Value::as_str).unwrap_or_default();
    if let Some((name, method)) = function.rsplit_once('.') {
        if method == "cases" {
            if let Some(value) = replay_look(&format!("{name}.search"), text) {
                let matched = replay_look(&format!("{name}.match"), text).unwrap_or(Value::Null);
                let full = replay_look(&format!("{name}.fullmatch"), text).unwrap_or(Value::Null);
                let found = replay_look(&format!("{name}.finditer"), text).unwrap_or(Value::Array(Vec::new()));
                return case_value(value, matched, full, found);
            }
            if let Some(re) = plain_regex(name) {
                let search = match python_captures(re, text) {
                    Some(caps) => found_from(&caps),
                    None => Value::Null,
                };
                let matched = match python_captures(re, text) {
                    Some(caps) => match caps.get(0) {
                        Some(whole) if whole.start() == 0 => found_from(&caps),
                        _ => Value::Null,
                    },
                    None => Value::Null,
                };
                let full = match PLAIN_FULL.get(name).and_then(|item| item.captures(text)) {
                    Some(caps) => found_from(&caps),
                    None => Value::Null,
                };
                let found = Value::Array(python_iter(re, text));
                return case_value(search, matched, full, found);
            }
            if let Some(re) = bytes_regex(name) {
                let bytes = text.as_bytes();
                let search = match re.captures(bytes) {
                    Some(caps) => bytes_found(&caps),
                    None => Value::Null,
                };
                let matched = match re.captures(bytes) {
                    Some(caps) => match caps.get(0) {
                        Some(whole) if whole.start() == 0 => bytes_found(&caps),
                        _ => Value::Null,
                    },
                    None => Value::Null,
                };
                let full = match bytes_source(name) {
                    Some(source) => {
                        let wrapped = format!("\\A(?:{source})\\z");
                        match regex::bytes::Regex::new(&wrapped) {
                            Ok(full_re) => match full_re.captures(bytes) {
                                Some(caps) => bytes_found(&caps),
                                None => Value::Null,
                            },
                            Err(_) => Value::Null,
                        }
                    }
                    None => Value::Null,
                };
                let found = Value::Array(re.captures_iter(bytes).map(|caps| bytes_found(&caps)).collect());
                return case_value(search, matched, full, found);
            }
        }
    }
    if let Some(value) = replay_look(function, text) {
        return value;
    }
    Value::Null
}

#[cfg(test)]
mod tests {
    use super::{in_plain_utilities, ps_target, set_ps_target, set_startup_rules, startup_rules, OBJECT_ID_PATTERN, emulator_address_sub};

    #[test]
    fn startup_rules_round_trip() {
        assert!(startup_rules());
        set_startup_rules(false);
        assert!(!startup_rules());
        set_startup_rules(true);
    }

    #[test]
    fn ps_target_matches_the_platform() {
        let expected = if cfg!(target_os = "macos") { "darwin" } else { "linux" };
        assert_eq!(ps_target(), expected);
        set_ps_target("linux");
        assert_eq!(ps_target(), "linux");
        set_ps_target(expected);
    }

    #[test]
    fn plain_utilities_contains_cat() {
        assert!(in_plain_utilities("cat"));
        assert!(!in_plain_utilities("no-such-tool"));
    }

    #[test]
    fn object_id_matches_forty_hex_digits() {
        let text = "0123456789abcdef0123456789abcdef01234567";
        assert!(OBJECT_ID_PATTERN.is_match(text));
        assert!(!OBJECT_ID_PATTERN.is_match("abc"));
    }

    #[test]
    fn emulator_substitution_removes_the_address() {
        assert_eq!(emulator_address_sub("ping 10.0.2.2 now", " "), "ping   now");
    }

    #[test]
    fn sensitive_example_suffix_is_not_a_match() {
        use super::sensitive_file_pattern_search;
        assert!(sensitive_file_pattern_search(" cat file.pem").is_some());
        assert!(sensitive_file_pattern_search(" cat file.pem.example").is_none());
    }
}
