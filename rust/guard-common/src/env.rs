use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::{overrides, sys};

pub const DEFAULT_LOCALE: &str = "en";

static LOCALE_NAME: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\A[A-Za-z0-9_-]{1,32}\z").unwrap_or_else(|_| {
        regex::Regex::new(r"\A\z").unwrap_or_else(|_| std::process::abort())
    })
});

pub fn locale_name_matches(name: &str) -> bool {
    LOCALE_NAME.is_match(name)
}

pub fn is_truthy(value: &str) -> bool {
    // Python `str.strip`/`lower` are Unicode-aware. `trim`/`to_lowercase` follow Rust's
    // whitespace and casefold tables, which differ for a few non-ASCII characters.
    matches!(
        crate::pychars::strip(value).to_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

struct Paths {
    user_home: String,
    plugin_root: String,
    trusted_dirs: Vec<String>,
    trusted_path: String,
}

static PATHS: LazyLock<Paths> = LazyLock::new(|| {
    let user_home = home_directory();
    let plugin_root = plugin_root_of_executable();
    let trusted_dirs = default_trusted_dirs(&user_home);
    let trusted_path = trusted_dirs.join(&PATH_SEPARATOR.to_string());
    Paths {
        user_home,
        plugin_root,
        trusted_dirs,
        trusted_path,
    }
});

const PATH_SEPARATOR: char = if cfg!(windows) { ';' } else { ':' };

#[cfg(unix)]
fn default_trusted_dirs(user_home: &str) -> Vec<String> {
    let mut dirs = vec![
        "/usr/bin".to_owned(),
        "/bin".to_owned(),
        "/usr/local/bin".to_owned(),
        "/opt/homebrew/bin".to_owned(),
        "/usr/sbin".to_owned(),
        "/sbin".to_owned(),
    ];
    dirs.push(join_dir(user_home, ".local/bin"));
    dirs
}

#[cfg(windows)]
fn default_trusted_dirs(user_home: &str) -> Vec<String> {
    let mut dirs: Vec<String> = Vec::new();
    for (variable, rest) in [
        ("SystemRoot", "System32"),
        ("ProgramFiles", "Git\\cmd"),
        ("ProgramFiles(x86)", "Git\\cmd"),
        ("LOCALAPPDATA", "Programs\\Git\\cmd"),
    ] {
        let Ok(root) = std::env::var(variable) else {
            continue;
        };
        if std::path::Path::new(&root).is_absolute() {
            dirs.push(join_dir(&root, rest));
        }
    }
    dirs.push(join_dir(user_home, ".local\\bin"));
    dirs
}

/// Passwd home when the account exists, otherwise `HOME`, otherwise `/`, then realpath.
pub fn home_directory() -> String {
    let home = match sys::passwd_home(sys::getuid()) {
        Some(dir) => dir,
        None => match std::env::var("HOME") {
            Ok(value) if !value.is_empty() => value,
            _ => "/".to_owned(),
        },
    };
    sys::realpath(&home)
}

pub fn user_home() -> &'static str {
    match overrides::string("USER_HOME") {
        Some(value) => leaked(value),
        None => PATHS.user_home.as_str(),
    }
}

fn leaked(value: String) -> &'static str {
    static CACHE: LazyLock<Mutex<HashMap<String, &'static str>>> = LazyLock::new(Default::default);
    let mut cache = CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.entry(value).or_insert_with_key(|key| Box::leak(key.clone().into_boxed_str()))
}

pub fn plugin_root() -> &'static str {
    PATHS.plugin_root.as_str()
}

pub fn trusted_dirs() -> &'static [String] {
    PATHS.trusted_dirs.as_slice()
}

pub fn trusted_path() -> &'static str {
    PATHS.trusted_path.as_str()
}

fn plugin_root_of_executable() -> String {
    let exe = std::env::current_exe()
        .map(|path| sys::path_bytes_lossy(&path))
        .unwrap_or_else(|_| ".".to_owned());
    let resolved = sys::realpath(&exe);
    sys::dirname(&sys::dirname(&resolved))
}

fn join_dir(root: &str, rest: &str) -> String {
    let separator = |c: char| c == '/' || (cfg!(windows) && c == '\\');
    let glue = if cfg!(windows) { '\\' } else { '/' };
    if rest.starts_with('/') || (cfg!(windows) && std::path::Path::new(rest).is_absolute()) {
        rest.to_owned()
    } else if root.is_empty() || root.ends_with(separator) {
        format!("{root}{rest}")
    } else {
        format!("{root}{glue}{rest}")
    }
}

pub fn env_flag(name: &str) -> bool {
    match std::env::var(name) {
        Ok(value) => is_truthy(&value),
        Err(_) => false,
    }
}

pub fn env_list(name: &str) -> Option<Vec<String>> {
    let raw = std::env::var(name).ok()?;
    Some(
        raw.split(PATH_SEPARATOR)
            .filter(|entry| !entry.is_empty())
            .map(|entry| entry.to_owned())
            .collect(),
    )
}

pub fn fail_open() -> bool {
    env_flag("AGENT_SAFEGUARDS_FAIL_OPEN")
}

#[cfg(unix)]
fn executable_names(name: &str) -> Vec<String> {
    vec![name.to_owned()]
}

#[cfg(windows)]
fn executable_names(name: &str) -> Vec<String> {
    if std::path::Path::new(name).extension().is_some() {
        return vec![name.to_owned()];
    }
    sys::executable_extensions().iter().map(|extension| format!("{name}{extension}")).collect()
}

pub fn find_executable(name: &str) -> Option<String> {
    for directory in trusted_dirs() {
        for file in executable_names(name) {
            let candidate = join_dir(directory, &file);
            if sys::access_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::{
        env_flag, env_list, fail_open, find_executable, home_directory, is_truthy,
        locale_name_matches, plugin_root, trusted_dirs, trusted_path, user_home, DEFAULT_LOCALE,
    };
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn truthy_values_ignore_case_and_surrounding_space() {
        for value in ["1", "true", "YES", "On", "  true  "] {
            assert!(is_truthy(value), "{value}");
        }
        for value in ["", "0", "false", "no", "off", "truely"] {
            assert!(!is_truthy(value), "{value}");
        }
    }

    #[test]
    fn locale_name_is_a_short_token() {
        assert!(locale_name_matches(DEFAULT_LOCALE));
        assert!(locale_name_matches("en_US"));
        assert!(locale_name_matches("a"));
        assert!(!locale_name_matches(""));
        assert!(!locale_name_matches("has space"));
        assert!(!locale_name_matches(&"a".repeat(33)));
        assert!(!locale_name_matches("en.utf8"));
    }

    #[test]
    fn env_flag_list_and_fail_open_follow_the_process_environment() {
        let _guard = LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let flag = "AGENT_SAFEGUARDS_TEST_FLAG_B2";
        let list = "AGENT_SAFEGUARDS_TEST_LIST_B2";
        let fail = "AGENT_SAFEGUARDS_FAIL_OPEN";
        unsafe {
            std::env::remove_var(flag);
            std::env::remove_var(list);
            std::env::remove_var(fail);
        }
        assert!(!env_flag(flag));
        assert_eq!(env_list(list), None);
        assert!(!fail_open());
        unsafe {
            std::env::set_var(flag, " YES ");
            let colon = super::PATH_SEPARATOR;
            std::env::set_var(list, format!("a{colon}{colon}b{colon}"));
            std::env::set_var(fail, "1");
        }
        assert!(env_flag(flag));
        assert_eq!(
            env_list(list),
            Some(vec!["a".to_owned(), "b".to_owned()])
        );
        assert!(fail_open());
        unsafe {
            std::env::set_var(list, "");
        }
        assert_eq!(env_list(list), Some(Vec::new()));
        unsafe {
            std::env::remove_var(flag);
            std::env::remove_var(list);
            std::env::remove_var(fail);
        }
    }

    #[cfg(windows)]
    #[test]
    fn home_plugin_root_and_trusted_dirs_are_stable_on_windows() {
        let home = user_home();
        assert!(std::path::Path::new(home).is_absolute(), "{home}");
        assert_eq!(home, home_directory());
        assert!(plugin_root().contains(':') || plugin_root().is_empty() || plugin_root() == ".");
        let dirs = trusted_dirs();
        assert!(dirs.iter().any(|dir| dir.to_ascii_lowercase().ends_with("system32")), "{dirs:?}");
        assert!(dirs.last().is_some_and(|dir| dir.ends_with("\\.local\\bin")), "{dirs:?}");
        assert_eq!(trusted_path(), dirs.join(";"));
        let found = find_executable("cmd");
        assert!(found.as_ref().is_some_and(|path| path.to_ascii_lowercase().ends_with("\\cmd.exe")), "{found:?}");
        assert_eq!(find_executable("no-such-guard-binary-b2"), None);
    }

    #[cfg(unix)]
    #[test]
    fn home_plugin_root_and_trusted_dirs_are_stable() {
        let home = user_home();
        assert!(home.starts_with('/'));
        assert_eq!(home, home_directory());
        assert!(plugin_root().starts_with('/') || plugin_root().is_empty() || plugin_root() == ".");
        let dirs = trusted_dirs();
        assert!(dirs.iter().any(|dir| dir == "/usr/bin"));
        assert!(dirs.iter().any(|dir| dir == "/bin"));
        assert!(dirs.last().is_some_and(|dir| dir.ends_with("/.local/bin")));
        assert_eq!(trusted_path(), dirs.join(":"));
        let found = find_executable("sh");
        assert!(found.as_ref().is_some_and(|path| path.ends_with("/sh")));
        assert_eq!(find_executable("no-such-guard-binary-b2"), None);
    }
}
