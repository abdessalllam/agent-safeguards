use std::ffi::OsString;
use std::io::{Error, ErrorKind};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};

const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
const DEFAULT_PATHEXT: &str = ".com;.exe;.bat;.cmd";

fn refused_link() -> Error {
    Error::new(ErrorKind::PermissionDenied, "the path goes through a symbolic link or junction")
}

// No openat here: check every folder first, then open without following a link.
pub fn open_without_symlinks(path: &str) -> std::io::Result<std::fs::File> {
    let target = Path::new(path);
    if path.bytes().any(|byte| byte == 0) || !target.is_absolute() || target.file_name().is_none() {
        return Err(Error::from(ErrorKind::InvalidInput));
    }
    let mut walked = PathBuf::new();
    for part in target.components() {
        walked.push(part);
        match std::fs::symlink_metadata(&walked) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(refused_link()),
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(target)?;
    if file.metadata()?.file_type().is_symlink() {
        return Err(refused_link());
    }
    Ok(file)
}

pub fn new_session(command: &mut std::process::Command) {
    command.creation_flags(CREATE_NEW_PROCESS_GROUP);
}

/// Windows has no numeric user id; this pairs with `passwd_home`, which ignores it.
pub fn getuid() -> u32 {
    0
}

fn absolute_env(name: &str) -> Option<String> {
    let value = std::env::var(name).ok()?;
    Path::new(&value).is_absolute().then_some(value)
}

/// The current user's profile folder, or `None` when the environment gives none.
pub fn passwd_home(_uid: u32) -> Option<String> {
    absolute_env("USERPROFILE").or_else(|| {
        let drive = std::env::var("HOMEDRIVE").ok()?;
        let path = std::env::var("HOMEPATH").ok()?;
        let joined = format!("{drive}{path}");
        Path::new(&joined).is_absolute().then_some(joined)
    })
}

/// There is no `~name` lookup on Windows.
pub fn passwd_home_by_name(name: &str) -> Result<Option<String>, EmbeddedNul> {
    if name.bytes().any(|byte| byte == 0) {
        return Err(EmbeddedNul);
    }
    Ok(None)
}

/// The extensions Windows runs (`PATHEXT`), lower case with the dot, in order.
pub fn executable_extensions() -> Vec<String> {
    let listed = std::env::var("PATHEXT").unwrap_or_else(|_| DEFAULT_PATHEXT.to_owned());
    listed
        .split(';')
        .map(|known| known.trim().to_ascii_lowercase())
        .filter(|known| known.len() > 1 && known.starts_with('.'))
        .collect()
}

/// A regular file with a runnable extension (`PATHEXT`); a NUL in the path is false.
pub fn access_executable(path: &str) -> bool {
    if path.bytes().any(|byte| byte == 0) {
        return false;
    }
    let target = Path::new(path);
    if !std::fs::metadata(target).is_ok_and(|meta| meta.is_file()) {
        return false;
    }
    let Some(extension) = target.extension().and_then(|text| text.to_str()) else {
        return false;
    };
    let wanted = format!(".{}", extension.to_ascii_lowercase());
    executable_extensions().contains(&wanted)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmbeddedNul;

fn plain(path: &Path) -> String {
    let text = path.to_string_lossy().into_owned();
    let stripped = if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else {
        match text.strip_prefix(r"\\?\") {
            Some(rest) if rest.as_bytes().get(1) == Some(&b':') => rest.to_owned(),
            _ => text,
        }
    };
    stripped.replace('\\', "/")
}

/// Python `os.path.realpath` on Windows: resolve links and keep a missing tail.
pub fn try_realpath(path: &str) -> Result<String, EmbeddedNul> {
    if path.bytes().any(|byte| byte == 0) {
        return Err(EmbeddedNul);
    }
    let absolute = std::path::absolute(path).unwrap_or_else(|_| PathBuf::from(path));
    let mut head = absolute.clone();
    let mut tail: Vec<OsString> = Vec::new();
    let resolved = loop {
        if let Ok(done) = std::fs::canonicalize(&head) {
            break done;
        }
        let Some(name) = head.file_name().map(OsString::from) else {
            return Ok(plain(&absolute));
        };
        tail.push(name);
        if !head.pop() {
            return Ok(plain(&absolute));
        }
    };
    let mut full = resolved;
    for name in tail.iter().rev() {
        full.push(name);
    }
    Ok(plain(&full))
}

pub fn realpath(path: &str) -> String {
    try_realpath(path).unwrap_or_else(|_| path.to_owned())
}

fn is_separator(c: char) -> bool {
    c == '\\' || c == '/'
}

fn split_drive(path: &str) -> (&str, &str) {
    let bytes = path.as_bytes();
    if bytes.get(1) == Some(&b':') && bytes.first().is_some_and(u8::is_ascii_alphabetic) {
        return path.split_at(2);
    }
    let is_sep = |at: usize| bytes.get(at).is_some_and(|byte| *byte == b'\\' || *byte == b'/');
    if is_sep(0) && is_sep(1) && !is_sep(2) {
        let after_host = path.get(2..).and_then(|rest| rest.find(is_separator)).map(|at| at.saturating_add(2));
        let Some(host_end) = after_host else {
            return (path, "");
        };
        let share_end = path
            .get(host_end.saturating_add(1)..)
            .and_then(|rest| rest.find(is_separator))
            .map_or(path.len(), |at| at.saturating_add(host_end).saturating_add(1));
        return path.split_at(share_end);
    }
    ("", path)
}

/// Python `ntpath.dirname`.
pub(crate) fn dirname(path: &str) -> String {
    let (drive, rest) = split_drive(path);
    let Some(index) = rest.rfind(is_separator) else {
        return drive.to_owned();
    };
    let head = rest.get(..=index).unwrap_or("");
    let head = if head.chars().all(is_separator) { head } else { head.trim_end_matches(is_separator) };
    format!("{drive}{head}")
}

pub(crate) fn path_bytes_lossy(path: &Path) -> String {
    path.as_os_str().to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::{access_executable, dirname, getuid, open_without_symlinks, passwd_home, passwd_home_by_name, realpath, try_realpath, EmbeddedNul};
    use std::fs;

    fn scratch(name: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("guard-common-win-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("folder");
        base
    }

    #[test]
    fn the_profile_folder_comes_from_the_environment_and_other_accounts_are_unknown() {
        assert_eq!(passwd_home(getuid()), std::env::var("USERPROFILE").ok().filter(|value| std::path::Path::new(value).is_absolute()));
        assert_eq!(passwd_home_by_name("anyone"), Ok(None));
        assert_eq!(passwd_home_by_name("a\0b"), Err(EmbeddedNul));
    }

    #[test]
    fn an_executable_is_a_regular_file_with_a_runnable_extension() {
        let dir = scratch("exec");
        let script = dir.join("tool.cmd");
        let text = dir.join("notes.txt");
        let bare = dir.join("tool");
        for file in [&script, &text, &bare] {
            fs::write(file, b"echo\r\n").expect("write");
        }
        assert!(access_executable(&script.to_string_lossy()));
        assert!(access_executable(&script.to_string_lossy().to_ascii_uppercase()));
        assert!(!access_executable(&text.to_string_lossy()));
        assert!(!access_executable(&bare.to_string_lossy()));
        assert!(!access_executable(&dir.to_string_lossy()));
        assert!(!access_executable("has\0nul"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn realpath_keeps_a_missing_tail_strips_the_verbatim_prefix_and_follows_a_directory_link() {
        let dir = scratch("real");
        let real = dir.join("real");
        fs::create_dir_all(&real).expect("folder");
        let canonical = realpath(&real.to_string_lossy());
        assert!(!canonical.starts_with(r"\\?\") && !canonical.contains('\\'), "{canonical}");
        let missing = format!("{}\\no-such\\..\\file.txt", real.display());
        assert_eq!(realpath(&missing), format!("{canonical}/file.txt"));
        assert_eq!(realpath(&format!("{}/sub/../", real.display())), canonical);
        assert_eq!(try_realpath("a\0b"), Err(EmbeddedNul));
        if std::os::windows::fs::symlink_dir(&real, dir.join("link")).is_ok() {
            assert_eq!(realpath(&dir.join("link").to_string_lossy()), canonical);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dirname_follows_ntpath_for_drives_roots_and_shares() {
        assert_eq!(dirname(r"C:\Users\me\file.txt"), r"C:\Users\me");
        assert_eq!(dirname(r"C:\Users"), r"C:\");
        assert_eq!(dirname(r"C:\"), r"C:\");
        assert_eq!(dirname("C:file"), "C:");
        assert_eq!(dirname("C:/a/b"), "C:/a");
        assert_eq!(dirname("plain"), "");
        assert_eq!(dirname(r"\\host\share\dir\file"), r"\\host\share\dir");
        assert_eq!(dirname(r"\\host\share\file"), r"\\host\share\");
        assert_eq!(dirname(r"\\host\share"), r"\\host\share");
    }

    #[test]
    fn open_without_symlinks_refuses_links_and_keeps_content() {
        use std::io::{Read, Write};
        let dir = scratch("nofollow");
        let real = dir.join("real");
        fs::create_dir_all(&real).expect("folder");
        let text = |path: &std::path::Path| path.to_string_lossy().into_owned();
        let file = real.join("exclude");
        let mut created = open_without_symlinks(&text(&file)).expect("create");
        created.write_all(b"kept").expect("write");
        drop(created);
        let mut again = open_without_symlinks(&text(&file)).expect("reopen");
        let mut content = String::new();
        again.read_to_string(&mut content).expect("read");
        assert_eq!(content, "kept");
        assert!(open_without_symlinks("").is_err());
        assert!(open_without_symlinks(r"relative\name").is_err());
        assert!(open_without_symlinks(&text(&dir.join("a\0b"))).is_err());
        let link = dir.join("link");
        if std::os::windows::fs::symlink_dir(&real, &link).is_ok() {
            assert!(open_without_symlinks(&text(&link.join("exclude"))).is_err());
        }
        let pointer = real.join("pointer");
        if std::os::windows::fs::symlink_file(&file, &pointer).is_ok() {
            assert!(open_without_symlinks(&text(&pointer)).is_err());
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
