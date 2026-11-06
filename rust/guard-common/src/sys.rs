use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::Error;
use std::mem::MaybeUninit;
use std::path::Path;

pub fn new_session(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: runs between fork and exec; setsid is async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
}

/// Process real user id.
pub fn getuid() -> u32 {
    // SAFETY: getuid reads the calling process's real user id and cannot fail.
    unsafe { libc::getuid() as u32 }
}

/// Home directory from the passwd database, or `None` when the lookup fails.
pub fn passwd_home(uid: u32) -> Option<String> {
    let mut capacity = passwd_buffer_size();
    loop {
        let mut buffer = vec![0u8; capacity];
        let mut pwd = MaybeUninit::<libc::passwd>::uninit();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: buffer is writable for `capacity` bytes and outlives the copy of pw_dir below.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                pwd.as_mut_ptr(),
                buffer.as_mut_ptr() as *mut libc::c_char,
                buffer.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE {
            capacity = capacity.saturating_mul(2);
            if capacity > 1_048_576 {
                return None;
            }
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        // SAFETY: a null result was rejected, so getpwuid_r initialized `pwd`.
        let pwd = unsafe { pwd.assume_init() };
        if pwd.pw_dir.is_null() {
            return None;
        }
        // SAFETY: pw_dir points into `buffer`, which is still alive, and is a C string.
        let dir = unsafe { CStr::from_ptr(pwd.pw_dir) };
        return Some(dir.to_string_lossy().into_owned());
    }
}

fn passwd_buffer_size() -> usize {
    // SAFETY: sysconf with this name only reads a libc limit.
    let hint = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    if hint > 0 {
        hint as usize
    } else {
        4096
    }
}

/// `os.access(path, X_OK)` on a regular file. A path containing NUL is false.
pub fn access_executable(path: &str) -> bool {
    if path.bytes().any(|byte| byte == 0) {
        return false;
    }
    let Ok(c_path) = CString::new(path) else {
        return false;
    };
    let mut st = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: c_path is a NUL-terminated path and st is writable for one stat.
    let rc = unsafe { libc::stat(c_path.as_ptr(), st.as_mut_ptr()) };
    if rc != 0 {
        return false;
    }
    // SAFETY: stat returned 0, so the struct is initialized.
    let st = unsafe { st.assume_init() };
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return false;
    }
    // SAFETY: c_path is still a valid NUL-terminated path; access only reads it.
    unsafe { libc::access(c_path.as_ptr(), libc::X_OK) == 0 }
}

/// Python raises `ValueError` from `os.path.realpath` for a path with a NUL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmbeddedNul;

/// Python `os.path.realpath`: resolve links and keep a missing tail.
pub fn try_realpath(path: &str) -> Result<String, EmbeddedNul> {
    if path.bytes().any(|byte| byte == 0) {
        return Err(EmbeddedNul);
    }
    let (resolved, _) = join_realpath(String::new(), path, &mut HashMap::new(), 0);
    Ok(abspath(&resolved))
}

pub fn realpath(path: &str) -> String {
    try_realpath(path).unwrap_or_else(|_| path.to_owned())
}

pub(crate) fn dirname(path: &str) -> String {
    let (head, _) = split_path(path);
    head.to_owned()
}

fn abspath(path: &str) -> String {
    if path.starts_with('/') {
        return normpath(path);
    }
    let cwd = std::env::current_dir()
        .map(|dir| dir.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "/".to_owned());
    normpath(&join_paths(&[&cwd, path]))
}

fn join_realpath(
    mut path: String,
    mut rest: &str,
    seen: &mut HashMap<String, Option<String>>,
    depth: usize,
) -> (String, bool) {
    if depth > 256 {
        return (join_paths(&[&path, rest]), false);
    }
    if rest.starts_with('/') {
        rest = rest.get(1..).unwrap_or("");
        path = "/".to_owned();
    }
    while !rest.is_empty() {
        let (name, next) = partition(rest, '/');
        rest = next;
        if name.is_empty() || name == "." {
            continue;
        }
        if name == ".." {
            if path.is_empty() {
                path = "..".to_owned();
            } else {
                let (head, tail) = split_path(&path);
                if tail == ".." {
                    path = join_paths(&[head, "..", ".."]);
                } else {
                    path = head.to_owned();
                }
            }
            continue;
        }
        let newpath = join_paths(&[&path, name]);
        let is_link = symlink_status(&newpath).unwrap_or_default();
        if !is_link {
            path = newpath;
            continue;
        }
        if let Some(cached) = seen.get(&newpath) {
            match cached {
                Some(done) => {
                    path = done.clone();
                    continue;
                }
                None => return (join_paths(&[&newpath, rest]), false),
            }
        }
        seen.insert(newpath.clone(), None);
        let Some(target) = read_link(&newpath) else {
            path = newpath;
            continue;
        };
        let (resolved, ok) = join_realpath(path, &target, seen, depth.saturating_add(1));
        if !ok {
            return (join_paths(&[&resolved, rest]), false);
        }
        seen.insert(newpath, Some(resolved.clone()));
        path = resolved;
    }
    (path, true)
}

fn symlink_status(path: &str) -> Result<bool, ()> {
    let c_path = CString::new(path).map_err(|_| ())?;
    let mut st = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: c_path is NUL-terminated and st is writable for one stat.
    let rc = unsafe { libc::lstat(c_path.as_ptr(), st.as_mut_ptr()) };
    if rc != 0 {
        return Err(());
    }
    // SAFETY: lstat returned 0, so the struct is initialized.
    let st = unsafe { st.assume_init() };
    Ok(st.st_mode & libc::S_IFMT == libc::S_IFLNK)
}

fn read_link(path: &str) -> Option<String> {
    let c_path = CString::new(path).ok()?;
    let mut capacity = 256usize;
    loop {
        let mut buffer = vec![0u8; capacity];
        // SAFETY: c_path is NUL-terminated and buffer is writable for `capacity` bytes.
        let read = unsafe {
            libc::readlink(
                c_path.as_ptr(),
                buffer.as_mut_ptr() as *mut libc::c_char,
                buffer.len(),
            )
        };
        if read < 0 {
            let _ = Error::last_os_error();
            return None;
        }
        let read = read as usize;
        if read < buffer.len() {
            buffer.truncate(read);
            return Some(String::from_utf8_lossy(&buffer).into_owned());
        }
        capacity = capacity.saturating_mul(2);
        if capacity > 1_048_576 {
            return None;
        }
    }
}

fn join_paths(parts: &[&str]) -> String {
    let mut path = String::new();
    for part in parts {
        if part.starts_with('/') {
            path = (*part).to_owned();
        } else if path.is_empty() || path.ends_with('/') {
            path.push_str(part);
        } else {
            path.push('/');
            path.push_str(part);
        }
    }
    path
}

fn partition(text: &str, sep: char) -> (&str, &str) {
    match text.find(sep) {
        Some(index) => {
            let name = text.get(..index).unwrap_or("");
            let rest = text.get(index.saturating_add(sep.len_utf8())..).unwrap_or("");
            (name, rest)
        }
        None => (text, ""),
    }
}

fn split_path(path: &str) -> (&str, &str) {
    let Some(index) = path.rfind('/') else {
        return ("", path);
    };
    let mut head = path.get(..=index).unwrap_or(path);
    let tail = path.get(index.saturating_add(1)..).unwrap_or("");
    if !head.is_empty() && !head.bytes().all(|byte| byte == b'/') {
        head = head.trim_end_matches('/');
    }
    (head, tail)
}

fn split_root(path: &str) -> (&str, &str) {
    let bytes = path.as_bytes();
    if bytes.first() != Some(&b'/') {
        return ("", path);
    }
    if bytes.get(1) != Some(&b'/') || bytes.get(2) == Some(&b'/') {
        return ("/", path.get(1..).unwrap_or(""));
    }
    ("//", path.get(2..).unwrap_or(""))
}

fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let (root, tail) = split_root(path);
    let mut comps: Vec<&str> = Vec::new();
    for comp in tail.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        let collapse = comp != ".."
            || (root.is_empty() && comps.is_empty())
            || comps.last().copied() == Some("..");
        if collapse {
            comps.push(comp);
        } else if !comps.is_empty() {
            comps.pop();
        }
    }
    let mut out = String::from(root);
    out.push_str(&comps.join("/"));
    if out.is_empty() {
        ".".to_owned()
    } else {
        out
    }
}

pub(crate) fn path_bytes_lossy(path: &Path) -> String {
    path.as_os_str().to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::{access_executable, dirname, getuid, passwd_home, realpath, try_realpath, EmbeddedNul};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn python(code: &str, arg: &str) -> String {
        let output = Command::new("python3")
            .arg("-c")
            .arg(code)
            .arg(arg)
            .output()
            .expect("python3");
        assert!(output.status.success());
        String::from_utf8(output.stdout).expect("utf8")
    }

    #[test]
    fn getuid_matches_python() {
        let expected = python("import os,sys; sys.stdout.write(str(os.getuid()))", "");
        assert_eq!(getuid().to_string(), expected);
    }

    #[test]
    fn passwd_home_matches_python_or_is_absent() {
        let uid = getuid();
        let expected = python(
            "import os,pwd,sys\ntry:\n sys.stdout.write(pwd.getpwuid(os.getuid()).pw_dir)\nexcept KeyError:\n sys.stdout.write('')",
            "",
        );
        match passwd_home(uid) {
            Some(home) => assert_eq!(home, expected),
            None => assert!(expected.is_empty()),
        }
        assert_eq!(passwd_home(u32::MAX), None);
    }

    #[test]
    fn access_executable_requires_a_regular_executable_file() {
        assert!(access_executable("/bin/sh") || access_executable("/usr/bin/sh"));
        assert!(!access_executable("/bin"));
        assert!(!access_executable("/no/such/agent-safeguards-binary"));
        assert!(!access_executable("has\0nul"));
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("guard-common-nox-{stamp}"));
        fs::write(&path, b"echo\n").unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&path, perms).unwrap();
        assert!(!access_executable(&path.to_string_lossy()));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn realpath_of_dot_dot_sequences_matches_python() {
        let pieces = ["..", ".", "a", "src", ""];
        let mut samples: Vec<String> = vec![String::new()];
        let mut layer: Vec<Vec<&str>> = vec![Vec::new()];
        for _ in 0..6 {
            let mut next = Vec::new();
            for parts in &layer {
                for piece in pieces {
                    let mut longer = parts.clone();
                    longer.push(piece);
                    samples.push(longer.join("/"));
                    samples.push(format!("/{}", longer.join("/")));
                    next.push(longer);
                }
            }
            layer = next;
        }
        let expected = python(
            "import os,sys; sys.stdout.write('\\n'.join(os.path.realpath(p) for p in sys.argv[1].split('\\n')))",
            &samples.join("\n"),
        );
        let actual: Vec<String> = samples.iter().map(|sample| realpath(sample)).collect();
        for (index, (left, right)) in actual.iter().zip(expected.split('\n')).enumerate() {
            assert_eq!(left, right, "{:?}", samples[index]);
        }
    }

    #[test]
    fn realpath_with_a_nul_fails_like_python() {
        for sample in ["\0", "a\0", "/\0", "/nonexistent/a\0b", "a/\0", "/tmp/\0/x", "x\0/..", "..\0"] {
            assert_eq!(try_realpath(sample), Err(EmbeddedNul), "{sample:?}");
        }
        assert_eq!(try_realpath("/tmp"), Ok(realpath("/tmp")));
    }

    #[test]
    fn realpath_matches_python_including_missing_tails_and_links() {
        let cwd = std::env::current_dir().unwrap();
        let cwd_text = cwd.to_string_lossy().into_owned();
        for sample in ["", ".", "..", "no-such-component", "/bin/sh", "/tmp"] {
            let expected = python(
                "import os,sys; sys.stdout.write(os.path.realpath(sys.argv[1]))",
                sample,
            );
            assert_eq!(realpath(sample), expected, "{sample}");
        }
        let missing = format!("{cwd_text}/does-not-exist-b2");
        let expected = python(
            "import os,sys; sys.stdout.write(os.path.realpath(sys.argv[1]))",
            &missing,
        );
        assert_eq!(realpath(&missing), expected);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("guard-common-link-{stamp}"));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        let link = dir.join("link");
        fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let link_text = link.to_string_lossy().into_owned();
        let expected = python(
            "import os,sys; sys.stdout.write(os.path.realpath(sys.argv[1]))",
            &link_text,
        );
        assert_eq!(realpath(&link_text), expected);
        assert_eq!(dirname("/usr/bin/sh"), "/usr/bin");
        assert_eq!(dirname("/"), "/");
        let _ = fs::remove_file(&link);
        let _ = fs::remove_file(&target);
        let _ = fs::remove_dir(&dir);
    }
}
