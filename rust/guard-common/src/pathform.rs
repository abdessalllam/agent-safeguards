/// `C:/` or `C:\` at the start. Only Windows treats this as an absolute path.
pub fn has_drive(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes.get(1) == Some(&b':')
        && matches!(bytes.get(2), Some(b'/' | b'\\'))
}

pub fn is_absolute(path: &str) -> bool {
    path.starts_with('/') || (cfg!(windows) && has_drive(path))
}

/// The form `realpath` returns: backslashes become slashes on Windows only.
pub fn slashed(path: &str) -> String {
    if cfg!(windows) {
        path.replace('\\', "/")
    } else {
        path.to_owned()
    }
}

/// `/`, or on Windows a bare drive root such as `C:/`.
pub fn is_root(path: &str) -> bool {
    path == "/" || (cfg!(windows) && has_drive(path) && path.len() == 3)
}

#[cfg(test)]
mod tests {
    use super::{has_drive, is_absolute, is_root};

    #[test]
    fn a_drive_prefix_is_absolute_only_on_windows() {
        assert!(is_absolute("/etc"));
        assert!(is_root("/"));
        assert!(!is_absolute("rel/x") && !is_root("/etc"));
        assert!(has_drive("C:/x") && has_drive("d:\\x") && !has_drive("C:x") && !has_drive("1:/x"));
        assert_eq!(is_absolute("C:/x"), cfg!(windows));
        assert_eq!(is_root("C:/"), cfg!(windows));
        assert!(!is_root("C:/x"));
    }
}
