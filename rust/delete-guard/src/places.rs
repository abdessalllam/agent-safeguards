use std::fs;
use std::sync::LazyLock;

use guard_common::env::user_home;
use guard_common::locale::{message, FormatValue};
use guard_common::sys::realpath;
use regex::Regex;

use crate::consts::{self, MOUNT_PARENTS, TRASH_FOLDER, TRASH_URI};
use crate::errors::Denied;

pub const MAX_REPOSITORY_SCAN: usize = 20000;
pub const MAX_REPOSITORY_DEPTH: usize = 3;
pub const REPOSITORY_SCAN_SKIP: &[&str] = &[
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "target",
    "build",
    "dist",
    ".gradle",
    "Pods",
];

static TRASH_FOLDER_FULL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"\A(?:{})\z", TRASH_FOLDER.as_str()))
        .unwrap_or_else(|error| panic!("trash folder regex: {error}"))
});

pub fn dirname(path: &str) -> &str {
    let split = path.rfind('/').map_or(0, |index| index.saturating_add(1));
    let head = path.get(..split).unwrap_or("");
    let trimmed = head.trim_end_matches('/');
    if trimmed.is_empty() {
        head
    } else {
        trimmed
    }
}

pub fn glob_base(path: &str) -> String {
    let Some(index) = path.find(['*', '?', '[']) else {
        return path.to_owned();
    };
    let head = path.get(..index).unwrap_or("");
    if head.ends_with('/') || head.is_empty() {
        head.to_owned()
    } else {
        let parent = dirname(head);
        if parent.is_empty() {
            ".".to_owned()
        } else {
            parent.to_owned()
        }
    }
}

pub fn inside(path: &str, root: &str) -> bool {
    path == root || path.starts_with(&format!("{}/", root.trim_end_matches('/')))
}

pub fn protected(path: &str) -> bool {
    if consts::system_root_paths().iter().any(|root| root == path)
        || consts::temp_roots().iter().any(|root| root == path)
        || path == user_home()
    {
        return true;
    }
    if inside(user_home(), path) {
        return true;
    }
    let parent = dirname(path);
    if parent == user_home() {
        return true;
    }
    MOUNT_PARENTS.contains(&parent)
}

pub fn names_trash(path: &str) -> bool {
    let path = path.replace('\\', "/");
    TRASH_URI
        .find(&path)
        .is_some_and(|found| found.start() == 0)
        || path.split('/').any(|part| TRASH_FOLDER_FULL.is_match(part))
        || consts::trash_home_folder_search(&path).is_some()
}

fn normpath(path: &str) -> String {
    let initial_slashes = if path.starts_with("//") && !path.starts_with("///") {
        "//"
    } else if path.starts_with('/') {
        "/"
    } else {
        ""
    };
    let mut components = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            if components.last().is_some_and(|last| *last != "..") {
                components.pop();
            } else if initial_slashes.is_empty() {
                components.push(part);
            }
        } else {
            components.push(part);
        }
    }
    let result = format!("{initial_slashes}{}", components.join("/"));
    if result.is_empty() {
        ".".to_owned()
    } else {
        result
    }
}

fn join(root: &str, child: &str) -> String {
    if root.ends_with('/') {
        format!("{root}{child}")
    } else {
        format!("{root}/{child}")
    }
}

pub fn trash_roots() -> Vec<String> {
    let home = user_home();
    let mut roots = vec![join(home, ".Trash"), join(home, ".local/share/Trash")];
    if let Ok(data_home) = std::env::var("XDG_DATA_HOME") {
        if data_home.starts_with('/') {
            roots.push(join(&normpath(&data_home), "Trash"));
        }
    }
    let resolved: Vec<String> = roots.iter().map(|root| realpath(root)).collect();
    let mut unique = Vec::new();
    for root in roots.into_iter().chain(resolved) {
        if !unique.contains(&root) {
            unique.push(root);
        }
    }
    unique
}

pub fn holds_repository(path: &str, levels: usize) -> bool {
    if path.rsplit('/').next() == Some(".git") {
        return true;
    }
    let mut level = vec![path.to_owned()];
    let mut visited = 0usize;
    for depth in 0..=levels {
        let mut following = Vec::new();
        for folder in level {
            let Ok(entries) = fs::read_dir(&folder) else {
                continue;
            };
            for entry in entries {
                let Ok(entry) = entry else {
                    break;
                };
                visited = visited.saturating_add(1);
                let name = entry.file_name().to_string_lossy().into_owned();
                if name == ".git" {
                    return true;
                }
                if visited > MAX_REPOSITORY_SCAN {
                    return false;
                }
                if depth < levels && !REPOSITORY_SCAN_SKIP.contains(&name.as_str()) {
                    match entry.file_type() {
                        Ok(kind) if kind.is_dir() => {
                            following.push(entry.path().to_string_lossy().into_owned())
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            }
        }
        level = following;
    }
    false
}

pub fn inside_repository(path: &str) -> bool {
    let mut folder = dirname(path);
    while dirname(folder) != folder && folder != user_home() {
        if fs::symlink_metadata(format!("{folder}/.git")).is_ok() {
            return true;
        }
        folder = dirname(folder);
    }
    false
}

pub fn check_repository(resolved: &str, verb: &str) -> Result<(), Denied> {
    if consts::temp_roots()
        .iter()
        .any(|root| inside(resolved, root))
    {
        return Ok(());
    }
    let levels = if inside_repository(resolved) {
        1
    } else {
        MAX_REPOSITORY_DEPTH
    };
    if holds_repository(resolved, levels) {
        return Err(Denied::new(message(
            "delete_guard.reason.trash_repository",
            &[
                ("verb", FormatValue::Text(verb.to_owned())),
                ("path", FormatValue::Text(resolved.to_owned())),
            ],
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{glob_base, inside, names_trash, protected};

    #[test]
    fn path_boundaries_are_component_aware() {
        assert!(inside("/tmp/a", "/tmp"));
        assert!(!inside("/tmp2/a", "/tmp"));
        assert_eq!(glob_base("a/b*.txt"), "a");
        assert_eq!(glob_base("/a/b/*"), "/a/b/");
    }

    #[test]
    fn trash_names_and_protected_parents_are_distinct() {
        assert!(names_trash("x/.Trash/y"));
        assert!(!names_trash("x/.Trashbin/y"));
        assert!(protected("/Volumes/disk"));
        assert!(!protected("/Volumes/disk/child"));
    }
}
