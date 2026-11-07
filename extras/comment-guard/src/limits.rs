use std::cell::Cell;
use std::ops::RangeInclusive;
use std::sync::OnceLock;

pub const DEFAULT_LINES: usize = 2;
pub const DEFAULT_LINE_CHARS: usize = 90;
pub const LINES_RANGE: RangeInclusive<usize> = 1..=50;
pub const LINE_CHARS_RANGE: RangeInclusive<usize> = 20..=500;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub lines: usize,
    pub line_chars: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            lines: DEFAULT_LINES,
            line_chars: DEFAULT_LINE_CHARS,
        }
    }
}

static CURRENT: OnceLock<Limits> = OnceLock::new();

pub fn configure(limits: Limits) {
    let _ = CURRENT.set(limits);
}

pub fn current() -> Limits {
    CURRENT.get().copied().unwrap_or_default()
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    Trim,
    #[default]
    Drop,
    Block,
}

impl Mode {
    pub fn parse(text: &str) -> Option<Mode> {
        let word = text.split('#').next().unwrap_or("").trim().to_ascii_lowercase();
        match word.as_str() {
            "trim" | "1" | "true" | "yes" | "on" => Some(Mode::Trim),
            "drop" | "remove" => Some(Mode::Drop),
            "block" | "refuse" | "0" | "false" | "no" | "off" => Some(Mode::Block),
            _ => None,
        }
    }
}

thread_local! {
    static MODE: Cell<Mode> = const { Cell::new(Mode::Drop) };
}

pub fn set_mode(mode: Mode) {
    MODE.with(|cell| cell.set(mode));
}

pub fn mode() -> Mode {
    MODE.with(Cell::get)
}

pub fn file_mode(file: Option<&str>) -> Option<Mode> {
    for raw in file.unwrap_or("").lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(['=', ':']) else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("mode") {
            return Mode::parse(value);
        }
    }
    None
}

fn number(text: &str, range: &RangeInclusive<usize>) -> Option<usize> {
    let value = text.split('#').next().unwrap_or("").trim();
    value.parse::<usize>().ok().filter(|found| range.contains(found))
}

pub fn parse(file: Option<&str>, lines_env: Option<&str>, line_chars_env: Option<&str>) -> Limits {
    let mut limits = Limits::default();
    for raw in file.unwrap_or("").lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(['=', ':']) else {
            continue;
        };
        match key.trim().to_ascii_lowercase().replace(['-', ' '], "_").as_str() {
            "lines" => limits.lines = number(value, &LINES_RANGE).unwrap_or(limits.lines),
            "line_chars" => limits.line_chars = number(value, &LINE_CHARS_RANGE).unwrap_or(limits.line_chars),
            _ => {}
        }
    }
    if let Some(found) = lines_env.and_then(|value| number(value, &LINES_RANGE)) {
        limits.lines = found;
    }
    if let Some(found) = line_chars_env.and_then(|value| number(value, &LINE_CHARS_RANGE)) {
        limits.line_chars = found;
    }
    limits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_set_gives_the_defaults() {
        assert_eq!(parse(None, None, None), Limits { lines: 2, line_chars: 90 });
        assert_eq!(parse(Some(""), None, None), Limits::default());
    }

    #[test]
    fn the_file_sets_both_limits_and_ignores_what_it_cannot_read() {
        let file = "# my limits\nlines = 4\nline_chars: 90  # wide\nother = 1\nnonsense\n";
        assert_eq!(parse(Some(file), None, None), Limits { lines: 4, line_chars: 90 });
        assert_eq!(parse(Some("Line-Chars = 60\nLINES=3"), None, None), Limits { lines: 3, line_chars: 60 });
    }

    #[test]
    fn a_value_out_of_range_or_not_a_number_keeps_the_default() {
        for bad in ["0", "51", "-1", "two", "", "2.5", "1000"] {
            assert_eq!(parse(Some(&format!("lines = {bad}")), None, None).lines, 2, "{bad}");
        }
        for bad in ["19", "501", "x", ""] {
            assert_eq!(parse(Some(&format!("line_chars = {bad}")), None, None).line_chars, 90, "{bad}");
        }
        assert_eq!(parse(Some("lines = 50\nline_chars = 500"), None, None), Limits { lines: 50, line_chars: 500 });
        assert_eq!(parse(Some("lines = 1\nline_chars = 20"), None, None), Limits { lines: 1, line_chars: 20 });
    }

    #[test]
    fn an_environment_value_wins_over_the_file() {
        let file = "lines = 4\nline_chars = 90\n";
        assert_eq!(parse(Some(file), Some("6"), Some("120")), Limits { lines: 6, line_chars: 120 });
        assert_eq!(parse(Some(file), Some("bad"), Some("1")), Limits { lines: 4, line_chars: 90 });
        assert_eq!(parse(None, Some(" 3 "), None).lines, 3);
    }
}
