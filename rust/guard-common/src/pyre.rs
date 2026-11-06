use regex::Regex;

const EXTRA_SPACE: &str = r"\x1c-\x1f";
const WORD: &str = r"\p{L}\p{N}_";

pub fn translate(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len() + 16);
    let mut depth = 0usize;
    let mut index = 0usize;
    while index < chars.len() {
        let current = chars[index];
        if current == '\\' && index + 1 < chars.len() {
            let escaped = chars[index + 1];
            let in_class = depth > 0;
            let already: String = chars.iter().skip(index + 2).take(EXTRA_SPACE.len()).collect();
            match escaped {
                's' if already == EXTRA_SPACE => out.push_str(r"\s"),
                's' if in_class => out.push_str(&format!(r"\s{EXTRA_SPACE}")),
                's' => out.push_str(&format!(r"[\s{EXTRA_SPACE}]")),
                'S' if !in_class => out.push_str(&format!(r"[^\s{EXTRA_SPACE}]")),
                'w' if in_class => out.push_str(WORD),
                'w' => out.push_str(&format!("[{WORD}]")),
                'W' if !in_class => out.push_str(&format!("[^{WORD}]")),
                other => {
                    out.push('\\');
                    out.push(other);
                }
            }
            index += 2;
            continue;
        }
        if current == '[' {
            depth += 1;
            out.push('[');
            index += 1;
            if chars.get(index) == Some(&'^') {
                out.push('^');
                index += 1;
            }
            if chars.get(index) == Some(&']') {
                out.push_str(r"\]");
                index += 1;
            }
            continue;
        }
        if current == ']' && depth > 0 {
            depth -= 1;
        }
        out.push(current);
        index += 1;
    }
    out
}

pub fn new(source: &str) -> Result<Regex, regex::Error> {
    Regex::new(&translate(source))
}

#[cfg(test)]
mod tests {
    use super::{new, translate};

    #[test]
    fn spaces_and_words_follow_python() {
        assert_eq!(translate(r"a\s+b"), r"a[\s\x1c-\x1f]+b");
        assert_eq!(translate(r"[\s,]"), r"[\s\x1c-\x1f,]");
        assert_eq!(translate(r"[^\s\x1c-\x1f]"), r"[^\s\x1c-\x1f]");
        assert_eq!(translate(r"\S"), r"[^\s\x1c-\x1f]");
        assert_eq!(translate(r"\\s"), r"\\s");
        assert_eq!(translate(r"[\w.-]"), r"[\p{L}\p{N}_.-]");
        assert_eq!(translate(r"\w+\W"), r"[\p{L}\p{N}_]+[^\p{L}\p{N}_]");
        assert_eq!(translate(r"[]a\s]"), r"[\]a\s\x1c-\x1f]");
        assert!(new(r"\s").is_ok_and(|found| found.is_match("\u{1c}")));
        assert!(new(r"\w").is_ok_and(|found| found.is_match("\u{b2}") && !found.is_match("\u{301}")));
    }
}
