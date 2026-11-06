use guard_common::shell::{ASSIGNMENT, DURATION, HEREDOC_FORBIDDEN};

fn unhex(text: &str) -> String {
    let bytes: Vec<u8> = (0..text.len() / 2)
        .map(|index| u8::from_str_radix(text.get(index * 2..index * 2 + 2).unwrap_or("00"), 16).unwrap_or(0))
        .collect();
    String::from_utf8(bytes).unwrap_or_default()
}

#[test]
fn exhaustive_small_strings_match_python() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/exhaustive_shell.txt");
    let text = std::fs::read_to_string(path).expect("file");
    let mut bad = Vec::new();
    let mut total = 0usize;
    for line in text.lines() {
        let mut parts = line.split('\t');
        let (kind, hex, want) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or("") == "1");
        let subject = unhex(hex);
        let got = match kind {
            "F" => HEREDOC_FORBIDDEN.is_match(&subject),
            "A" => ASSIGNMENT.is_match(&subject),
            "D" => DURATION.is_match(&subject),
            _ => continue,
        };
        total += 1;
        if got != want && bad.len() < 30 {
            bad.push(format!("{kind} {subject:?} got {got} want {want}"));
        }
    }
    for line in &bad {
        eprintln!("MISMATCH {line}");
    }
    eprintln!("TOTAL {total} BAD {}", bad.len());
    assert!(bad.is_empty());
}
