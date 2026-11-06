include!("pychars_tables.rs");

fn contains(table: &[(u32, u32)], character: char) -> bool {
    let code = character as u32;
    table
        .binary_search_by(|(low, high)| {
            if code < *low {
                std::cmp::Ordering::Greater
            } else if code > *high {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

pub fn is_alpha(character: char) -> bool {
    if character.is_ascii() {
        return character.is_ascii_alphabetic();
    }
    contains(ALPHA, character)
}

pub fn is_decimal(character: char) -> bool {
    if character.is_ascii() {
        return character.is_ascii_digit();
    }
    contains(DECIMAL, character)
}

pub fn is_digit(character: char) -> bool {
    if character.is_ascii() {
        return character.is_ascii_digit();
    }
    contains(DIGIT, character)
}

pub fn is_numeric(character: char) -> bool {
    if character.is_ascii() {
        return character.is_ascii_digit();
    }
    contains(NUMERIC, character)
}

pub fn is_alnum(character: char) -> bool {
    is_alpha(character) || is_decimal(character) || is_digit(character) || is_numeric(character)
}

pub fn is_space(character: char) -> bool {
    if character.is_ascii() {
        return matches!(character, ' ' | '\t'..='\r' | '\u{1c}'..='\u{1f}');
    }
    contains(SPACE, character)
}

/// The value of a Unicode decimal digit, as `int()` reads it.
pub fn decimal_value(character: char) -> Option<u32> {
    if character.is_ascii() {
        return character.to_digit(10);
    }
    let code = character as u32;
    let at = DECIMAL_ZEROS.partition_point(|zero| *zero <= code);
    let zero = *DECIMAL_ZEROS.get(at.checked_sub(1)?)?;
    (code - zero < 10 && contains(DECIMAL, character)).then_some(code - zero)
}

pub fn strip(text: &str) -> &str {
    text.trim_matches(is_space)
}

#[cfg(test)]
mod tests {
    use super::{decimal_value, is_alnum, is_digit, is_space, strip};

    #[test]
    fn predicates_follow_python() {
        assert!(is_space('\u{1c}') && is_space('\u{a0}') && !is_space('\u{200b}'));
        assert!(is_alnum('\u{b2}') && !is_alnum('\u{345}'));
        assert!(is_digit('\u{b2}'));
        assert_eq!(decimal_value('\u{662}'), Some(2));
        assert_eq!(decimal_value('\u{b2}'), None);
        assert_eq!(strip("\u{1c}true\u{1f}"), "true");
    }
}
