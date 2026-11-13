use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};

use crate::emit::python_float_repr;
use crate::env::{locale_name_matches, plugin_root, DEFAULT_LOCALE};

const EMBEDDED_EN: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../locales/en.json"));

#[derive(Clone, Debug)]
pub enum FormatValue {
    Text(String),
    Int(i64),
    Float(f64),
}

fn platform_template(key: &str) -> String {
    if crate::powershell::active() {
        let mut options: Vec<String> = Vec::new();
        if crate::env::env_flag("AGENT_SAFEGUARDS_RECYCLE_OK") {
            options.push(format!("{key}.windows_recycle"));
        }
        options.push(format!("{key}.windows"));
        for option in options {
            let found = template_for(&option);
            if found != option {
                return found;
            }
        }
    }
    template_for(key)
}

pub fn message(key: &str, values: &[(&str, FormatValue)]) -> String {
    let template = platform_template(key);
    match render(&template, values) {
        Ok(rendered) => rendered,
        Err(()) => template,
    }
}

fn template_for(key: &str) -> String {
    let locale = current_locale();
    if let Some(text) = file_template(&locale, key) {
        return text;
    }
    if locale != DEFAULT_LOCALE {
        if let Some(text) = file_template(DEFAULT_LOCALE, key) {
            return text;
        }
    }
    if let Some(text) = embedded_en().get(key) {
        if !text.is_empty() {
            return text.clone();
        }
    }
    key.to_owned()
}

fn current_locale() -> String {
    match std::env::var("AGENT_SAFEGUARDS_LOCALE") {
        Ok(value) if locale_name_matches(&value) => value,
        _ => DEFAULT_LOCALE.to_owned(),
    }
}

fn file_template(locale: &str, key: &str) -> Option<String> {
    static CACHE: Mutex<BTreeMap<String, BTreeMap<String, String>>> = Mutex::new(BTreeMap::new());
    let mut cache = CACHE.lock().unwrap_or_else(|err| err.into_inner());
    if !cache.contains_key(locale) {
        let loaded = read_catalog(locale);
        cache.insert(locale.to_owned(), loaded);
    }
    cache
        .get(locale)
        .and_then(|catalog| catalog.get(key))
        .filter(|text| !text.is_empty())
        .cloned()
}

fn read_catalog(locale: &str) -> BTreeMap<String, String> {
    let path = format!("{}/locales/{locale}.json", plugin_root());
    match std::fs::read_to_string(path) {
        Ok(text) => parse_catalog(&text),
        Err(_) => BTreeMap::new(),
    }
}

fn embedded_en() -> &'static BTreeMap<String, String> {
    static TABLE: LazyLock<BTreeMap<String, String>> = LazyLock::new(|| parse_catalog(EMBEDDED_EN));
    &TABLE
}

fn parse_catalog(text: &str) -> BTreeMap<String, String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return BTreeMap::new();
    };
    let serde_json::Value::Object(map) = value else {
        return BTreeMap::new();
    };
    let mut out = BTreeMap::new();
    for (key, item) in map {
        if let Some(template) = item.as_str() {
            if !template.is_empty() {
                out.insert(key, template.to_owned());
            }
        }
    }
    out
}

fn render(template: &str, values: &[(&str, FormatValue)]) -> Result<String, ()> {
    let chars: Vec<char> = template.chars().collect();
    let mut out = String::new();
    let mut index = 0usize;
    while index < chars.len() {
        let ch = *chars.get(index).ok_or(())?;
        if ch == '{' {
            if chars.get(index.saturating_add(1)) == Some(&'{') {
                out.push('{');
                index = index.saturating_add(2);
                continue;
            }
            let start = index.saturating_add(1);
            let end = chars
                .iter()
                .enumerate()
                .skip(start)
                .find(|(_, item)| **item == '}')
                .map(|(at, _)| at)
                .ok_or(())?;
            let field: String = chars.get(start..end).unwrap_or(&[]).iter().collect();
            out.push_str(&render_field(&field, values)?);
            index = end.saturating_add(1);
            continue;
        }
        if ch == '}' {
            if chars.get(index.saturating_add(1)) == Some(&'}') {
                out.push('}');
                index = index.saturating_add(2);
                continue;
            }
            return Err(());
        }
        out.push(ch);
        index = index.saturating_add(1);
    }
    Ok(out)
}

fn render_field(field: &str, values: &[(&str, FormatValue)]) -> Result<String, ()> {
    if field.is_empty() || field.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(());
    }
    let (name, rest) = split_field(field);
    if name.contains('.') || name.contains('[') {
        return render_index(name, rest, values);
    }
    let value = values
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
        .ok_or(())?;
    let (conversion, spec_text) = split_conversion(rest)?;
    let spec = parse_spec(spec_text)?;
    if let Some(kind) = conversion {
        let text = match kind {
            's' => python_str(value),
            'r' => python_repr(value),
            'a' => python_ascii(value),
            _ => return Err(()),
        };
        return format_string(&text, &spec);
    }
    match value {
        FormatValue::Text(text) => format_string(text, &spec),
        FormatValue::Int(number) => format_int(*number, &spec),
        FormatValue::Float(number) => format_float(*number, &spec),
    }
}

fn render_index(name: &str, rest: &str, values: &[(&str, FormatValue)]) -> Result<String, ()> {
    let Some(open) = name.find('[') else {
        return Err(());
    };
    if !name.ends_with(']') || rest.contains('.') {
        return Err(());
    }
    let ident = name.get(..open).unwrap_or("");
    let inside = name.get(open.saturating_add(1)..name.len().saturating_sub(1)).unwrap_or("");
    if inside.is_empty() || !inside.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(());
    }
    let index: usize = inside.parse().map_err(|_| ())?;
    let value = values
        .iter()
        .find(|(key, _)| *key == ident)
        .map(|(_, value)| value)
        .ok_or(())?;
    let FormatValue::Text(text) = value else {
        return Err(());
    };
    let ch = text.chars().nth(index).ok_or(())?;
    let (_, spec_text) = split_conversion(rest)?;
    if spec_text.contains('!') {
        return Err(());
    }
    let spec = parse_spec(spec_text)?;
    format_string(&ch.to_string(), &spec)
}

fn split_field(field: &str) -> (&str, &str) {
    if let Some(at) = field.find(['!', ':']) {
        (field.get(..at).unwrap_or(field), field.get(at..).unwrap_or(""))
    } else {
        (field, "")
    }
}

fn split_conversion(rest: &str) -> Result<(Option<char>, &str), ()> {
    if let Some(stripped) = rest.strip_prefix('!') {
        let mut chars = stripped.chars();
        let kind = chars.next().ok_or(())?;
        let leftover = chars.as_str();
        if let Some(spec) = leftover.strip_prefix(':') {
            Ok((Some(kind), spec))
        } else if leftover.is_empty() {
            Ok((Some(kind), ""))
        } else {
            Err(())
        }
    } else if let Some(spec) = rest.strip_prefix(':') {
        Ok((None, spec))
    } else if rest.is_empty() {
        Ok((None, ""))
    } else {
        Err(())
    }
}

#[derive(Clone, Copy)]
enum Align {
    Left,
    Right,
    Center,
    Sign,
    Unset,
}

#[derive(Clone, Copy)]
enum Sign {
    Minus,
    Plus,
    Space,
}

struct Spec {
    fill: char,
    align: Align,
    sign: Sign,
    alternate: bool,
    zero: bool,
    width: usize,
    precision: Option<usize>,
    ty: Option<char>,
    align_set: bool,
    fill_set: bool,
}

fn parse_spec(spec: &str) -> Result<Spec, ()> {
    let chars: Vec<char> = spec.chars().collect();
    let mut index = 0usize;
    let mut parsed = Spec {
        fill: ' ',
        align: Align::Unset,
        sign: Sign::Minus,
        alternate: false,
        zero: false,
        width: 0,
        precision: None,
        ty: None,
        align_set: false,
        fill_set: false,
    };
    if chars.len() >= 2 && is_align(*chars.get(1).unwrap_or(&' ')) {
        parsed.fill = *chars.first().ok_or(())?;
        parsed.fill_set = true;
        parsed.align = align_of(*chars.get(1).ok_or(())?);
        parsed.align_set = true;
        index = 2;
    } else if chars.first().copied().is_some_and(is_align) {
        parsed.align = align_of(*chars.first().ok_or(())?);
        parsed.align_set = true;
        index = 1;
    }
    if let Some(ch) = chars.get(index).copied() {
        if matches!(ch, '+' | '-' | ' ') {
            parsed.sign = match ch {
                '+' => Sign::Plus,
                ' ' => Sign::Space,
                _ => Sign::Minus,
            };
            index = index.saturating_add(1);
        }
    }
    if chars.get(index) == Some(&'#') {
        parsed.alternate = true;
        index = index.saturating_add(1);
    }
    if chars.get(index) == Some(&'0') {
        parsed.zero = true;
        index = index.saturating_add(1);
    }
    let width_start = index;
    while chars.get(index).copied().is_some_and(|ch| ch.is_ascii_digit()) {
        index = index.saturating_add(1);
    }
    if index > width_start {
        let text: String = chars.get(width_start..index).unwrap_or(&[]).iter().collect();
        parsed.width = text.parse().map_err(|_| ())?;
        if parsed.width > 100_000 {
            return Err(());
        }
    }
    if matches!(chars.get(index), Some(',' | '_')) {
        return Err(());
    }
    if chars.get(index) == Some(&'.') {
        index = index.saturating_add(1);
        let prec_start = index;
        while chars.get(index).copied().is_some_and(|ch| ch.is_ascii_digit()) {
            index = index.saturating_add(1);
        }
        if index == prec_start {
            return Err(());
        }
        let text: String = chars.get(prec_start..index).unwrap_or(&[]).iter().collect();
        let precision: usize = text.parse().map_err(|_| ())?;
        if precision > 100_000 {
            return Err(());
        }
        parsed.precision = Some(precision);
    }
    if let Some(ch) = chars.get(index).copied() {
        parsed.ty = Some(ch);
        index = index.saturating_add(1);
    }
    if index != chars.len() {
        return Err(());
    }
    Ok(parsed)
}

fn is_align(ch: char) -> bool {
    matches!(ch, '<' | '>' | '^' | '=')
}

fn align_of(ch: char) -> Align {
    match ch {
        '<' => Align::Left,
        '>' => Align::Right,
        '^' => Align::Center,
        '=' => Align::Sign,
        _ => Align::Unset,
    }
}

fn format_string(text: &str, spec: &Spec) -> Result<String, ()> {
    if spec.alternate || matches!(spec.sign, Sign::Plus | Sign::Space) || matches!(spec.align, Align::Sign)
    {
        return Err(());
    }
    if spec.ty.is_some_and(|ty| ty != 's') {
        return Err(());
    }
    let mut spec = copy_spec(spec);
    if spec.zero && !spec.align_set && !spec.fill_set {
        spec.fill = '0';
        spec.align = Align::Left;
        spec.align_set = true;
    }
    if !spec.align_set {
        spec.align = Align::Left;
    }
    let shown = if let Some(precision) = spec.precision {
        text.chars().take(precision).collect()
    } else {
        text.to_owned()
    };
    Ok(pad(&shown, &spec))
}

fn format_int(number: i64, spec: &Spec) -> Result<String, ()> {
    if spec.ty.is_some_and(|ty| ty != 'd') || spec.precision.is_some() {
        return Err(());
    }
    let mut spec = copy_spec(spec);
    if spec.zero && !spec.align_set {
        spec.align = Align::Sign;
        if !spec.fill_set {
            spec.fill = '0';
        }
        spec.align_set = true;
    }
    if !spec.align_set {
        spec.align = Align::Right;
    }
    let negative = number < 0;
    let magnitude = if number >= 0 {
        number as u64
    } else {
        (number as u64).wrapping_neg()
    };
    let digits = magnitude.to_string();
    let sign = match (negative, spec.sign) {
        (true, _) => "-",
        (false, Sign::Plus) => "+",
        (false, Sign::Space) => " ",
        (false, Sign::Minus) => "",
    };
    Ok(pad_numeric(sign, &digits, &spec))
}

fn format_float(number: f64, spec: &Spec) -> Result<String, ()> {
    if spec.ty.is_some() || spec.precision.is_some() {
        return Err(());
    }
    let mut spec = copy_spec(spec);
    if spec.zero && !spec.align_set {
        spec.align = Align::Sign;
        if !spec.fill_set {
            spec.fill = '0';
        }
        spec.align_set = true;
    }
    if !spec.align_set {
        spec.align = Align::Right;
    }
    let rendered = python_float_repr(number);
    let (negative, body) = if let Some(rest) = rendered.strip_prefix('-') {
        (true, rest)
    } else {
        (false, rendered.as_str())
    };
    let sign = match (negative, spec.sign) {
        (true, _) => "-",
        (false, Sign::Plus) => "+",
        (false, Sign::Space) => " ",
        (false, Sign::Minus) => "",
    };
    Ok(pad_numeric(sign, body, &spec))
}

fn pad_numeric(sign: &str, digits: &str, spec: &Spec) -> String {
    if matches!(spec.align, Align::Sign) {
        let raw = char_len(sign).saturating_add(char_len(digits));
        let pad_len = spec.width.saturating_sub(raw);
        let mut out = String::new();
        out.push_str(sign);
        push_repeat(&mut out, spec.fill, pad_len);
        out.push_str(digits);
        out
    } else {
        let mut core = String::new();
        core.push_str(sign);
        core.push_str(digits);
        pad(&core, spec)
    }
}

fn pad(text: &str, spec: &Spec) -> String {
    let len = char_len(text);
    if spec.width <= len {
        return text.to_owned();
    }
    let extra = spec.width.saturating_sub(len);
    match spec.align {
        Align::Right | Align::Unset => {
            let mut out = String::new();
            push_repeat(&mut out, spec.fill, extra);
            out.push_str(text);
            out
        }
        Align::Left => {
            let mut out = text.to_owned();
            push_repeat(&mut out, spec.fill, extra);
            out
        }
        Align::Center => {
            let left = extra / 2;
            let right = extra.saturating_sub(left);
            let mut out = String::new();
            push_repeat(&mut out, spec.fill, left);
            out.push_str(text);
            push_repeat(&mut out, spec.fill, right);
            out
        }
        Align::Sign => text.to_owned(),
    }
}

fn copy_spec(spec: &Spec) -> Spec {
    Spec {
        fill: spec.fill,
        align: spec.align,
        sign: spec.sign,
        alternate: spec.alternate,
        zero: spec.zero,
        width: spec.width,
        precision: spec.precision,
        ty: spec.ty,
        align_set: spec.align_set,
        fill_set: spec.fill_set,
    }
}

fn push_repeat(out: &mut String, fill: char, count: usize) {
    for _ in 0..count {
        out.push(fill);
    }
}

fn char_len(text: &str) -> usize {
    text.chars().count()
}

fn python_str(value: &FormatValue) -> String {
    match value {
        FormatValue::Text(text) => text.clone(),
        FormatValue::Int(number) => number.to_string(),
        FormatValue::Float(number) => python_float_repr(*number),
    }
}

fn python_repr(value: &FormatValue) -> String {
    match value {
        FormatValue::Text(text) => python_string_literal(text, false),
        FormatValue::Int(number) => number.to_string(),
        FormatValue::Float(number) => python_float_repr(*number),
    }
}

fn python_ascii(value: &FormatValue) -> String {
    match value {
        FormatValue::Text(text) => python_string_literal(text, true),
        _ => python_repr(value),
    }
}

fn python_string_literal(text: &str, ascii_only: bool) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for ch in text.chars() {
        let code = ch as u32;
        if ch == '\\' || ch == quote {
            out.push('\\');
            out.push(ch);
        } else if ch == '\n' {
            out.push_str("\\n");
        } else if ch == '\r' {
            out.push_str("\\r");
        } else if ch == '\t' {
            out.push_str("\\t");
        } else if code < 32 || code == 127 {
            push_byte(&mut out, code);
        } else if code > 127 && (ascii_only || !repr_printable(ch)) {
            if code < 0x100 {
                push_byte(&mut out, code);
            } else if code < 0x10000 {
                out.push_str(&format!("\\u{code:04x}"));
            } else {
                out.push_str(&format!("\\U{code:08x}"));
            }
        } else {
            out.push(ch);
        }
    }
    out.push(quote);
    out
}

fn push_byte(out: &mut String, code: u32) {
    out.push_str(&format!("\\x{code:02x}"));
}

fn repr_printable(ch: char) -> bool {
    !ch.is_control() && !is_private_use(ch)
}

fn is_private_use(ch: char) -> bool {
    matches!(ch, '\u{E000}'..='\u{F8FF}' | '\u{F0000}'..='\u{FFFFD}' | '\u{100000}'..='\u{10FFFD}')
}

#[cfg(test)]
mod tests {
    use super::{message, FormatValue};

    fn s(text: &str) -> FormatValue {
        FormatValue::Text(text.to_owned())
    }

    #[test]
    fn catalog_fields_format_and_missing_keys_stay_literal() {
        let text = message(
            "comment_guard.detail.too_long",
            &[
                ("file", s("a.rs")),
                ("limit", FormatValue::Int(3)),
                ("line", FormatValue::Int(9)),
            ],
        );
        assert!(text.contains("a.rs"), "{text}");
        assert!(text.contains('3'), "{text}");
        assert!(text.contains('9'), "{text}");
        assert!(!text.contains("{file}"), "{text}");
        let raw = message("comment_guard.detail.too_long", &[("file", s("a.rs"))]);
        assert!(raw.contains("{limit}"), "{raw}");
        assert_eq!(message("not.a.real.key", &[]), "not.a.real.key");
    }

    #[test]
    fn format_specs_conversions_and_bad_templates_match_python_rules() {
        assert_eq!(message("{{ok}} {n}", &[("n", FormatValue::Int(1))]), "{ok} 1");
        assert_eq!(message("{s!r}", &[("s", s("hi"))]), "'hi'");
        assert_eq!(
            message("{s!a}", &[("s", s("héllo"))]),
            "'h\\xe9llo'"
        );
        assert_eq!(message("{s:*^10}", &[("s", s("hi"))]), "****hi****");
        assert_eq!(message("{n:05d}", &[("n", FormatValue::Int(42))]), "00042");
        assert_eq!(message("{n:+05d}", &[("n", FormatValue::Int(-3))]), "-0003");
        assert_eq!(message("a {", &[]), "a {");
        assert_eq!(message("{}", &[]), "{}");
        assert_eq!(message("{a.b}", &[("a", s("z"))]), "{a.b}");
        assert_eq!(message("{s[1]}", &[("s", s("ab"))]), "b");
        assert_eq!(message("{s[5]}", &[("s", s("ab"))]), "{s[5]}");
    }
}
