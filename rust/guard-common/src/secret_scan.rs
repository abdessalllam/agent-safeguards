use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use regex::{Captures, Regex};

pub const SCAN_BUDGET_SECONDS: f64 = 3.0;

const INTEGRITY_PREFIXES: [&str; 5] = ["sha1-", "sha256-", "sha384-", "sha512-", "md5-"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PyErr {
    IndexError,
}

impl PyErr {
    pub fn name(self) -> &'static str {
        match self {
            PyErr::IndexError => "IndexError",
        }
    }
}

#[derive(Clone, Copy)]
pub struct Deadline {
    at: Instant,
}

impl Deadline {
    pub fn after(seconds: f64) -> Self {
        if seconds < 0.0 {
            return Self::expired();
        }
        if seconds == 0.0 {
            return Self { at: Instant::now() };
        }
        Self {
            at: Instant::now() + Duration::from_secs_f64(seconds),
        }
    }

    pub fn open() -> Self {
        Self::after(3_600.0)
    }

    pub fn expired() -> Self {
        Self {
            at: Instant::now()
                .checked_sub(Duration::from_secs(86_400))
                .unwrap_or_else(Instant::now),
        }
    }

    pub fn exceeded(self) -> bool {
        Instant::now() > self.at
    }
}

fn compile(source: &str) -> Regex {
    match crate::pyre::new(source) {
        Ok(compiled) => compiled,
        Err(_) => match Regex::new(r"\A\z") {
            Ok(compiled) => compiled,
            Err(_) => std::process::abort(),
        },
    }
}

fn compile_full(source: &str) -> Regex {
    let (flags, body) = if let Some(rest) = source.strip_prefix("(?i)") {
        ("(?i)", rest)
    } else {
        ("", source)
    };
    compile(&format!("{flags}\\A(?:{body})\\z"))
}

macro_rules! re {
    ($name:ident, $pattern:expr) => {
        fn $name() -> &'static Regex {
            static COMPILED: LazyLock<Regex> = LazyLock::new(|| compile($pattern));
            &COMPILED
        }
    };
}

macro_rules! refull {
    ($name:ident, $pattern:expr) => {
        fn $name() -> &'static Regex {
            static COMPILED: LazyLock<Regex> = LazyLock::new(|| compile_full($pattern));
            &COMPILED
        }
    };
}

re!(
    aws_re,
    r"(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}"
);
re!(
    prefixed_re,
    r"(?:(?:\A|[^A-Za-z])sk-(?:ant-|proj-)?|xox[baprs]-|sk_live_|rk_live_|sk_test_|rk_test_)(?P<value>[A-Za-z0-9_-]{12,})"
);
re!(
    authorization_re,
    r#"(?i)authorization\s*[:=]\s*["']?(?P<scheme>bearer|basic|token|digest)\s+(?P<value>[A-Za-z0-9._~+/=-]{8,})"#
);
re!(
    bearer_re,
    r"(?i)bearer\s+(?P<value>[A-Za-z0-9._~+/=-]{24,})"
);
re!(
    query_re,
    r"(?i)[?&](?:[a-z0-9.-]{0,30}_)?(?P<name>token|key|secret|password|passwd|apikey)=(?P<value>[^\s&#]+)"
);
re!(
    url_re,
    r"(?i)[a-z][a-z0-9+.-]{0,30}://[^\s/:@]*:(?P<value>[^\s/@]+)@"
);
re!(
    private_key_re,
    r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY[A-Z ]{0,40}-----"
);
re!(pem_re, r"LS0tLS1CRUdJTi[A-Za-z0-9+/]{16,}");
re!(
    github_re,
    r"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})"
);
re!(
    gitlab_re,
    r"gl(?:pat|dt|ptt|rt|soat|imt|agent|cbt|ft)-[A-Za-z0-9_-]{16,}"
);
re!(
    npm_re,
    r"(?:(?:\A|[^A-Za-z_])npm_[A-Za-z0-9]{30,}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{12,})"
);
re!(xapp_re, r"xapp-\d-[A-Za-z0-9-]{20,}");
re!(whsec_re, r"whsec_[A-Za-z0-9]{24,}");
re!(google_re, r"AIza[0-9A-Za-z_-]{35}");
re!(ya29_re, r"ya29\.[0-9A-Za-z_-]{20,}");
re!(sk_hex_re, r"(?:\A|[^A-Za-z])SK[0-9a-f]{32}");
re!(
    sendgrid_re,
    r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"
);
re!(key_hex_re, r"(?:\A|[^A-Za-z])key-[0-9a-f]{32}");
re!(
    vendor_re,
    r"(?:(?:\A|[^A-Za-z])(?:hf_[A-Za-z0-9]{30,}|gsk_[A-Za-z0-9]{40,}|xai-[A-Za-z0-9]{40,}|pplx-[A-Za-z0-9]{40,}|sbp_[a-f0-9]{40}|shp(?:at|ca|pa|ss)_[a-f0-9]{32})|dop_v1_[a-f0-9]{64}|lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10})"
);
re!(
    login_re,
    r"(?i)\blogin\s+\S+\s+password\s+\S{4,}"
);
re!(
    auth_field_re,
    r#"(?i)"auth"\s*:\s*"[A-Za-z0-9+/=]{16,}""#
);
re!(
    signed_re,
    r"(?i)[?&](?:sig|signature|x-amz-signature)=[A-Za-z0-9%+/=_-]{20,}"
);
re!(
    labeled_main_re,
    r#"(?i)(?P<label>pass(?:word|wd)|pwd|secret|token|credential|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth[_-]?(?:key|token)|account[_-]?key|shared[_-]?access[_-]?key|signing[_-]?key|encryption[_-]?key|session[_-]?key|master[_-]?key)[a-z0-9_.-]{0,40}["']?\s*[:=]\s*["']?(?P<value>[^\s"'<>{}()\[\],;`]{6,})"#
);
re!(
    labeled_auth_re,
    r#"(?i)(?P<label2>_auth)(?:[0-9_.-][A-Za-z0-9_.-]{0,39})?["']?\s*[:=]\s*["']?(?P<value>[^\s"'<>{}()\[\],;`]{6,})"#
);
re!(
    bare_re,
    r"(?:\A|[^A-Za-z0-9+/=_.-])([A-Za-z0-9+/_-]{40,}={0,2})(?:([^A-Za-z0-9+/=_.-])|\z)"
);
re!(
    public_block_re,
    r"-----BEGIN (CERTIFICATE|TRUSTED CERTIFICATE|X509 CERTIFICATE|CERTIFICATE REQUEST|NEW CERTIFICATE REQUEST|X509 CRL|PUBLIC KEY|RSA PUBLIC KEY|EC PUBLIC KEY|PGP PUBLIC KEY BLOCK)-----"
);
re!(
    public_inline_re,
    r"(?:ssh-[a-z0-9]+|ecdsa-sha2-[a-z0-9]+)\s+AAAA[A-Za-z0-9+/=]+|data:[a-z0-9/+.-]+;base64,[A-Za-z0-9+/=]+"
);
re!(jwt_first_re, r"eyJ[A-Za-z0-9_-]{8,}");
re!(base64url_re, r"[A-Za-z0-9_-]{5,}");
re!(query_continuation_re, r"\A([^&]+)&[A-Za-z_][\w.-]*=");
re!(percent_escape_re, r"\A%[0-9A-Fa-f]{2}");
re!(hyphen_re, r"[-_]");
re!(password_label_re, r"(?i)pass|pwd");
refull!(word_part_re, r"[a-z]{4,}[0-9]{0,3}");

refull!(lower_words_re, r"[a-z]+(?:[-_][a-z]+)*");
refull!(
    word_list_re,
    r"[a-z]{2,}[0-9]{0,3}(?:[-_][a-z]{2,}[0-9]{0,3})*"
);
refull!(
    fixture_re,
    r"(?i)(?:test|testing|dummy|fake|sample|example|demo|mock|placeholder|changeme|insert|replace)(?:[-_.][A-Za-z0-9._-]*|[0-9]*)"
);
refull!(
    placeholder_re,
    r"(?i)(?:x+|\*+|\.+|-+|_+|changeme|change-me|redacted|your[-_].*|example.*|placeholder|todo|null|none|nil|undefined|true|false|yes|no|required|optional|enabled|disabled|password|secret|token)"
);
refull!(
    identifier_re,
    r"_*[A-Za-z]{2,}(?:[_:-][A-Za-z]+)+(?:[-_][0-9]{1,4})?|_+[A-Za-z][A-Za-z_]{2,}|[a-z]{2,}[-_][0-9]{1,6}"
);
refull!(code_name_re, r"[a-z]+(?:[A-Z][a-z]+)+|(?:[A-Z][a-z]+){2,}|[A-Z]{2,}(?:_[A-Z]{2,})+");
refull!(title_re, r"[A-Z][a-z]{5,}");
refull!(
    code_reference_re,
    r"&?[A-Za-z_]\w*(?:(?:[!?]?\.|::)[A-Za-z_]\w*)+[!?]?(?:\(\))?"
);
refull!(rust_path_re, r"&?[A-Za-z_]\w*(?:::[A-Za-z_]\w*)+");
refull!(letters_re, r"[A-Za-z_]{2,}");
refull!(template_percent_re, r"%[A-Za-z_]\w*%");
refull!(snake_re, r"_*[a-z]+(?:_[a-z]+)+");
refull!(
    password_fixture_re,
    r"[a-z_-]*(?:password|passwd|secret|token)[a-z_-]*"
);
refull!(
    non_secret_re,
    r"[0-9][0-9_]*(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?|[^@\s]+@[^@\s]+\.[A-Za-z]{2,}|[A-Za-z_.]+/[A-Z][A-Z0-9_]+|[a-z]{2,10}[0-9]{1,6}"
);
refull!(env_reference_re, r"[A-Za-z_.]+/[A-Z][A-Z0-9_]+");
refull!(
    range_version_re,
    r"[\^~<>=v]+\d+(?:\.\d+)*(?:[-+][\w.+-]*)?"
);
refull!(
    version_re,
    r"(?:[\^~<>=v]+\d+(?:\.\d+)*|\d+(?:\.\d+)+)(?:[-+][\w.+-]*)?"
);
refull!(
    dotted_re,
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+"
);
refull!(slug_segment_re, r"[a-z]+|[A-Z]+|(?:[A-Z][a-z]+)+|[0-9]+|[0-9a-f]{3,12}");
refull!(slug_word_re, r"[a-z]{4,}|[A-Z][a-z]{3,}(?:[A-Z][a-z]+)*");
re!(separators_re, r"[-_/.+:]+");

/// Python `isdigit` is narrower than `char::is_numeric` (fractions, roman numerals) and wider than ASCII.
fn py_isdigit(ch: char) -> bool {
    crate::pychars::is_digit(ch)
}

fn py_isupper(value: &str) -> bool {
    let mut cased = false;
    for ch in value.chars() {
        if ch.is_lowercase() {
            return false;
        }
        if ch.is_uppercase() {
            cased = true;
        }
    }
    cased
}

fn py_islower(value: &str) -> bool {
    let mut cased = false;
    for ch in value.chars() {
        if ch.is_uppercase() {
            return false;
        }
        if ch.is_lowercase() {
            cased = true;
        }
    }
    cased
}

fn char_len(value: &str) -> usize {
    value.chars().count()
}

fn full(re: &Regex, text: &str) -> bool {
    re.is_match(text)
}

pub fn entropy(value: &str) -> Result<f64, PyErr> {
    let chars: Vec<char> = value.chars().collect();
    if chars.is_empty() {
        return Ok(0.0);
    }
    let mut counts: Vec<(char, usize)> = Vec::new();
    for ch in chars.iter().copied() {
        if let Some(slot) = counts.iter_mut().find(|(found, _)| *found == ch) {
            slot.1 = slot.1.saturating_add(1);
        } else {
            counts.push((ch, 1));
        }
    }
    let total = chars.len() as f64;
    let mut sum = 0.0f64;
    for (_, count) in counts {
        let portion = count as f64 / total;
        sum += portion * portion.log2();
    }
    Ok(-sum)
}

pub fn ascending_run(value: &str, length: usize) -> bool {
    let mut chars = value.chars();
    let Some(mut previous) = chars.next() else {
        return false;
    };
    let mut run = 1usize;
    for current in chars {
        if (current as u32) == (previous as u32).saturating_add(1) && crate::pychars::is_alnum(current) {
            run = run.saturating_add(1);
        } else {
            run = 1;
        }
        if run >= length {
            return true;
        }
        previous = current;
    }
    false
}

fn repeated_alnum(value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        let Some(ch) = chars.get(index).copied() else {
            break;
        };
        if ch.is_ascii_alphanumeric() {
            let mut next = index.saturating_add(1);
            while chars.get(next).copied() == Some(ch) {
                next = next.saturating_add(1);
            }
            if next.saturating_sub(index) >= 5 {
                return true;
            }
            index = next;
        } else {
            index = index.saturating_add(1);
        }
    }
    false
}

pub fn placeholder_shaped(value: &str) -> bool {
    full(lower_words_re(), value)
        || (full(word_list_re(), value)
            && hyphen_re()
                .split(value)
                .filter(|part| full(word_part_re(), part))
                .count()
                >= 2)
        || full(fixture_re(), value)
        || full(placeholder_re(), value)
        || repeated_alnum(value)
        || ascending_run(value, 6)
}

pub fn is_slug(value: &str) -> bool {
    let parts: Vec<&str> = separators_re().split(value).filter(|part| !part.is_empty()).collect();
    if parts.len() < 4 {
        return false;
    }
    let total: usize = parts.iter().map(|part| char_len(part)).sum();
    let covered: usize = parts
        .iter()
        .filter(|part| full(slug_segment_re(), part))
        .map(|part| char_len(part))
        .sum();
    let words = parts.iter().filter(|part| full(slug_word_re(), part)).count();
    (covered as f64) >= 0.8 * (total as f64) && total.saturating_sub(covered) < 20 && words >= 2
}

pub fn annotation(value: &str) -> bool {
    let rest = value.trim_matches(|ch| matches!(ch, '&' | ':' | '*'));
    if rest.is_empty() || rest == value {
        return false;
    }
    full(code_name_re(), rest)
        || full(title_re(), rest)
        || full(identifier_re(), rest)
        || full(code_reference_re(), rest)
        || full(rust_path_re(), rest)
        || full(letters_re(), rest)
        || type_name(rest)
}

pub fn template_percent(value: &str) -> Result<bool, PyErr> {
    let Some(first) = value.chars().next() else {
        return Err(PyErr::IndexError);
    };
    Ok(first == '%' && (full(template_percent_re(), value) || !percent_escape_re().is_match(value)))
}

fn camel_words(value: &str) -> usize {
    let chars: Vec<char> = value.chars().collect();
    let mut index = 0usize;
    let mut count = 0usize;
    while index < chars.len() {
        let Some(ch) = chars.get(index).copied() else {
            break;
        };
        if ch.is_ascii_uppercase() {
            let start = index;
            while chars.get(index).copied().is_some_and(|item| item.is_ascii_uppercase()) {
                index = index.saturating_add(1);
            }
            if chars.get(index).copied().is_some_and(|item| item.is_ascii_lowercase()) {
                if index.saturating_sub(start) >= 2 {
                    count = count.saturating_add(1);
                    index = index.saturating_sub(1);
                }
                index = index.saturating_add(1);
                while chars.get(index).copied().is_some_and(|item| item.is_ascii_lowercase()) {
                    index = index.saturating_add(1);
                }
                count = count.saturating_add(1);
            } else {
                count = count.saturating_add(1);
            }
        } else if ch.is_ascii_lowercase() {
            while chars.get(index).copied().is_some_and(|item| item.is_ascii_lowercase()) {
                index = index.saturating_add(1);
            }
            count = count.saturating_add(1);
        } else {
            index = index.saturating_add(1);
        }
    }
    count
}

pub fn type_name(value: &str) -> bool {
    if !full(letters_only_re(), value) || py_islower(value) || py_isupper(value) {
        return false;
    }
    char_len(value) >= 3usize.saturating_mul(camel_words(value))
}

refull!(letters_only_re, r"[A-Za-z]{8,}");

pub fn looks_like_path(value: &str) -> Result<bool, PyErr> {
    let Some(first) = value.chars().next() else {
        return Err(PyErr::IndexError);
    };
    Ok(first == '/'
        && (char_len(value) < 24
            || value.contains('.')
            || value.chars().filter(|ch| ch.is_uppercase()).count() < 3))
}

fn within_chars(value: &str, count: usize) -> &str {
    let mut end = 0usize;
    for (seen, ch) in value.chars().enumerate() {
        if seen == count {
            break;
        }
        end = end.saturating_add(ch.len_utf8());
    }
    value.get(..end).unwrap_or(value)
}

pub fn plausible_value(label: &str, value: &str) -> Result<bool, PyErr> {
    let Some(first) = value.chars().next() else {
        return Err(PyErr::IndexError);
    };
    if full(placeholder_re(), value)
        || matches!(first, '$' | '<' | '{' | '*' | '~' | '.')
        || template_percent(value)?
        || annotation(value)
        || value.starts_with("-----BEGIN")
        || within_chars(value, 12).contains("://")
        || looks_like_path(value)?
    {
        return Ok(false);
    }
    let password = password_label_re().is_match(label);
    if full(code_name_re(), value)
        || full(title_re(), value)
        || (char_len(value) <= 48 && (full(fixture_re(), value) || value.contains("EXAMPLE")))
    {
        return Ok(false);
    }
    if password {
        if full(snake_re(), value)
            || full(rust_path_re(), value)
            || (char_len(value) <= 40 && full(password_fixture_re(), value))
        {
            return Ok(false);
        }
    } else if full(identifier_re(), value)
        || full(code_reference_re(), value)
        || full(non_secret_re(), value)
        || type_name(value)
        || placeholder_shaped(value)
    {
        return Ok(false);
    }
    if password {
        if full(range_version_re(), value)
            || (full(dotted_re(), value)
                && first.is_lowercase()
                && !value.chars().any(py_isdigit))
        {
            return Ok(false);
        }
    } else if full(version_re(), value) || full(dotted_re(), value) {
        return Ok(false);
    }
    let minimum = if password { 6 } else { 8 };
    if char_len(value) < minimum {
        return Ok(false);
    }
    if value
        .chars()
        .any(|ch| py_isdigit(ch) || ch.is_uppercase() || !crate::pychars::is_alnum(ch))
    {
        return Ok(true);
    }
    Ok(password && char_len(value) >= 10)
}

pub fn token_looks_real(value: &str) -> bool {
    if placeholder_shaped(value)
        || value.contains("...")
        || value.contains('\u{2026}')
        || value.contains("EXAMPLE")
    {
        return false;
    }
    let mixed = value.chars().any(|ch| ch.is_uppercase())
        && value.chars().any(|ch| ch.is_lowercase())
        && value.chars().any(py_isdigit);
    if mixed {
        return true;
    }
    let Ok(score) = entropy(value) else {
        return false;
    };
    let len = char_len(value);
    (len >= 24 && score >= 3.3) || (len >= 16 && value.chars().any(py_isdigit) && score >= 3.0)
}

pub fn real_aws_key(matched: &str) -> bool {
    !matched.ends_with("EXAMPLE")
}

pub fn real_prefixed_key(value: &str) -> bool {
    token_looks_real(value)
}

pub fn real_authorization(value: &str) -> bool {
    !(placeholder_shaped(value)
        || full(code_name_re(), value)
        || value.contains("...")
        || value.contains('\u{2026}'))
}

pub fn real_credentials(value: &str) -> Result<bool, PyErr> {
    let Some(first) = value.chars().next() else {
        return Err(PyErr::IndexError);
    };
    Ok(!(matches!(first, '$' | '<' | '{' | '*' | '[')
        || template_percent(value)?
        || annotation(value)
        || placeholder_shaped(value)
        || full(code_name_re(), value)
        || full(non_secret_re(), value)
        || full(env_reference_re(), value)))
}

pub fn real_query_value(raw: &str) -> bool {
    let value = raw.trim_matches(|ch| matches!(ch, '\'' | '"' | '`' | ',' | ';' | ')' | ']' | '}' | '>'));
    let Some(first) = value.chars().next() else {
        return false;
    };
    if matches!(first, '$' | '<' | '{' | '*' | '[' | '@' | '(')
        || matches!(template_percent(value), Ok(true) | Err(_))
        || annotation(value)
    {
        return false;
    }
    !(full(code_name_re(), value)
        || full(code_reference_re(), value)
        || full(identifier_re(), value)
        || full(placeholder_re(), value)
        || full(env_reference_re(), value))
}

#[derive(Clone, Copy)]
enum Check {
    None,
    Aws,
    Token,
    Authorization,
    Credentials,
    Query,
}

struct Pattern {
    name: &'static str,
    key: bool,
    regex: fn() -> &'static Regex,
    check: Check,
}

fn patterns() -> &'static [Pattern] {
    &[
        Pattern { name: "private_key", key: true, regex: private_key_re, check: Check::None },
        Pattern { name: "pem_header", key: true, regex: pem_re, check: Check::None },
        Pattern { name: "aws_access_key", key: true, regex: aws_re, check: Check::Aws },
        Pattern { name: "github", key: true, regex: github_re, check: Check::None },
        Pattern { name: "gitlab", key: true, regex: gitlab_re, check: Check::None },
        Pattern { name: "npm", key: true, regex: npm_re, check: Check::None },
        Pattern { name: "prefixed", key: true, regex: prefixed_re, check: Check::Token },
        Pattern { name: "xapp", key: true, regex: xapp_re, check: Check::None },
        Pattern { name: "whsec", key: true, regex: whsec_re, check: Check::None },
        Pattern { name: "google", key: true, regex: google_re, check: Check::None },
        Pattern { name: "ya29", key: true, regex: ya29_re, check: Check::None },
        Pattern { name: "sk_hex", key: true, regex: sk_hex_re, check: Check::None },
        Pattern { name: "sendgrid", key: true, regex: sendgrid_re, check: Check::None },
        Pattern { name: "mailgun", key: true, regex: key_hex_re, check: Check::None },
        Pattern { name: "vendor", key: true, regex: vendor_re, check: Check::None },
        Pattern { name: "authorization", key: true, regex: authorization_re, check: Check::Authorization },
        Pattern { name: "bearer", key: true, regex: bearer_re, check: Check::Token },
        Pattern { name: "login", key: true, regex: login_re, check: Check::None },
        Pattern { name: "auth_field", key: true, regex: auth_field_re, check: Check::None },
        Pattern { name: "signed_url", key: false, regex: signed_re, check: Check::None },
        Pattern { name: "query", key: false, regex: query_re, check: Check::Query },
        Pattern { name: "url_credentials", key: true, regex: url_re, check: Check::Credentials },
    ]
}

fn group<'a>(caps: &'a Captures<'a>, name: &str) -> Option<&'a str> {
    caps.name(name).map(|item| item.as_str())
}

fn check_hit(check: Check, caps: &Captures<'_>) -> bool {
    match check {
        Check::None => true,
        Check::Aws => caps.get(0).is_some_and(|item| real_aws_key(item.as_str())),
        Check::Token => group(caps, "value").is_some_and(real_prefixed_key),
        Check::Authorization => group(caps, "value").is_some_and(real_authorization),
        Check::Credentials => group(caps, "value")
            .is_some_and(|value| matches!(real_credentials(value), Ok(true))),
        Check::Query => group(caps, "value").is_some_and(real_query_value),
    }
}

fn scan_pattern(pattern: &Pattern, text: &str, deadline: Deadline) -> bool {
    let regex = (pattern.regex)();
    match pattern.check {
        Check::None => regex.is_match(text),
        _ => {
            for caps in regex.captures_iter(text) {
                if check_hit(pattern.check, &caps) || deadline.exceeded() {
                    return true;
                }
            }
            false
        }
    }
}

pub fn format_secret(name: &str, text: &str, deadline: Deadline) -> bool {
    let Some(pattern) = patterns().iter().find(|pattern| pattern.name == name) else {
        return false;
    };
    scan_pattern(pattern, text, deadline)
}

fn next_char(text: &str, byte: usize) -> Option<char> {
    text.get(byte..)?.chars().next()
}

fn chars_before(text: &str, byte: usize, count: usize) -> &str {
    let prefix = text.get(..byte).unwrap_or("");
    let total = prefix.chars().count();
    let skip = total.saturating_sub(count);
    let mut rest = prefix;
    for _ in 0..skip {
        let Some(ch) = rest.chars().next() else {
            break;
        };
        rest = rest.get(ch.len_utf8()..).unwrap_or("");
    }
    rest
}

pub fn labeled_secret(text: &str, deadline: Deadline) -> bool {
    let mut pos = 0usize;
    loop {
        let main = labeled_main_re().find_at(text, pos);
        let auth = labeled_auth_re().find_at(text, pos);
        let use_main = match (main, auth) {
            (Some(left), Some(right)) => left.start() <= right.start(),
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => return false,
        };
        let Some(caps) = (if use_main {
            labeled_main_re().captures_at(text, pos)
        } else {
            labeled_auth_re().captures_at(text, pos)
        }) else {
            return false;
        };
        if deadline.exceeded() {
            return true;
        }
        let Some(whole) = caps.get(0) else {
            return false;
        };
        let Some(value_match) = caps.name("value") else {
            return false;
        };
        let next = if whole.end() > pos {
            whole.end()
        } else {
            pos.saturating_add(1)
        };
        if matches!(next_char(text, value_match.end()), Some('(' | '[')) {
            pos = next;
            continue;
        }
        let label = caps
            .name("label")
            .or_else(|| caps.name("label2"))
            .map(|item| item.as_str())
            .unwrap_or("");
        let raw = value_match.as_str();
        let value = if let Some(found) = query_continuation_re().captures(raw) {
            found.get(1).map(|item| item.as_str()).unwrap_or(raw)
        } else {
            raw
        };
        if !value.is_empty() && matches!(plausible_value(label, value), Ok(true)) {
            return true;
        }
        pos = next;
    }
}

pub fn without_public_material(text: &str) -> String {
    let mut kept = Vec::new();
    let mut position = 0usize;
    let mut ends: HashMap<String, isize> = HashMap::new();
    for caps in public_block_re().captures_iter(text) {
        let Some(whole) = caps.get(0) else {
            continue;
        };
        if whole.start() < position {
            continue;
        }
        let Some(label_match) = caps.get(1) else {
            continue;
        };
        let label = label_match.as_str();
        let marker = format!("-----END {label}-----");
        let mut end = ends.get(label).copied().unwrap_or(-2);
        if end != -1 && end < whole.end() as isize {
            end = text
                .get(whole.end()..)
                .and_then(|rest| rest.find(&marker))
                .map(|at| whole.end().saturating_add(at) as isize)
                .unwrap_or(-1);
            ends.insert(label.to_owned(), end);
        }
        if end < 0 {
            continue;
        }
        kept.push(text.get(position..whole.start()).unwrap_or("").to_owned());
        position = (end as usize).saturating_add(marker.len());
    }
    kept.push(text.get(position..).unwrap_or("").to_owned());
    let joined = join_space(&kept);
    public_inline_re().replace_all(&joined, " ").into_owned()
}

fn join_space(parts: &[String]) -> String {
    let mut out = String::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        out.push_str(part);
    }
    out
}

pub fn jwt_secret(text: &str) -> bool {
    for found in jwt_first_re().find_iter(text) {
        if next_char(text, found.end()) != Some('.') {
            continue;
        }
        let second_at = found.end().saturating_add(1);
        let Some(second) = base64url_re().find_at(text, second_at) else {
            continue;
        };
        if second.start() != second_at || next_char(text, second.end()) != Some('.') {
            continue;
        }
        let third_at = second.end().saturating_add(1);
        if let Some(third) = base64url_re().find_at(text, third_at) {
            if third.start() == third_at {
                return true;
            }
        }
    }
    false
}

pub fn bare_secret(text: &str, deadline: Deadline) -> bool {
    let cleaned = without_public_material(text);
    let mut pos = 0usize;
    while pos <= cleaned.len() {
        let Some(caps) = bare_re().captures_at(&cleaned, pos) else {
            break;
        };
        if deadline.exceeded() {
            return true;
        }
        let Some(whole) = caps.get(0) else {
            break;
        };
        let Some(candidate_match) = caps.get(1) else {
            break;
        };
        let resume = caps.get(2).map(|item| item.start()).unwrap_or_else(|| whole.end());
        let advance = if resume > pos { resume } else { pos.saturating_add(1) };
        let candidate = candidate_match.as_str();
        let lower = candidate.to_lowercase();
        let slashes = candidate.chars().filter(|ch| *ch == '/').count();
        let length = char_len(candidate);
        let skip = INTEGRITY_PREFIXES.iter().any(|prefix| lower.starts_with(prefix))
            || (slashes as f64) > (length as f64) * 0.08
            || is_slug(candidate)
            || chars_before(&cleaned, candidate_match.start(), 3) == "h1:";
        if !skip {
            let mixed = candidate.chars().any(|ch| ch.is_uppercase())
                && candidate.chars().any(|ch| ch.is_lowercase())
                && candidate.chars().any(py_isdigit);
            if mixed {
                if let Ok(score) = entropy(candidate) {
                    if score >= 4.2 {
                        return true;
                    }
                }
            }
        }
        pos = advance;
    }
    false
}

pub fn contains_secret(text: &str) -> bool {
    contains_secret_by(text, Deadline::after(SCAN_BUDGET_SECONDS))
}

pub fn contains_secret_by(text: &str, deadline: Deadline) -> bool {
    for pattern in patterns() {
        if scan_pattern(pattern, text, deadline) || deadline.exceeded() {
            return true;
        }
    }
    let found = jwt_secret(text) || labeled_secret(text, deadline) || bare_secret(text, deadline);
    found || deadline.exceeded()
}

pub fn contains_key(text: &str) -> bool {
    contains_key_by(text, Deadline::after(SCAN_BUDGET_SECONDS))
}

pub fn contains_key_by(text: &str, deadline: Deadline) -> bool {
    for pattern in patterns().iter().filter(|pattern| pattern.key) {
        if scan_pattern(pattern, text, deadline) || deadline.exceeded() {
            return true;
        }
    }
    jwt_secret(text) || deadline.exceeded()
}

#[cfg(test)]
mod tests {
    use super::{
        contains_key, contains_secret, contains_secret_by, entropy, jwt_secret, placeholder_shaped,
        Deadline,
    };

    #[test]
    fn labelled_passwords_and_versions_follow_the_python_regressions() {
        for text in [
            "password=4815162342",
            "db_passwd=12345678",
            "password=123.456.789",
            "password=10.20.30",
            "password=Red.Bicycle.Sample",
            "password=Summer.Holiday.Plans",
        ] {
            assert!(contains_secret(text), "{text}");
        }
        for text in [
            "\"password-validator\": \"^1.2.3\"",
            "\"jsonwebtoken\": \"9.0.2\"",
            "const secretKey = process.env.SECRET_KEY;",
            "token: v2.31.0",
            "added 3 packages in 1s",
        ] {
            assert!(!contains_secret(text), "{text}");
        }
    }

    #[test]
    fn jwt_needs_three_segments_and_a_past_deadline_withholds() {
        assert!(jwt_secret("eyJaaaaaaaa.bbbbbbbb.cccccccc"));
        assert!(!contains_secret(&format!("eyJ{}{}", "a".repeat(40), ".short")));
        assert!(!contains_secret(&format!("eyJ{}", "a".repeat(40))));
        assert!(contains_secret_by("added 3 packages in 1s", Deadline::expired()));
        assert!(!contains_key("added 3 packages in 1s"));
        assert!(contains_key_by_expired());
    }

    fn contains_key_by_expired() -> bool {
        super::contains_key_by("added 3 packages in 1s", Deadline::expired())
    }

    #[test]
    fn entropy_and_placeholders_cover_the_obvious_shapes() {
        assert_eq!(entropy("").ok(), Some(0.0));
        assert_eq!(entropy("aaaa").ok(), Some(0.0));
        assert_eq!(entropy("ab").ok(), Some(1.0));
        assert!(placeholder_shaped("changeme"));
        assert!(placeholder_shaped("xxxxxxxx"));
        assert!(placeholder_shaped("abcdef"));
        assert!(!placeholder_shaped("Aa1"));
    }
}
