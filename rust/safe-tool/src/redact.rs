use std::io::Read;
use std::net::Ipv6Addr;
use std::str::FromStr;

use guard_common::locale::{message, FormatValue};
use guard_common::secret_scan::contains_secret;
use serde_json::Value;

use crate::{consts, hooks};

pub fn all_octets(candidate: &str) -> Result<bool, &'static str> {
    for part in candidate.split('.') {
        if part
            .chars()
            .any(|character| ('\u{001c}'..='\u{001f}').contains(&character))
        {
            return Err("ValueError");
        }
        let trimmed = part.trim_matches(char::is_whitespace);
        let unsigned = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
        if unsigned.is_empty()
            || unsigned.starts_with(char::is_whitespace)
            || unsigned.split('_').any(str::is_empty)
        {
            return Err("ValueError");
        }
        let digits = unsigned.replace('_', "");
        let value = hooks::line_number(&Value::String(digits), 0)
            .map_err(|_| "ValueError")?
            .ok_or("ValueError")?;
        if trimmed.starts_with('-') && value != 0 {
            continue;
        }
        if value > 255 {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn is_ipv6(candidate: &str) -> bool {
    let address = match candidate.split_once('%') {
        Some((address, scope)) if !scope.is_empty() && !scope.contains(['%', '/']) => address,
        Some(_) => return false,
        None => candidate,
    };
    Ipv6Addr::from_str(address).is_ok()
}

pub fn redact_bytes(raw: &[u8]) -> String {
    if raw.len() > consts::MAX_OUTPUT_BYTES {
        return format!(
            "{}\n",
            message(
                "safe_tool.redact.too_large",
                &[(
                    "kilobytes",
                    FormatValue::Int((consts::MAX_OUTPUT_BYTES / 1024) as i64)
                )]
            )
        );
    }
    let text = String::from_utf8_lossy(raw);
    if contains_secret(&text) || consts::login_banner_pattern_search(&text).is_some() {
        return format!("{}\n", message("safe_tool.withheld.placeholder", &[]));
    }
    let text = consts::redact_url_sub(&text, "<url>");
    let text = consts::redact_user_ipv6_sub_with(&text, |found| {
        if found
            .groups
            .get(1)
            .and_then(Option::as_deref)
            .is_some_and(is_ipv6)
        {
            "\u{e020}".to_owned()
        } else {
            text.get(found.start..found.end).unwrap_or("").to_owned()
        }
    });
    let text = consts::REDACT_USER_HOST
        .replace_all(&text, "<user@host>")
        .into_owned();
    let text = consts::redact_ipv6_sub_with(&text, |found| {
        let candidate = text.get(found.start..found.end).unwrap_or("");
        if is_ipv6(candidate) {
            "<ip6>".to_owned()
        } else {
            candidate.to_owned()
        }
    });
    let text = consts::redact_ipv4_sub_with(&text, |found| {
        if found
            .groups
            .first()
            .and_then(Option::as_deref)
            .is_some_and(|candidate| all_octets(candidate).unwrap_or(false))
        {
            "<ip>".to_owned()
        } else {
            text.get(found.start..found.end).unwrap_or("").to_owned()
        }
    });
    text.replace('\u{e020}', "<user@host>")
}

pub fn redact() -> i32 {
    let mut raw = Vec::new();
    let mut input = std::io::stdin().take(consts::MAX_OUTPUT_BYTES.saturating_add(1) as u64);
    if input.read_to_end(&mut raw).is_err() {
        return 1;
    }
    guard_common::emit::write_stdout(redact_bytes(&raw).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{all_octets, is_ipv6};

    #[test]
    fn octet_boundaries_and_python_integer_forms() {
        assert_eq!(all_octets("255.0.1.2"), Ok(true));
        assert_eq!(all_octets("256.0.1.2"), Ok(false));
        assert_eq!(all_octets("-1.+2.0.1"), Ok(true));
        assert_eq!(all_octets("١.٢.٣.٤"), Ok(true));
        assert_eq!(all_octets("1..2"), Err("ValueError"));
        assert_eq!(all_octets("+ 0"), Err("ValueError"));
        assert_eq!(all_octets("-\r1"), Err("ValueError"));
        assert_eq!(all_octets(" +0 .1.2.3"), Ok(true));
    }

    #[test]
    fn ipv6_scope_and_invalid_address() {
        assert!(is_ipv6("::1%en0"));
        assert!(!is_ipv6("::1%"));
        assert!(!is_ipv6("1:2:3"));
    }
}
