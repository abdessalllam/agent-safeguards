use std::net::Ipv4Addr;
use std::sync::LazyLock;

use guard_common::{emit, env, locale, secret_scan, shell};
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::{command, consts, words};

pub const MAX_RESPONSE_DEPTH: usize = 64;
pub const MAX_LABEL_VALUE: usize = 2048;
pub const MAX_LABEL_VIEW: usize = 262144;
pub const MAX_SHAPE_DEPTH: usize = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseTooComplex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownWhy;

fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => {
            match guard_common::pyjson::integer_text(number) {
                Some(text) => Some(text),
                None => Some(guard_common::emit::python_float_repr(number.as_f64()?)),
            }
        }
        _ => None,
    }
}

pub fn response_text(value: &Value, depth: usize) -> Result<String, ResponseTooComplex> {
    if depth > MAX_RESPONSE_DEPTH {
        return Err(ResponseTooComplex);
    }
    match value {
        Value::Object(fields) => fields
            .iter()
            .map(|(key, child)| {
                Ok(format!(
                    "{key}={}",
                    response_text(child, depth.saturating_add(1))?
                ))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|lines| lines.join("\n")),
        Value::Array(items) => items
            .iter()
            .map(|child| response_text(child, depth.saturating_add(1)))
            .collect::<Result<Vec<_>, _>>()
            .map(|lines| lines.join("\n")),
        _ => Ok(scalar_text(value).unwrap_or_default()),
    }
}

fn prefix_chars(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

fn gather_labels(
    value: &Value,
    depth: usize,
    found: &mut Vec<String>,
    size: &mut usize,
) -> Result<(), ResponseTooComplex> {
    if depth > MAX_RESPONSE_DEPTH {
        return Err(ResponseTooComplex);
    }
    match value {
        Value::Object(fields) => {
            for (key, child) in fields {
                if let Some(text) = scalar_text(child) {
                    let text = prefix_chars(&text, MAX_LABEL_VALUE);
                    let key = prefix_chars(key, 256);
                    *size = size
                        .saturating_add(text.chars().count())
                        .saturating_add(key.chars().count())
                        .saturating_add(1);
                    found.push(format!("{key}={text}"));
                    if *size > MAX_LABEL_VIEW {
                        return Err(ResponseTooComplex);
                    }
                } else {
                    gather_labels(child, depth.saturating_add(1), found, size)?;
                }
            }
        }
        Value::Array(items) => {
            for child in items {
                gather_labels(child, depth.saturating_add(1), found, size)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn response_labels(value: &Value, depth: usize) -> Result<String, ResponseTooComplex> {
    let mut found = Vec::new();
    let mut size = 0;
    gather_labels(value, depth, &mut found, &mut size)?;
    Ok(found.join("\n"))
}

pub fn response_values(value: &Value, depth: usize) -> Result<String, ResponseTooComplex> {
    if depth > MAX_RESPONSE_DEPTH {
        return Err(ResponseTooComplex);
    }
    match value {
        Value::String(text) => Ok(text.clone()),
        Value::Object(fields) => fields
            .iter()
            .map(|(key, child)| {
                Ok(format!(
                    "{key}\n{}",
                    response_values(child, depth.saturating_add(1))?
                ))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|lines| lines.join("\n")),
        Value::Array(items) => items
            .iter()
            .map(|child| response_values(child, depth.saturating_add(1)))
            .collect::<Result<Vec<_>, _>>()
            .map(|lines| lines.join("\n")),
        _ => Ok(String::new()),
    }
}

pub fn shows_private_address(text: &str) -> bool {
    if env::env_flag("AGENT_SAFEGUARDS_SHOW_ADDRESSES") {
        return false;
    }
    let stripped = consts::emulator_address_sub(text, " ");
    consts::private_address_v4_search(&stripped).is_some()
        || consts::private_address_v6_search(&stripped).is_some()
}

pub fn reportable_address(candidate: &str) -> bool {
    let Ok(address) = candidate.parse::<Ipv4Addr>() else {
        return false;
    };
    !(address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || address.octets() == [255, 255, 255, 255])
}

pub fn shows_host_details(command: &str, text: &str) -> bool {
    if env::env_flag("AGENT_SAFEGUARDS_SHOW_ADDRESSES") {
        return false;
    }
    if consts::login_banner_pattern_search(text).is_some() {
        return true;
    }
    let stripped = consts::emulator_address_sub(text, " ");
    if consts::labelled_address_finditer(&stripped)
        .iter()
        .filter_map(|found| found.groups.first().and_then(Option::as_deref))
        .any(reportable_address)
    {
        return true;
    }
    consts::ADDRESS_LOOKUP_COMMAND.is_match(command)
        && consts::bare_address_finditer(&stripped)
            .iter()
            .filter_map(|found| found.groups.first().and_then(Option::as_deref))
            .any(reportable_address)
}

pub fn plain_chunk(chunk: &[String]) -> bool {
    let mut words = chunk
        .iter()
        .filter(|word| !shell::ASSIGNMENT.is_match(word));
    words
        .next()
        .is_some_and(|word| consts::in_plain_utilities(&words::normalized(word)))
}

fn identity_email(full: &str, domain: &str) -> bool {
    let domain = domain.to_lowercase();
    let local = full
        .rsplit_once('@')
        .map_or("", |(local, _)| local)
        .to_lowercase();
    if consts::RESERVED_EMAIL_DOMAINS.contains(&domain.as_str())
        || consts::FIXTURE_EMAIL_DOMAINS.contains(&domain.as_str())
        || consts::RESERVED_EMAIL_SUFFIXES
            .iter()
            .any(|suffix| domain.ends_with(suffix))
    {
        return false;
    }
    !consts::in_shared_email_locals(&local)
        && !local.starts_with("noreply")
        && !local.starts_with("no-reply")
}

pub fn sensitive_output(command: &str, response: &Value) -> Result<bool, ResponseTooComplex> {
    Ok(withheld_because(command, response)?.is_some())
}

pub fn withheld_because(
    command: &str,
    response: &Value,
) -> Result<Option<String>, ResponseTooComplex> {
    let text = response_text(response, 0)?;
    if secret_scan::contains_secret(&response_values(response, 0)?)
        || secret_scan::contains_secret(&response_labels(response, 0)?)
    {
        return Ok(Some("secret".to_owned()));
    }
    let private_email = consts::EMAIL_PATTERN.captures_iter(&text).any(|found| {
        let full = found.get(0).map_or("", |item| item.as_str());
        let domain = found.get(1).map_or("", |item| item.as_str());
        identity_email(full, domain)
    });
    let identity_context = std::iter::once(command.to_owned())
        .chain(shell::command_substitutions(command))
        .flat_map(|text| words::tokenize(&text))
        .filter(|chunk| !plain_chunk(chunk))
        .flatten()
        .map(|token| words::normalized(&token))
        .any(|token| {
            matches!(
                token.as_str(),
                "account"
                    | "auth"
                    | "doctor"
                    | "identity"
                    | "org"
                    | "organization"
                    | "profile"
                    | "status"
                    | "whoami"
            ) || token.contains("identity")
        });
    let labeled_non_email_identity = consts::NON_EMAIL_IDENTITY_FIELD_PATTERN.is_match(&text);
    let values = response_values(response, 0)?;
    if private_email {
        return Ok(Some("email".to_owned()));
    }
    if identity_context && labeled_non_email_identity {
        return Ok(Some("identity".to_owned()));
    }
    if consts::DEFINITION_OUTPUT_PATTERN.is_match(&values) {
        return Ok(Some("definition".to_owned()));
    }
    if shows_private_address(&values) {
        return Ok(Some("address".to_owned()));
    }
    if shows_host_details(command, &values) {
        return Ok(Some("host".to_owned()));
    }
    Ok(None)
}

static SHAPE_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A[A-Za-z][A-Za-z0-9_]{0,31}\z")
        .unwrap_or_else(|error| panic!("invalid shape pattern: {error}"))
});

pub fn shape_key(key: &str, position: usize) -> String {
    if SHAPE_FIELD.is_match(key) && !secret_scan::contains_secret(key) {
        key.to_owned()
    } else {
        format!("field{position}")
    }
}

pub fn withheld_shape(value: &Value, root: bool, depth: usize) -> Value {
    let placeholder = locale::message("safe_tool.withheld.placeholder", &[]);
    if depth > MAX_SHAPE_DEPTH {
        return Value::Null;
    }
    match value {
        Value::Object(fields) => {
            let replacement: Map<String, Value> = fields
                .iter()
                .enumerate()
                .map(|(position, (key, child))| {
                    (
                        shape_key(key, position),
                        withheld_shape(child, false, depth.saturating_add(1)),
                    )
                })
                .collect();
            let mut replacement = replacement;
            for key in ["stdout", "output", "content"] {
                if replacement.get(key).is_some_and(Value::is_string) {
                    replacement.insert(key.to_owned(), Value::String(placeholder));
                    break;
                }
            }
            Value::Object(replacement)
        }
        Value::Array(_) => json!([]),
        Value::String(_) => Value::String(if root { placeholder } else { String::new() }),
        Value::Bool(_) | Value::Null => value.clone(),
        Value::Number(_) => json!(0),
    }
}

fn why_key(why: &str) -> Option<&'static str> {
    match why {
        "secret" => Some("safe_tool.withheld.why.secret"),
        "email" => Some("safe_tool.withheld.why.email"),
        "identity" => Some("safe_tool.withheld.why.identity"),
        "definition" => Some("safe_tool.withheld.why.definition"),
        "address" => Some("safe_tool.withheld.why.address"),
        "host" => Some("safe_tool.withheld.why.host"),
        _ => None,
    }
}

pub fn withhold_post_hook(
    runtime: &str,
    response: &Value,
    why: Option<&str>,
    replacement: Option<&Value>,
) -> Result<Value, UnknownWhy> {
    command::set_decision_made(true);
    let why_message = why
        .map(|reason| why_key(reason).ok_or(UnknownWhy))
        .transpose()?
        .map(|key| locale::message(key, &[]));
    let payload = if runtime == "claude" {
        let shape = replacement.cloned().unwrap_or_else(|| {
            if response.is_object() {
                withheld_shape(response, true, 0)
            } else {
                withheld_shape(
                    &json!({"stdout": "", "stderr": "", "interrupted": false, "isImage": false}),
                    true,
                    0,
                )
            }
        });
        let mut specific = Map::new();
        specific.insert("hookEventName".to_owned(), json!("PostToolUse"));
        specific.insert("updatedToolOutput".to_owned(), shape);
        if let Some(why) = why_message {
            specific.insert(
                "additionalContext".to_owned(),
                json!(locale::message(
                    "safe_tool.withheld.context",
                    &[("why", locale::FormatValue::Text(why))]
                )),
            );
        }
        json!({"hookSpecificOutput": specific})
    } else if let Some(why) = why_message {
        json!({"decision": "block", "reason": locale::message("safe_tool.withheld.reason_why", &[("why", locale::FormatValue::Text(why))])})
    } else {
        json!({"decision": "block", "reason": locale::message("safe_tool.withheld.reason", &[])})
    };
    emit::emit(&payload);
    Ok(payload)
}
