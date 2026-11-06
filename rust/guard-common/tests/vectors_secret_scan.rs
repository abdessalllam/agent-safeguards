use guard_common::secret_scan::{
    annotation, ascending_run, bare_secret, contains_key, contains_secret, entropy, format_secret,
    is_slug, jwt_secret, labeled_secret, looks_like_path, placeholder_shaped, plausible_value,
    real_authorization, real_aws_key, real_credentials, real_prefixed_key, real_query_value,
    template_percent, token_looks_real, type_name, without_public_material, Deadline,
};
use serde_json::Value;

#[test]
fn vectors_match_python() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/secret_scan.json");
    let text = std::fs::read_to_string(path).expect("vector file");
    let rows: Vec<Value> = serde_json::from_str(&text).expect("vector json");
    for (index, row) in rows.iter().enumerate() {
        let name = row.get("fn").and_then(Value::as_str).unwrap_or("");
        let args = row.get("args").and_then(Value::as_array).expect("args");
        let outcome = dispatch(name, args);
        assert_row(index, name, row, outcome);
    }
}

enum Outcome {
    Bool(bool),
    Float(f64),
    Text(String),
    Err(&'static str),
}

fn dispatch(name: &str, args: &[Value]) -> Outcome {
    match name {
        "contains_secret" => Outcome::Bool(contains_secret(text_at(args, 0))),
        "contains_key" => Outcome::Bool(contains_key(text_at(args, 0))),
        "jwt_secret" => Outcome::Bool(jwt_secret(text_at(args, 0))),
        "without_public_material" => Outcome::Text(without_public_material(text_at(args, 0))),
        "labeled_secret" => Outcome::Bool(labeled_secret(text_at(args, 0), deadline_at(args, 1))),
        "bare_secret" => Outcome::Bool(bare_secret(text_at(args, 0), deadline_at(args, 1))),
        "format_secret" => Outcome::Bool(format_secret(
            text_at(args, 0),
            text_at(args, 1),
            deadline_at(args, 2),
        )),
        "entropy" => match entropy(text_at(args, 0)) {
            Ok(value) => Outcome::Float(value),
            Err(err) => Outcome::Err(err.name()),
        },
        "placeholder_shaped" => Outcome::Bool(placeholder_shaped(text_at(args, 0))),
        "is_slug" => Outcome::Bool(is_slug(text_at(args, 0))),
        "annotation" => Outcome::Bool(annotation(text_at(args, 0))),
        "template_percent" => match template_percent(text_at(args, 0)) {
            Ok(value) => Outcome::Bool(value),
            Err(err) => Outcome::Err(err.name()),
        },
        "type_name" => Outcome::Bool(type_name(text_at(args, 0))),
        "looks_like_path" => match looks_like_path(text_at(args, 0)) {
            Ok(value) => Outcome::Bool(value),
            Err(err) => Outcome::Err(err.name()),
        },
        "token_looks_real" => Outcome::Bool(token_looks_real(text_at(args, 0))),
        "real_aws_key" => Outcome::Bool(real_aws_key(text_at(args, 0))),
        "real_authorization" => Outcome::Bool(real_authorization(text_at(args, 0))),
        "real_prefixed_key" => Outcome::Bool(real_prefixed_key(text_at(args, 0))),
        "real_credentials" => match real_credentials(text_at(args, 0)) {
            Ok(value) => Outcome::Bool(value),
            Err(err) => Outcome::Err(err.name()),
        },
        "real_query_value" => Outcome::Bool(real_query_value(text_at(args, 0))),
        "ascending_run" => Outcome::Bool(ascending_run(text_at(args, 0), int_at(args, 1) as usize)),
        "plausible_value" => match plausible_value(text_at(args, 0), text_at(args, 1)) {
            Ok(value) => Outcome::Bool(value),
            Err(err) => Outcome::Err(err.name()),
        },
        _ => Outcome::Err("unknown"),
    }
}

fn assert_row(index: usize, name: &str, row: &Value, outcome: Outcome) {
    let exc = row.get("exc").and_then(Value::as_str);
    if let Some(expected) = exc {
        match outcome {
            Outcome::Err(got) if got == expected => return,
            _ => panic!("index={index} fn={name} expected_exc={expected}"),
        }
    }
    let ret = row.get("ret").unwrap_or(&Value::Null);
    let ok = match (&outcome, ret) {
        (Outcome::Bool(got), Value::Bool(expected)) => got == expected,
        (Outcome::Float(got), Value::Number(expected)) => {
            let Some(value) = expected.as_f64() else {
                return;
            };
            let delta = (got - value).abs();
            if delta > 1e-12 {
                panic!("index={index} fn={name} got={got:.18} exp={value:.18} delta={delta:.3e}");
            }
            true
        }
        (Outcome::Text(got), Value::String(expected)) => got == expected,
        _ => false,
    };
    if !ok {
        let kind = match outcome {
            Outcome::Bool(value) => format!("bool {value}"),
            Outcome::Float(value) => format!("float {value:.18}"),
            Outcome::Text(value) => format!("text {}", value.len()),
            Outcome::Err(value) => format!("err {value}"),
        };
        let ret_kind = match ret {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        };
        panic!("index={index} fn={name} got={kind} ret={ret_kind}");
    }
}

fn text_at(args: &[Value], index: usize) -> &str {
    args.get(index).and_then(Value::as_str).unwrap_or("")
}

fn int_at(args: &[Value], index: usize) -> i64 {
    args.get(index).and_then(Value::as_i64).unwrap_or(0)
}

fn deadline_at(args: &[Value], index: usize) -> Deadline {
    if args.get(index).and_then(Value::as_str) == Some("expired") {
        Deadline::expired()
    } else {
        Deadline::open()
    }
}
