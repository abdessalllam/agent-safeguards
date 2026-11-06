#[cfg(feature = "test-overrides")]
mod active {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::LazyLock;

    use serde_json::Value;

    static FROM_ENVIRONMENT: LazyLock<Value> = LazyLock::new(|| {
        std::env::var("AGENT_SAFEGUARDS_TEST_OVERRIDES")
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or(Value::Null)
    });

    thread_local! {
        static LOCAL: RefCell<HashMap<String, Value>> = RefCell::new(HashMap::new());
    }

    pub fn value(name: &str) -> Option<Value> {
        LOCAL
            .with(|local| local.borrow().get(name).cloned())
            .or_else(|| FROM_ENVIRONMENT.get(name).cloned())
    }

    pub fn set_local(name: &str, value: Value) {
        LOCAL.with(|local| local.borrow_mut().insert(name.to_owned(), value));
    }

    pub fn clear_local() {
        LOCAL.with(|local| local.borrow_mut().clear());
    }
}

#[cfg(feature = "test-overrides")]
pub use active::{clear_local, set_local};

#[cfg(feature = "test-overrides")]
pub fn string(name: &str) -> Option<String> {
    active::value(name)?.as_str().map(str::to_owned)
}

#[cfg(feature = "test-overrides")]
pub fn number(name: &str) -> Option<f64> {
    active::value(name)?.as_f64()
}

#[cfg(feature = "test-overrides")]
pub fn list(name: &str) -> Option<Vec<String>> {
    let value = active::value(name)?;
    let items = value.as_array()?;
    Some(items.iter().filter_map(|item| item.as_str().map(str::to_owned)).collect())
}

#[cfg(feature = "test-overrides")]
pub fn nullable_string(name: &str) -> Option<Option<String>> {
    let value = active::value(name)?;
    if value.is_null() {
        Some(None)
    } else {
        value.as_str().map(|text| Some(text.to_owned()))
    }
}

#[cfg(not(feature = "test-overrides"))]
pub fn string(_name: &str) -> Option<String> {
    None
}

#[cfg(not(feature = "test-overrides"))]
pub fn number(_name: &str) -> Option<f64> {
    None
}

#[cfg(not(feature = "test-overrides"))]
pub fn list(_name: &str) -> Option<Vec<String>> {
    None
}

#[cfg(not(feature = "test-overrides"))]
pub fn nullable_string(_name: &str) -> Option<Option<String>> {
    None
}

#[cfg(all(test, feature = "test-overrides"))]
mod tests {
    use serde_json::json;

    use super::{clear_local, list, nullable_string, number, set_local, string};

    #[test]
    fn local_overrides_are_typed_and_cleared() {
        set_local("USER_HOME", json!("/x/y"));
        set_local("MAX_MATCHES", json!(5));
        set_local("TEMP_ROOTS", json!(["/a", "/b"]));
        set_local("RTK_PATH", json!(null));
        assert_eq!(string("USER_HOME").as_deref(), Some("/x/y"));
        assert_eq!(crate::env::user_home(), "/x/y");
        assert_eq!(number("MAX_MATCHES"), Some(5.0));
        assert_eq!(list("TEMP_ROOTS"), Some(vec!["/a".to_owned(), "/b".to_owned()]));
        assert_eq!(nullable_string("RTK_PATH"), Some(None));
        assert_eq!(string("MAX_MATCHES"), None);
        clear_local();
        assert_eq!(string("USER_HOME"), None);
        assert_ne!(crate::env::user_home(), "/x/y");
    }
}
