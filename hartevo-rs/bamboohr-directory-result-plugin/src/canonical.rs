use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::model::Digest;

pub(crate) fn digest_parts(domain: &str, parts: &[String]) -> Digest {
    let mut bytes = Vec::new();
    append_part(&mut bytes, domain);
    for part in parts {
        append_part(&mut bytes, part);
    }
    Digest::from_bytes(&bytes)
}

pub(crate) fn canonical_digest<T: Serialize>(domain: &str, value: &T) -> Digest {
    let value = serde_json::to_value(value).expect("typed Layer-1 value serializes");
    digest_parts(domain, &[canonical_value(&value)])
}

pub(crate) fn append_part(bytes: &mut Vec<u8>, part: &str) {
    bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
    bytes.extend_from_slice(part.as_bytes());
}

fn canonical_value(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).expect("JSON string serializes"),
        Value::Array(values) => {
            let values = values
                .iter()
                .map(canonical_value)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{values}]")
        }
        Value::Object(values) => {
            let values = values
                .iter()
                .map(|(key, value)| (key, canonical_value(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .map(|(key, value)| {
                    let key = serde_json::to_string(key).expect("JSON key serializes");
                    format!("{key}:{value}")
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{values}}}")
        }
    }
}

pub(crate) fn valid_text(value: &str, max_bytes: usize, allow_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (allow_whitespace || !value.chars().any(char::is_whitespace))
}

pub(crate) fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
