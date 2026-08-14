use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as ShaDigest, Sha256};
use url::Url;

pub(crate) fn canonical_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    Ok(canonical_value(&value))
}

pub(crate) fn canonical_digest<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let canonical = canonical_json(value)?;
    Ok(sha256_hex(canonical.as_bytes()))
}

pub(crate) fn digest_parts(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(part.as_bytes());
        hasher.update(b"|");
    }
    to_hex(&hasher.finalize())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    to_hex(&hasher.finalize())
}

pub(crate) fn validate_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn validate_identifier(value: &str, field: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        });
    if valid {
        Ok(())
    } else {
        Err(format!("{field} must be a bounded opaque identifier"))
    }
}

pub(crate) fn validate_immutable_id(
    value: &str,
    field: &str,
    accepted_prefixes: &[&str],
) -> Result<(), String> {
    validate_identifier(value, field)?;
    let has_accepted_prefix = accepted_prefixes
        .iter()
        .any(|prefix| value.starts_with(prefix) && value.len() > prefix.len());
    if !has_accepted_prefix || value.contains('@') {
        return Err(format!(
            "{field} must use an immutable Okta identifier, not a login, email, or name"
        ));
    }
    Ok(())
}

pub(crate) fn normalize_https_domain(value: &str) -> Result<String, String> {
    let parsed = Url::parse(value).map_err(|_| "custom domain must be a URL".to_owned())?;
    if parsed.scheme() != "https"
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        return Err(
            "custom domain must be an exact HTTPS origin without credentials, port, or path"
                .to_owned(),
        );
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "custom domain must include a host".to_owned())?
        .to_ascii_lowercase();
    if host.is_empty() || host.contains('*') {
        return Err("custom domain host is invalid".to_owned());
    }
    Ok(format!("https://{host}"))
}

fn canonical_value(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).expect("JSON string serialization"),
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
                    let key = serde_json::to_string(key).expect("JSON key serialization");
                    format!("{key}:{value}")
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{values}}}")
        }
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
