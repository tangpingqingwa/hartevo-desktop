//! Config interpolation for Cordis plugins.
//!
//! Plugin `config` interpolates from the plugin context **after** `inject`.
//! Plugin `disabled` interpolates from the loader context, not the plugin context.

use std::collections::BTreeMap;
use std::fmt;

/// Nested config value used by plugin entries and interpolation sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigValue {
    Null,
    Bool(bool),
    Int(i64),
    String(String),
    Array(Vec<ConfigValue>),
    Object(BTreeMap<String, ConfigValue>),
}

impl ConfigValue {
    #[must_use]
    pub fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }

    #[must_use]
    pub fn object<K, I>(entries: I) -> Self
    where
        K: Into<String>,
        I: IntoIterator<Item = (K, ConfigValue)>,
    {
        Self::Object(
            entries
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        )
    }

    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    #[must_use]
    pub fn lookup(&self, path: &str) -> Option<&ConfigValue> {
        let mut current = self;
        if path.is_empty() {
            return Some(current);
        }
        for segment in path.split('.') {
            current = match current {
                Self::Object(map) => map.get(segment)?,
                _ => return None,
            };
        }
        Some(current)
    }

    /// Expand `{dot.path}` placeholders against `source`.
    pub fn interpolate(&self, source: &ConfigValue) -> Result<ConfigValue, InterpolateError> {
        match self {
            Self::String(template) => interpolate_template(template, source),
            Self::Array(items) => Ok(Self::Array(
                items
                    .iter()
                    .map(|item| item.interpolate(source))
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            Self::Object(map) => {
                let mut out = BTreeMap::new();
                for (key, value) in map {
                    out.insert(key.clone(), value.interpolate(source)?);
                }
                Ok(Self::Object(out))
            }
            other => Ok(other.clone()),
        }
    }
}

impl Default for ConfigValue {
    fn default() -> Self {
        Self::Object(BTreeMap::new())
    }
}

impl From<bool> for ConfigValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i64> for ConfigValue {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}

impl From<&str> for ConfigValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_string())
    }
}

impl From<String> for ConfigValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

/// Failure expanding `{dot.path}` placeholders against a config source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterpolateError {
    UnclosedPlaceholder { template: String },
    EmptyPlaceholder { template: String },
    MissingPath { path: String, template: String },
    NonScalar { path: String, template: String },
    InvalidDisabled { value: String },
}

impl fmt::Display for InterpolateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnclosedPlaceholder { template } => {
                write!(f, "unclosed interpolation placeholder in `{template}`")
            }
            Self::EmptyPlaceholder { template } => {
                write!(f, "empty interpolation placeholder in `{template}`")
            }
            Self::MissingPath { path, template } => {
                write!(f, "interpolation path `{path}` is missing for `{template}`")
            }
            Self::NonScalar { path, template } => {
                write!(
                    f,
                    "interpolation path `{path}` is not a scalar for `{template}`"
                )
            }
            Self::InvalidDisabled { value } => {
                write!(f, "cannot coerce `{value}` to a disabled boolean")
            }
        }
    }
}

impl std::error::Error for InterpolateError {}

fn interpolate_template(
    template: &str,
    source: &ConfigValue,
) -> Result<ConfigValue, InterpolateError> {
    if let Some(path) = whole_placeholder(template) {
        let value = lookup_path(source, path, template)?;
        return match value {
            ConfigValue::Null
            | ConfigValue::Bool(_)
            | ConfigValue::Int(_)
            | ConfigValue::String(_) => Ok(value.clone()),
            ConfigValue::Array(_) | ConfigValue::Object(_) => Err(InterpolateError::NonScalar {
                path: path.to_string(),
                template: template.to_string(),
            }),
        };
    }

    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        rest = &rest[start + 1..];
        let Some(end) = rest.find('}') else {
            return Err(InterpolateError::UnclosedPlaceholder {
                template: template.to_string(),
            });
        };
        let path = rest[..end].trim();
        if path.is_empty() {
            return Err(InterpolateError::EmptyPlaceholder {
                template: template.to_string(),
            });
        }
        out.push_str(&scalar_text(
            lookup_path(source, path, template)?,
            path,
            template,
        )?);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(ConfigValue::String(out))
}

fn whole_placeholder(template: &str) -> Option<&str> {
    let trimmed = template.trim();
    if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        return None;
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    if inner.contains('{') || inner.contains('}') {
        return None;
    }
    let path = inner.trim();
    if path.is_empty() { None } else { Some(path) }
}

fn lookup_path<'a>(
    source: &'a ConfigValue,
    path: &str,
    template: &str,
) -> Result<&'a ConfigValue, InterpolateError> {
    source
        .lookup(path)
        .ok_or_else(|| InterpolateError::MissingPath {
            path: path.to_string(),
            template: template.to_string(),
        })
}

fn scalar_text(
    value: &ConfigValue,
    path: &str,
    template: &str,
) -> Result<String, InterpolateError> {
    match value {
        ConfigValue::Null => Ok(String::new()),
        ConfigValue::Bool(flag) => Ok(flag.to_string()),
        ConfigValue::Int(number) => Ok(number.to_string()),
        ConfigValue::String(text) => Ok(text.clone()),
        ConfigValue::Array(_) | ConfigValue::Object(_) => Err(InterpolateError::NonScalar {
            path: path.to_string(),
            template: template.to_string(),
        }),
    }
}

/// Coerce an interpolated `disabled` expression into a boolean.
pub fn coerce_disabled(value: &ConfigValue) -> Result<bool, InterpolateError> {
    match value {
        ConfigValue::Bool(flag) => Ok(*flag),
        ConfigValue::Null | ConfigValue::Int(0) => Ok(false),
        ConfigValue::Int(_) => Ok(true),
        ConfigValue::String(text) => match text.trim() {
            "" | "0" | "false" | "False" | "FALSE" | "no" | "off" => Ok(false),
            "1" | "true" | "True" | "TRUE" | "yes" | "on" => Ok(true),
            other => Err(InterpolateError::InvalidDisabled {
                value: other.to_string(),
            }),
        },
        ConfigValue::Array(_) | ConfigValue::Object(_) => Err(InterpolateError::InvalidDisabled {
            value: "disabled".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigValue, InterpolateError, coerce_disabled};

    #[test]
    fn whole_placeholder_preserves_scalar_type() {
        let source = ConfigValue::object([("flags", ConfigValue::object([("off", true.into())]))]);
        assert_eq!(
            ConfigValue::string("{flags.off}")
                .interpolate(&source)
                .unwrap(),
            ConfigValue::Bool(true)
        );
        assert!(coerce_disabled(&ConfigValue::Bool(true)).unwrap());
    }

    #[test]
    fn mixed_template_stringifies_scalars() {
        let source = ConfigValue::object([
            ("env", ConfigValue::object([("name", "dev".into())])),
            ("port", 8080.into()),
        ]);
        assert_eq!(
            ConfigValue::string("http://{env.name}:{port}")
                .interpolate(&source)
                .unwrap(),
            ConfigValue::string("http://dev:8080")
        );
    }

    #[test]
    fn nested_objects_and_arrays_interpolate() {
        let source = ConfigValue::object([("tools", ConfigValue::object([("id", "t1".into())]))]);
        let template = ConfigValue::object([(
            "items",
            ConfigValue::Array(vec![ConfigValue::string("use {tools.id}")]),
        )]);
        assert_eq!(
            template.interpolate(&source).unwrap(),
            ConfigValue::object([(
                "items",
                ConfigValue::Array(vec![ConfigValue::string("use t1")])
            )])
        );
    }

    #[test]
    fn missing_path_and_unclosed_fail_closed() {
        let source = ConfigValue::default();
        assert_eq!(
            ConfigValue::string("{missing.path}")
                .interpolate(&source)
                .unwrap_err(),
            InterpolateError::MissingPath {
                path: "missing.path".to_string(),
                template: "{missing.path}".to_string(),
            }
        );
        assert_eq!(
            ConfigValue::string("{unclosed")
                .interpolate(&source)
                .unwrap_err(),
            InterpolateError::UnclosedPlaceholder {
                template: "{unclosed".to_string(),
            }
        );
    }
}
