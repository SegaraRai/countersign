//! The form schema of a question: the restricted JSON Schema subset of MCP
//! elicitation (`requestedSchema`, revision 2025-11-25).
//!
//! A schema is a flat object whose properties are strings (with length,
//! `pattern` and `format` checks), numbers or integers (with bounds),
//! booleans, single-select enums (`enum`, or `oneOf` with `const`/`title`)
//! and multi-select enums (`array` of those). Every property may carry
//! `title`, `description` and `default`. Any other keyword is refused, as are
//! schemas or answers over the size limits: they are rejected, never cut.

use std::collections::BTreeSet;
use std::fmt;

use serde_json::{Map, Value};

/// Most properties in one form.
pub const MAX_FIELDS: usize = 20;
/// Most options in one enum.
pub const MAX_OPTIONS: usize = 50;
/// Longest property name, enum value, title or option label.
pub const MAX_LABEL: usize = 200;
/// Longest description.
pub const MAX_DESCRIPTION: usize = 1000;
/// Longest `pattern`.
pub const MAX_PATTERN: usize = 500;
/// Longest string answer.
pub const MAX_TEXT: usize = 10_000;
/// Largest schema, as JSON.
pub const MAX_SCHEMA_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct FormError(pub String);

fn err<T>(m: impl Into<String>) -> Result<T, FormError> {
    Err(FormError(m.into()))
}

/// The `format` of a string property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextFormat {
    Email,
    Uri,
    Date,
    DateTime,
}

impl TextFormat {
    fn parse(s: &str) -> Result<Self, FormError> {
        match s {
            "email" => Ok(Self::Email),
            "uri" => Ok(Self::Uri),
            "date" => Ok(Self::Date),
            "date-time" => Ok(Self::DateTime),
            // Secrets are out of scope for questions (MCP form mode).
            "password" => err("format \"password\" is not allowed: questions must not collect secrets"),
            other => err(format!("unsupported format {other:?}")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Uri => "uri",
            Self::Date => "date",
            Self::DateTime => "date-time",
        }
    }

    fn check(self, s: &str) -> bool {
        match self {
            Self::Email => {
                s.split_once('@').is_some_and(|(l, d)| !l.is_empty() && d.contains('.') && !d.starts_with('.'))
                    && !s.chars().any(char::is_whitespace)
            }
            Self::Uri => {
                s.split_once(':').is_some_and(|(scheme, rest)| {
                    !rest.is_empty()
                        && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                        && scheme.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
                }) && !s.chars().any(char::is_whitespace)
            }
            Self::Date => s.parse::<jiff::civil::Date>().is_ok() && s.len() == 10,
            Self::DateTime => s.parse::<jiff::Timestamp>().is_ok(),
        }
    }
}

/// One choice of an enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub value: String,
    /// The label to show; the value itself when untitled.
    pub title: Option<String>,
}

impl Choice {
    pub fn label(&self) -> &str {
        self.title.as_deref().unwrap_or(&self.value)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldKind {
    Text {
        min_length: Option<u64>,
        max_length: Option<u64>,
        pattern: Option<String>,
        format: Option<TextFormat>,
        default: Option<String>,
    },
    Number {
        integer: bool,
        minimum: Option<f64>,
        maximum: Option<f64>,
        default: Option<f64>,
    },
    Boolean {
        default: Option<bool>,
    },
    /// Single-select.
    Choice {
        options: Vec<Choice>,
        default: Option<String>,
    },
    /// Multi-select.
    Choices {
        options: Vec<Choice>,
        min_items: Option<u64>,
        max_items: Option<u64>,
        default: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub name: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub required: bool,
    pub kind: FieldKind,
}

impl Field {
    pub fn label(&self) -> &str {
        self.title.as_deref().unwrap_or(&self.name)
    }
}

/// A parsed, checked form schema.
#[derive(Debug, Clone, PartialEq)]
pub struct FormSchema {
    pub fields: Vec<Field>,
}

fn object<'a>(v: &'a Value, what: &str) -> Result<&'a Map<String, Value>, FormError> {
    v.as_object().ok_or_else(|| FormError(format!("{what} must be an object")))
}

fn only(map: &Map<String, Value>, allowed: &[&str], what: &str) -> Result<(), FormError> {
    match map.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => err(format!("{what}: keyword {k:?} is not supported")),
        None => Ok(()),
    }
}

fn label(v: Option<&Value>, max: usize, what: &str) -> Result<Option<String>, FormError> {
    match v {
        None => Ok(None),
        Some(Value::String(s)) if s.chars().count() <= max => Ok(Some(s.clone())),
        Some(Value::String(_)) => err(format!("{what} is longer than {max} characters")),
        Some(_) => err(format!("{what} must be a string")),
    }
}

fn count(v: Option<&Value>, what: &str) -> Result<Option<u64>, FormError> {
    match v {
        None => Ok(None),
        Some(v) => v.as_u64().map(Some).ok_or_else(|| FormError(format!("{what} must be a non-negative integer"))),
    }
}

fn number(v: Option<&Value>, what: &str) -> Result<Option<f64>, FormError> {
    match v {
        None => Ok(None),
        Some(v) => {
            v.as_f64().filter(|f| f.is_finite()).map(Some).ok_or_else(|| FormError(format!("{what} must be a number")))
        }
    }
}

/// Choices from `enum` (untitled) or `oneOf`/`anyOf` of `{const, title}`.
fn choices(map: &Map<String, Value>, list_key: &str, what: &str) -> Result<Vec<Choice>, FormError> {
    let options: Vec<Choice> = if let Some(e) = map.get("enum") {
        let names = match map.get("enumNames") {
            None => None,
            Some(Value::Array(a)) => Some(a),
            Some(_) => return err(format!("{what}: enumNames must be an array")),
        };
        let items = e.as_array().ok_or_else(|| FormError(format!("{what}: enum must be an array")))?;
        if names.is_some_and(|n| n.len() != items.len()) {
            return err(format!("{what}: enumNames must have one entry per enum value"));
        }
        items
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let value = label(Some(v), MAX_LABEL, &format!("{what}: enum value"))?.unwrap_or_default();
                let title =
                    names.map(|n| label(n.get(i), MAX_LABEL, &format!("{what}: enumNames"))).transpose()?.flatten();
                Ok(Choice { value, title })
            })
            .collect::<Result<_, FormError>>()?
    } else if let Some(list) = map.get(list_key) {
        let items = list.as_array().ok_or_else(|| FormError(format!("{what}: {list_key} must be an array")))?;
        items
            .iter()
            .map(|item| {
                let m = object(item, &format!("{what}: {list_key} entry"))?;
                only(m, &["const", "title"], &format!("{what}: {list_key} entry"))?;
                let value = label(m.get("const"), MAX_LABEL, &format!("{what}: const"))?
                    .ok_or_else(|| FormError(format!("{what}: every {list_key} entry needs a string const")))?;
                Ok(Choice { value, title: label(m.get("title"), MAX_LABEL, &format!("{what}: option title"))? })
            })
            .collect::<Result<_, FormError>>()?
    } else {
        return Ok(Vec::new());
    };
    if options.is_empty() || options.len() > MAX_OPTIONS {
        return err(format!("{what}: needs between 1 and {MAX_OPTIONS} options"));
    }
    let distinct: BTreeSet<&str> = options.iter().map(|o| o.value.as_str()).collect();
    if distinct.len() != options.len() {
        return err(format!("{what}: option values must be distinct"));
    }
    Ok(options)
}

fn property(name: &str, v: &Value, required: bool) -> Result<Field, FormError> {
    let what = format!("property {name:?}");
    let map = object(v, &what)?;
    let title = label(map.get("title"), MAX_LABEL, &format!("{what}: title"))?;
    let description = label(map.get("description"), MAX_DESCRIPTION, &format!("{what}: description"))?;
    let common = ["type", "title", "description", "default"];
    let ty = map.get("type").and_then(Value::as_str).ok_or_else(|| FormError(format!("{what}: needs a type")))?;
    let kind = match ty {
        "string" if map.contains_key("enum") || map.contains_key("oneOf") => {
            only(map, &[&common[..], &["enum", "enumNames", "oneOf"]].concat(), &what)?;
            let options = choices(map, "oneOf", &what)?;
            let default = label(map.get("default"), MAX_LABEL, &format!("{what}: default"))?;
            if default.as_ref().is_some_and(|d| !options.iter().any(|o| &o.value == d)) {
                return err(format!("{what}: default is not one of the options"));
            }
            FieldKind::Choice { options, default }
        }
        "string" => {
            only(map, &[&common[..], &["minLength", "maxLength", "pattern", "format"]].concat(), &what)?;
            let pattern = label(map.get("pattern"), MAX_PATTERN, &format!("{what}: pattern"))?;
            if let Some(p) = &pattern {
                compile(p).map_err(|e| FormError(format!("{what}: pattern: {e}")))?;
            }
            let format = map
                .get("format")
                .map(|f| f.as_str().ok_or_else(|| FormError(format!("{what}: format must be a string"))))
                .transpose()?
                .map(TextFormat::parse)
                .transpose()
                .map_err(|e| FormError(format!("{what}: {e}")))?;
            FieldKind::Text {
                min_length: count(map.get("minLength"), &format!("{what}: minLength"))?,
                max_length: count(map.get("maxLength"), &format!("{what}: maxLength"))?,
                pattern,
                format,
                default: label(map.get("default"), MAX_TEXT, &format!("{what}: default"))?,
            }
        }
        "number" | "integer" => {
            only(map, &[&common[..], &["minimum", "maximum"]].concat(), &what)?;
            FieldKind::Number {
                integer: ty == "integer",
                minimum: number(map.get("minimum"), &format!("{what}: minimum"))?,
                maximum: number(map.get("maximum"), &format!("{what}: maximum"))?,
                default: number(map.get("default"), &format!("{what}: default"))?,
            }
        }
        "boolean" => {
            only(map, &common, &what)?;
            let default = match map.get("default") {
                None => None,
                Some(Value::Bool(b)) => Some(*b),
                Some(_) => return err(format!("{what}: default must be a boolean")),
            };
            FieldKind::Boolean { default }
        }
        "array" => {
            only(map, &[&common[..], &["items", "minItems", "maxItems"]].concat(), &what)?;
            let items = object(map.get("items").unwrap_or(&Value::Null), &format!("{what}: items"))?;
            let items_what = format!("{what}: items");
            if items.contains_key("enum") {
                only(items, &["type", "enum"], &items_what)?;
                if items.get("type").and_then(Value::as_str) != Some("string") {
                    return err(format!("{items_what}: type must be \"string\""));
                }
            } else {
                only(items, &["anyOf"], &items_what)?;
            }
            let options = choices(items, "anyOf", &items_what)?;
            if options.is_empty() {
                return err(format!("{items_what}: needs enum or anyOf"));
            }
            let default = match map.get("default") {
                None => Vec::new(),
                Some(Value::Array(a)) => a
                    .iter()
                    .map(|v| v.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| FormError(format!("{what}: default must be an array of strings")))?,
                Some(_) => return err(format!("{what}: default must be an array")),
            };
            if default.iter().any(|d| !options.iter().any(|o| &o.value == d)) {
                return err(format!("{what}: default is not one of the options"));
            }
            FieldKind::Choices {
                options,
                min_items: count(map.get("minItems"), &format!("{what}: minItems"))?,
                max_items: count(map.get("maxItems"), &format!("{what}: maxItems"))?,
                default,
            }
        }
        other => return err(format!("{what}: unsupported type {other:?}")),
    };
    Ok(Field { name: name.to_owned(), title, description, required, kind })
}

fn compile(pattern: &str) -> Result<regex::Regex, String> {
    regex::RegexBuilder::new(pattern).size_limit(1 << 20).build().map_err(|e| e.to_string())
}

impl FormSchema {
    /// Parse and check a `requestedSchema`.
    pub fn parse(v: &Value) -> Result<Self, FormError> {
        if serde_json::to_string(v).map_or(true, |s| s.len() > MAX_SCHEMA_BYTES) {
            return err(format!("the schema is larger than {MAX_SCHEMA_BYTES} bytes"));
        }
        let map = object(v, "requestedSchema")?;
        only(map, &["type", "properties", "required", "$schema"], "requestedSchema")?;
        if map.get("type").and_then(Value::as_str) != Some("object") {
            return err("requestedSchema: type must be \"object\"");
        }
        let props = object(map.get("properties").unwrap_or(&Value::Null), "requestedSchema: properties")?;
        if props.is_empty() || props.len() > MAX_FIELDS {
            return err(format!("requestedSchema: needs between 1 and {MAX_FIELDS} properties"));
        }
        let required: BTreeSet<String> = match map.get("required") {
            None => BTreeSet::new(),
            Some(Value::Array(a)) => a
                .iter()
                .map(|v| v.as_str().map(str::to_owned))
                .collect::<Option<_>>()
                .ok_or_else(|| FormError("requestedSchema: required must list property names".into()))?,
            Some(_) => return err("requestedSchema: required must be an array"),
        };
        if let Some(r) = required.iter().find(|r| !props.contains_key(*r)) {
            return err(format!("requestedSchema: required names unknown property {r:?}"));
        }
        let fields = props
            .iter()
            .map(|(name, v)| {
                if name.is_empty() || name.chars().count() > MAX_LABEL || name.chars().any(char::is_control) {
                    return err(format!("property name {name:?} is empty, too long or has control characters"));
                }
                property(name, v, required.contains(name))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { fields })
    }

    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Check an answer against the schema. Returns the content as it will be
    /// stored and handed to the asker.
    pub fn validate(&self, content: &Map<String, Value>) -> Result<Map<String, Value>, FormError> {
        if let Some(k) = content.keys().find(|k| self.field(k).is_none()) {
            return err(format!("unknown field {k:?}"));
        }
        let mut out = Map::new();
        for f in &self.fields {
            let Some(v) = content.get(&f.name).filter(|v| !v.is_null()) else {
                if f.required {
                    return err(format!("{} is required", f.label()));
                }
                continue;
            };
            check_value(f, v)?;
            out.insert(f.name.clone(), v.clone());
        }
        Ok(out)
    }

    /// The only field, if the form is a single required choice or yes/no
    /// that a chat button can answer.
    pub fn single_button_field(&self) -> Option<&Field> {
        match self.fields.as_slice() {
            [f] if f.required && matches!(f.kind, FieldKind::Boolean { .. } | FieldKind::Choice { .. }) => Some(f),
            _ => None,
        }
    }
}

fn check_value(f: &Field, v: &Value) -> Result<(), FormError> {
    let name = f.label();
    match &f.kind {
        FieldKind::Text { min_length, max_length, pattern, format, .. } => {
            let s = v.as_str().ok_or_else(|| FormError(format!("{name} must be text")))?;
            let len = s.chars().count() as u64;
            if len > MAX_TEXT as u64 || max_length.is_some_and(|m| len > m) {
                return err(format!("{name} is too long"));
            }
            if min_length.is_some_and(|m| len < m) {
                return err(format!("{name} is too short"));
            }
            if let Some(p) = pattern
                && !compile(p).is_ok_and(|re| re.is_match(s))
            {
                return err(format!("{name} does not have the expected form"));
            }
            if let Some(fmt) = format
                && !fmt.check(s)
            {
                return err(format!("{name} must be a valid {}", fmt.as_str()));
            }
        }
        FieldKind::Number { integer, minimum, maximum, .. } => {
            let n =
                v.as_f64().filter(|n| n.is_finite()).ok_or_else(|| FormError(format!("{name} must be a number")))?;
            if *integer && !(v.is_i64() || v.is_u64()) {
                return err(format!("{name} must be a whole number"));
            }
            if minimum.is_some_and(|m| n < m) || maximum.is_some_and(|m| n > m) {
                return err(format!("{name} is out of range"));
            }
        }
        FieldKind::Boolean { .. } => {
            if !v.is_boolean() {
                return err(format!("{name} must be true or false"));
            }
        }
        FieldKind::Choice { options, .. } => {
            let s = v.as_str().ok_or_else(|| FormError(format!("{name} must be one of the options")))?;
            if !options.iter().any(|o| o.value == s) {
                return err(format!("{name} must be one of the options"));
            }
        }
        FieldKind::Choices { options, min_items, max_items, .. } => {
            let items = v.as_array().ok_or_else(|| FormError(format!("{name} must be a list of options")))?;
            let mut seen = BTreeSet::new();
            for item in items {
                let s = item.as_str().filter(|s| options.iter().any(|o| o.value == *s));
                if !s.is_some_and(|s| seen.insert(s)) {
                    return err(format!("{name} must list distinct options"));
                }
            }
            let n = items.len() as u64;
            if min_items.is_some_and(|m| n < m) || max_items.is_some_and(|m| n > m) {
                return err(format!("{name} has the wrong number of choices"));
            }
        }
    }
    Ok(())
}

impl fmt::Display for FieldKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Text { .. } => "text",
            Self::Number { integer: true, .. } => "integer",
            Self::Number { .. } => "number",
            Self::Boolean { .. } => "yes/no",
            Self::Choice { .. } => "choice",
            Self::Choices { .. } => "choices",
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn schema() -> FormSchema {
        FormSchema::parse(&json!({
            "type": "object",
            "properties": {
                "branch": { "type": "string", "enum": ["main", "release"], "title": "Branch" },
                "env": { "type": "string", "oneOf": [{ "const": "prod", "title": "Production" }, { "const": "stg" }] },
                "note": { "type": "string", "maxLength": 10, "pattern": "^[a-z ]*$" },
                "when": { "type": "string", "format": "date" },
                "count": { "type": "integer", "minimum": 1, "maximum": 3, "default": 1 },
                "ok": { "type": "boolean", "default": true },
                "tags": { "type": "array", "items": { "anyOf": [{ "const": "a", "title": "A" }, { "const": "b" }] }, "maxItems": 1 }
            },
            "required": ["branch"]
        }))
        .unwrap()
    }

    #[test]
    fn keeps_property_order_and_parses_every_kind() {
        let s = schema();
        let names: Vec<_> = s.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["branch", "env", "note", "when", "count", "ok", "tags"]);
        assert!(s.fields[0].required);
        assert!(matches!(&s.fields[1].kind, FieldKind::Choice { options, .. } if options[0].label() == "Production"));
        assert!(s.single_button_field().is_none());
    }

    #[test]
    fn validates_answers() {
        let s = schema();
        let ok = s.validate(
            json!({ "branch": "main", "count": 2, "tags": ["a"], "when": "2026-11-16" }).as_object().unwrap(),
        );
        assert!(ok.is_ok(), "{ok:?}");
        for bad in [
            json!({}),
            json!({ "branch": "dev" }),
            json!({ "branch": "main", "count": 1.5 }),
            json!({ "branch": "main", "count": 9 }),
            json!({ "branch": "main", "note": "UPPER" }),
            json!({ "branch": "main", "note": "far too long text" }),
            json!({ "branch": "main", "when": "16/11/2026" }),
            json!({ "branch": "main", "tags": ["a", "b"] }),
            json!({ "branch": "main", "tags": ["a", "a"] }),
            json!({ "branch": "main", "extra": 1 }),
            json!({ "branch": "main", "ok": "yes" }),
        ] {
            assert!(s.validate(bad.as_object().unwrap()).is_err(), "{bad}");
        }
    }

    #[test]
    fn refuses_what_is_outside_the_subset() {
        for bad in [
            json!({ "type": "object", "properties": {} }),
            json!({ "type": "object", "properties": { "a": { "type": "object" } } }),
            json!({ "type": "object", "properties": { "a": { "type": "string", "format": "password" } } }),
            json!({ "type": "object", "properties": { "a": { "type": "string", "$ref": "#/x" } } }),
            json!({ "type": "object", "properties": { "a": { "type": "string" } }, "additionalProperties": true }),
            json!({ "type": "object", "properties": { "a": { "type": "string" } }, "required": ["b"] }),
            json!({ "type": "object", "properties": { "a": { "type": "string", "pattern": "(" } } }),
            json!({ "type": "object", "properties": { "a": { "type": "string", "enum": ["x", "x"] } } }),
            json!({ "type": "object", "properties": { "a": { "type": "string", "enum": ["x"], "default": "y" } } }),
            json!({ "type": "array" }),
        ] {
            assert!(FormSchema::parse(&bad).is_err(), "{bad}");
        }
        let many: Map<String, Value> =
            (0..=MAX_FIELDS).map(|i| (format!("f{i}"), json!({ "type": "boolean" }))).collect();
        assert!(FormSchema::parse(&json!({ "type": "object", "properties": many })).is_err());
    }

    #[test]
    fn single_buttons_for_one_required_choice() {
        let s = FormSchema::parse(&json!({
            "type": "object", "properties": { "go": { "type": "boolean" } }, "required": ["go"]
        }))
        .unwrap();
        assert_eq!(s.single_button_field().unwrap().name, "go");
    }

    #[test]
    fn formats() {
        assert!(TextFormat::Email.check("a@example.com"));
        assert!(!TextFormat::Email.check("a example.com"));
        assert!(TextFormat::Uri.check("https://example.com/x"));
        assert!(!TextFormat::Uri.check("not a uri"));
        assert!(TextFormat::DateTime.check("2026-11-16T10:00:00Z"));
        assert!(!TextFormat::Date.check("2026-13-01"));
    }
}
