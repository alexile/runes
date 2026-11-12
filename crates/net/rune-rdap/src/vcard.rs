//! The useful parts of a jCard
//! ([RFC 7095](https://www.rfc-editor.org/rfc/rfc7095)) `vcardArray`.

use serde_json::Value;

/// Contact details read from an entity's jCard.
///
/// Only the commonly populated properties are extracted; redacted values
/// (empty strings) are skipped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Contact {
    /// `kind`: `individual`, `org`, `group`, …
    pub kind: Option<String>,
    /// `fn`: the formatted name.
    pub name: Option<String>,
    /// `org`: the organisation.
    pub org: Option<String>,
    /// `email` values.
    pub emails: Vec<String>,
    /// `tel` values (a `tel:` URI scheme prefix is removed).
    pub phones: Vec<String>,
    /// `adr`: the `label` parameter, or the non-empty structured
    /// components joined with newlines.
    pub address: Option<String>,
    /// The country: the `adr` `cc` parameter, or the last structured
    /// component.
    pub country: Option<String>,
    /// `url` values.
    pub urls: Vec<String>,
}

impl Contact {
    /// Reads a `["vcard", [[name, params, type, value…], …]]` array.
    /// Returns `None` when `value` is not a jCard.
    #[must_use]
    pub fn from_jcard(value: &Value) -> Option<Self> {
        let outer = value.as_array()?;
        if !outer.first()?.as_str()?.eq_ignore_ascii_case("vcard") {
            return None;
        }
        let mut contact = Self::default();
        for prop in outer.get(1)?.as_array()? {
            let Some(prop) = prop.as_array() else {
                continue;
            };
            let (Some(name), Some(params)) = (prop.first().and_then(Value::as_str), prop.get(1))
            else {
                continue;
            };
            let values = prop.get(3..).unwrap_or_default();
            match name.to_ascii_lowercase().as_str() {
                "kind" => set_once(&mut contact.kind, first_text(values)),
                "fn" => set_once(&mut contact.name, first_text(values)),
                "org" => set_once(&mut contact.org, first_text(values)),
                "email" => push(&mut contact.emails, first_text(values)),
                "tel" => push(
                    &mut contact.phones,
                    first_text(values).map(|t| {
                        t.strip_prefix("tel:")
                            .map_or_else(|| t.clone(), str::to_owned)
                    }),
                ),
                "url" => push(&mut contact.urls, first_text(values)),
                "adr" => read_adr(&mut contact, params, values),
                _ => {}
            }
        }
        Some(contact)
    }
}

fn read_adr(contact: &mut Contact, params: &Value, values: &[Value]) {
    if contact.address.is_some() {
        return;
    }
    let label = params
        .get("label")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.replace("\r\n", "\n"));
    let parts: Vec<String> = match values.first() {
        Some(Value::Array(items)) => items.iter().flat_map(flatten).collect(),
        Some(v) => flatten(v),
        None => Vec::new(),
    };
    let joined = (!parts.is_empty()).then(|| parts.join("\n"));
    contact.address = label.or(joined);
    let cc = params
        .get("cc")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|s| !s.is_empty());
    let last = match values.first() {
        Some(Value::Array(items)) if items.len() == 7 => items.last().and_then(text),
        _ => None,
    };
    contact.country = cc.or(last);
}

/// Non-empty strings in a value that may itself be a list.
fn flatten(v: &Value) -> Vec<String> {
    match v {
        Value::Array(items) => items.iter().filter_map(text).collect(),
        other => text(other).into_iter().collect(),
    }
}

fn text(v: &Value) -> Option<String> {
    v.as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// The first value as text; a structured value (e.g. `org` with units)
/// yields its non-empty components joined with `, `.
fn first_text(values: &[Value]) -> Option<String> {
    match values.first()? {
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().filter_map(text).collect();
            (!parts.is_empty()).then(|| parts.join(", "))
        }
        other => text(other),
    }
}

fn set_once(slot: &mut Option<String>, value: Option<String>) {
    if slot.is_none() {
        *slot = value;
    }
}

fn push(list: &mut Vec<String>, value: Option<String>) {
    if let Some(v) = value
        && !list.contains(&v)
    {
        list.push(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_common_properties() {
        let jcard: Value = serde_json::from_str(
            r#"["vcard",[["version",{},"text","4.0"],["fn",{},"text","Joe"],
               ["org",{},"text",["Example","Ops"]],["kind",{},"text","individual"],
               ["email",{},"text","joe@example.net"],["email",{},"text",""],
               ["tel",{"type":["work","voice"]},"uri","tel:+1-555-0100"],
               ["adr",{"cc":"US"},"text",["","","1 Main St","Town","ST","00000",""]],
               ["url",{},"uri","https://example.net/"],
               "junk",[1,2]]]"#,
        )
        .unwrap();
        let c = Contact::from_jcard(&jcard).unwrap();
        assert_eq!(c.name.as_deref(), Some("Joe"));
        assert_eq!(c.org.as_deref(), Some("Example, Ops"));
        assert_eq!(c.kind.as_deref(), Some("individual"));
        assert_eq!(c.emails, ["joe@example.net"]);
        assert_eq!(c.phones, ["+1-555-0100"]);
        assert_eq!(c.address.as_deref(), Some("1 Main St\nTown\nST\n00000"));
        assert_eq!(c.country.as_deref(), Some("US"));
        assert_eq!(c.urls, ["https://example.net/"]);
    }

    #[test]
    fn label_wins_and_non_jcards_are_none() {
        let jcard: Value = serde_json::from_str(
            r#"["vcard",[["adr",{"label":"1 Main St\r\nTown"},"text",["","","","","","",""]]]]"#,
        )
        .unwrap();
        let c = Contact::from_jcard(&jcard).unwrap();
        assert_eq!(c.address.as_deref(), Some("1 Main St\nTown"));
        assert!(c.country.is_none());
        for v in [r"{}", r"[]", r#"["vcalendar",[]]"#, r#"["vcard"]"#] {
            let v: Value = serde_json::from_str(v).unwrap();
            assert!(Contact::from_jcard(&v).is_none());
        }
    }
}
