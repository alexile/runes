//! A streaming walk over a Burp export.
//!
//! Burp exports are flat: a root (`items` or `issues`) holding records
//! whose children are text fields. The walk keeps only the open path in
//! memory: each element's leaf children are collected as [`Field`]s, and
//! an element that holds a `request` field is handed to the caller as soon
//! as it closes, together with the fields of its ancestors (an issue's
//! `host`, say). Memory therefore stays bounded by one record, however
//! large the export.

use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

use crate::BurpError;

/// Deepest element nesting read; Burp's exports use four levels.
const MAX_DEPTH: usize = 32;

/// An element without child elements: its name, attributes and text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    pub text: String,
}

impl Field {
    /// The value of an attribute.
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// Finds a field by name.
pub fn field<'a>(fields: &'a [Field], name: &str) -> Option<&'a Field> {
    fields.iter().find(|field| field.name == name)
}

/// The root element and how the walk ended.
pub struct Outcome {
    /// `items` or `issues`.
    pub root: String,
    /// The root's attributes (`burpVersion`, `exportTime`).
    pub attributes: Vec<(String, String)>,
    /// Why the walk stopped before the end of the document, if it did.
    pub stopped: Option<String>,
}

/// Whether to keep walking after a record.
pub enum Flow {
    Continue,
    Stop,
}

struct Frame {
    field: Field,
    fields: Vec<Field>,
    has_children: bool,
}

fn element(start: &BytesStart<'_>) -> Field {
    let name = start.local_name().as_ref().to_owned();
    let attributes = start
        .attributes()
        .flatten()
        .map(|attribute| {
            let key = attribute.key.local_name().as_ref().to_owned();
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_or_else(
                    |_| attribute.value.clone().into_owned(),
                    std::borrow::Cow::into_owned,
                );
            (key, value)
        })
        .collect();
    Field {
        name,
        attributes,
        text: String::new(),
    }
}

/// Walks `input`, calling `on_record(fields, ancestors)` for each element
/// that holds a `request` field. `ancestors` lists the enclosing elements'
/// fields, innermost first.
///
/// # Errors
///
/// [`BurpError::Xml`] when the document is malformed before its root
/// element, [`BurpError::NotBurp`] when the root is not `items` or
/// `issues`. Malformed XML later on ends the walk, as [`Outcome::stopped`].
pub fn walk(
    input: &str,
    mut on_record: impl FnMut(&[Field], &[&[Field]]) -> Flow,
) -> Result<Outcome, BurpError> {
    let mut reader = Reader::from_str(input);
    let (root, empty) = loop {
        match reader
            .read_event()
            .map_err(|error| BurpError::Xml(error.to_string()))?
        {
            Event::Start(start) => break (element(&start), false),
            Event::Empty(start) => break (element(&start), true),
            Event::Eof => return Err(BurpError::NotBurp("no root element")),
            _ => {}
        }
    };
    if root.name != "items" && root.name != "issues" {
        return Err(BurpError::NotBurp(
            "the root element is not `items` or `issues`",
        ));
    }
    let mut outcome = Outcome {
        root: root.name.clone(),
        attributes: root.attributes.clone(),
        stopped: None,
    };
    if empty {
        // `<items/>`: an export with nothing in it.
        return Ok(outcome);
    }
    let mut stack = vec![Frame {
        field: root,
        fields: Vec::new(),
        has_children: false,
    }];
    loop {
        let event = match reader.read_event() {
            Ok(event) => event,
            Err(error) => {
                outcome.stopped = Some(format!("malformed XML: {error}"));
                return Ok(outcome);
            }
        };
        match event {
            Event::Start(start) => {
                if stack.len() >= MAX_DEPTH {
                    outcome.stopped = Some("elements nested too deeply".to_owned());
                    return Ok(outcome);
                }
                if let Some(parent) = stack.last_mut() {
                    parent.has_children = true;
                    parent.field.text.clear();
                }
                stack.push(Frame {
                    field: element(&start),
                    fields: Vec::new(),
                    has_children: false,
                });
            }
            Event::Empty(start) => {
                if let Some(parent) = stack.last_mut() {
                    parent.has_children = true;
                    parent.field.text.clear();
                    parent.fields.push(element(&start));
                }
            }
            Event::Text(text) => push_text(&mut stack, &text.into_inner()),
            Event::CData(data) => push_text(&mut stack, &data.into_inner()),
            Event::GeneralRef(reference) => {
                let text = if let Ok(Some(c)) = reference.resolve_char_ref() {
                    c.to_string()
                } else {
                    let name: &str = &reference;
                    resolve_predefined_entity(name)
                        .map_or_else(|| format!("&{name};"), str::to_owned)
                };
                push_text(&mut stack, &text);
            }
            Event::End(_) => {
                let Some(frame) = stack.pop() else {
                    return Ok(outcome);
                };
                let Some(parent) = stack.last_mut() else {
                    // The root closed: the export is complete.
                    return Ok(outcome);
                };
                if !frame.has_children {
                    parent.fields.push(frame.field);
                } else if field(&frame.fields, "request").is_some() {
                    let ancestors: Vec<&[Field]> = stack
                        .iter()
                        .rev()
                        .map(|frame| frame.fields.as_slice())
                        .collect();
                    if matches!(on_record(&frame.fields, &ancestors), Flow::Stop) {
                        outcome.stopped = Some("stopped by the caller".to_owned());
                        return Ok(outcome);
                    }
                }
            }
            Event::Eof => {
                outcome.stopped = Some("unexpected end of document (truncated export?)".to_owned());
                return Ok(outcome);
            }
            _ => {}
        }
    }
}

/// Text inside an element that has no child elements yet.
fn push_text(stack: &mut [Frame], text: &str) {
    if let Some(frame) = stack.last_mut()
        && !frame.has_children
    {
        frame.field.text.push_str(text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records(input: &str) -> (Vec<Vec<String>>, Outcome) {
        let mut seen = Vec::new();
        let outcome = walk(input, |fields, ancestors| {
            let mut names: Vec<String> = fields
                .iter()
                .map(|field| format!("{}={}", field.name, field.text))
                .collect();
            names.push(format!("ancestors={}", ancestors.len()));
            seen.push(names);
            Flow::Continue
        })
        .unwrap();
        (seen, outcome)
    }

    #[test]
    fn walks_items_with_doctype_cdata_and_entities() {
        let (seen, outcome) = records(
            r#"<?xml version="1.0"?>
<!DOCTYPE items [
<!ELEMENT items (item*)>
<!ATTLIST items burpVersion CDATA "">
]>
<items burpVersion="2024.1" exportTime="now">
  <item><url><![CDATA[https://h.test/?a=1&b=2]]></url><comment>a &amp; b &#65;&unknown;</comment>
  <request base64="true"><![CDATA[R0VU]]></request><response/></item>
</items>"#,
        );
        assert_eq!(outcome.root, "items");
        assert_eq!(outcome.stopped, None);
        assert_eq!(
            outcome.attributes[0],
            ("burpVersion".into(), "2024.1".into())
        );
        assert_eq!(
            seen,
            [[
                "url=https://h.test/?a=1&b=2",
                "comment=a & b A&unknown;",
                "request=R0VU",
                "response=",
                "ancestors=1"
            ]]
        );
    }

    #[test]
    fn issues_see_their_ancestors() {
        let (seen, _) = records(
            "<issues><issue><host ip=\"1.2.3.4\">https://h.test</host>\
             <requestresponse><request>x</request></requestresponse>\
             <requestresponse><request>y</request></requestresponse></issue></issues>",
        );
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1], ["request=y", "ancestors=2"]);
    }

    #[test]
    fn truncated_and_malformed_documents_keep_what_was_read() {
        let (seen, outcome) =
            records("<items><item><request>a</request></item><item><request>b</req");
        assert_eq!(seen.len(), 1);
        assert!(outcome.stopped.is_some());
        let (seen, outcome) =
            records("<items><item><request>a</request></item><item></wrong></items>");
        assert_eq!(seen.len(), 1);
        assert!(outcome.stopped.unwrap().contains("malformed"));
    }

    #[test]
    fn rejects_other_documents() {
        let error = |input: &str| walk(input, |_, _| Flow::Continue).err().map(|e| e.code());
        assert_eq!(error("<html><body/></html>"), Some("not_burp"));
        assert_eq!(error(""), Some("not_burp"));
        assert_eq!(error("<items"), Some("invalid_xml"));
        assert_eq!(error("<items/>"), None);
        let deep = format!("<items>{}", "<a>".repeat(100));
        assert!(
            walk(&deep, |_, _| Flow::Continue)
                .unwrap()
                .stopped
                .is_some()
        );
    }
}
