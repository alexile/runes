//! A small namespace-aware XML tree over `quick-xml` events.
//!
//! Document type declarations are skipped and never expanded, so entity
//! bombs and external entities have no effect; unknown entity references
//! stay literal. Depth and element count are bounded.

use std::collections::BTreeMap;
use std::rc::Rc;

use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

use crate::WsdlError;

/// Deepest element nesting accepted.
pub const MAX_DEPTH: usize = 128;
/// Most elements accepted in one document.
pub const MAX_ELEMENTS: usize = 200_000;

/// The `xml` prefix is always bound.
const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";

/// An attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub prefix: String,
    pub local: String,
    pub value: String,
}

/// An element with its in-scope namespace bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    pub local: String,
    pub namespace: Option<String>,
    pub attributes: Vec<Attribute>,
    pub children: Vec<Self>,
    pub text: String,
    scope: Rc<BTreeMap<String, String>>,
}

/// A namespace-qualified name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QName {
    pub namespace: Option<String>,
    pub local: String,
}

impl QName {
    pub fn new(namespace: Option<&str>, local: &str) -> Self {
        Self {
            namespace: namespace
                .filter(|namespace| !namespace.is_empty())
                .map(str::to_owned),
            local: local.to_owned(),
        }
    }
}

/// Local part of a `prefix:local` name.
pub fn local_name(qualified: &str) -> &str {
    qualified.rsplit(':').next().unwrap_or(qualified)
}

impl Element {
    /// The attribute `local` without a prefix, else with any prefix other
    /// than `xmlns`.
    pub fn attr(&self, local: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|attribute| attribute.prefix.is_empty() && attribute.local == local)
            .or_else(|| {
                self.attributes.iter().find(|attribute| {
                    attribute.local == local
                        && attribute.prefix != "xmlns"
                        && !(attribute.prefix.is_empty() && attribute.local == "xmlns")
                })
            })
            .map(|attribute| attribute.value.as_str())
    }

    /// The attribute `local` whose prefix is bound to `namespace`.
    pub fn attr_ns(&self, namespace: &str, local: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|attribute| {
                attribute.local == local
                    && !attribute.prefix.is_empty()
                    && self.scope.get(&attribute.prefix).map(String::as_str) == Some(namespace)
            })
            .map(|attribute| attribute.value.as_str())
    }

    /// The first child named `local`.
    pub fn child(&self, local: &str) -> Option<&Self> {
        self.children.iter().find(|child| child.local == local)
    }

    /// Children named `local`.
    pub fn children_named<'a>(&'a self, local: &'a str) -> impl Iterator<Item = &'a Self> + 'a {
        self.children
            .iter()
            .filter(move |child| child.local == local)
    }

    /// Resolves a `prefix:local` value (such as `type="tns:Foo"`) against
    /// the namespaces in scope here. An unprefixed value takes the default
    /// namespace.
    pub fn resolve(&self, value: &str) -> QName {
        let value = value.trim();
        let (prefix, local) = value.split_once(':').unwrap_or(("", value));
        QName::new(self.scope.get(prefix).map(String::as_str), local)
    }

    /// The text of the `documentation` child, trimmed.
    pub fn documentation(&self) -> Option<String> {
        self.child("documentation")
            .map(|doc| doc.text.trim().to_owned())
            .filter(|text| !text.is_empty())
    }
}

fn start_element(start: &BytesStart<'_>, parent: Option<&Element>) -> Result<Element, WsdlError> {
    let mut attributes = Vec::new();
    let mut declared: Vec<(String, String)> = Vec::new();
    for attribute in start.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| WsdlError::Xml(error.to_string()))?;
        let key: &str = attribute.key.as_ref();
        let key = key.to_owned();
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|error| WsdlError::Xml(error.to_string()))?
            .into_owned();
        let (prefix, local) = match key.split_once(':') {
            Some((prefix, local)) => (prefix.to_owned(), local.to_owned()),
            None => (String::new(), key.clone()),
        };
        if key == "xmlns" {
            declared.push((String::new(), value.clone()));
        } else if prefix == "xmlns" {
            declared.push((local.clone(), value.clone()));
        }
        attributes.push(Attribute {
            prefix,
            local,
            value,
        });
    }
    let scope = match parent {
        Some(parent) if declared.is_empty() => Rc::clone(&parent.scope),
        parent => {
            let mut scope = parent.map_or_else(
                || {
                    let mut root = BTreeMap::new();
                    root.insert(String::from("xml"), String::from(XML_NAMESPACE));
                    root
                },
                |parent| (*parent.scope).clone(),
            );
            for (prefix, namespace) in declared {
                if namespace.is_empty() && !prefix.is_empty() {
                    scope.remove(&prefix);
                } else {
                    scope.insert(prefix, namespace);
                }
            }
            Rc::new(scope)
        }
    };
    let name = start.name();
    let qualified: &str = name.as_ref();
    let qualified = qualified.to_owned();
    let (prefix, local) = qualified.split_once(':').unwrap_or(("", &qualified));
    Ok(Element {
        local: local.to_owned(),
        namespace: scope
            .get(prefix)
            .filter(|namespace| !namespace.is_empty())
            .cloned(),
        attributes,
        children: Vec::new(),
        text: String::new(),
        scope,
    })
}

/// Parses a document into its root element.
pub fn parse(text: &str) -> Result<Element, WsdlError> {
    let mut reader = Reader::from_str(text);
    reader.config_mut().check_end_names = true;
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut count = 0_usize;
    let attach = |element: Element, stack: &mut Vec<Element>, root: &mut Option<Element>| {
        if let Some(parent) = stack.last_mut() {
            parent.children.push(element);
            Ok(())
        } else if root.is_none() {
            *root = Some(element);
            Ok(())
        } else {
            Err(WsdlError::Xml(String::from("more than one root element")))
        }
    };
    loop {
        let event = reader.read_event().map_err(|error| {
            WsdlError::Xml(format!("{error} at byte {}", reader.error_position()))
        })?;
        match event {
            Event::Start(start) | Event::Empty(start) if count >= MAX_ELEMENTS => {
                drop(start);
                return Err(WsdlError::TooLarge(format!(
                    "more than {MAX_ELEMENTS} elements"
                )));
            }
            Event::Start(start) => {
                count += 1;
                if stack.len() >= MAX_DEPTH {
                    return Err(WsdlError::TooLarge(format!(
                        "elements nested deeper than {MAX_DEPTH}"
                    )));
                }
                let element = start_element(&start, stack.last())?;
                stack.push(element);
            }
            Event::Empty(start) => {
                count += 1;
                let element = start_element(&start, stack.last())?;
                attach(element, &mut stack, &mut root)?;
            }
            Event::End(_) => {
                let element = stack
                    .pop()
                    .ok_or_else(|| WsdlError::Xml(String::from("unbalanced end tag")))?;
                attach(element, &mut stack, &mut root)?;
            }
            Event::Text(content) => {
                if let Some(current) = stack.last_mut() {
                    current.text.push_str(&content.xml10_content());
                }
            }
            Event::CData(data) => {
                if let Some(current) = stack.last_mut() {
                    current.text.push_str(&data.xml10_content());
                }
            }
            Event::GeneralRef(reference) => {
                if let Some(current) = stack.last_mut() {
                    if let Ok(Some(character)) = reference.resolve_char_ref() {
                        current.text.push(character);
                    } else {
                        let name: &str = &reference;
                        if let Some(resolved) = resolve_predefined_entity(name) {
                            current.text.push_str(resolved);
                        } else {
                            current.text.push('&');
                            current.text.push_str(name);
                            current.text.push(';');
                        }
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Err(WsdlError::Xml(String::from("unexpected end of document")));
    }
    root.ok_or_else(|| WsdlError::Xml(String::from("no root element")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_and_text() {
        let root = parse(
            r#"<?xml version="1.0"?>
            <!DOCTYPE d [<!ENTITY boom "x">]>
            <d:root xmlns:d="urn:d" xmlns="urn:default" a="1 &amp; 2">
              <child b:x="y" xmlns:b="urn:b">t&lt;&#65;&boom;<![CDATA[<c>]]></child>
              <d:other xmlns:d="urn:other" ref="d:thing" plain="noprefix"/>
            </d:root>"#,
        )
        .unwrap();
        assert_eq!(root.local, "root");
        assert_eq!(root.namespace.as_deref(), Some("urn:d"));
        assert_eq!(root.attr("a"), Some("1 & 2"));
        let child = root.child("child").unwrap();
        assert_eq!(child.namespace.as_deref(), Some("urn:default"));
        assert_eq!(child.text, "t<A&boom;<c>");
        assert_eq!(child.attr_ns("urn:b", "x"), Some("y"));
        assert_eq!(child.attr("x"), Some("y"));
        let other = root.child("other").unwrap();
        assert_eq!(other.namespace.as_deref(), Some("urn:other"));
        assert_eq!(
            other.resolve("d:thing"),
            QName::new(Some("urn:other"), "thing")
        );
        assert_eq!(
            other.resolve("noprefix"),
            QName::new(Some("urn:default"), "noprefix")
        );
        assert_eq!(root.resolve("zz:a"), QName::new(None, "a"));
        assert_eq!(local_name("a:b"), "b");
    }

    #[test]
    fn malformed() {
        for bad in [
            "",
            "<a>",
            "<a></b>",
            "</a>",
            "<a/><b/>",
            "<a x='1' x='2'/>",
            "<a x=1/>",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        let deep = format!("{}{}", "<a>".repeat(200), "</a>".repeat(200));
        assert_eq!(parse(&deep).unwrap_err().code(), "too_large");
    }
}
