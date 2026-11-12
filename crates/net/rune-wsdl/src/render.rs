//! Envelope serialization, element paths and request building.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use rune_http_model::{HttpBody, HttpRequest};

use crate::model::{
    InsertionLocation, InsertionPoint, Options, SoapOperation, SoapVersion, ValueKind, XmlNode,
};

/// Where requests go when neither [`Options::endpoint`] nor the document
/// gives an absolute address.
pub const DEFAULT_ENDPOINT: &str = "http://localhost/";

/// What the schema says about one leaf value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafMeta {
    pub xsd_type: String,
    pub kind: ValueKind,
    pub required: bool,
    pub nillable: bool,
    pub repeated: bool,
    pub enum_values: Vec<String>,
}

/// A sample element with leaf metadata, before paths are assigned.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Draft {
    pub node: XmlNode,
    pub leaf: Option<LeafMeta>,
    pub attribute_meta: Vec<Option<LeafMeta>>,
    pub children: Vec<Self>,
}

/// Path segments for a list of siblings: `name`, then `name[2]`, ….
fn segments<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    names
        .map(|name| {
            let count = seen.entry(name).or_insert(0);
            *count += 1;
            if *count == 1 {
                name.to_owned()
            } else {
                format!("{name}[{count}]")
            }
        })
        .collect()
}

/// Turns drafts into nodes, collecting insertion points under `base`.
pub fn finish(drafts: Vec<Draft>, base: &str, points: &mut Vec<InsertionPoint>) -> Vec<XmlNode> {
    let names = segments(drafts.iter().map(|draft| draft.node.name.as_str()));
    drafts
        .into_iter()
        .zip(names)
        .map(|(draft, segment)| {
            let path = format!("{base}/{segment}");
            let mut node = draft.node;
            for (attribute, meta) in node.attributes.iter().zip(draft.attribute_meta) {
                if let Some(meta) = meta {
                    points.push(point(
                        InsertionLocation::Attribute,
                        format!("{path}/@{}", attribute.name),
                        attribute.value.clone(),
                        meta,
                    ));
                }
            }
            if let Some(meta) = draft.leaf {
                points.push(point(
                    InsertionLocation::Element,
                    path.clone(),
                    node.value.clone().unwrap_or_default(),
                    meta,
                ));
            }
            node.children = finish(draft.children, &path, points);
            node
        })
        .collect()
}

fn point(
    location: InsertionLocation,
    name: String,
    value: String,
    meta: LeafMeta,
) -> InsertionPoint {
    InsertionPoint {
        location,
        name,
        value,
        xsd_type: meta.xsd_type,
        kind: meta.kind,
        required: meta.required,
        nillable: meta.nillable,
        repeated: meta.repeated,
        enum_values: meta.enum_values,
    }
}

/// Escapes text content and attribute values.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\r' => out.push_str("&#13;"),
            other => out.push(other),
        }
    }
    out
}

struct Prefixes {
    order: Vec<(String, String)>,
}

impl Prefixes {
    fn collect(envelope: &str, nodes: &[&[XmlNode]]) -> Self {
        let mut prefixes = Self {
            order: vec![(envelope.to_owned(), String::from("soap"))],
        };
        for list in nodes {
            for node in *list {
                prefixes.visit(node);
            }
        }
        prefixes
    }

    fn add(&mut self, namespace: Option<&String>) {
        if let Some(namespace) = namespace
            && !self.order.iter().any(|(known, _)| known == namespace)
        {
            let prefix = format!("ns{}", self.order.len());
            self.order.push((namespace.clone(), prefix));
        }
    }

    fn visit(&mut self, node: &XmlNode) {
        self.add(node.namespace.as_ref());
        for attribute in &node.attributes {
            self.add(attribute.namespace.as_ref());
        }
        for child in &node.children {
            self.visit(child);
        }
    }

    fn qualify(&self, namespace: Option<&String>, name: &str) -> String {
        namespace
            .and_then(|namespace| self.order.iter().find(|(known, _)| known == namespace))
            .map_or_else(|| name.to_owned(), |(_, prefix)| format!("{prefix}:{name}"))
    }
}

fn write_nodes(
    out: &mut String,
    prefixes: &Prefixes,
    nodes: &[XmlNode],
    base: &str,
    values: Option<&BTreeMap<String, String>>,
) {
    let names = segments(nodes.iter().map(|node| node.name.as_str()));
    for (node, segment) in nodes.iter().zip(names) {
        let path = format!("{base}/{segment}");
        let tag = prefixes.qualify(node.namespace.as_ref(), &node.name);
        let _ = write!(out, "<{tag}");
        for attribute in &node.attributes {
            let value = values
                .and_then(|values| values.get(&format!("{path}/@{}", attribute.name)))
                .unwrap_or(&attribute.value);
            let _ = write!(
                out,
                " {}=\"{}\"",
                prefixes.qualify(attribute.namespace.as_ref(), &attribute.name),
                escape(value)
            );
        }
        let value = values
            .and_then(|values| values.get(&path))
            .or(node.value.as_ref());
        if node.children.is_empty() && value.is_none() {
            out.push_str("/>");
            continue;
        }
        out.push('>');
        if let Some(value) = value {
            out.push_str(&escape(value));
        }
        write_nodes(out, prefixes, &node.children, &path, values);
        let _ = write!(out, "</{tag}>");
    }
}

/// Serializes a SOAP envelope, optionally replacing values by path.
pub fn envelope(
    version: SoapVersion,
    header: &[XmlNode],
    body: &[XmlNode],
    values: Option<&BTreeMap<String, String>>,
) -> String {
    let namespace = version.envelope_namespace();
    let prefixes = Prefixes::collect(namespace, &[header, body]);
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<soap:Envelope");
    for (namespace, prefix) in &prefixes.order {
        let _ = write!(out, " xmlns:{prefix}=\"{}\"", escape(namespace));
    }
    out.push('>');
    if !header.is_empty() {
        out.push_str("<soap:Header>");
        write_nodes(&mut out, &prefixes, header, "/Header", values);
        out.push_str("</soap:Header>");
    }
    out.push_str("<soap:Body>");
    write_nodes(&mut out, &prefixes, body, "/Body", values);
    out.push_str("</soap:Body></soap:Envelope>");
    out
}

/// A header-safe rendering of a SOAP action.
fn header_safe(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_control() && *character != '"')
        .collect()
}

/// The request for an operation carrying `envelope`.
pub fn request(operation: &SoapOperation, envelope: &str, options: &Options) -> HttpRequest {
    let url = options.endpoint.as_ref().map_or_else(
        || {
            operation
                .address
                .as_deref()
                .filter(|address| url::Url::parse(address).is_ok())
                .unwrap_or(DEFAULT_ENDPOINT)
                .to_owned()
        },
        |endpoint| endpoint.as_str().to_owned(),
    );
    let action = header_safe(operation.soap_action.as_deref().unwrap_or_default());
    let mut request = HttpRequest::new("POST", url);
    request = match operation.soap_version {
        SoapVersion::Soap11 => request
            .with_header("Content-Type", "text/xml; charset=utf-8")
            .with_header("SOAPAction", format!("\"{action}\"")),
        SoapVersion::Soap12 if action.is_empty() => {
            request.with_header("Content-Type", "application/soap+xml; charset=utf-8")
        }
        SoapVersion::Soap12 => request.with_header(
            "Content-Type",
            format!("application/soap+xml; charset=utf-8; action=\"{action}\""),
        ),
    };
    for (name, value) in &options.headers {
        request = request.with_header(name.as_str(), value.as_str());
    }
    request.with_body(HttpBody::from_text(envelope.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::XmlAttribute;

    fn leaf(name: &str, value: &str) -> XmlNode {
        let mut node = XmlNode::new(None, name);
        node.value = Some(value.to_owned());
        node
    }

    #[test]
    fn serializes_with_prefixes_and_paths() {
        let mut wrapper = XmlNode::new(Some(String::from("urn:a")), "Op");
        wrapper.attributes.push(XmlAttribute {
            namespace: Some(String::from("urn:b")),
            name: String::from("lang"),
            value: String::from("e\"n"),
        });
        wrapper.children = vec![
            leaf("x", "1 < 2"),
            leaf("x", "two"),
            XmlNode::new(None, "empty"),
        ];
        let text = envelope(SoapVersion::Soap11, &[], &[wrapper.clone()], None);
        assert_eq!(
            text,
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns1=\"urn:a\" xmlns:ns2=\"urn:b\"><soap:Body><ns1:Op ns2:lang=\"e&quot;n\"><x>1 &lt; 2</x><x>two</x><empty/></ns1:Op></soap:Body></soap:Envelope>"
        );
        let mut values = BTreeMap::new();
        values.insert(String::from("/Body/Op/x[2]"), String::from("<inj>"));
        values.insert(String::from("/Body/Op/@lang"), String::from("fr"));
        let replaced = envelope(
            SoapVersion::Soap12,
            &[leaf("h", "v")],
            &[wrapper],
            Some(&values),
        );
        assert!(
            replaced.contains("<x>1 &lt; 2</x><x>&lt;inj&gt;</x>"),
            "{replaced}"
        );
        assert!(replaced.contains("ns2:lang=\"fr\""));
        assert!(replaced.contains("<soap:Header><h>v</h></soap:Header>"));
        assert!(replaced.contains("http://www.w3.org/2003/05/soap-envelope"));
        assert_eq!(header_safe("a\"b\r\nc"), "abc");
    }
}
