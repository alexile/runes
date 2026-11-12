//! WSDL 1.1 and 2.0 documents to [`WsdlSpec`].

use std::collections::BTreeMap;

use rune_http_model::HttpRequest;

use crate::WsdlError;
use crate::model::{
    BodyUse, InsertionLocation, InsertionPoint, MessagePart, OperationStyle, Options,
    SoapOperation, SoapVersion, ValueKind, WsdlSpec, WsdlVersion, XmlAttribute, XmlNode,
};
use crate::render::{self, Draft};
use crate::schema::{Generator, SOAP_ENCODING_NAMESPACE, Schemas, clark, lookup};
use crate::xml::{self, Element, QName, local_name};

const WSDL11_NAMESPACE: &str = "http://schemas.xmlsoap.org/wsdl/";
const WSDL20_NAMESPACE: &str = "http://www.w3.org/ns/wsdl";
const SOAP11_BINDING_NAMESPACE: &str = "http://schemas.xmlsoap.org/wsdl/soap/";
const SOAP12_BINDING_NAMESPACE: &str = "http://schemas.xmlsoap.org/wsdl/soap12/";
const WSDL20_SOAP_NAMESPACE: &str = "http://www.w3.org/ns/wsdl/soap";
/// Deepest search for a `soap:body` under a binding message (MIME
/// multipart wrappers put it a few levels down).
const MAX_BODY_SEARCH_DEPTH: usize = 6;

/// Parses a WSDL 1.1 or 2.0 document.
///
/// Inline schemas are expanded into sample messages; imports are not
/// fetched (the crate does no I/O) and are reported as warnings.
///
/// # Errors
///
/// [`WsdlError`] when the input is larger than
/// [`Options::max_input_bytes`], is not UTF-8 or well-formed XML, or is not
/// a WSDL document.
///
/// ```
/// use rune_wsdl::{Options, parse};
///
/// let error = parse(b"<definitions", &Options::default()).unwrap_err();
/// assert_eq!(error.code(), "xml_error");
/// ```
pub fn parse(input: &[u8], options: &Options) -> Result<WsdlSpec, WsdlError> {
    if input.len() > options.max_input_bytes {
        return Err(WsdlError::TooLarge(format!(
            "{} bytes, more than the limit of {}",
            input.len(),
            options.max_input_bytes
        )));
    }
    let input = input.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(input);
    let text = std::str::from_utf8(input).map_err(|_| WsdlError::NotUtf8)?;
    let root = xml::parse(text)?;
    let namespace = root.namespace.as_deref();
    match (root.local.as_str(), namespace) {
        ("definitions", None | Some(WSDL11_NAMESPACE)) => {
            Ok(Importer::new(&root, options).wsdl11())
        }
        ("description", None | Some(WSDL20_NAMESPACE)) => {
            Ok(Importer::new(&root, options).wsdl20())
        }
        (local, namespace) => Err(WsdlError::NotWsdl(format!(
            "root element is `{}`",
            clark(&QName::new(namespace, local))
        ))),
    }
}

/// Named top-level children of the root, by `{targetNamespace}name`.
fn named<'a>(
    root: &'a Element,
    target: Option<&str>,
    local: &'static str,
) -> BTreeMap<QName, &'a Element> {
    root.children_named(local)
        .filter_map(|element| Some((QName::new(target, element.attr("name")?), element)))
        .collect()
}

/// A binding operation waiting for a service.
struct Endpoint<'a> {
    service: Option<String>,
    port: Option<String>,
    binding: &'a Element,
    address: Option<String>,
}

/// Binding-level facts shared by every operation of a binding.
#[derive(Clone, Copy)]
struct BindingInfo {
    version: SoapVersion,
    style: OperationStyle,
}

/// The parts of one message as the body needs them.
struct BodySpec<'a> {
    parts: Vec<(MessagePart, &'a Element)>,
    style: OperationStyle,
    body_use: BodyUse,
    rpc_namespace: Option<String>,
}

struct Importer<'a, 'o> {
    root: &'a Element,
    options: &'o Options,
    target: Option<String>,
    schemas: Schemas<'a>,
    spec: WsdlSpec,
}

impl<'a, 'o> Importer<'a, 'o> {
    fn new(root: &'a Element, options: &'o Options) -> Self {
        let mut warnings = Vec::new();
        let schemas = Schemas::collect(root.children_named("types"), &mut warnings);
        let target = root
            .attr("targetNamespace")
            .filter(|namespace| !namespace.is_empty())
            .map(str::to_owned);
        for import in root
            .children_named("import")
            .chain(root.children_named("include"))
        {
            if let Some(location) = import.attr("location") {
                warnings.push(format!(
                    "WSDL `{location}` is not fetched; what it declares is missing"
                ));
            }
        }
        let version = if root.local == "description" {
            WsdlVersion::Wsdl20
        } else {
            WsdlVersion::Wsdl11
        };
        Self {
            root,
            options,
            schemas,
            spec: WsdlSpec {
                version,
                name: root.attr("name").map(str::to_owned),
                target_namespace: target.clone(),
                services: root
                    .children_named("service")
                    .filter_map(|service| service.attr("name"))
                    .map(str::to_owned)
                    .collect(),
                operations: Vec::new(),
                warnings,
                truncated: false,
            },
            target,
        }
    }

    fn warn(&mut self, warning: String) {
        if !self.spec.warnings.contains(&warning) {
            self.spec.warnings.push(warning);
        }
    }

    /// Each port / endpoint of each service, or every binding when the
    /// document has no services. `binding_attr` is `binding` in both
    /// versions; `port_local` is `port` or `endpoint`.
    fn endpoints(
        &mut self,
        bindings: &BTreeMap<QName, &'a Element>,
        port_local: &str,
    ) -> Vec<Endpoint<'a>> {
        let mut endpoints = Vec::new();
        let mut used: Vec<&Element> = Vec::new();
        let root = self.root;
        for service in root.children_named("service") {
            for port in service.children_named(port_local) {
                let Some(reference) = port.attr("binding") else {
                    continue;
                };
                let name = port.resolve(reference);
                let Some(binding) = lookup(bindings, &name).copied() else {
                    self.warn(format!("binding `{}` is not declared", clark(&name)));
                    continue;
                };
                used.push(binding);
                let address = port
                    .attr("address")
                    .or_else(|| {
                        port.children_named("address")
                            .find_map(|address| address.attr("location"))
                    })
                    .map(str::to_owned);
                endpoints.push(Endpoint {
                    service: service.attr("name").map(str::to_owned),
                    port: port.attr("name").map(str::to_owned),
                    binding,
                    address,
                });
            }
        }
        let has_services = root.child("service").is_some();
        for binding in bindings.values() {
            if used.iter().any(|known| std::ptr::eq(*known, *binding)) {
                continue;
            }
            if has_services {
                let name = binding.attr("name").unwrap_or_default();
                self.warn(format!(
                    "binding `{name}` is not exposed by a service; skipped"
                ));
            } else {
                endpoints.push(Endpoint {
                    service: None,
                    port: None,
                    binding,
                    address: None,
                });
            }
        }
        endpoints
    }

    fn wsdl11(mut self) -> WsdlSpec {
        let target = self.target.clone();
        let target = target.as_deref();
        let messages = named(self.root, target, "message");
        let port_types = named(self.root, target, "portType");
        let bindings = named(self.root, target, "binding");
        let endpoints = self.endpoints(&bindings, "port");
        for endpoint in endpoints {
            let binding = endpoint.binding;
            let binding_name = binding.attr("name").unwrap_or_default().to_owned();
            let Some(info) = soap11_binding(binding) else {
                self.warn(format!("binding `{binding_name}` is not SOAP; skipped"));
                continue;
            };
            let port_type_name = binding.attr("type").map(|name| binding.resolve(name));
            let port_type = port_type_name
                .as_ref()
                .and_then(|name| lookup(&port_types, name).copied());
            if port_type.is_none() {
                let name = port_type_name.as_ref().map(clark).unwrap_or_default();
                self.warn(format!(
                    "port type `{name}` of binding `{binding_name}` is not declared"
                ));
            }
            for operation in binding.children_named("operation") {
                if self.spec.operations.len() >= self.options.max_operations {
                    self.spec.truncated = true;
                    return self.finish();
                }
                let Some(name) = operation.attr("name") else {
                    continue;
                };
                let abstract_operation = port_type.and_then(|port_type| {
                    port_type
                        .children_named("operation")
                        .find(|candidate| candidate.attr("name") == Some(name))
                });
                if abstract_operation.is_none() && port_type.is_some() {
                    self.warn(format!(
                        "operation `{name}` of binding `{binding_name}` is not in its port type"
                    ));
                }
                let soap_operation = operation
                    .children_named("operation")
                    .find(|child| is_soap_binding_namespace(child.namespace.as_deref()));
                let style = soap_operation
                    .and_then(|soap| soap.attr("style"))
                    .map_or(info.style, parse_style);
                let parts_of = |direction: &str| -> Vec<(MessagePart, &'a Element)> {
                    abstract_operation
                        .and_then(|operation| operation.child(direction))
                        .and_then(|io| io.attr("message").map(|message| io.resolve(message)))
                        .and_then(|message| lookup(&messages, &message).copied())
                        .map(message_parts)
                        .unwrap_or_default()
                };
                let input_binding = operation.child("input");
                let soap_body = input_binding.and_then(|input| find_soap_body(input, 0));
                let mut input = parts_of("input");
                if let Some(selected) = soap_body.and_then(|body| body.attr("parts")) {
                    let selected: Vec<&str> = selected.split_whitespace().collect();
                    input.retain(|(part, _)| selected.contains(&part.name.as_str()));
                }
                let body_spec = BodySpec {
                    parts: input,
                    style,
                    body_use: soap_body
                        .and_then(|body| body.attr("use"))
                        .map_or(BodyUse::Literal, parse_use),
                    rpc_namespace: soap_body
                        .and_then(|body| body.attr("namespace"))
                        .filter(|namespace| !namespace.is_empty())
                        .map(str::to_owned)
                        .or_else(|| self.target.clone()),
                };
                let headers: Vec<(MessagePart, &'a Element)> = input_binding
                    .into_iter()
                    .flat_map(|input| input.children_named("header"))
                    .filter(|header| is_soap_binding_namespace(header.namespace.as_deref()))
                    .filter_map(|header| {
                        let message = header.resolve(header.attr("message")?);
                        let part = header.attr("part")?;
                        let message = lookup(&messages, &message).copied()?;
                        message_parts(message)
                            .into_iter()
                            .find(|(candidate, _)| candidate.name == part)
                    })
                    .collect();
                let operation = self.build(
                    name,
                    &endpoint,
                    &binding_name,
                    port_type_name.as_ref().map(|name| name.local.clone()),
                    info.version,
                    soap_operation
                        .and_then(|soap| soap.attr("soapAction"))
                        .map(str::to_owned),
                    abstract_operation.and_then(Element::documentation),
                    body_spec,
                    &headers,
                    parts_of("output")
                        .into_iter()
                        .map(|(part, _)| part)
                        .collect(),
                    abstract_operation
                        .into_iter()
                        .flat_map(|operation| operation.children_named("fault"))
                        .filter_map(|fault| fault.attr("name"))
                        .map(str::to_owned)
                        .collect(),
                );
                self.spec.operations.push(operation);
            }
        }
        self.finish()
    }

    fn wsdl20(mut self) -> WsdlSpec {
        let target = self.target.clone();
        let target = target.as_deref();
        let interfaces = named(self.root, target, "interface");
        let bindings = named(self.root, target, "binding");
        let endpoints = self.endpoints(&bindings, "endpoint");
        for endpoint in endpoints {
            let binding = endpoint.binding;
            let binding_name = binding.attr("name").unwrap_or_default().to_owned();
            if binding.attr("type") != Some(WSDL20_SOAP_NAMESPACE) {
                self.warn(format!("binding `{binding_name}` is not SOAP; skipped"));
                continue;
            }
            let version = match binding.attr_ns(WSDL20_SOAP_NAMESPACE, "version") {
                Some("1.1") => SoapVersion::Soap11,
                _ => SoapVersion::Soap12,
            };
            let interface_name = binding.attr("interface").map(|name| binding.resolve(name));
            let mut operations: Vec<&'a Element> = Vec::new();
            if let Some(name) = &interface_name {
                collect_interface_operations(&interfaces, name, &mut operations, 0);
                if operations.is_empty() && lookup(&interfaces, name).is_none() {
                    self.warn(format!(
                        "interface `{}` of binding `{binding_name}` is not declared",
                        clark(name)
                    ));
                }
            }
            for binding_operation in binding.children_named("operation") {
                if self.spec.operations.len() >= self.options.max_operations {
                    self.spec.truncated = true;
                    return self.finish();
                }
                let Some(reference) = binding_operation.attr("ref") else {
                    continue;
                };
                let reference = binding_operation.resolve(reference);
                let Some(operation) = operations
                    .iter()
                    .copied()
                    .find(|operation| operation.attr("name") == Some(reference.local.as_str()))
                else {
                    self.warn(format!(
                        "operation `{}` of binding `{binding_name}` is not in its interface",
                        clark(&reference)
                    ));
                    continue;
                };
                let parts = |direction: &'static str| -> Vec<(MessagePart, &'a Element)> {
                    operation
                        .children_named(direction)
                        .filter_map(|message| {
                            let element = message.attr("element")?;
                            if element.starts_with('#') {
                                return None;
                            }
                            let element = message.resolve(element);
                            Some((
                                MessagePart {
                                    name: element.local.clone(),
                                    element: Some(clark(&element)),
                                    type_name: None,
                                },
                                message,
                            ))
                        })
                        .collect()
                };
                let body_spec = BodySpec {
                    parts: parts("input"),
                    style: OperationStyle::Document,
                    body_use: BodyUse::Literal,
                    rpc_namespace: None,
                };
                let output = parts("output").into_iter().map(|(part, _)| part).collect();
                let faults = operation
                    .children_named("outfault")
                    .filter_map(|fault| fault.attr("ref"))
                    .map(|reference| local_name(reference).to_owned())
                    .collect();
                let action = binding_operation
                    .attr_ns(WSDL20_SOAP_NAMESPACE, "action")
                    .map(str::to_owned);
                let built = self.build(
                    &reference.local,
                    &endpoint,
                    &binding_name,
                    interface_name.as_ref().map(|name| name.local.clone()),
                    version,
                    action,
                    operation.documentation(),
                    body_spec,
                    &[],
                    output,
                    faults,
                );
                self.spec.operations.push(built);
            }
        }
        self.finish()
    }

    #[allow(clippy::too_many_arguments, reason = "one call site per WSDL version")]
    fn build(
        &mut self,
        name: &str,
        endpoint: &Endpoint<'a>,
        binding: &str,
        interface: Option<String>,
        soap_version: SoapVersion,
        soap_action: Option<String>,
        documentation: Option<String>,
        body_spec: BodySpec<'a>,
        headers: &[(MessagePart, &'a Element)],
        output: Vec<MessagePart>,
        faults: Vec<String>,
    ) -> SoapOperation {
        let mut generator = Generator::new(&self.schemas, self.options);
        let header_drafts: Vec<Draft> = headers
            .iter()
            .filter_map(|(part, scope)| document_part(&mut generator, part, scope))
            .collect();
        let body_drafts = match body_spec.style {
            OperationStyle::Document => body_spec
                .parts
                .iter()
                .filter_map(|(part, scope)| document_part(&mut generator, part, scope))
                .collect(),
            OperationStyle::Rpc => {
                let mut wrapper = Draft {
                    node: XmlNode::new(body_spec.rpc_namespace.clone(), name),
                    ..Draft::default()
                };
                if body_spec.body_use == BodyUse::Encoded {
                    wrapper.node.attributes.push(XmlAttribute {
                        namespace: Some(soap_version.envelope_namespace().to_owned()),
                        name: String::from("encodingStyle"),
                        value: String::from(SOAP_ENCODING_NAMESPACE),
                    });
                    wrapper.attribute_meta.push(None);
                }
                wrapper.children = body_spec
                    .parts
                    .iter()
                    .filter_map(|(part, scope)| rpc_part(&mut generator, part, scope))
                    .collect();
                vec![wrapper]
            }
        };
        for warning in std::mem::take(&mut generator.warnings) {
            self.warn(format!("{name}: {warning}"));
        }
        let mut insertion_points = Vec::new();
        let header = render::finish(header_drafts, "/Header", &mut insertion_points);
        let body = render::finish(body_drafts, "/Body", &mut insertion_points);
        if soap_version == SoapVersion::Soap11 {
            insertion_points.push(InsertionPoint {
                location: InsertionLocation::HttpHeader,
                name: String::from("SOAPAction"),
                value: soap_action.clone().unwrap_or_default(),
                xsd_type: String::from("string"),
                kind: ValueKind::String,
                required: true,
                nillable: false,
                repeated: false,
                enum_values: Vec::new(),
            });
        }
        let envelope = render::envelope(soap_version, &header, &body, None);
        let mut operation = SoapOperation {
            name: name.to_owned(),
            service: endpoint.service.clone(),
            port: endpoint.port.clone(),
            binding: binding.to_owned(),
            interface,
            soap_version,
            style: body_spec.style,
            body_use: body_spec.body_use,
            soap_action,
            address: endpoint.address.clone(),
            documentation,
            input: body_spec.parts.into_iter().map(|(part, _)| part).collect(),
            output,
            faults,
            header,
            body,
            envelope: String::new(),
            request: HttpRequest::new("POST", render::DEFAULT_ENDPOINT),
            insertion_points,
        };
        operation.request = render::request(&operation, &envelope, self.options);
        operation.envelope = envelope;
        operation
    }

    fn finish(mut self) -> WsdlSpec {
        if self.spec.operations.is_empty() {
            self.warn(String::from("no SOAP operations found"));
        }
        self.spec
    }
}

/// Operations of an interface and the interfaces it extends.
fn collect_interface_operations<'a>(
    interfaces: &BTreeMap<QName, &'a Element>,
    name: &QName,
    out: &mut Vec<&'a Element>,
    depth: usize,
) {
    if depth > 16 {
        return;
    }
    let Some(interface) = lookup(interfaces, name).copied() else {
        return;
    };
    out.extend(interface.children_named("operation"));
    if let Some(extends) = interface.attr("extends") {
        for parent in extends.split_whitespace() {
            collect_interface_operations(interfaces, &interface.resolve(parent), out, depth + 1);
        }
    }
}

fn is_soap_binding_namespace(namespace: Option<&str>) -> bool {
    matches!(
        namespace,
        Some(SOAP11_BINDING_NAMESPACE | SOAP12_BINDING_NAMESPACE)
    )
}

/// SOAP version and default style of a WSDL 1.1 binding, if it is SOAP.
fn soap11_binding(binding: &Element) -> Option<BindingInfo> {
    let soap = binding
        .children_named("binding")
        .find(|child| is_soap_binding_namespace(child.namespace.as_deref()))?;
    let version = if soap.namespace.as_deref() == Some(SOAP12_BINDING_NAMESPACE) {
        SoapVersion::Soap12
    } else {
        SoapVersion::Soap11
    };
    Some(BindingInfo {
        version,
        style: soap
            .attr("style")
            .map_or(OperationStyle::Document, parse_style),
    })
}

fn parse_style(style: &str) -> OperationStyle {
    if style.trim() == "rpc" {
        OperationStyle::Rpc
    } else {
        OperationStyle::Document
    }
}

fn parse_use(body_use: &str) -> BodyUse {
    if body_use.trim() == "encoded" {
        BodyUse::Encoded
    } else {
        BodyUse::Literal
    }
}

/// The `soap:body` under a binding message, looking through MIME wrappers.
fn find_soap_body(element: &Element, depth: usize) -> Option<&Element> {
    if depth > MAX_BODY_SEARCH_DEPTH {
        return None;
    }
    element.children.iter().find_map(|child| {
        if child.local == "body" && is_soap_binding_namespace(child.namespace.as_deref()) {
            Some(child)
        } else {
            find_soap_body(child, depth + 1)
        }
    })
}

/// The parts of a WSDL 1.1 message, each with the element it was declared
/// on (for resolving its prefixes).
fn message_parts(message: &Element) -> Vec<(MessagePart, &Element)> {
    message
        .children_named("part")
        .filter_map(|part| {
            Some((
                MessagePart {
                    name: part.attr("name")?.to_owned(),
                    element: part.attr("element").map(|name| clark(&part.resolve(name))),
                    type_name: part.attr("type").map(|name| clark(&part.resolve(name))),
                },
                part,
            ))
        })
        .collect()
}

/// A document-style part: its global element, or an unqualified element
/// named after the part when it names a type.
fn document_part(
    generator: &mut Generator<'_, '_>,
    part: &MessagePart,
    scope: &Element,
) -> Option<Draft> {
    if let Some(element) = scope.attr("element") {
        return generator.global_element(&scope.resolve(element));
    }
    let type_name = scope.resolve(scope.attr("type")?);
    generator.typed_element(None, &part.name, &type_name)
}

/// An RPC part: an unqualified accessor named after the part.
fn rpc_part(
    generator: &mut Generator<'_, '_>,
    part: &MessagePart,
    scope: &Element,
) -> Option<Draft> {
    if let Some(type_name) = scope.attr("type") {
        return generator.typed_element(None, &part.name, &scope.resolve(type_name));
    }
    let element = scope.resolve(scope.attr("element")?);
    generator.global_element(&element)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_wsdl() {
        let options = Options::default();
        assert_eq!(parse(b"<html/>", &options).unwrap_err().code(), "not_wsdl");
        assert_eq!(parse(b"\xff<a/>", &options).unwrap_err().code(), "not_utf8");
        assert_eq!(
            parse(b"<definitions/>", &options.clone().with_max_input_bytes(3))
                .unwrap_err()
                .code(),
            "too_large"
        );
        let empty = parse(b"\xEF\xBB\xBF<definitions/>", &options).unwrap();
        assert_eq!(empty.version, WsdlVersion::Wsdl11);
        assert_eq!(empty.warnings, ["no SOAP operations found"]);
        assert_eq!(
            parse(br#"<x:definitions xmlns:x="urn:other"/>"#, &options)
                .unwrap_err()
                .to_string(),
            format!(
                "not a WSDL document: root element is `{{{}}}definitions`",
                "urn:other"
            )
        );
    }
}
