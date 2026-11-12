//! Inline XSD: global declarations and their expansion into sample
//! elements.
//!
//! Only what sample messages need is modelled: element and attribute
//! declarations, named and anonymous complex and simple types, model groups
//! (`sequence`, `all`, the first branch of a `choice`), attribute groups,
//! simple and complex content derivation, and simple-type facets
//! (`enumeration`, `minInclusive`, `minExclusive`, `minLength`). Wildcards
//! (`any`, `anyAttribute`) are skipped. Recursion, depth and size are
//! bounded and reported as warnings.

use std::collections::BTreeMap;

use crate::model::{Options, ValueKind, XmlAttribute, XmlNode};
use crate::render::{Draft, LeafMeta};
use crate::xml::{Element, QName};

/// XML Schema namespace.
pub const XSD_NAMESPACE: &str = "http://www.w3.org/2001/XMLSchema";
/// SOAP 1.1 encoding namespace (`soapenc:string`, `soapenc:Array`, …).
pub const SOAP_ENCODING_NAMESPACE: &str = "http://schemas.xmlsoap.org/soap/encoding/";

/// Deepest chain of simple-type restrictions, unions and lists followed.
const MAX_SIMPLE_DEPTH: usize = 32;

/// Whether `namespace` holds the XSD built-in types (the 2001 namespace and
/// the 1999 / 2000 drafts some old toolkits still emit).
fn is_builtin_namespace(namespace: Option<&str>) -> bool {
    matches!(
        namespace,
        Some(
            XSD_NAMESPACE
                | "http://www.w3.org/1999/XMLSchema"
                | "http://www.w3.org/2000/10/XMLSchema"
                | SOAP_ENCODING_NAMESPACE
        )
    )
}

/// Renders a name as `{namespace}local`, or `local` without a namespace.
pub fn clark(name: &QName) -> String {
    name.namespace.as_ref().map_or_else(
        || name.local.clone(),
        |namespace| format!("{{{namespace}}}{}", name.local),
    )
}

/// Looks `name` up exactly, else by local name when that is unambiguous.
/// Hand-written WSDLs often get prefixes wrong; the fallback keeps them
/// importable.
pub fn lookup<'m, V>(map: &'m BTreeMap<QName, V>, name: &QName) -> Option<&'m V> {
    map.get(name).or_else(|| {
        let mut matches = map.iter().filter(|(key, _)| key.local == name.local);
        match (matches.next(), matches.next()) {
            (Some((_, value)), None) => Some(value),
            _ => None,
        }
    })
}

/// Per-schema defaults that decide how local names are qualified.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SchemaInfo {
    target: Option<String>,
    elements_qualified: bool,
    attributes_qualified: bool,
}

/// A global declaration and the schema it came from.
type Decl<'a> = (usize, &'a Element);

/// The global declarations of every inline schema.
#[derive(Debug, Default)]
pub struct Schemas<'a> {
    infos: Vec<SchemaInfo>,
    elements: BTreeMap<QName, Decl<'a>>,
    types: BTreeMap<QName, Decl<'a>>,
    groups: BTreeMap<QName, Decl<'a>>,
    attribute_groups: BTreeMap<QName, Decl<'a>>,
    attributes: BTreeMap<QName, Decl<'a>>,
}

impl<'a> Schemas<'a> {
    /// Collects the `schema` children of every `types` element, warning
    /// about imports and includes that would need fetching.
    pub fn collect(types: impl Iterator<Item = &'a Element>, warnings: &mut Vec<String>) -> Self {
        let mut schemas = Self::default();
        let mut external: Vec<String> = Vec::new();
        for schema in types.flat_map(|types| types.children_named("schema")) {
            let index = schemas.infos.len();
            let target = schema
                .attr("targetNamespace")
                .filter(|namespace| !namespace.is_empty())
                .map(str::to_owned);
            schemas.infos.push(SchemaInfo {
                target: target.clone(),
                elements_qualified: schema.attr("elementFormDefault") == Some("qualified"),
                attributes_qualified: schema.attr("attributeFormDefault") == Some("qualified"),
            });
            for child in &schema.children {
                let Some(name) = child.attr("name") else {
                    if matches!(child.local.as_str(), "import" | "include" | "redefine")
                        && let Some(location) = child.attr("schemaLocation")
                    {
                        external.push(location.to_owned());
                    }
                    continue;
                };
                let key = QName::new(target.as_deref(), name);
                let map = match child.local.as_str() {
                    "element" => &mut schemas.elements,
                    "complexType" | "simpleType" => &mut schemas.types,
                    "group" => &mut schemas.groups,
                    "attributeGroup" => &mut schemas.attribute_groups,
                    "attribute" => &mut schemas.attributes,
                    _ => continue,
                };
                map.entry(key).or_insert((index, child));
            }
        }
        for location in external {
            warnings.push(format!(
                "schema `{location}` is not fetched; types it declares become placeholders"
            ));
        }
        schemas
    }

    /// The global element named `name`.
    pub fn element(&self, name: &QName) -> Option<Decl<'a>> {
        lookup(&self.elements, name).copied()
    }

    fn target(&self, schema: usize) -> Option<String> {
        self.infos.get(schema).and_then(|info| info.target.clone())
    }
}

/// How often a particle may occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Occurs {
    /// `minOccurs` is not 0.
    pub required: bool,
    /// `maxOccurs` is more than 1.
    pub repeated: bool,
}

impl Occurs {
    /// Exactly once.
    pub const ONCE: Self = Self {
        required: true,
        repeated: false,
    };

    fn of(particle: &Element) -> Self {
        let max = particle.attr("maxOccurs").map(str::trim);
        Self {
            required: particle.attr("minOccurs").map(str::trim) != Some("0"),
            repeated: match max {
                Some("unbounded") => true,
                Some(text) => text.parse::<u64>().is_ok_and(|max| max > 1),
                None => false,
            },
        }
    }
}

/// A resolved simple type.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Simple {
    xsd_type: String,
    kind: ValueKind,
    enum_values: Vec<String>,
    value: String,
}

impl Simple {
    fn any() -> Self {
        builtin("anyType")
    }
}

/// The sample value and category of a built-in type.
fn builtin(local: &str) -> Simple {
    let (kind, value) = match local {
        "boolean" => (ValueKind::Boolean, "true"),
        "int" | "integer" | "long" | "short" | "byte" | "nonNegativeInteger"
        | "nonPositiveInteger" | "negativeInteger" | "unsignedLong" | "unsignedInt"
        | "unsignedShort" | "unsignedByte" => (ValueKind::Integer, "0"),
        "positiveInteger" => (ValueKind::Integer, "1"),
        "decimal" => (ValueKind::Number, "0"),
        "float" | "double" => (ValueKind::Number, "0.0"),
        "dateTime" | "dateTimeStamp" => (ValueKind::Temporal, "2024-01-01T00:00:00Z"),
        "date" => (ValueKind::Temporal, "2024-01-01"),
        "time" => (ValueKind::Temporal, "00:00:00"),
        "duration" | "dayTimeDuration" | "yearMonthDuration" => (ValueKind::Temporal, "P1D"),
        "gYear" => (ValueKind::Temporal, "2024"),
        "gYearMonth" => (ValueKind::Temporal, "2024-01"),
        "gMonth" => (ValueKind::Temporal, "--01"),
        "gMonthDay" => (ValueKind::Temporal, "--01-01"),
        "gDay" => (ValueKind::Temporal, "---01"),
        "base64Binary" => (ValueKind::Binary, "AA=="),
        "hexBinary" => (ValueKind::Binary, "00"),
        "anyURI" => (ValueKind::String, "http://example.com/"),
        "QName" | "NOTATION" => (ValueKind::String, "name"),
        "language" => (ValueKind::String, "en"),
        "anyType" | "anySimpleType" | "anyAtomicType" | "Array" | "Struct" => (ValueKind::Any, "?"),
        _ => (ValueKind::String, "string"),
    };
    Simple {
        xsd_type: local.to_owned(),
        kind,
        enum_values: Vec::new(),
        value: value.to_owned(),
    }
}

/// Expands declarations into sample elements for one message.
#[derive(Debug)]
pub struct Generator<'s, 'a> {
    schemas: &'s Schemas<'a>,
    options: &'s Options,
    nodes: usize,
    stack: Vec<QName>,
    /// Problems met while expanding.
    pub warnings: Vec<String>,
}

impl<'s, 'a> Generator<'s, 'a> {
    /// A generator with a fresh node budget.
    pub const fn new(schemas: &'s Schemas<'a>, options: &'s Options) -> Self {
        Self {
            schemas,
            options,
            nodes: 0,
            stack: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn warn(&mut self, warning: String) {
        if !self.warnings.contains(&warning) {
            self.warnings.push(warning);
        }
    }

    /// Takes one node from the budget.
    fn spend(&mut self) -> bool {
        if self.nodes >= self.options.max_nodes {
            let limit = self.options.max_nodes;
            self.warn(format!("sample message cut off at {limit} nodes"));
            return false;
        }
        self.nodes += 1;
        true
    }

    /// The sample for the global element `name`; an unresolved name still
    /// yields a placeholder element.
    pub fn global_element(&mut self, name: &QName) -> Option<Draft> {
        if let Some((schema, declaration)) = self.schemas.element(name) {
            return self.element(declaration, schema, true, Occurs::ONCE, 0);
        }
        self.warn(format!("element `{}` is not declared", clark(name)));
        self.placeholder(name.namespace.clone(), &name.local)
    }

    /// The sample for an element named `local` of type `type_name` (RPC
    /// parts and type-based document parts).
    pub fn typed_element(
        &mut self,
        namespace: Option<String>,
        local: &str,
        type_name: &QName,
    ) -> Option<Draft> {
        if !self.spend() {
            return None;
        }
        let mut draft = Draft {
            node: XmlNode::new(namespace, local),
            ..Draft::default()
        };
        self.fill_named_type(&mut draft, type_name, Occurs::ONCE, false, None, 0);
        Some(draft)
    }

    fn placeholder(&mut self, namespace: Option<String>, local: &str) -> Option<Draft> {
        if !self.spend() {
            return None;
        }
        let simple = Simple::any();
        Some(Draft {
            node: XmlNode {
                value: Some(simple.value.clone()),
                ..XmlNode::new(namespace, local)
            },
            leaf: Some(leaf_meta(simple, Occurs::ONCE, false)),
            ..Draft::default()
        })
    }

    /// Expands an `element` declaration (or a reference to one).
    fn element(
        &mut self,
        declaration: &'a Element,
        schema: usize,
        global: bool,
        occurs: Occurs,
        depth: usize,
    ) -> Option<Draft> {
        if let Some(reference) = declaration.attr("ref") {
            let name = declaration.resolve(reference);
            let occurs = Occurs::of(declaration);
            if !occurs.required && !self.options.include_optional {
                return None;
            }
            if let Some((schema, target)) = self.schemas.element(&name) {
                return self.element(target, schema, true, occurs, depth);
            }
            self.warn(format!("element `{}` is not declared", clark(&name)));
            return self.placeholder(name.namespace.clone(), &name.local);
        }
        if !occurs.required && !self.options.include_optional {
            return None;
        }
        let local = declaration.attr("name")?;
        if !self.spend() {
            return None;
        }
        let qualified = global
            || declaration.attr("form").map_or_else(
                || {
                    self.schemas
                        .infos
                        .get(schema)
                        .is_some_and(|info| info.elements_qualified)
                },
                |form| form == "qualified",
            );
        let namespace = if qualified {
            self.schemas.target(schema)
        } else {
            None
        };
        let mut draft = Draft {
            node: XmlNode::new(namespace, local),
            ..Draft::default()
        };
        let nillable = declaration.attr("nillable") == Some("true");
        let fixed = declaration
            .attr("fixed")
            .or_else(|| declaration.attr("default"));
        if depth >= self.options.max_depth {
            let limit = self.options.max_depth;
            self.warn(format!("sample message cut off at depth {limit}"));
            return Some(draft);
        }
        if let Some(type_name) = declaration.attr("type") {
            let type_name = declaration.resolve(type_name);
            self.fill_named_type(&mut draft, &type_name, occurs, nillable, fixed, depth);
        } else if let Some(complex) = declaration.child("complexType") {
            self.complex(complex, schema, &mut draft, depth);
        } else if let Some(simple) = declaration.child("simpleType") {
            let simple = self.simple_inline(simple, 0);
            set_leaf(&mut draft, simple, occurs, nillable, fixed);
        } else {
            set_leaf(&mut draft, Simple::any(), occurs, nillable, fixed);
        }
        // Simple content reaches the leaf through a base type; the
        // particle's cardinality still applies.
        if let Some(leaf) = draft.leaf.as_mut() {
            leaf.required = occurs.required;
            leaf.repeated = occurs.repeated;
            leaf.nillable = nillable;
        }
        Some(draft)
    }

    /// Fills `draft` from the type `type_name`.
    #[allow(
        clippy::too_many_arguments,
        reason = "leaf facts of the referencing particle"
    )]
    fn fill_named_type(
        &mut self,
        draft: &mut Draft,
        type_name: &QName,
        occurs: Occurs,
        nillable: bool,
        fixed: Option<&str>,
        depth: usize,
    ) {
        if is_builtin_namespace(type_name.namespace.as_deref()) {
            set_leaf(draft, builtin(&type_name.local), occurs, nillable, fixed);
            return;
        }
        match lookup(&self.schemas.types, type_name).copied() {
            Some((schema, declaration)) if declaration.local == "complexType" => {
                if self.stack.contains(type_name) {
                    self.warn(format!("recursive type `{}` cut off", clark(type_name)));
                    return;
                }
                self.stack.push(type_name.clone());
                self.complex(declaration, schema, draft, depth);
                self.stack.pop();
            }
            Some((_, declaration)) => {
                let simple = self.simple_inline(declaration, 0);
                set_leaf(draft, simple, occurs, nillable, fixed);
            }
            None => {
                self.warn(format!("type `{}` is not declared", clark(type_name)));
                set_leaf(draft, Simple::any(), occurs, nillable, fixed);
            }
        }
    }

    /// Adds the attributes and children of a complex type (or of the
    /// `extension` / `restriction` inside complex content, which has the
    /// same shape) to `draft`.
    fn complex(&mut self, complex: &'a Element, schema: usize, draft: &mut Draft, depth: usize) {
        for child in &complex.children {
            match child.local.as_str() {
                "sequence" | "all" | "choice" => self.particles(child, schema, draft, depth),
                "group" => self.group(child, draft, depth),
                "attribute" => self.attribute(child, schema, draft),
                "attributeGroup" => self.attribute_group(child, draft, 0),
                "complexContent" => {
                    for derivation in &child.children {
                        if derivation.local == "extension"
                            && let Some(base) = derivation.attr("base")
                        {
                            let base = derivation.resolve(base);
                            if !is_builtin_namespace(base.namespace.as_deref()) {
                                self.fill_named_type(
                                    draft,
                                    &base,
                                    Occurs::ONCE,
                                    false,
                                    None,
                                    depth,
                                );
                            }
                        }
                        if matches!(derivation.local.as_str(), "extension" | "restriction") {
                            self.complex(derivation, schema, draft, depth);
                        }
                    }
                }
                "simpleContent" => {
                    for derivation in &child.children {
                        if !matches!(derivation.local.as_str(), "extension" | "restriction") {
                            continue;
                        }
                        if let Some(base) = derivation.attr("base") {
                            let base = derivation.resolve(base);
                            self.fill_named_type(draft, &base, Occurs::ONCE, false, None, depth);
                        }
                        if derivation.local == "restriction"
                            && let Some(leaf) = draft.leaf.as_mut()
                        {
                            restrict(leaf, &mut draft.node, derivation);
                        }
                        for attribute in &derivation.children {
                            match attribute.local.as_str() {
                                "attribute" => self.attribute(attribute, schema, draft),
                                "attributeGroup" => self.attribute_group(attribute, draft, 0),
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// The children of a model group; a `choice` contributes its first
    /// branch.
    fn particles(&mut self, group: &'a Element, schema: usize, draft: &mut Draft, depth: usize) {
        if !Occurs::of(group).required && !self.options.include_optional {
            return;
        }
        let take = if group.local == "choice" {
            1
        } else {
            usize::MAX
        };
        let particles = group
            .children
            .iter()
            .filter(|child| {
                matches!(
                    child.local.as_str(),
                    "element" | "sequence" | "choice" | "all" | "group" | "any"
                )
            })
            .take(take);
        for particle in particles {
            match particle.local.as_str() {
                "element" => {
                    let occurs = Occurs::of(particle);
                    if let Some(child) = self.element(particle, schema, false, occurs, depth + 1) {
                        draft.children.push(child);
                    }
                }
                "sequence" | "choice" | "all" => self.particles(particle, schema, draft, depth),
                "group" => self.group(particle, draft, depth),
                _ => {}
            }
        }
    }

    fn group(&mut self, reference: &'a Element, draft: &mut Draft, depth: usize) {
        if !Occurs::of(reference).required && !self.options.include_optional {
            return;
        }
        let Some(name) = reference.attr("ref").map(|name| reference.resolve(name)) else {
            return;
        };
        let Some((schema, group)) = lookup(&self.schemas.groups, &name).copied() else {
            self.warn(format!("group `{}` is not declared", clark(&name)));
            return;
        };
        if self.stack.contains(&name) {
            self.warn(format!("recursive group `{}` cut off", clark(&name)));
            return;
        }
        self.stack.push(name);
        for child in &group.children {
            if matches!(child.local.as_str(), "sequence" | "choice" | "all") {
                self.particles(child, schema, draft, depth);
            }
        }
        self.stack.pop();
    }

    fn attribute_group(&mut self, reference: &'a Element, draft: &mut Draft, depth: usize) {
        let Some(name) = reference.attr("ref").map(|name| reference.resolve(name)) else {
            return;
        };
        if depth >= MAX_SIMPLE_DEPTH {
            self.warn(format!(
                "attribute group `{}` nested too deep",
                clark(&name)
            ));
            return;
        }
        let Some((schema, group)) = lookup(&self.schemas.attribute_groups, &name).copied() else {
            self.warn(format!(
                "attribute group `{}` is not declared",
                clark(&name)
            ));
            return;
        };
        for child in &group.children {
            match child.local.as_str() {
                "attribute" => self.attribute(child, schema, draft),
                "attributeGroup" => self.attribute_group(child, draft, depth + 1),
                _ => {}
            }
        }
    }

    fn attribute(&mut self, declaration: &'a Element, schema: usize, draft: &mut Draft) {
        let usage = declaration.attr("use").unwrap_or("optional");
        if usage == "prohibited" {
            return;
        }
        let required = usage == "required";
        if !required && !self.options.include_optional {
            return;
        }
        let (target, namespace) = if let Some(reference) = declaration.attr("ref") {
            let name = declaration.resolve(reference);
            let Some((schema, target)) = lookup(&self.schemas.attributes, &name).copied() else {
                self.warn(format!("attribute `{}` is not declared", clark(&name)));
                return;
            };
            (target, self.schemas.target(schema))
        } else {
            {
                let qualified = declaration.attr("form").map_or_else(
                    || {
                        self.schemas
                            .infos
                            .get(schema)
                            .is_some_and(|info| info.attributes_qualified)
                    },
                    |form| form == "qualified",
                );
                let namespace = if qualified {
                    self.schemas.target(schema)
                } else {
                    None
                };
                (declaration, namespace)
            }
        };
        let Some(name) = target.attr("name") else {
            return;
        };
        if !self.spend() {
            return;
        }
        let mut simple = if let Some(type_name) = target.attr("type") {
            self.simple(&target.resolve(type_name), 0)
        } else if let Some(inline) = target.child("simpleType") {
            self.simple_inline(inline, 0)
        } else {
            builtin("string")
        };
        if let Some(fixed) = declaration
            .attr("fixed")
            .or_else(|| declaration.attr("default"))
            .or_else(|| target.attr("fixed"))
            .or_else(|| target.attr("default"))
        {
            fixed.clone_into(&mut simple.value);
        }
        draft.node.attributes.push(XmlAttribute {
            namespace,
            name: name.to_owned(),
            value: simple.value.clone(),
        });
        draft.attribute_meta.push(Some(leaf_meta(
            simple,
            Occurs {
                required,
                repeated: false,
            },
            false,
        )));
    }

    /// Resolves a named simple type to its built-in base and facets.
    fn simple(&mut self, name: &QName, depth: usize) -> Simple {
        if is_builtin_namespace(name.namespace.as_deref()) {
            return builtin(&name.local);
        }
        match lookup(&self.schemas.types, name).copied() {
            Some((_, declaration)) if declaration.local == "simpleType" => {
                self.simple_inline(declaration, depth + 1)
            }
            Some(_) => Simple::any(),
            None => {
                self.warn(format!("type `{}` is not declared", clark(name)));
                Simple::any()
            }
        }
    }

    /// Resolves an inline or global `simpleType`.
    fn simple_inline(&mut self, declaration: &'a Element, depth: usize) -> Simple {
        if depth >= MAX_SIMPLE_DEPTH {
            self.warn(String::from("simple type derivation nested too deep"));
            return Simple::any();
        }
        if let Some(restriction) = declaration.child("restriction") {
            let mut simple = match restriction.attr("base") {
                Some(base) => self.simple(&restriction.resolve(base), depth + 1),
                None => restriction
                    .child("simpleType")
                    .map_or_else(Simple::any, |inner| self.simple_inline(inner, depth + 1)),
            };
            apply_facets(&mut simple, restriction);
            return simple;
        }
        if let Some(list) = declaration.child("list") {
            return match list.attr("itemType") {
                Some(item) => self.simple(&list.resolve(item), depth + 1),
                None => list.child("simpleType").map_or_else(
                    || builtin("string"),
                    |inner| self.simple_inline(inner, depth + 1),
                ),
            };
        }
        if let Some(union) = declaration.child("union") {
            if let Some(first) = union
                .attr("memberTypes")
                .and_then(|members| members.split_whitespace().next())
            {
                return self.simple(&union.resolve(first), depth + 1);
            }
            return union.child("simpleType").map_or_else(
                || builtin("string"),
                |inner| self.simple_inline(inner, depth + 1),
            );
        }
        Simple::any()
    }
}

/// Applies `enumeration`, lower-bound and `minLength` facets.
fn apply_facets(simple: &mut Simple, restriction: &Element) {
    let enumerations: Vec<String> = restriction
        .children_named("enumeration")
        .filter_map(|facet| facet.attr("value"))
        .map(str::to_owned)
        .collect();
    if let Some(first) = enumerations.first() {
        simple.value.clone_from(first);
        simple.enum_values = enumerations;
        return;
    }
    for facet in &restriction.children {
        let Some(value) = facet.attr("value").map(str::trim) else {
            continue;
        };
        match (facet.local.as_str(), simple.kind) {
            ("minInclusive", ValueKind::Integer | ValueKind::Number) => {
                value.clone_into(&mut simple.value);
            }
            ("minExclusive", ValueKind::Integer) => {
                if let Ok(bound) = value.parse::<i128>() {
                    simple.value = bound.saturating_add(1).to_string();
                }
            }
            ("minLength" | "length", ValueKind::String) => {
                if let Ok(length) = value.parse::<usize>() {
                    let length = length.min(4096);
                    let current = simple.value.chars().count();
                    if current < length {
                        simple.value.push_str(&"x".repeat(length - current));
                    }
                }
            }
            _ => {}
        }
    }
}

/// Applies facets of a simple-content restriction to an existing leaf.
fn restrict(leaf: &mut LeafMeta, node: &mut XmlNode, restriction: &Element) {
    let mut simple = Simple {
        xsd_type: leaf.xsd_type.clone(),
        kind: leaf.kind,
        enum_values: leaf.enum_values.clone(),
        value: node.value.clone().unwrap_or_default(),
    };
    apply_facets(&mut simple, restriction);
    leaf.enum_values = simple.enum_values;
    node.value = Some(simple.value);
}

fn leaf_meta(simple: Simple, occurs: Occurs, nillable: bool) -> LeafMeta {
    LeafMeta {
        xsd_type: simple.xsd_type,
        kind: simple.kind,
        required: occurs.required,
        nillable,
        repeated: occurs.repeated,
        enum_values: simple.enum_values,
    }
}

fn set_leaf(
    draft: &mut Draft,
    mut simple: Simple,
    occurs: Occurs,
    nillable: bool,
    fixed: Option<&str>,
) {
    if let Some(fixed) = fixed {
        fixed.clone_into(&mut simple.value);
    }
    draft.node.value = Some(simple.value.clone());
    draft.leaf = Some(leaf_meta(simple, occurs, nillable));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::finish;
    use crate::xml;

    const SCHEMA: &str = r#"<types xmlns:xs="http://www.w3.org/2001/XMLSchema">
      <xs:schema targetNamespace="urn:t" xmlns:t="urn:t" elementFormDefault="qualified">
        <xs:element name="Order">
          <xs:complexType>
            <xs:sequence>
              <xs:element name="id" type="xs:int"/>
              <xs:element name="note" type="xs:string" minOccurs="0"/>
              <xs:element name="status" type="t:Status"/>
              <xs:element name="line" type="t:Line" maxOccurs="unbounded"/>
              <xs:element name="tree" type="t:Node"/>
              <xs:choice><xs:element name="a" type="xs:boolean"/><xs:element name="b" type="xs:date"/></xs:choice>
              <xs:group ref="t:Extra"/>
            </xs:sequence>
            <xs:attribute name="lang" type="xs:language" use="required"/>
            <xs:attribute name="v" type="xs:string" fixed="2"/>
          </xs:complexType>
        </xs:element>
        <xs:simpleType name="Status">
          <xs:restriction base="xs:string">
            <xs:enumeration value="open"/><xs:enumeration value="closed"/>
          </xs:restriction>
        </xs:simpleType>
        <xs:complexType name="Line">
          <xs:simpleContent>
            <xs:extension base="xs:decimal"><xs:attribute name="unit" type="xs:string"/></xs:extension>
          </xs:simpleContent>
        </xs:complexType>
        <xs:complexType name="Node">
          <xs:sequence><xs:element name="child" type="t:Node" minOccurs="0"/></xs:sequence>
        </xs:complexType>
        <xs:group name="Extra"><xs:sequence><xs:element name="extra" type="t:Qty"/></xs:sequence></xs:group>
        <xs:simpleType name="Qty"><xs:restriction base="xs:int"><xs:minExclusive value="4"/></xs:restriction></xs:simpleType>
      </xs:schema>
    </types>"#;

    #[test]
    fn expands_a_schema() {
        let root = xml::parse(SCHEMA).unwrap();
        let mut warnings = Vec::new();
        let schemas = Schemas::collect(std::iter::once(&root), &mut warnings);
        assert_eq!(warnings, Vec::<String>::new());
        let options = Options::default();
        let mut generator = Generator::new(&schemas, &options);
        let draft = generator
            .global_element(&QName::new(Some("urn:t"), "Order"))
            .unwrap();
        assert_eq!(
            generator.warnings,
            vec![format!("recursive type `{{{}}}Node` cut off", "urn:t")]
        );
        let mut points = Vec::new();
        let nodes = finish(vec![draft], "/Body", &mut points);
        let order = &nodes[0];
        assert_eq!(order.namespace.as_deref(), Some("urn:t"));
        let names: Vec<_> = order
            .children
            .iter()
            .map(|node| node.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["id", "note", "status", "line", "tree", "a", "extra"]
        );
        assert!(
            order
                .children
                .iter()
                .all(|node| node.namespace.as_deref() == Some("urn:t"))
        );
        let get = |name: &str| points.iter().find(|point| point.name == name).unwrap();
        assert_eq!(get("/Body/Order/status").enum_values, ["open", "closed"]);
        assert_eq!(get("/Body/Order/status").value, "open");
        assert!(get("/Body/Order/line").repeated);
        assert_eq!(get("/Body/Order/line").kind, ValueKind::Number);
        assert_eq!(get("/Body/Order/line/@unit").value, "string");
        assert!(!get("/Body/Order/note").required);
        assert_eq!(get("/Body/Order/extra").value, "5");
        assert_eq!(get("/Body/Order/@v").value, "2");
        assert!(get("/Body/Order/@lang").required);
        let tree = &order.children[4];
        assert_eq!(tree.children[0].children, Vec::new());
        assert!(
            points
                .iter()
                .all(|point| point.name != "/Body/Order/tree/child")
        );

        let options = Options::default().with_optional(false).with_max_nodes(3);
        let mut generator = Generator::new(&schemas, &options);
        let draft = generator
            .global_element(&QName::new(Some("urn:t"), "Order"))
            .unwrap();
        // Order, id and status fit; `note` is optional and skipped.
        let names: Vec<_> = draft
            .children
            .iter()
            .map(|child| child.node.name.as_str())
            .collect();
        assert_eq!(names, ["id", "status"]);
        assert_eq!(draft.node.attributes, Vec::new());
        assert!(generator.warnings[0].contains("3 nodes"));
    }

    #[test]
    fn lookup_falls_back_to_a_unique_local_name() {
        let mut map = BTreeMap::new();
        map.insert(QName::new(Some("urn:a"), "x"), 1);
        assert_eq!(lookup(&map, &QName::new(Some("urn:b"), "x")), Some(&1));
        map.insert(QName::new(Some("urn:c"), "x"), 2);
        assert_eq!(lookup(&map, &QName::new(Some("urn:b"), "x")), None);
        assert_eq!(clark(&QName::new(None, "y")), "y");
    }
}
