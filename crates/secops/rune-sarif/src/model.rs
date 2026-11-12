//! The SARIF 2.1.0 object model: typed, serde-ready structs for the parts of
//! the format security tools use.
//!
//! Names follow the [OASIS SARIF 2.1.0 specification][spec] (section numbers
//! in the docs below), with members in camelCase on the wire. Every struct
//! derives `Default` and is `#[non_exhaustive]`: build one with
//! `Default::default()` or a constructor, then set its public fields.
//!
//! Members the model does not cover are ignored when a log is read, so any
//! valid SARIF 2.1.0 log parses. Writing never emits members that are empty
//! or unset, which keeps the output small and schema-valid.
//!
//! [spec]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// The SARIF version this crate reads and writes.
pub const VERSION: &str = "2.1.0";

/// The `$schema` URI the writer puts in a log by default (the JSON Schema
/// Store copy of the OASIS schema, which GitHub and most editors resolve).
pub const SCHEMA_URI: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// A SARIF log file, the top-level object (§3.13).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Log {
    /// URI of the JSON schema the log conforms to.
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// The SARIF version, always `"2.1.0"` for a log this crate accepts.
    pub version: String,
    /// The analysis runs in the log.
    #[serde(default)]
    pub runs: Vec<Run>,
    /// Additional properties.
    #[serde(default, skip_serializing_if = "PropertyBag::is_empty")]
    pub properties: PropertyBag,
}

impl Log {
    /// An empty SARIF 2.1.0 log with the default `$schema`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema: Some(SCHEMA_URI.to_owned()),
            version: VERSION.to_owned(),
            runs: Vec::new(),
            properties: PropertyBag::default(),
        }
    }
}

/// One invocation of one analysis tool (§3.14).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Run {
    /// The tool that produced the results.
    pub tool: Tool,
    /// The results. Always written, so that an empty list says "no
    /// findings" (§3.14.23); a log without the member reads as empty.
    #[serde(default)]
    pub results: Vec<Result>,
    /// Taxonomies, such as CWE, that results classify themselves in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taxonomies: Vec<ToolComponent>,
    /// How the tool was run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invocations: Vec<Invocation>,
    /// Identifies the run among runs of the same tool. GitHub code scanning
    /// reads `automationDetails.id` as the upload's category.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automation_details: Option<RunAutomationDetails>,
    /// Absolute URIs for the `uriBaseId`s that artifact locations use.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub original_uri_base_ids: BTreeMap<String, ArtifactLocation>,
    /// How columns are counted: `"utf16CodeUnits"` or `"unicodeCodePoints"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column_kind: Option<String>,
    /// Additional properties.
    #[serde(default, skip_serializing_if = "PropertyBag::is_empty")]
    pub properties: PropertyBag,
}

/// The analysis tool: a driver plus optional extensions such as query packs
/// (§3.18).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Tool {
    /// The tool's primary executable.
    pub driver: ToolComponent,
    /// Plug-ins and rule packs. `CodeQL` lists its query packs here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<ToolComponent>,
    /// Additional properties.
    #[serde(default, skip_serializing_if = "PropertyBag::is_empty")]
    pub properties: PropertyBag,
}

/// A tool driver, a tool extension, or a taxonomy such as CWE (§3.19).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ToolComponent {
    /// Name of the component, e.g. `CodeQL` or `CWE`.
    pub name: String,
    /// Organization or company that produces the component.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// Version in whatever format the component uses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Version in Semantic Versioning 2.0 format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_version: Option<String>,
    /// Where to find out more about the component.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<String>,
    /// The rules the component checks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<ReportingDescriptor>,
    /// The entries of a taxonomy component.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taxa: Vec<ReportingDescriptor>,
    /// Additional properties.
    #[serde(default, skip_serializing_if = "PropertyBag::is_empty")]
    pub properties: PropertyBag,
}

impl ToolComponent {
    /// A component with just a name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }
}

/// A rule, or an entry in a taxonomy (§3.49).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ReportingDescriptor {
    /// Stable identifier, e.g. `py/sql-injection` or `CWE-89`.
    pub id: String,
    /// Human-readable identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// One-line description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_description: Option<MultiformatMessageString>,
    /// Full description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_description: Option<MultiformatMessageString>,
    /// Default level and enablement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_configuration: Option<ReportingConfiguration>,
    /// Link to documentation for the rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
    /// Help text, typically how to fix the problem.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<MultiformatMessageString>,
    /// Additional properties. GitHub code scanning reads `tags`,
    /// `precision` and `security-severity` here.
    #[serde(default, skip_serializing_if = "PropertyBag::is_empty")]
    pub properties: PropertyBag,
}

impl ReportingDescriptor {
    /// A descriptor with just an id.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ..Self::default()
        }
    }
}

/// Default configuration of a rule (§3.50).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ReportingConfiguration {
    /// Whether the rule is enabled. Absent means enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Level of results the rule produces when they set none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<Level>,
    /// Additional properties.
    #[serde(default, skip_serializing_if = "PropertyBag::is_empty")]
    pub properties: PropertyBag,
}

/// A reference to a rule or a taxon (§3.52).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ReportingDescriptorReference {
    /// The descriptor's id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Index into the component's `rules` or `taxa`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<i64>,
    /// The component the descriptor lives in. Absent means the driver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_component: Option<ToolComponentReference>,
}

/// A reference to a tool component (§3.54).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ToolComponentReference {
    /// The component's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Index into `run.taxonomies` (for a taxon) or `tool.extensions`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<i64>,
}

/// One finding (§3.27).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Result {
    /// Id of the rule that was violated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Index of the rule in the driver's `rules`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_index: Option<i64>,
    /// Reference to the rule, possibly in an extension.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<ReportingDescriptorReference>,
    /// Whether this is a failure, a pass, a review item, ...; absent means
    /// a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<ResultKind>,
    /// Severity level. Absent means the rule's default, else `warning`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<Level>,
    /// What was found.
    pub message: Message,
    /// Where it was found. The first location is the primary one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<Location>,
    /// Additional properties.
    #[serde(default, skip_serializing_if = "PropertyBag::is_empty")]
    pub properties: PropertyBag,
    /// Contributions to the result's identity, by fingerprint scheme.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub partial_fingerprints: BTreeMap<String, String>,
    /// Complete identities, by fingerprint scheme.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fingerprints: BTreeMap<String, String>,
    /// Classifications of the result in `run.taxonomies`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taxa: Vec<ReportingDescriptorReference>,
    /// Paths through the code, e.g. a taint flow from source to sink.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_flows: Vec<CodeFlow>,
    /// Other locations that help understand the result.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_locations: Vec<Location>,
    /// Proposed fixes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixes: Vec<Fix>,
    /// Suppressions that apply to the result.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suppressions: Vec<Suppression>,
    /// The HTTP request that exposed the result (DAST).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_request: Option<WebRequest>,
    /// The HTTP response to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_response: Option<WebResponse>,
    /// Supporting artifacts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
}

/// SARIF result level (§3.27.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum Level {
    /// No problem, or not applicable.
    None,
    /// A minor problem or an opportunity for improvement.
    Note,
    /// A problem.
    Warning,
    /// A serious problem.
    Error,
}

impl Level {
    /// The wire name, e.g. `"warning"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Note => "note",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// The level with this wire name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "none" => Some(Self::None),
            "note" => Some(Self::Note),
            "warning" => Some(Self::Warning),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

/// SARIF result kind (§3.27.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum ResultKind {
    /// The rule was evaluated and no problem was found.
    Pass,
    /// The rule was evaluated and a problem was found.
    Fail,
    /// The rule needs a human to decide.
    Review,
    /// The tool could not decide.
    Open,
    /// The rule does not apply.
    NotApplicable,
    /// Information that is not a problem.
    Informational,
}

/// A message string (§3.11).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Message {
    /// Plain text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// GitHub-flavoured Markdown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
    /// Id of a message string in the rule's `messageStrings`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Arguments substituted into the message string.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<String>,
}

impl Message {
    /// A plain-text message.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: Some(text.into()),
            ..Self::default()
        }
    }
}

/// A message with a plain-text and an optional Markdown form (§3.12).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MultiformatMessageString {
    /// Plain text.
    pub text: String,
    /// GitHub-flavoured Markdown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
}

impl MultiformatMessageString {
    /// A plain-text message string.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            markdown: None,
        }
    }
}

/// A location: physical, logical, or both (§3.28).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Location {
    /// Identifier of the location within the result, for links in messages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    /// A file and a region in it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physical_location: Option<PhysicalLocation>,
    /// Functions, classes and other logical constructs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub logical_locations: Vec<LogicalLocation>,
    /// What is at the location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
    /// Additional properties.
    #[serde(default, skip_serializing_if = "PropertyBag::is_empty")]
    pub properties: PropertyBag,
}

/// A location in an artifact (§3.29).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PhysicalLocation {
    /// The artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_location: Option<ArtifactLocation>,
    /// A region of the artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<Region>,
    /// A larger region around `region`, for context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_region: Option<Region>,
    /// A memory or file address, for binary artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    /// Additional properties.
    #[serde(default, skip_serializing_if = "PropertyBag::is_empty")]
    pub properties: PropertyBag,
}

/// The location of an artifact (§3.4).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ArtifactLocation {
    /// URI reference, relative to `uriBaseId` when that is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Symbolic base for a relative `uri`, e.g. `%SRCROOT%`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri_base_id: Option<String>,
    /// Index into `run.artifacts`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<i64>,
    /// Description of the artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Message>,
    /// Additional properties.
    #[serde(default, skip_serializing_if = "PropertyBag::is_empty")]
    pub properties: PropertyBag,
}

impl ArtifactLocation {
    /// An artifact location with just a URI.
    pub fn uri(uri: impl Into<String>) -> Self {
        Self {
            uri: Some(uri.into()),
            ..Self::default()
        }
    }
}

/// A region of an artifact (§3.30). Lines and columns are 1-based; byte
/// and character offsets 0-based. `endColumn` is exclusive.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Region {
    /// First line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u32>,
    /// First column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u32>,
    /// Last line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    /// Column after the last character.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
    /// Offset of the first character.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub char_offset: Option<u64>,
    /// Length in characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub char_length: Option<u64>,
    /// Offset of the first byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<u64>,
    /// Length in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_length: Option<u64>,
    /// The text of the region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<ArtifactContent>,
    /// What is in the region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
    /// Additional properties.
    #[serde(default, skip_serializing_if = "PropertyBag::is_empty")]
    pub properties: PropertyBag,
}

impl Region {
    /// Whether no member is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// An address in a binary artifact (§3.32).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Address {
    /// Absolute address, from the start of the artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub absolute_address: Option<u64>,
    /// Offset from the parent address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    /// Kind, e.g. `"section"` or `"function"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Name, e.g. `".text"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// A logical location such as a function or class (§3.33).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LogicalLocation {
    /// Short name, e.g. `user`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Fully qualified name, e.g. `app.views.user`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fully_qualified_name: Option<String>,
    /// Kind, e.g. `"function"`, `"member"` or `"type"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Index into `run.logicalLocations`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<i64>,
}

/// Content of an artifact or a region: text or base64 binary (§3.3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ArtifactContent {
    /// UTF-8 text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Base64-encoded bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
}

impl ArtifactContent {
    /// Text content.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: Some(text.into()),
            binary: None,
        }
    }
}

/// A path through the code, e.g. a taint flow (§3.36).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CodeFlow {
    /// Summary of the flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
    /// One flow per thread; single-threaded flows have one.
    pub thread_flows: Vec<ThreadFlow>,
    /// Additional properties.
    #[serde(default, skip_serializing_if = "PropertyBag::is_empty")]
    pub properties: PropertyBag,
}

impl CodeFlow {
    /// A single-threaded code flow through `locations`, in order.
    pub fn single(locations: impl IntoIterator<Item = ThreadFlowLocation>) -> Self {
        Self {
            thread_flows: vec![ThreadFlow {
                locations: locations.into_iter().collect(),
                ..ThreadFlow::default()
            }],
            ..Self::default()
        }
    }
}

/// The steps one thread takes in a [`CodeFlow`] (§3.37).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ThreadFlow {
    /// Identifier of the thread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Summary of the thread's flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
    /// The steps, in execution order.
    pub locations: Vec<ThreadFlowLocation>,
    /// Additional properties.
    #[serde(default, skip_serializing_if = "PropertyBag::is_empty")]
    pub properties: PropertyBag,
}

/// One step of a [`ThreadFlow`] (§3.38).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ThreadFlowLocation {
    /// Where the step is. Its `message` says what happens there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    /// Kinds of step, e.g. `"source"`, `"sink"`, `"taint"`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<String>,
    /// Call depth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nesting_level: Option<u32>,
    /// Order among all steps of the code flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_order: Option<i64>,
    /// `"important"`, `"essential"` or `"unimportant"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub importance: Option<String>,
    /// Additional properties.
    #[serde(default, skip_serializing_if = "PropertyBag::is_empty")]
    pub properties: PropertyBag,
}

impl ThreadFlowLocation {
    /// A step at `location`.
    #[must_use]
    pub fn new(location: Location) -> Self {
        Self {
            location: Some(location),
            ..Self::default()
        }
    }
}

/// A proposed fix (§3.55).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Fix {
    /// What the fix does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Message>,
    /// The changes, one per artifact.
    pub artifact_changes: Vec<ArtifactChange>,
    /// Additional properties.
    #[serde(default, skip_serializing_if = "PropertyBag::is_empty")]
    pub properties: PropertyBag,
}

/// Changes to one artifact (§3.56).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ArtifactChange {
    /// The artifact to change.
    pub artifact_location: ArtifactLocation,
    /// The replacements, applied in order.
    pub replacements: Vec<Replacement>,
}

/// Replace one region with new content (§3.57).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Replacement {
    /// The region to delete. An empty region inserts.
    pub deleted_region: Region,
    /// The content to insert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inserted_content: Option<ArtifactContent>,
}

/// A suppression of a result, e.g. an inline ignore comment (§3.35).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Suppression {
    /// `"inSource"` or `"external"`.
    pub kind: String,
    /// `"accepted"`, `"underReview"` or `"rejected"`. Absent means accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Why the result is suppressed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
}

/// An HTTP request (§3.46).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WebRequest {
    /// Protocol, e.g. `HTTP`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Protocol version, e.g. `1.1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The request target, usually a URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The method, e.g. `GET`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Headers, by name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// Query or form parameters, by name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: BTreeMap<String, String>,
    /// The body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<ArtifactContent>,
}

/// An HTTP response (§3.47).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct WebResponse {
    /// Protocol, e.g. `HTTP`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Protocol version, e.g. `1.1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Status code, e.g. `200`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// Reason phrase, e.g. `OK`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_phrase: Option<String>,
    /// Headers, by name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// The body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<ArtifactContent>,
    /// Whether the request timed out or failed without a response.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub no_response_received: bool,
}

/// An artifact attached to a result (§3.21).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Attachment {
    /// What the attachment is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Message>,
    /// Where it is.
    pub artifact_location: ArtifactLocation,
}

/// How a tool was run (§3.20).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Invocation {
    /// Whether the tool ran to completion.
    pub execution_successful: bool,
    /// The command line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    /// Start time, RFC 3339 UTC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_time_utc: Option<String>,
    /// End time, RFC 3339 UTC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_time_utc: Option<String>,
    /// Additional properties.
    #[serde(default, skip_serializing_if = "PropertyBag::is_empty")]
    pub properties: PropertyBag,
}

/// Identifies a run among runs of the same tool (§3.17).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RunAutomationDetails {
    /// Identifier, e.g. `python/`. GitHub code scanning uses it as the
    /// category.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Stable GUID of the run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guid: Option<String>,
}

/// A property bag (§3.8): free-form extra data.
///
/// The two members GitHub code scanning reads have their own fields, so they
/// come first on the wire; every other property is in `additional`, in key
/// order. `security-severity` reads from a string or a number.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PropertyBag {
    /// GitHub's `security-severity`: a CVSS-like score, as text.
    #[serde(
        rename = "security-severity",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "string_or_number"
    )]
    pub security_severity: Option<String>,
    /// Tags, e.g. `security` or `external/cwe/cwe-89`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Every other property.
    #[serde(flatten)]
    pub additional: BTreeMap<String, Value>,
}

impl PropertyBag {
    /// Whether the bag has no property.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.security_severity.is_none() && self.tags.is_empty() && self.additional.is_empty()
    }

    /// Set a property, replacing any previous value.
    pub fn insert(&mut self, key: impl Into<String>, value: Value) {
        self.additional.insert(key.into(), value);
    }

    /// The value of a property other than `security-severity` and `tags`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.additional.get(key)
    }

    /// The value of a string property.
    #[must_use]
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Value::as_str)
    }
}

/// Accept `"7.5"` or `7.5` (some tools write a number) as a string.
fn string_or_number<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> core::result::Result<Option<String>, D::Error> {
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::String(text)) => Some(text),
        Some(Value::Number(number)) => Some(number.to_string()),
        Some(Value::Null) | None => None,
        Some(other) => {
            return Err(serde::de::Error::invalid_type(
                serde::de::Unexpected::Other(match other {
                    Value::Bool(_) => "a boolean",
                    Value::Array(_) => "an array",
                    _ => "an object",
                }),
                &"a string or a number",
            ));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn property_bag_orders_github_members_first() {
        let mut bag = PropertyBag {
            security_severity: Some("8.0".to_owned()),
            tags: vec!["security".to_owned()],
            ..PropertyBag::default()
        };
        bag.insert("confidence", Value::from("firm"));
        bag.insert("a", Value::from(1));
        assert_eq!(
            serde_json::to_string(&bag).unwrap(),
            r#"{"security-severity":"8.0","tags":["security"],"a":1,"confidence":"firm"}"#
        );
        let back: PropertyBag =
            serde_json::from_str(&serde_json::to_string(&bag).unwrap()).unwrap();
        assert_eq!(back, bag);
        assert_eq!(back.get_str("confidence"), Some("firm"));
    }

    #[test]
    fn security_severity_accepts_numbers() {
        let bag: PropertyBag = serde_json::from_str(r#"{"security-severity": 7.5}"#).unwrap();
        assert_eq!(bag.security_severity.as_deref(), Some("7.5"));
        let bag: PropertyBag = serde_json::from_str(r#"{"security-severity": null}"#).unwrap();
        assert_eq!(bag.security_severity, None);
        assert!(serde_json::from_str::<PropertyBag>(r#"{"security-severity": true}"#).is_err());
    }

    #[test]
    fn empty_members_are_not_written() {
        let log = Log::new();
        assert_eq!(
            serde_json::to_string(&log).unwrap(),
            r#"{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[]}"#
        );
        let result = Result {
            message: Message::text("m"),
            ..Result::default()
        };
        assert_eq!(
            serde_json::to_string(&result).unwrap(),
            r#"{"message":{"text":"m"}}"#
        );
    }

    #[test]
    fn levels() {
        for level in [Level::None, Level::Note, Level::Warning, Level::Error] {
            assert_eq!(Level::parse(level.as_str()), Some(level));
            assert_eq!(
                serde_json::to_value(level).unwrap(),
                Value::from(level.as_str())
            );
        }
        assert_eq!(Level::parse("fatal"), None);
    }
}
