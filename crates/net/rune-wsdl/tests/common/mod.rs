//! Shared helpers: an independent well-formedness check of envelopes.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test helpers")]
#![allow(dead_code, reason = "not every test file uses every helper")]

use quick_xml::NsReader;
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;

/// One element of a parsed envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read {
    /// `/Envelope/Body/...` path of local names.
    pub path: String,
    /// Resolved namespace.
    pub namespace: Option<String>,
    /// Text content.
    pub text: String,
}

/// Parses `envelope` with quick-xml's namespace-aware reader, panicking
/// unless it is well-formed with every element prefix bound, and returns
/// every element in document order.
pub fn read_envelope(envelope: &str) -> Vec<Read> {
    let mut reader = NsReader::from_str(envelope);
    reader.config_mut().check_end_names = true;
    let mut stack: Vec<usize> = Vec::new();
    let mut out: Vec<Read> = Vec::new();
    let mut roots = 0;
    loop {
        let (resolved, event) = reader
            .read_resolved_event()
            .unwrap_or_else(|error| panic!("{error}: {envelope}"));
        let namespace = match resolved {
            ResolveResult::Bound(namespace) => {
                let namespace: &str = namespace.as_ref();
                Some(namespace.to_owned())
            }
            ResolveResult::Unbound => None,
            ResolveResult::Unknown(prefix) => panic!("unbound prefix {prefix:?}: {envelope}"),
        };
        match event {
            Event::Start(ref start) | Event::Empty(ref start) => {
                if stack.is_empty() {
                    roots += 1;
                }
                let name = start.local_name();
                let local: &str = name.as_ref();
                let parent = stack
                    .last()
                    .map(|index| out[*index].path.clone())
                    .unwrap_or_default();
                out.push(Read {
                    path: format!("{parent}/{local}"),
                    namespace,
                    text: String::new(),
                });
                if matches!(event, Event::Start(_)) {
                    stack.push(out.len() - 1);
                }
            }
            Event::End(_) => {
                stack.pop().unwrap();
            }
            Event::Text(text) => {
                if let Some(index) = stack.last() {
                    out[*index].text.push_str(&text.xml10_content());
                }
            }
            Event::GeneralRef(reference) => {
                if let Some(index) = stack.last() {
                    let name: &str = &reference;
                    let resolved = quick_xml::escape::resolve_predefined_entity(name)
                        .map(str::to_owned)
                        .or_else(|| {
                            reference
                                .resolve_char_ref()
                                .ok()
                                .flatten()
                                .map(String::from)
                        })
                        .unwrap_or_else(|| panic!("unknown entity {name}: {envelope}"));
                    out[*index].text.push_str(&resolved);
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    assert!(stack.is_empty(), "unclosed elements: {envelope}");
    assert_eq!(roots, 1, "{envelope}");
    out
}

/// The text of the element at `path` (`/Envelope/Body/...`).
pub fn text_at<'a>(elements: &'a [Read], path: &str) -> &'a str {
    &elements
        .iter()
        .find(|element| element.path == path)
        .unwrap_or_else(|| panic!("no {path} in {elements:?}"))
        .text
}
