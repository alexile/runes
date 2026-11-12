//! Variable scopes and `{{name}}` resolution.
//!
//! Postman looks a variable up in its narrowest scope first: local values
//! (set by scripts with `pm.variables.set`), then the active environment,
//! then collection variables, then globals. Values may refer to other
//! variables; resolution recurses, with a depth limit and cycle detection,
//! and stops growing a string at a size limit.

use std::collections::BTreeMap;

/// How deep a value may refer to other variables.
const MAX_DEPTH: usize = 16;
/// Longest variable name considered; longer `{{…}}` spans are literal text.
const MAX_NAME_LEN: usize = 256;

/// Text after `{{variable}}` resolution.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Resolved {
    /// The text with every known variable replaced.
    pub text: String,
    /// Names referred to but not defined (or defined in a cycle), in order
    /// of first use. Their `{{name}}` placeholders stay in [`Resolved::text`].
    pub unresolved: Vec<String>,
    /// Whether expansion stopped at the size limit; [`Resolved::text`] is
    /// then cut short.
    pub truncated: bool,
}

/// Something variables are looked up in.
pub trait Lookup {
    /// The raw (unresolved) value of `name`.
    fn get(&self, name: &str) -> Option<&str>;
}

impl Lookup for BTreeMap<String, String> {
    fn get(&self, name: &str) -> Option<&str> {
        Self::get(self, name).map(String::as_str)
    }
}

/// Where a script assignment stores its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// `pm.globals.set`, `postman.setGlobalVariable`.
    Global,
    /// `pm.collectionVariables.set`.
    Collection,
    /// `pm.environment.set`, `postman.setEnvironmentVariable`.
    Environment,
    /// `pm.variables.set`.
    Local,
}

/// The variable scopes in effect at one point of the collection tree.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    pub globals: BTreeMap<String, String>,
    pub collection: BTreeMap<String, String>,
    pub environment: BTreeMap<String, String>,
    pub local: BTreeMap<String, String>,
}

impl Scope {
    /// Stores a value as a script assignment to `target` would.
    pub fn set(&mut self, target: Target, key: String, value: String) {
        let layer = match target {
            Target::Global => &mut self.globals,
            Target::Collection => &mut self.collection,
            Target::Environment => &mut self.environment,
            Target::Local => &mut self.local,
        };
        layer.insert(key, value);
    }
}

/// A [`Scope`] under the caller's overrides, which win over everything.
pub struct Layers<'a> {
    pub overrides: &'a BTreeMap<String, String>,
    pub scope: &'a Scope,
}

impl Lookup for Layers<'_> {
    fn get(&self, name: &str) -> Option<&str> {
        [
            self.overrides,
            &self.scope.local,
            &self.scope.environment,
            &self.scope.collection,
            &self.scope.globals,
        ]
        .into_iter()
        .find_map(|layer| layer.get(name))
        .map(String::as_str)
    }
}

/// Whether `inner` (between `{{` and `}}`) can be a variable name.
fn is_name(inner: &str) -> bool {
    !inner.trim().is_empty()
        && inner.len() <= MAX_NAME_LEN
        && !inner.contains(['{', '}', '\n', '\r', '"'])
}

struct Resolver<'a> {
    lookup: &'a dyn Lookup,
    limit: usize,
    out: String,
    unresolved: Vec<String>,
    truncated: bool,
    active: Vec<&'a str>,
}

impl<'a> Resolver<'a> {
    fn push(&mut self, text: &str) {
        if self.truncated {
            return;
        }
        if self.out.len() + text.len() > self.limit {
            let mut room = self.limit.saturating_sub(self.out.len());
            while !text.is_char_boundary(room) {
                room -= 1;
            }
            self.out.push_str(&text[..room]);
            self.truncated = true;
        } else {
            self.out.push_str(text);
        }
    }

    fn unresolved(&mut self, name: &str) {
        if !self.unresolved.iter().any(|known| known == name) {
            self.unresolved.push(name.to_owned());
        }
    }

    fn expand(&mut self, text: &'a str, depth: usize) {
        let mut rest = text;
        while let Some(start) = rest.find("{{") {
            if self.truncated {
                return;
            }
            self.push(&rest[..start]);
            let after = &rest[start + 2..];
            let Some(end) = after.find("}}") else {
                self.push(&rest[start..]);
                return;
            };
            let inner = &after[..end];
            if !is_name(inner) {
                // Not a placeholder: keep one brace and look again from the
                // next one, so `{{{name}}}` still resolves the inner name.
                self.push("{");
                rest = &rest[start + 1..];
                continue;
            }
            let name = inner.trim();
            let lookup = self.lookup;
            let value = lookup.get(name);
            match value {
                Some(value) if depth < MAX_DEPTH && !self.active.contains(&name) => {
                    self.active.push(name);
                    self.expand(value, depth + 1);
                    self.active.pop();
                }
                _ => {
                    self.unresolved(name);
                    self.push(&rest[start..start + 2 + end + 2]);
                }
            }
            rest = &after[end + 2..];
        }
        self.push(rest);
    }
}

/// Resolves `{{name}}` placeholders in `text` against `lookup`, growing the
/// text to at most `limit` bytes (or its own length, if longer).
pub fn resolve_with(text: &str, lookup: &dyn Lookup, limit: usize) -> Resolved {
    let mut resolver = Resolver {
        lookup,
        limit: limit.max(text.len()),
        out: String::with_capacity(text.len()),
        unresolved: Vec::new(),
        truncated: false,
        active: Vec::new(),
    };
    resolver.expand(text, 0);
    Resolved {
        text: resolver.out,
        unresolved: resolver.unresolved,
        truncated: resolver.truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn run(text: &str, pairs: &[(&str, &str)]) -> Resolved {
        resolve_with(text, &vars(pairs), 1 << 20)
    }

    #[test]
    fn replaces_known_and_keeps_unknown() {
        let resolved = run("{{a}}/{{ b }}/{{c}}/{{c}}", &[("a", "1"), ("b", "2")]);
        assert_eq!(resolved.text, "1/2/{{c}}/{{c}}");
        assert_eq!(resolved.unresolved, ["c"]);
        assert!(!resolved.truncated);
    }

    #[test]
    fn recurses_and_detects_cycles() {
        let resolved = run("{{url}}", &[("url", "{{host}}/x"), ("host", "h.test")]);
        assert_eq!(resolved.text, "h.test/x");
        let cyclic = run("{{a}}", &[("a", "<{{b}}>"), ("b", "[{{a}}]")]);
        assert_eq!(cyclic.text, "<[{{a}}]>");
        assert_eq!(cyclic.unresolved, ["a"]);
    }

    #[test]
    fn braces_that_are_not_placeholders() {
        let resolved = run(
            r#"{"x":{{v}}} {{"a":1}} {{{v}}} {{ }} {{open"#,
            &[("v", "7")],
        );
        assert_eq!(resolved.text, r#"{"x":7} {{"a":1}} {7} {{ }} {{open"#);
        assert_eq!(resolved.unresolved.len(), 0);
    }

    #[test]
    fn stops_exponential_growth() {
        let mut pairs = vec![("v0".to_owned(), "x".repeat(64))];
        for level in 1..16 {
            let prev = format!("{{{{v{}}}}}", level - 1);
            pairs.push((format!("v{level}"), format!("{prev}{prev}")));
        }
        let map: BTreeMap<String, String> = pairs.into_iter().collect();
        let resolved = resolve_with("{{v15}}", &map, 4096);
        assert!(resolved.truncated);
        assert_eq!(resolved.text.len(), 4096);
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        let resolved = resolve_with("{{a}}", &vars(&[("a", "ééééé")]), 6);
        assert!(resolved.truncated);
        assert_eq!(resolved.text, "ééé");
    }

    #[test]
    fn layers_follow_postman_precedence() {
        let mut scope = Scope::default();
        scope.set(Target::Global, "k".into(), "global".into());
        scope.set(Target::Global, "g".into(), "global".into());
        scope.set(Target::Collection, "k".into(), "collection".into());
        scope.set(Target::Environment, "k".into(), "environment".into());
        let overrides = BTreeMap::new();
        let layers = Layers {
            overrides: &overrides,
            scope: &scope,
        };
        assert_eq!(layers.get("k"), Some("environment"));
        assert_eq!(layers.get("g"), Some("global"));
        scope.set(Target::Local, "k".into(), "local".into());
        let overrides = vars(&[("k", "override")]);
        let layers = Layers {
            overrides: &overrides,
            scope: &scope,
        };
        assert_eq!(layers.get("k"), Some("override"));
    }
}
