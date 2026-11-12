//! The rule model and the Wappalyzer-format loader.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::error::clip;
use crate::{Error, Pattern};

/// A technology implied by another, e.g. `WordPress` implies `PHP`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Implied {
    /// The implied technology's name.
    pub name: String,
    /// Confidence (0 to 100) of the implication.
    pub confidence: u8,
}

impl Implied {
    /// Parses `Name` or `Name\;confidence:50`.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let pattern = Pattern::parse(text);
        Self {
            name: pattern.regex.trim().to_owned(),
            confidence: pattern.confidence,
        }
    }
}

/// One technology and the evidence that reveals it.
///
/// Keyed fields (`headers`, `cookies`, `meta`) map a lowercase name to
/// patterns over its value. Wappalyzer's browser-only fields (`js`, `dom`,
/// `css`, `xhr`, …) need a rendered page and are ignored when loading.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Technology {
    /// The name, unique within a ruleset.
    pub name: String,
    /// Category ids (see [`Ruleset::categories`]).
    pub categories: Vec<u32>,
    /// Home page.
    pub website: Option<String>,
    /// Response header patterns by lowercase header name.
    pub headers: BTreeMap<String, Vec<Pattern>>,
    /// `Set-Cookie` value patterns by lowercase cookie name.
    pub cookies: BTreeMap<String, Vec<Pattern>>,
    /// `<meta>` `content` patterns by lowercase `name`/`property`.
    pub meta: BTreeMap<String, Vec<Pattern>>,
    /// Patterns over the HTML body.
    pub html: Vec<Pattern>,
    /// Patterns over each `<script src>` URL.
    pub script_src: Vec<Pattern>,
    /// Patterns over the request URL.
    pub url: Vec<Pattern>,
    /// Shodan-style favicon hashes ([`rune_favicon_hash`]); an extension
    /// of the Wappalyzer format (`"favicon": [-1234, …]`).
    pub favicon: Vec<i32>,
    /// Technologies this one implies.
    pub implies: Vec<Implied>,
    /// Technologies that must also be detected for this one to count.
    pub requires: Vec<String>,
    /// Technologies this one rules out.
    pub excludes: Vec<String>,
}

impl Technology {
    /// A technology without rules.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }
}

/// A set of technologies and category names.
///
/// ```
/// use rune_tech_detect::Ruleset;
///
/// let rules = Ruleset::from_wappalyzer_json(r#"{
///   "Example CMS": {
///     "cats": [1],
///     "meta": { "generator": "^Example CMS ([\\d.]+)\\;version:\\1" },
///     "implies": "PHP"
///   },
///   "PHP": { "headers": { "X-Powered-By": "^PHP/([\\d.]+)\\;version:\\1" } }
/// }"#)?;
/// assert_eq!(rules.technologies.len(), 2);
/// assert_eq!(rules.technologies[0].meta["generator"][0].version.as_deref(), Some(r"\1"));
/// # Ok::<(), rune_tech_detect::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Ruleset {
    /// The technologies, sorted by name.
    pub technologies: Vec<Technology>,
    /// Category names by id.
    pub categories: BTreeMap<u32, String>,
}

impl Ruleset {
    /// An empty ruleset.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads a Wappalyzer-format `technologies` object
    /// (`{"Name": {"cats": […], "headers": {…}, …}}`).
    ///
    /// # Errors
    ///
    /// [`Error::Json`] for invalid JSON, [`Error::InvalidRule`] for a field
    /// with the wrong shape.
    pub fn from_wappalyzer_json(json: &str) -> Result<Self, Error> {
        let mut rules = Self::new();
        rules.extend_from_wappalyzer_json(json)?;
        Ok(rules)
    }

    /// Adds the technologies of a Wappalyzer-format object (rule sets are
    /// often split across files, e.g. `a.json` … `z.json`). A technology
    /// with a name already present replaces it. On error nothing is added.
    ///
    /// # Errors
    ///
    /// As [`Ruleset::from_wappalyzer_json`].
    pub fn extend_from_wappalyzer_json(&mut self, json: &str) -> Result<(), Error> {
        let value: Value =
            serde_json::from_str(json).map_err(|error| Error::Json(error.to_string()))?;
        let Value::Object(object) = value else {
            return Err(Error::Json("expected an object of technologies".into()));
        };
        let parsed = object
            .iter()
            .map(|(name, body)| technology(name, body))
            .collect::<Result<Vec<_>, _>>()?;
        for technology in parsed {
            self.insert(technology);
        }
        Ok(())
    }

    /// Adds the categories of a Wappalyzer-format `categories` object
    /// (`{"1": {"name": "CMS", …}}`).
    ///
    /// # Errors
    ///
    /// [`Error::Json`] for invalid JSON or a non-numeric id.
    pub fn extend_categories_from_json(&mut self, json: &str) -> Result<(), Error> {
        let value: Value =
            serde_json::from_str(json).map_err(|error| Error::Json(error.to_string()))?;
        let Value::Object(object) = value else {
            return Err(Error::Json("expected an object of categories".into()));
        };
        let mut parsed = Vec::new();
        for (id, body) in &object {
            let id: u32 = id
                .parse()
                .map_err(|_| Error::Json(format!("category id {:?} is not a number", clip(id))))?;
            let name = body
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| body.as_str())
                .ok_or_else(|| Error::Json(format!("category {id} has no name")))?;
            parsed.push((id, name.to_owned()));
        }
        self.categories.extend(parsed);
        Ok(())
    }

    /// Adds or replaces a technology, keeping the list sorted by name.
    pub fn insert(&mut self, technology: Technology) {
        match self
            .technologies
            .binary_search_by(|t| t.name.as_str().cmp(&technology.name))
        {
            Ok(index) => self.technologies[index] = technology,
            Err(index) => self.technologies.insert(index, technology),
        }
    }

    /// The technology called `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Technology> {
        self.technologies
            .binary_search_by(|t| t.name.as_str().cmp(name))
            .ok()
            .map(|index| &self.technologies[index])
    }
}

fn invalid(technology: &str, field: &str, message: impl Into<String>) -> Error {
    Error::InvalidRule {
        technology: clip(technology),
        field: field.to_owned(),
        message: message.into(),
    }
}

/// A string or an array of strings.
fn strings(name: &str, field: &str, value: &Value) -> Result<Vec<String>, Error> {
    match value {
        Value::String(text) => Ok(vec![text.clone()]),
        Value::Array(items) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| invalid(name, field, "expected strings"))
            })
            .collect(),
        _ => Err(invalid(
            name,
            field,
            "expected a string or an array of strings",
        )),
    }
}

fn patterns(name: &str, field: &str, value: &Value) -> Result<Vec<Pattern>, Error> {
    Ok(strings(name, field, value)?
        .iter()
        .map(|text| Pattern::parse(text))
        .collect())
}

fn keyed(name: &str, field: &str, value: &Value) -> Result<BTreeMap<String, Vec<Pattern>>, Error> {
    let Value::Object(object) = value else {
        return Err(invalid(name, field, "expected an object"));
    };
    let mut out: BTreeMap<String, Vec<Pattern>> = BTreeMap::new();
    for (key, value) in object {
        out.entry(key.to_ascii_lowercase())
            .or_default()
            .extend(patterns(name, field, value)?);
    }
    Ok(out)
}

fn technology(name: &str, body: &Value) -> Result<Technology, Error> {
    let Value::Object(fields) = body else {
        return Err(invalid(name, "", "expected an object"));
    };
    let get = |key: &str| fields.get(key);
    let mut tech = Technology::new(name);
    if let Some(value) = get("cats") {
        let Value::Array(items) = value else {
            return Err(invalid(name, "cats", "expected an array of numbers"));
        };
        tech.categories = items
            .iter()
            .map(|item| {
                item.as_u64()
                    .and_then(|id| u32::try_from(id).ok())
                    .ok_or_else(|| invalid(name, "cats", "expected an array of numbers"))
            })
            .collect::<Result<_, _>>()?;
    }
    tech.website = get("website").and_then(Value::as_str).map(str::to_owned);
    if let Some(value) = get("headers") {
        tech.headers = keyed(name, "headers", value)?;
    }
    if let Some(value) = get("cookies") {
        tech.cookies = keyed(name, "cookies", value)?;
    }
    if let Some(value) = get("meta") {
        tech.meta = keyed(name, "meta", value)?;
    }
    if let Some(value) = get("html") {
        tech.html = patterns(name, "html", value)?;
    }
    // `script` is the pre-2021 name of `scriptSrc`.
    for key in ["scriptSrc", "script"] {
        if let Some(value) = get(key) {
            tech.script_src.extend(patterns(name, key, value)?);
        }
    }
    if let Some(value) = get("url") {
        tech.url = patterns(name, "url", value)?;
    }
    if let Some(value) = get("favicon") {
        tech.favicon = favicon_hashes(name, value)?;
    }
    for (key, target) in [
        ("requires", &mut tech.requires),
        ("excludes", &mut tech.excludes),
    ] {
        if let Some(value) = get(key) {
            *target = strings(name, key, value)?
                .iter()
                .map(|text| Pattern::parse(text).regex.trim().to_owned())
                .collect();
        }
    }
    if let Some(value) = get("implies") {
        tech.implies = strings(name, "implies", value)?
            .iter()
            .map(|text| Implied::parse(text))
            .collect();
    }
    Ok(tech)
}

fn favicon_hashes(name: &str, value: &Value) -> Result<Vec<i32>, Error> {
    let one = |item: &Value| {
        item.as_i64()
            .and_then(|hash| i32::try_from(hash).ok())
            .or_else(|| item.as_str().and_then(|text| text.trim().parse().ok()))
            .ok_or_else(|| invalid(name, "favicon", "expected 32-bit signed hashes"))
    };
    match value {
        Value::Array(items) => items.iter().map(one).collect(),
        other => Ok(vec![one(other)?]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_every_supported_field() {
        let rules = Ruleset::from_wappalyzer_json(
            r#"{"T": {
                "cats": [1, 2], "website": "https://t.test",
                "headers": {"X-Powered-By": ["^T", "t2"]},
                "cookies": {"T_SESSION": ""},
                "meta": {"Generator": "T ([\\d.]+)\\;version:\\1"},
                "html": "<t-app", "scriptSrc": ["t\\.js"], "script": "legacy\\.js",
                "url": "^https?://t\\.", "favicon": [123, "-45"],
                "implies": ["A\\;confidence:50", "B"], "requires": "C", "excludes": ["D"],
                "js": {"ignored": ""}, "dom": "ignored"
            }}"#,
        )
        .unwrap();
        let t = rules.get("T").unwrap();
        assert_eq!(t.categories, [1, 2]);
        assert_eq!(t.website.as_deref(), Some("https://t.test"));
        assert_eq!(t.headers["x-powered-by"].len(), 2);
        assert_eq!(t.cookies["t_session"][0].regex, "");
        assert_eq!(t.meta["generator"][0].version.as_deref(), Some(r"\1"));
        assert_eq!(t.script_src.len(), 2);
        assert_eq!(t.favicon, [123, -45]);
        assert_eq!(
            t.implies[0],
            Implied {
                name: "A".into(),
                confidence: 50
            }
        );
        assert_eq!(t.requires, ["C"]);
        assert_eq!(t.excludes, ["D"]);
    }

    #[test]
    fn rejects_bad_shapes_atomically() {
        let mut rules = Ruleset::new();
        for (json, code) in [
            ("[", "invalid_json"),
            ("[]", "invalid_json"),
            (r#"{"A": {}, "B": 1}"#, "invalid_rule"),
            (r#"{"A": {"cats": "x"}}"#, "invalid_rule"),
            (r#"{"A": {"headers": ["x"]}}"#, "invalid_rule"),
            (r#"{"A": {"html": [1]}}"#, "invalid_rule"),
            (r#"{"A": {"favicon": [1e12]}}"#, "invalid_rule"),
        ] {
            let error = rules.extend_from_wappalyzer_json(json).unwrap_err();
            assert_eq!(error.code(), code, "{json}");
        }
        assert_eq!(rules.technologies.len(), 0);
    }

    #[test]
    fn categories_and_replacement() {
        let mut rules = Ruleset::new();
        rules
            .extend_categories_from_json(r#"{"1": {"name": "CMS"}, "2": "Web servers"}"#)
            .unwrap();
        assert_eq!(rules.categories[&2], "Web servers");
        assert!(rules.extend_categories_from_json(r#"{"x": "y"}"#).is_err());
        assert!(rules.extend_categories_from_json(r#"{"3": {}}"#).is_err());
        rules
            .extend_from_wappalyzer_json(r#"{"B": {}, "A": {"html": "1"}}"#)
            .unwrap();
        rules
            .extend_from_wappalyzer_json(r#"{"A": {"html": "2"}}"#)
            .unwrap();
        let names: Vec<_> = rules.technologies.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["A", "B"]);
        assert_eq!(rules.get("A").unwrap().html[0].regex, "2");
        assert!(rules.get("Z").is_none());
    }
}
