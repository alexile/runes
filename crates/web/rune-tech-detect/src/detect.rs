//! The detection engine.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use rune_http_model::HttpExchange;

use crate::error::clip;
use crate::pattern::{CompiledPattern, compare_versions};
use crate::{Error, Page, Pattern, Ruleset, Technology};

/// The kind of evidence a detection rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum Source {
    /// A response header.
    Header,
    /// A cookie.
    Cookie,
    /// A `<meta>` tag.
    Meta,
    /// The HTML body.
    Html,
    /// A `<script src>` URL.
    ScriptSrc,
    /// The URL.
    Url,
    /// The favicon hash.
    Favicon,
    /// Implied by another detected technology.
    Implied,
}

impl Source {
    /// The lowercase name, as in rule files (`scriptSrc` is `script_src`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Cookie => "cookie",
            Self::Meta => "meta",
            Self::Html => "html",
            Self::ScriptSrc => "script_src",
            Self::Url => "url",
            Self::Favicon => "favicon",
            Self::Implied => "implied",
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One rule that matched.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Evidence {
    /// Where it matched.
    pub source: Source,
    /// The header, cookie or meta name, or the implying technology.
    pub key: Option<String>,
    /// The points it added.
    pub confidence: u8,
}

/// A detected technology.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Detection {
    /// The technology name.
    pub name: String,
    /// The highest version any matching pattern resolved, if any.
    pub version: Option<String>,
    /// Sum of the matching patterns' confidences, capped at 100.
    pub confidence: u8,
    /// Category names (or `#<id>` for ids missing from the ruleset).
    pub categories: Vec<String>,
    /// What matched.
    pub evidence: Vec<Evidence>,
}

/// A pattern that was skipped because it does not compile.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkippedPattern {
    /// The technology it belongs to.
    pub technology: String,
    /// Why it failed (typically JavaScript-only regex syntax such as
    /// lookaround or backreferences).
    pub error: rune_matchers::MatchError,
}

#[derive(Debug, Clone)]
struct CompiledTechnology {
    name: String,
    categories: Vec<String>,
    headers: Vec<(String, Vec<CompiledPattern>)>,
    cookies: Vec<(String, Vec<CompiledPattern>)>,
    meta: Vec<(String, Vec<CompiledPattern>)>,
    html: Vec<CompiledPattern>,
    script_src: Vec<CompiledPattern>,
    url: Vec<CompiledPattern>,
    favicon: Vec<i32>,
    implies: Vec<(String, u8)>,
    requires: Vec<String>,
    excludes: Vec<String>,
}

/// A compiled [`Ruleset`] that detects technologies on [`Page`]s.
///
/// ```
/// use rune_tech_detect::Detector;
/// use rune_http_model::{ExchangeId, HttpExchange, HttpRequest, HttpResponse};
///
/// let detector = Detector::builtin();
/// let exchange = HttpExchange::new(ExchangeId(1), "docs", HttpRequest::get("https://blog.example.test/"))
///     .with_response(
///         HttpResponse::new(200)
///             .with_header("Server", "nginx/1.25.3")
///             .with_body(r#"<meta name="generator" content="WordPress 6.4.2">"#),
///     );
/// let found = detector.detect_exchange(&exchange);
/// let wordpress = found.iter().find(|d| d.name == "WordPress").unwrap();
/// assert_eq!(wordpress.version.as_deref(), Some("6.4.2"));
/// assert!(found.iter().any(|d| d.name == "PHP"));   // implied by WordPress
/// assert!(found.iter().any(|d| d.name == "Nginx"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct Detector {
    technologies: Vec<CompiledTechnology>,
    skipped: Vec<SkippedPattern>,
}

impl Detector {
    /// Compiles `rules`, skipping patterns that do not compile (see
    /// [`Detector::skipped`]). Real-world Wappalyzer rule files contain a
    /// few JavaScript-only regexes; the rest of each technology still works.
    #[must_use]
    pub fn new(rules: &Ruleset) -> Self {
        let mut detector = Self::default();
        for technology in &rules.technologies {
            let compiled = compile(technology, rules, &mut |technology, error| {
                detector.skipped.push(SkippedPattern {
                    technology: technology.to_owned(),
                    error,
                });
                Ok(())
            });
            if let Ok(compiled) = compiled {
                detector.technologies.push(compiled);
            }
        }
        detector
    }

    /// Compiles `rules`, failing on the first pattern that does not compile.
    ///
    /// # Errors
    ///
    /// [`Error::Pattern`] naming the technology and the pattern.
    pub fn strict(rules: &Ruleset) -> Result<Self, Error> {
        let mut detector = Self::default();
        for technology in &rules.technologies {
            detector
                .technologies
                .push(compile(technology, rules, &mut |name, source| {
                    Err(Error::Pattern {
                        technology: clip(name),
                        source,
                    })
                })?);
        }
        Ok(detector)
    }

    /// A detector over [`builtin_ruleset`](crate::builtin_ruleset).
    #[must_use]
    pub fn builtin() -> Self {
        Self::new(&crate::builtin_ruleset())
    }

    /// The patterns [`Detector::new`] skipped.
    #[must_use]
    pub fn skipped(&self) -> &[SkippedPattern] {
        &self.skipped
    }

    /// Number of technologies.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.technologies.len()
    }

    /// Whether there are no technologies.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.technologies.is_empty()
    }

    /// Detects technologies on the page of `exchange`
    /// ([`Page::from_exchange`]).
    #[must_use]
    pub fn detect_exchange(&self, exchange: &HttpExchange) -> Vec<Detection> {
        self.detect(&Page::from_exchange(exchange))
    }

    /// Detects technologies on `page`: direct matches, then implications
    /// (transitively), then `excludes` and `requires`. Sorted by
    /// confidence, then name.
    #[must_use]
    pub fn detect(&self, page: &Page) -> Vec<Detection> {
        let mut found: BTreeMap<&str, Hit> = BTreeMap::new();
        for technology in &self.technologies {
            let hit = direct_hit(technology, page);
            if !hit.evidence.is_empty() {
                found.insert(&technology.name, hit);
            }
        }
        self.apply_implies(&mut found);
        let by_name: BTreeMap<&str, &CompiledTechnology> = self
            .technologies
            .iter()
            .map(|technology| (technology.name.as_str(), technology))
            .collect();
        let excluded: BTreeSet<&str> = found
            .keys()
            .filter_map(|name| by_name.get(name))
            .flat_map(|technology| technology.excludes.iter().map(String::as_str))
            .collect();
        found.retain(|name, _| !excluded.contains(name));
        // `requires` may chain; drop until stable.
        loop {
            let missing: Vec<&str> = found
                .keys()
                .copied()
                .filter(|name| {
                    by_name.get(name).is_some_and(|technology| {
                        technology
                            .requires
                            .iter()
                            .any(|required| !found.contains_key(required.as_str()))
                    })
                })
                .collect();
            if missing.is_empty() {
                break;
            }
            for name in missing {
                found.remove(name);
            }
        }
        let mut detections: Vec<Detection> = found
            .into_iter()
            .map(|(name, hit)| Detection {
                name: name.to_owned(),
                version: hit.version,
                confidence: u8::try_from(hit.confidence.min(100)).unwrap_or(100),
                categories: by_name
                    .get(name)
                    .map(|technology| technology.categories.clone())
                    .unwrap_or_default(),
                evidence: hit.evidence,
            })
            .collect();
        detections.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.name.cmp(&b.name))
        });
        detections
    }

    fn apply_implies<'a>(&'a self, found: &mut BTreeMap<&'a str, Hit>) {
        let by_name: BTreeMap<&str, &CompiledTechnology> = self
            .technologies
            .iter()
            .map(|technology| (technology.name.as_str(), technology))
            .collect();
        let mut queue: Vec<&str> = found.keys().copied().collect();
        let mut visited: BTreeSet<&str> = BTreeSet::new();
        while let Some(name) = queue.pop() {
            if !visited.insert(name) {
                continue;
            }
            let Some(technology) = by_name.get(name) else {
                continue;
            };
            let parent = found.get(name).map_or(0, |hit| hit.confidence.min(100));
            for (implied, confidence) in &technology.implies {
                // Implied technologies outside the ruleset are reported too,
                // without categories.
                let implied: &str = by_name
                    .get_key_value(implied.as_str())
                    .map_or(implied.as_str(), |(key, _)| key);
                let points = parent * u32::from(*confidence) / 100;
                let hit = found.entry(implied).or_default();
                hit.add(
                    Evidence {
                        source: crate::Source::Implied,
                        key: Some(name.to_owned()),
                        confidence: u8::try_from(points).unwrap_or(100),
                    },
                    None,
                );
                queue.push(implied);
            }
        }
    }
}

#[derive(Debug, Default)]
struct Hit {
    confidence: u32,
    version: Option<String>,
    evidence: Vec<Evidence>,
}

impl Hit {
    fn add(&mut self, evidence: Evidence, version: Option<String>) {
        self.confidence += u32::from(evidence.confidence);
        if let Some(version) = version
            && self
                .version
                .as_deref()
                .is_none_or(|old| compare_versions(&version, old) == Ordering::Greater)
        {
            self.version = Some(version);
        }
        if !self.evidence.contains(&evidence) {
            self.evidence.push(evidence);
        }
    }

    fn try_patterns<'t>(
        &mut self,
        patterns: &[CompiledPattern],
        texts: &(impl IntoIterator<Item = &'t str> + Clone),
        source: Source,
        key: Option<&str>,
    ) {
        for pattern in patterns {
            if let Some(hit) = texts
                .clone()
                .into_iter()
                .find_map(|text| pattern.matches(text))
            {
                self.add(
                    Evidence {
                        source,
                        key: key.map(str::to_owned),
                        confidence: hit.confidence,
                    },
                    hit.version,
                );
            }
        }
    }
}

fn direct_hit(technology: &CompiledTechnology, page: &Page) -> Hit {
    let mut hit = Hit::default();
    for (source, rules, values) in [
        (Source::Header, &technology.headers, &page.headers),
        (Source::Cookie, &technology.cookies, &page.cookies),
        (Source::Meta, &technology.meta, &page.meta),
    ] {
        for (key, patterns) in rules {
            if let Some(values) = values.get(key) {
                hit.try_patterns(
                    patterns,
                    &values.iter().map(String::as_str),
                    source,
                    Some(key),
                );
            }
        }
    }
    hit.try_patterns(&technology.html, &[page.html.as_str()], Source::Html, None);
    hit.try_patterns(
        &technology.script_src,
        &page.script_src.iter().map(String::as_str),
        Source::ScriptSrc,
        None,
    );
    hit.try_patterns(&technology.url, &[page.url.as_str()], Source::Url, None);
    if page
        .favicon_hash
        .is_some_and(|hash| technology.favicon.contains(&hash))
    {
        hit.add(
            Evidence {
                source: Source::Favicon,
                key: None,
                confidence: 100,
            },
            None,
        );
    }
    hit
}

type OnError<'a> = dyn FnMut(&str, rune_matchers::MatchError) -> Result<(), Error> + 'a;

fn compile(
    technology: &Technology,
    rules: &Ruleset,
    on_error: &mut OnError<'_>,
) -> Result<CompiledTechnology, Error> {
    let name = technology.name.as_str();
    let mut list = |patterns: &[Pattern]| -> Result<Vec<CompiledPattern>, Error> {
        let mut out = Vec::with_capacity(patterns.len());
        for pattern in patterns {
            match CompiledPattern::new(pattern) {
                Ok(compiled) => out.push(compiled),
                Err(error) => on_error(name, error)?,
            }
        }
        Ok(out)
    };
    let mut keyed = |map: &BTreeMap<String, Vec<Pattern>>| {
        map.iter()
            .map(|(key, patterns)| Ok((key.to_ascii_lowercase(), list(patterns)?)))
            .collect::<Result<Vec<_>, Error>>()
    };
    let headers = keyed(&technology.headers)?;
    let cookies = keyed(&technology.cookies)?;
    let meta = keyed(&technology.meta)?;
    Ok(CompiledTechnology {
        name: technology.name.clone(),
        categories: technology
            .categories
            .iter()
            .map(|id| {
                rules
                    .categories
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| format!("#{id}"))
            })
            .collect(),
        headers,
        cookies,
        meta,
        html: list(&technology.html)?,
        script_src: list(&technology.script_src)?,
        url: list(&technology.url)?,
        favicon: technology.favicon.clone(),
        implies: technology
            .implies
            .iter()
            .map(|implied| (implied.name.clone(), implied.confidence))
            .collect(),
        requires: technology.requires.clone(),
        excludes: technology.excludes.clone(),
    })
}
