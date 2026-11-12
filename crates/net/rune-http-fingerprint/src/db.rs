//! Signatures of known server stacks and the matcher that ranks them.

use rune_matchers::{
    CompiledExtractor, CompiledMatcher, Extractor, ExtractorKind, Matcher, MatcherKind,
    ResponsePart,
};

use crate::shape::{Casing, ResponseShape};
use crate::{Error, Observations, ProbeKind};

/// What a [`Clue`] checks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum ClueKind {
    /// A [`rune_matchers`] rule holds on the probe's exchange: a `Server`
    /// token, a default error page, a vendor header.
    Matcher {
        /// The rule.
        matcher: Matcher,
    },
    /// Header `first` comes before header `second` (both present).
    HeaderBefore {
        /// The earlier header (case-insensitive).
        first: String,
        /// The later header (case-insensitive).
        second: String,
    },
    /// The header names are capitalised this way.
    Casing {
        /// The expected casing.
        casing: Casing,
    },
}

/// One piece of evidence for a [`Signature`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Clue {
    /// The probe whose response is checked.
    pub probe: ProbeKind,
    /// What is checked.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub kind: ClueKind,
    /// Confidence points (0 to 100) the clue adds when it holds.
    pub weight: u8,
    /// A short human description, reported as evidence.
    pub note: String,
}

impl Clue {
    /// A clue of `kind` on `probe`.
    #[must_use]
    pub fn new(probe: ProbeKind, kind: ClueKind, weight: u8, note: impl Into<String>) -> Self {
        Self {
            probe,
            kind,
            weight,
            note: note.into(),
        }
    }

    /// The `Server` header of `probe` matches `regex` (ignoring case).
    #[must_use]
    pub fn server(probe: ProbeKind, regex: &str, weight: u8) -> Self {
        Self::header(probe, "server", regex, weight)
    }

    /// Header `name` of `probe` exists with a value matching `regex`
    /// (ignoring case).
    #[must_use]
    pub fn header(probe: ProbeKind, name: &str, regex: &str, weight: u8) -> Self {
        let matcher = Matcher::new(MatcherKind::Header {
            name: name.to_owned(),
            value: Some(regex.to_owned()),
        })
        .ignoring_case();
        Self::new(
            probe,
            ClueKind::Matcher { matcher },
            weight,
            format!("{name} header matches {regex:?}"),
        )
    }

    /// The body of `probe` contains `word` (ignoring case).
    #[must_use]
    pub fn body(probe: ProbeKind, word: &str, weight: u8) -> Self {
        Self::new(
            probe,
            ClueKind::Matcher {
                matcher: Matcher::word([word]).ignoring_case(),
            },
            weight,
            format!("{probe} body contains {word:?}"),
        )
    }

    /// Header `first` precedes header `second` in `probe`'s response.
    #[must_use]
    pub fn before(probe: ProbeKind, first: &str, second: &str, weight: u8) -> Self {
        Self::new(
            probe,
            ClueKind::HeaderBefore {
                first: first.to_ascii_lowercase(),
                second: second.to_ascii_lowercase(),
            },
            weight,
            format!("{first} before {second}"),
        )
    }
}

/// A known server stack: clues and an optional version extractor.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Signature {
    /// Product name, e.g. `nginx`.
    pub name: String,
    /// The evidence.
    pub clues: Vec<Clue>,
    /// Extracts the version from the [`ProbeKind::Baseline`] exchange
    /// (or, when absent, the first observed probe that yields one).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub version: Option<Extractor>,
}

impl Signature {
    /// A signature without clues.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            clues: Vec::new(),
            version: None,
        }
    }

    /// Adds a clue.
    #[must_use]
    pub fn with_clue(mut self, clue: Clue) -> Self {
        self.clues.push(clue);
        self
    }

    /// Takes the version from capture group 1 of `regex` over the `Server`
    /// header.
    #[must_use]
    pub fn with_server_version(mut self, regex: &str) -> Self {
        self.version = Some(
            Extractor::new(ExtractorKind::Regex {
                regex: vec![regex.to_owned()],
                group: 1,
            })
            .with_part(ResponsePart::Header("server".to_owned())),
        );
        self
    }
}

/// A clue that held, as reported in a [`Candidate`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Evidence {
    /// The probe it held on.
    pub probe: ProbeKind,
    /// The clue's note.
    pub note: String,
    /// The points it added.
    pub weight: u8,
}

/// A signature that matched the observations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Candidate {
    /// The signature name.
    pub name: String,
    /// Sum of the weights of the clues that held, capped at 100.
    pub confidence: u8,
    /// The version, when the signature extracts one and it was found.
    pub version: Option<String>,
    /// The clues that held, in signature order.
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone)]
enum CompiledClueKind {
    Matcher(CompiledMatcher),
    HeaderBefore(String, String),
    Casing(Casing),
}

#[derive(Debug, Clone)]
struct CompiledSignature {
    source: Signature,
    clues: Vec<CompiledClueKind>,
    version: Option<CompiledExtractor>,
}

/// Compiled [`Signature`]s, ready to [`identify`](Database::identify)
/// observations.
///
/// ```
/// use rune_http_fingerprint::{Database, Observations, ProbeKind};
/// use rune_http_model::HttpResponse;
///
/// let observations = Observations::new().with_response(
///     ProbeKind::Baseline,
///     HttpResponse::new(200).with_header("Server", "nginx/1.25.3"),
/// );
/// let best = &Database::builtin().identify(&observations)[0];
/// assert_eq!(best.name, "nginx");
/// assert_eq!(best.version.as_deref(), Some("1.25.3"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct Database {
    signatures: Vec<CompiledSignature>,
}

impl Database {
    /// An empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Compiles `signatures`.
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] when a matcher or extractor does not compile.
    pub fn from_signatures(signatures: impl IntoIterator<Item = Signature>) -> Result<Self, Error> {
        let mut db = Self::new();
        for signature in signatures {
            db.add(signature)?;
        }
        Ok(db)
    }

    /// The [`builtin_signatures`].
    #[must_use]
    pub fn builtin() -> Self {
        let mut db = Self::new();
        for signature in builtin_signatures() {
            // The builtin rules are constants checked by the tests; a bad
            // one is a bug there, and skipping it beats panicking.
            let _ = db.add(signature);
        }
        db
    }

    /// Compiles and adds one signature.
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] when a matcher or extractor does not compile;
    /// the database is left unchanged.
    pub fn add(&mut self, signature: Signature) -> Result<(), Error> {
        let wrap = |source| Error::Signature {
            signature: crate::error::clip(&signature.name),
            source,
        };
        let clues = signature
            .clues
            .iter()
            .map(|clue| {
                Ok(match &clue.kind {
                    ClueKind::Matcher { matcher } => CompiledClueKind::Matcher(matcher.compile()?),
                    ClueKind::HeaderBefore { first, second } => CompiledClueKind::HeaderBefore(
                        first.to_ascii_lowercase(),
                        second.to_ascii_lowercase(),
                    ),
                    ClueKind::Casing { casing } => CompiledClueKind::Casing(*casing),
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(wrap)?;
        let version = signature
            .version
            .as_ref()
            .map(Extractor::compile)
            .transpose()
            .map_err(wrap)?;
        self.signatures.push(CompiledSignature {
            source: signature,
            clues,
            version,
        });
        Ok(())
    }

    /// The signatures, in insertion order.
    pub fn signatures(&self) -> impl Iterator<Item = &Signature> {
        self.signatures.iter().map(|signature| &signature.source)
    }

    /// Number of signatures.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Whether there are no signatures.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Every signature with at least one [`ClueKind::Matcher`] clue that
    /// held, most confident first (ties by name). Header-order and casing
    /// clues add confidence but never make a candidate on their own. Clues
    /// on probes that were not observed are skipped.
    #[must_use]
    pub fn identify(&self, observations: &Observations) -> Vec<Candidate> {
        let shapes: Vec<(ProbeKind, Option<ResponseShape>)> = ProbeKind::ALL
            .into_iter()
            .map(|probe| (probe, observations.response(probe).map(ResponseShape::of)))
            .collect();
        let shape = |probe: ProbeKind| {
            shapes
                .iter()
                .find(|(kind, _)| *kind == probe)
                .and_then(|(_, shape)| shape.as_ref())
        };
        let mut candidates: Vec<Candidate> = self
            .signatures
            .iter()
            .filter_map(|signature| {
                let mut named = false;
                let evidence: Vec<Evidence> = signature
                    .source
                    .clues
                    .iter()
                    .zip(&signature.clues)
                    .filter(|(clue, compiled)| {
                        let Some(exchange) = observations.exchange(clue.probe) else {
                            return false;
                        };
                        match compiled {
                            CompiledClueKind::Matcher(matcher) => {
                                let hit = matcher.matches(exchange);
                                named |= hit;
                                hit
                            }
                            CompiledClueKind::HeaderBefore(first, second) => shape(clue.probe)
                                .is_some_and(|shape| {
                                    let position = |name: &String| {
                                        shape.header_order.iter().position(|n| n == name)
                                    };
                                    matches!(
                                        (position(first), position(second)),
                                        (Some(a), Some(b)) if a < b
                                    )
                                }),
                            CompiledClueKind::Casing(casing) => {
                                shape(clue.probe).is_some_and(|shape| shape.casing == *casing)
                            }
                        }
                    })
                    .map(|(clue, _)| Evidence {
                        probe: clue.probe,
                        note: clue.note.clone(),
                        weight: clue.weight.min(100),
                    })
                    .collect();
                // Structural clues only strengthen a candidate: many stacks
                // share an order or a casing, so they never name one alone.
                if !named {
                    return None;
                }
                let total: u32 = evidence.iter().map(|e| u32::from(e.weight)).sum();
                let version = signature.version.as_ref().and_then(|extractor| {
                    let order = std::iter::once(ProbeKind::Baseline).chain(
                        ProbeKind::ALL
                            .into_iter()
                            .filter(|p| *p != ProbeKind::Baseline),
                    );
                    order
                        .filter_map(|probe| observations.exchange(probe))
                        .find_map(|exchange| extractor.extract(exchange).into_iter().next())
                        .filter(|version| !version.is_empty())
                });
                Some(Candidate {
                    name: signature.source.name.clone(),
                    confidence: u8::try_from(total.min(100)).unwrap_or(100),
                    version,
                    evidence,
                })
            })
            .collect();
        candidates.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.name.cmp(&b.name))
        });
        candidates
    }
}

/// The built-in signatures: common web servers, application servers and
/// fronts.
///
/// They were written for this crate from their documented and widely
/// observed default behaviour (`Server` tokens, default error pages,
/// vendor headers). They are deliberately few; add your own with
/// [`Database::add`].
#[must_use]
pub fn builtin_signatures() -> Vec<Signature> {
    use ProbeKind::{Baseline as B, NotFound as NF};
    vec![
        Signature::new("nginx")
            .with_clue(Clue::server(B, r"^nginx\b", 60))
            .with_clue(Clue::server(NF, r"^nginx\b", 60))
            .with_clue(Clue::body(NF, "<center>nginx", 40))
            .with_clue(Clue::before(B, "Server", "Date", 5))
            .with_server_version(r"^nginx/([0-9][0-9A-Za-z.\-]*)"),
        Signature::new("OpenResty")
            .with_clue(Clue::server(B, r"^openresty\b", 60))
            .with_clue(Clue::server(NF, r"^openresty\b", 60))
            .with_clue(Clue::body(NF, "<center>openresty", 40))
            .with_server_version(r"^openresty/([0-9][0-9A-Za-z.\-]*)"),
        Signature::new("Apache HTTP Server")
            .with_clue(Clue::server(B, r"^Apache\b(?:/|$|\s)", 60))
            .with_clue(Clue::server(NF, r"^Apache\b(?:/|$|\s)", 60))
            .with_clue(Clue::body(NF, "<address>Apache", 40))
            .with_clue(Clue::body(
                NF,
                "The requested URL was not found on this server",
                20,
            ))
            .with_clue(Clue::before(B, "Date", "Server", 5))
            .with_server_version(r"^Apache/([0-9][0-9.]*)"),
        Signature::new("Microsoft IIS")
            .with_clue(Clue::server(B, r"^Microsoft-IIS\b", 60))
            .with_clue(Clue::server(NF, r"^Microsoft-IIS\b", 60))
            .with_clue(Clue::header(B, "x-powered-by", r"ASP\.NET", 10))
            .with_clue(Clue::body(NF, "404 - File or directory not found", 40))
            .with_server_version(r"^Microsoft-IIS/([0-9][0-9.]*)"),
        Signature::new("lighttpd")
            .with_clue(Clue::server(B, r"^lighttpd\b", 60))
            .with_clue(Clue::server(NF, r"^lighttpd\b", 60))
            .with_server_version(r"^lighttpd/([0-9][0-9.]*)"),
        Signature::new("Caddy")
            .with_clue(Clue::server(B, r"^Caddy\b", 60))
            .with_clue(Clue::server(NF, r"^Caddy\b", 60)),
        Signature::new("LiteSpeed")
            .with_clue(Clue::server(B, r"^LiteSpeed\b", 60))
            .with_clue(Clue::server(NF, r"^LiteSpeed\b", 60)),
        Signature::new("Apache Tomcat")
            .with_clue(Clue::body(NF, "HTTP Status 404", 40))
            .with_clue(Clue::body(NF, "Apache Tomcat", 40)),
        Signature::new("Eclipse Jetty")
            .with_clue(Clue::server(B, r"^Jetty\b", 60))
            .with_clue(Clue::server(NF, r"^Jetty\b", 60))
            .with_clue(Clue::body(NF, "Powered by Jetty", 40))
            .with_server_version(r"^Jetty\(([0-9][0-9A-Za-z.\-]*)\)"),
        Signature::new("Kestrel")
            .with_clue(Clue::server(B, r"^Kestrel\b", 60))
            .with_clue(Clue::server(NF, r"^Kestrel\b", 60)),
        Signature::new("Go net/http")
            .with_clue(Clue::body(NF, "404 page not found", 50))
            .with_clue(Clue::header(NF, "x-content-type-options", "^nosniff$", 10))
            .with_clue(Clue::new(
                NF,
                ClueKind::Casing {
                    casing: Casing::Title,
                },
                10,
                "canonical Title-Case header names",
            )),
        Signature::new("Express")
            .with_clue(Clue::header(B, "x-powered-by", r"^Express\b", 60))
            .with_clue(Clue::header(NF, "x-powered-by", r"^Express\b", 60))
            .with_clue(Clue::body(NF, "Cannot GET /", 40)),
        Signature::new("Python http.server")
            .with_clue(Clue::server(B, r"^(?:SimpleHTTP|BaseHTTP)/", 60))
            .with_clue(Clue::server(NF, r"^(?:SimpleHTTP|BaseHTTP)/", 60))
            .with_clue(Clue::body(NF, "Error code explanation", 30))
            .with_server_version(r"Python/([0-9][0-9.]*)"),
        Signature::new("Werkzeug")
            .with_clue(Clue::server(B, r"^Werkzeug\b", 60))
            .with_clue(Clue::server(NF, r"^Werkzeug\b", 60))
            .with_server_version(r"^Werkzeug/([0-9][0-9.]*)"),
        Signature::new("Gunicorn")
            .with_clue(Clue::server(B, r"^gunicorn\b", 60))
            .with_clue(Clue::server(NF, r"^gunicorn\b", 60))
            .with_server_version(r"^gunicorn/([0-9][0-9.]*)"),
        Signature::new("Envoy")
            .with_clue(Clue::server(B, r"^envoy\b", 60))
            .with_clue(Clue::header(B, "x-envoy-upstream-service-time", ".", 30))
            .with_clue(Clue::new(
                B,
                ClueKind::Casing {
                    casing: Casing::Lower,
                },
                10,
                "lowercase header names",
            )),
        Signature::new("Cloudflare")
            .with_clue(Clue::server(B, r"^cloudflare\b", 60))
            .with_clue(Clue::header(B, "cf-ray", ".", 40)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_http_model::HttpResponse;

    #[test]
    fn builtin_compiles_completely() {
        assert_eq!(Database::builtin().len(), builtin_signatures().len());
        assert!(!Database::builtin().is_empty());
    }

    #[test]
    fn bad_signature_is_rejected_atomically() {
        let mut db = Database::new();
        let bad = Signature::new("bad").with_clue(Clue::server(ProbeKind::Baseline, "(", 1));
        let error = db.add(bad).unwrap_err();
        assert_eq!(error.code(), "invalid_signature");
        assert!(db.is_empty());
        let bad_version = Signature::new("v").with_server_version("no-group");
        assert!(Database::from_signatures([bad_version]).is_err());
    }

    #[test]
    fn missing_probes_are_skipped_and_weights_cap() {
        let db = Database::from_signatures([Signature::new("x")
            .with_clue(Clue::server(ProbeKind::Baseline, "x", 90))
            .with_clue(Clue::server(ProbeKind::NotFound, "x", 90))
            .with_clue(Clue::server(ProbeKind::Options, "x", 90))])
        .unwrap();
        let both = Observations::new()
            .with_response(
                ProbeKind::Baseline,
                HttpResponse::new(200).with_header("Server", "x"),
            )
            .with_response(
                ProbeKind::NotFound,
                HttpResponse::new(404).with_header("Server", "x"),
            );
        let candidates = db.identify(&both);
        assert_eq!(candidates[0].confidence, 100);
        assert_eq!(candidates[0].evidence.len(), 2);
        assert_eq!(db.identify(&Observations::new()), []);
    }

    #[test]
    fn header_order_and_casing_clues() {
        let db = Database::from_signatures([Signature::new("o")
            .with_clue(Clue::server(ProbeKind::Baseline, "^o$", 1))
            .with_clue(Clue::before(ProbeKind::Baseline, "Date", "Server", 20))
            .with_clue(Clue::new(
                ProbeKind::Baseline,
                ClueKind::Casing {
                    casing: Casing::Title,
                },
                30,
                "title",
            ))])
        .unwrap();
        let observe = |names: &[&str]| {
            let response = names
                .iter()
                .fold(HttpResponse::new(200), |r, name| r.with_header(*name, "o"));
            db.identify(&Observations::new().with_response(ProbeKind::Baseline, response))
        };
        assert_eq!(observe(&["Date", "Server"])[0].confidence, 51);
        assert_eq!(observe(&["server", "date"])[0].confidence, 1);
        assert_eq!(observe(&["date", "server"])[0].confidence, 21);
        // Structural clues alone name nothing.
        assert_eq!(observe(&["Date"]), []);
    }
}
