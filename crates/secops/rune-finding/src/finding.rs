//! [`Finding`] and the supporting detail it carries: [`Evidence`],
//! [`Remediation`] and [`Cvss`].

use core::hash::{Hash, Hasher};
use core::ops::{Deref, DerefMut};

use crate::ext::{HasExchanges, HasLegacyCwe, HasProof, HasSeenTimes};
use crate::{Confidence, Error, Location, Severity, Taxonomy, TaxonomyRef};

/// One security issue a tool reports.
///
/// Every scanner emits this shape, so reports, SARIF output and correlation
/// share one model. Product-specific data goes in the extension slot `ext`
/// (type parameter `X`, `()` by default) instead of a stringly typed
/// metadata map: a DAST scanner keeps its HTTP exchanges and proofs there, a
/// SAST tool its dataflow paths. `Finding<X>` dereferences to `X`, so
/// `finding.exchanges` reads an extension field directly.
///
/// # JSON shape
///
/// With the `serde` feature a finding serializes as one flat object. The
/// extension's members are flattened into it, after the core members:
///
/// ```json
/// {
///   "check_id": "xss.reflected",
///   "title": "Reflected XSS",
///   "severity": "high",
///   "confidence": "firm",
///   "location": {"location_kind": "url", "url": "https://shop.test/s?q=x", "parameter": "q"},
///   "evidence": [{"label": "reflection", "snippet": "<script>alert(1)</script>"}],
///   "remediation": {"summary": "Encode output", "references": []},
///   "taxonomy": [{"framework": "cwe", "id": "CWE-79"}],
///   "remediation_refs": ["https://cheatsheetseries.owasp.org/"],
///   "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "base_score": 6.1}
/// }
/// ```
///
/// `evidence` is always written. `remediation`, `taxonomy`,
/// `remediation_refs` and `cvss` are left out when empty, and all of them
/// default when absent.
///
/// The extension must serialize as a map (a struct, or `()`) whose keys do
/// not clash with the core members. Because of the flattening, findings
/// need a self-describing format such as JSON, and unknown members are
/// ignored rather than rejected.
///
/// # Examples
///
/// ```
/// use rune_finding::{Confidence, Evidence, Finding, Location, Severity, TaxonomyRef};
///
/// let finding = Finding::<()>::new(
///     "tls.weak_protocol",
///     "TLS 1.0 accepted",
///     Severity::Medium,
///     Confidence::Certain,
///     Location::network("example.test", 443),
/// )
/// .push_taxonomy(TaxonomyRef::cwe(327))
/// .push_evidence(Evidence::new("tls_version", "TLSv1.0"));
///
/// assert_eq!(finding.fingerprint().len(), 64);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Finding<X = ()> {
    /// Stable identifier of the issue class (the rule or check id), e.g.
    /// `tls.weak_protocol`.
    pub check_id: String,
    /// Short human title or message.
    pub title: String,
    /// How much it matters.
    pub severity: Severity,
    /// How sure the tool is.
    pub confidence: Confidence,
    /// Where the issue lives.
    pub location: Location,
    /// What the tool saw. Producers keep the list bounded.
    #[cfg_attr(feature = "serde", serde(default))]
    pub evidence: Vec<Evidence>,
    /// What to do about it.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub remediation: Option<Remediation>,
    /// Classification in one or more taxonomies (CWE, OWASP, ...).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub taxonomy: Vec<TaxonomyRef>,
    /// Reference URLs for remediation, e.g. advisories or cheat sheets,
    /// for tools that have links but no [`Remediation`] text.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub remediation_refs: Vec<String>,
    /// CVSS vector and base score, when the tool can score the issue.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub cvss: Option<Cvss>,
    /// Product-specific data. Flattened into the finding when serialized.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub ext: X,
}

impl<X: Default> Finding<X> {
    /// Start a finding with the required members. Optional members start
    /// empty, and the extension starts at its `Default`.
    ///
    /// The struct is `#[non_exhaustive]`, so other crates build findings
    /// with this and the `with_*`/`push_*` methods.
    ///
    /// Rust does not infer a defaulted type parameter through a method
    /// chain, so name the extension when chaining: `Finding::<()>::new(…)`,
    /// or a product alias such as `type Finding = rune_finding::Finding<MyExt>`.
    pub fn new(
        check_id: impl Into<String>,
        title: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
        location: Location,
    ) -> Self {
        Self {
            check_id: check_id.into(),
            title: title.into(),
            severity,
            confidence,
            location,
            evidence: Vec::new(),
            remediation: None,
            taxonomy: Vec::new(),
            remediation_refs: Vec::new(),
            cvss: None,
            ext: X::default(),
        }
    }
}

impl<X> Finding<X> {
    /// Replace the extension, changing its type.
    #[must_use]
    pub fn with_ext<Y>(self, ext: Y) -> Finding<Y> {
        self.map_ext(|_| ext)
    }

    /// Transform the extension, changing its type.
    #[must_use]
    pub fn map_ext<Y>(self, f: impl FnOnce(X) -> Y) -> Finding<Y> {
        Finding {
            check_id: self.check_id,
            title: self.title,
            severity: self.severity,
            confidence: self.confidence,
            location: self.location,
            evidence: self.evidence,
            remediation: self.remediation,
            taxonomy: self.taxonomy,
            remediation_refs: self.remediation_refs,
            cvss: self.cvss,
            ext: f(self.ext),
        }
    }

    /// Split off the extension, leaving a plain `Finding`.
    #[must_use]
    pub fn into_parts(self) -> (Finding, X) {
        let Self {
            check_id,
            title,
            severity,
            confidence,
            location,
            evidence,
            remediation,
            taxonomy,
            remediation_refs,
            cvss,
            ext,
        } = self;
        let core = Finding {
            check_id,
            title,
            severity,
            confidence,
            location,
            evidence,
            remediation,
            taxonomy,
            remediation_refs,
            cvss,
            ext: (),
        };
        (core, ext)
    }

    /// Replace the evidence list.
    #[must_use]
    pub fn with_evidence(mut self, evidence: Vec<Evidence>) -> Self {
        self.evidence = evidence;
        self
    }

    /// Append one evidence item.
    #[must_use]
    pub fn push_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    /// Attach remediation guidance.
    #[must_use]
    pub fn with_remediation(mut self, remediation: Remediation) -> Self {
        self.remediation = Some(remediation);
        self
    }

    /// Replace the taxonomy classifications.
    #[must_use]
    pub fn with_taxonomy(mut self, taxonomy: Vec<TaxonomyRef>) -> Self {
        self.taxonomy = taxonomy;
        self
    }

    /// Append one taxonomy classification.
    #[must_use]
    pub fn push_taxonomy(mut self, entry: TaxonomyRef) -> Self {
        self.taxonomy.push(entry);
        self
    }

    /// Replace the remediation reference URLs.
    #[must_use]
    pub fn with_remediation_refs(mut self, refs: Vec<String>) -> Self {
        self.remediation_refs = refs;
        self
    }

    /// Append one remediation reference URL.
    #[must_use]
    pub fn push_remediation_ref(mut self, url: impl Into<String>) -> Self {
        self.remediation_refs.push(url.into());
        self
    }

    /// Attach a CVSS score.
    #[must_use]
    pub fn with_cvss(mut self, cvss: Cvss) -> Self {
        self.cvss = Some(cvss);
        self
    }

    /// The classifications in one taxonomy, in order.
    pub fn taxonomy_in<'a>(
        &'a self,
        framework: &'a Taxonomy,
    ) -> impl Iterator<Item = &'a TaxonomyRef> + 'a {
        self.taxonomy
            .iter()
            .filter(move |entry| &entry.framework == framework)
    }

    /// A stable identity for this issue, for deduplication across scans.
    ///
    /// Lowercase hex SHA-256 (64 characters) of the UTF-8 preimage
    /// `"netsec-fingerprint/v1" US check_id US location US parameter`, where
    /// `US` is the byte `0x1F`. Only the check id and the location count:
    /// title, severity, evidence, the extension and every other member are
    /// left out, so a re-scan that words its finding differently still
    /// matches. The algorithm is stable, so stored fingerprints stay valid.
    ///
    /// The location is normalized by kind (`parameter` is empty except for
    /// a URL):
    ///
    /// - `Url`: the URL as described below; `parameter` is the location's
    ///   parameter name, verbatim.
    /// - `Network`: `tcp://{lowercase host}:{port}`.
    /// - `File`: `file:{path}`, plus `:{start_line}` when set. Columns, byte
    ///   offsets and the snippet do not count.
    /// - `ClusterObject`: `k8s://{namespace}/{kind}/{name}`.
    /// - `Artifact`: `artifact:{path}`, plus `@{offset as 0x-prefixed
    ///   lowercase hex}` when set.
    ///
    /// URL normalization:
    ///
    /// 1. trim surrounding whitespace and drop the fragment and any userinfo;
    /// 2. lowercase scheme and host, and drop the port when it is the
    ///    scheme's default;
    /// 3. replace each path segment that is all ASCII digits with `{id}`, and
    ///    each canonical UUID (8-4-4-4-12 hex) with `{uuid}`;
    /// 4. trim trailing slashes from the path (`/` becomes empty);
    /// 5. keep only the query parameter *names*, percent-decoded,
    ///    deduplicated and sorted bytewise, joined with `&`.
    ///
    /// Unparseable or relative URLs get steps 1 and 3 to 5 applied to the
    /// raw text. The algorithm is versioned by the `v1` prefix and does not
    /// change within a version; a new location kind only adds a rule.
    ///
    /// # Examples
    ///
    /// ```
    /// use rune_finding::{Confidence, Finding, Location, Severity};
    ///
    /// let at = |url: &str| -> Finding {
    ///     Finding::new("idor", "IDOR", Severity::High, Confidence::Firm, Location::url(url))
    /// };
    /// assert_eq!(
    ///     at("https://a.test/users/1?b=1&a=2").fingerprint(),
    ///     at("HTTPS://A.test:443/users/2/?a=9&b=8#top").fingerprint(),
    /// );
    /// ```
    #[must_use]
    pub fn fingerprint(&self) -> String {
        crate::fingerprint::fingerprint(&self.check_id, &self.location)
    }
}

impl<X: HasLegacyCwe> Finding<X> {
    /// Set the extension's legacy CWE id, e.g. `CWE-319`, and add the same
    /// id to [`taxonomy`](Self::taxonomy) as a [`Taxonomy::Cwe`] reference
    /// unless it is already there.
    #[must_use]
    pub fn with_cwe(mut self, cwe: impl Into<String>) -> Self {
        let cwe = cwe.into();
        if !self
            .taxonomy_in(&Taxonomy::Cwe)
            .any(|entry| entry.id == cwe)
        {
            self.taxonomy
                .push(TaxonomyRef::new(Taxonomy::Cwe, cwe.clone()));
        }
        *self.ext.legacy_cwe_mut() = Some(cwe);
        self
    }
}

impl<X: HasExchanges> Finding<X> {
    /// Replace the extension's exchange list.
    #[must_use]
    pub fn with_exchanges(mut self, exchanges: Vec<X::Exchange>) -> Self {
        *self.ext.exchanges_mut() = exchanges;
        self
    }

    /// Append one exchange to the extension's list.
    #[must_use]
    pub fn push_exchange(mut self, exchange: X::Exchange) -> Self {
        self.ext.exchanges_mut().push(exchange);
        self
    }
}

impl<X: HasProof> Finding<X> {
    /// Attach the extension's proof.
    #[must_use]
    pub fn with_proof(mut self, proof: X::Proof) -> Self {
        *self.ext.proof_mut() = Some(proof);
        self
    }
}

impl<X: HasSeenTimes> Finding<X> {
    /// Set when the issue was first observed, Unix epoch milliseconds.
    #[must_use]
    pub fn with_first_seen_unix_ms(mut self, at: u64) -> Self {
        *self.ext.first_seen_unix_ms_mut() = Some(at);
        self
    }

    /// Set when the issue was last observed, Unix epoch milliseconds.
    #[must_use]
    pub fn with_last_seen_unix_ms(mut self, at: u64) -> Self {
        *self.ext.last_seen_unix_ms_mut() = Some(at);
        self
    }
}

impl<X> Deref for Finding<X> {
    type Target = X;

    /// The extension, so its fields read like the finding's own.
    fn deref(&self) -> &X {
        &self.ext
    }
}

impl<X> DerefMut for Finding<X> {
    fn deref_mut(&mut self) -> &mut X {
        &mut self.ext
    }
}

/// One piece of supporting detail.
///
/// JSON shape: `{"label": "response_header", "snippet": "Server: nginx/1.18"}`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Evidence {
    /// What this snippet is, e.g. `response_header` or `tls_cipher`.
    pub label: String,
    /// The snippet. Producers truncate it to a sane length.
    pub snippet: String,
}

impl Evidence {
    /// One evidence item.
    pub fn new(label: impl Into<String>, snippet: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            snippet: snippet.into(),
        }
    }
}

/// How to fix a finding.
///
/// JSON shape: `{"summary": "Disable TLS 1.0", "references": ["https://…"]}`.
/// `references` is always written and defaults to empty when absent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Remediation {
    /// What to change.
    pub summary: String,
    /// Reference links.
    #[cfg_attr(feature = "serde", serde(default))]
    pub references: Vec<String>,
}

impl Remediation {
    /// Remediation with just a summary.
    pub fn new(summary: impl Into<String>) -> Self {
        Self {
            summary: summary.into(),
            references: Vec::new(),
        }
    }

    /// Replace the reference links.
    #[must_use]
    pub fn with_references(mut self, references: Vec<String>) -> Self {
        self.references = references;
        self
    }

    /// Append one reference link.
    #[must_use]
    pub fn push_reference(mut self, url: impl Into<String>) -> Self {
        self.references.push(url.into());
        self
    }
}

/// A CVSS vector and its base score.
///
/// JSON shape: `{"vector": "CVSS:3.1/AV:N/…", "base_score": 9.8}`.
///
/// [`Cvss::new`] stores the score as given and [`Cvss::try_new`] checks it is
/// between 0.0 and 10.0. With the `cvss` feature, the score is computed
/// from the vector instead: [`Cvss::parse`] and [`Cvss::from_vector`] take
/// a `rune_cvss::Vector` (CVSS v3.0, v3.1 or v4.0) and store its canonical
/// string and its base score, and [`Cvss::verify`] checks a stored score
/// against its vector. The base score is the v3 Base Score or the v4.0
/// CVSS-B score, as in NVD's `baseScore`.
/// Equality and hashing compare `base_score` bit for bit (so `NaN == NaN`
/// and `0.0 != -0.0`), which keeps `Eq` and `Hash` lawful.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Cvss {
    /// The vector string, e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.
    pub vector: String,
    /// The base score, 0.0 to 10.0.
    pub base_score: f64,
}

impl Cvss {
    /// A CVSS score, unchecked.
    pub fn new(vector: impl Into<String>, base_score: f64) -> Self {
        Self {
            vector: vector.into(),
            base_score,
        }
    }

    /// A CVSS score, checking that `base_score` is between 0.0 and 10.0.
    pub fn try_new(vector: impl Into<String>, base_score: f64) -> Result<Self, Error> {
        if (0.0..=10.0).contains(&base_score) {
            Ok(Self::new(vector, base_score))
        } else {
            Err(Error::CvssScoreOutOfRange(base_score))
        }
    }

    /// The CVSS v3 qualitative rating of the base score, as a [`Severity`].
    #[must_use]
    pub fn severity(&self) -> Severity {
        Severity::from_cvss_score(self.base_score)
    }
}

#[cfg(feature = "cvss")]
impl Cvss {
    /// The CVSS score of a parsed vector: its canonical vector string and
    /// its computed base score.
    ///
    /// ```
    /// use rune_finding::Cvss;
    ///
    /// let vector: rune_cvss::Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N".parse()?;
    /// let cvss = Cvss::from_vector(&vector);
    /// assert_eq!(cvss.base_score, 6.1);
    /// assert_eq!(cvss.severity(), rune_finding::Severity::Medium);
    /// # Ok::<(), rune_cvss::Error>(())
    /// ```
    #[must_use]
    pub fn from_vector(vector: &rune_cvss::Vector) -> Self {
        Self::new(vector.to_string(), vector.base_score().value())
    }

    /// Parses a CVSS v3.0, v3.1 or v4.0 vector string and computes its base
    /// score. The stored vector is the canonical form.
    ///
    /// ```
    /// use rune_finding::Cvss;
    ///
    /// let cvss = Cvss::parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X")?;
    /// assert_eq!(cvss.vector, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
    /// assert_eq!(cvss.base_score, 9.3);
    /// assert!(Cvss::parse("CVSS:3.1/AV:N").is_err());
    /// # Ok::<(), rune_finding::Error>(())
    /// ```
    pub fn parse(vector: &str) -> Result<Self, Error> {
        let vector: rune_cvss::Vector = vector.parse()?;
        Ok(Self::from_vector(&vector))
    }

    /// Parses the stored vector string.
    pub fn to_vector(&self) -> Result<rune_cvss::Vector, Error> {
        Ok(self.vector.parse()?)
    }

    /// Checks that the stored base score is the score of the stored vector,
    /// and returns the parsed vector.
    ///
    /// ```
    /// use rune_finding::{Cvss, Error};
    ///
    /// let supplied = Cvss::new("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8);
    /// assert!(supplied.verify().is_ok());
    /// let wrong = Cvss::new("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 7.5);
    /// assert!(matches!(wrong.verify(), Err(Error::CvssScoreMismatch { .. })));
    /// ```
    pub fn verify(&self) -> Result<rune_cvss::Vector, Error> {
        let vector = self.to_vector()?;
        let computed = vector.base_score();
        if rune_cvss::Score::try_from(self.base_score).ok() == Some(computed) {
            Ok(vector)
        } else {
            Err(Error::CvssScoreMismatch {
                stated: self.base_score,
                computed: computed.value(),
            })
        }
    }
}

#[cfg(feature = "cvss")]
impl From<rune_cvss::Vector> for Cvss {
    fn from(vector: rune_cvss::Vector) -> Self {
        Self::from_vector(&vector)
    }
}

impl PartialEq for Cvss {
    fn eq(&self, other: &Self) -> bool {
        self.vector == other.vector && self.base_score.to_bits() == other.base_score.to_bits()
    }
}

impl Eq for Cvss {}

impl Hash for Cvss {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.vector.hash(state);
        self.base_score.to_bits().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "cvss")]
    #[test]
    fn cvss_scores_are_computed_from_the_vector() {
        let cvss = Cvss::parse("CVSS:3.1/S:C/AV:N/AC:L/PR:N/UI:R/C:L/I:L/A:N/E:X").unwrap();
        assert_eq!(cvss.vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
        assert_eq!(cvss.base_score.to_bits(), 6.1_f64.to_bits());
        assert_eq!(cvss.severity(), Severity::Medium);
        assert_eq!(cvss.verify().unwrap().to_string(), cvss.vector);
        assert_eq!(Cvss::from(cvss.to_vector().unwrap()), cvss);

        // v4.0: the base score is the CVSS-B score; threat metrics lower
        // the vector's own score but not the base score.
        let v4 = Cvss::parse("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U")
            .unwrap();
        assert_eq!(v4.base_score.to_bits(), 7.7_f64.to_bits());
        assert_eq!(v4.to_vector().unwrap().score().value(), 5.2);

        let supplied = Cvss::new("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.2);
        assert_eq!(
            supplied.verify(),
            Err(Error::CvssScoreMismatch {
                stated: 6.2,
                computed: 6.1
            })
        );
        let garbage = Cvss::new("CVSS:3.1/AV:N", 6.1);
        assert!(matches!(garbage.verify(), Err(Error::InvalidCvssVector(_))));
        assert!(matches!(
            Cvss::parse("nope"),
            Err(Error::InvalidCvssVector(_))
        ));
    }

    fn finding() -> Finding {
        Finding::new(
            "xss.reflected",
            "Reflected XSS",
            Severity::High,
            Confidence::Firm,
            Location::url("https://shop.test/s?q=x").with_parameter("q"),
        )
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    struct Ext {
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Vec::is_empty")
        )]
        steps: Vec<String>,
    }

    #[test]
    fn builders_fill_members() {
        let finding = finding()
            .with_evidence(vec![Evidence::new("a", "1")])
            .push_evidence(Evidence::new("b", "2"))
            .with_remediation(Remediation::new("Encode").push_reference("https://r.test"))
            .with_taxonomy(vec![TaxonomyRef::cwe(79)])
            .push_taxonomy(TaxonomyRef::owasp("A03:2021"))
            .push_taxonomy(TaxonomyRef::cwe(80))
            .with_remediation_refs(vec!["https://a.test".to_owned()])
            .push_remediation_ref("https://b.test")
            .with_cvss(Cvss::new("CVSS:3.1/AV:N", 6.1));
        assert_eq!(finding.evidence.len(), 2);
        assert_eq!(
            finding.remediation.as_ref().map(|r| r.references.len()),
            Some(1)
        );
        let cwes: Vec<_> = finding
            .taxonomy_in(&Taxonomy::Cwe)
            .filter_map(TaxonomyRef::cwe_number)
            .collect();
        assert_eq!(cwes, [79, 80]);
        assert_eq!(finding.remediation_refs.len(), 2);
        assert_eq!(
            finding.cvss.as_ref().map(Cvss::severity),
            Some(Severity::Medium)
        );
    }

    #[test]
    fn extension_slot() {
        let finding = finding().with_ext(Ext {
            steps: vec!["one".to_owned()],
        });
        // Deref exposes extension fields directly.
        assert_eq!(finding.steps, ["one"]);
        let mut finding = finding.map_ext(|mut ext| {
            ext.steps.push("two".to_owned());
            ext
        });
        finding.steps.push("three".to_owned());
        let fingerprint = finding.fingerprint();
        let (core, ext) = finding.into_parts();
        assert_eq!(ext.steps, ["one", "two", "three"]);
        assert_eq!(core.fingerprint(), fingerprint);
        assert_eq!(core, self::finding());

        let defaulted: Finding<Ext> = Finding::new(
            "c",
            "t",
            Severity::Low,
            Confidence::Tentative,
            Location::file("f"),
        );
        assert_eq!(defaulted.steps, Vec::<String>::new());
    }

    #[derive(Debug, Default, PartialEq)]
    struct Capable {
        cwe: Option<String>,
        exchanges: Vec<u8>,
        proof: Option<&'static str>,
        first: Option<u64>,
        last: Option<u64>,
    }

    impl crate::ext::HasLegacyCwe for Capable {
        fn legacy_cwe_mut(&mut self) -> &mut Option<String> {
            &mut self.cwe
        }
    }

    impl crate::ext::HasExchanges for Capable {
        type Exchange = u8;
        fn exchanges_mut(&mut self) -> &mut Vec<u8> {
            &mut self.exchanges
        }
    }

    impl crate::ext::HasProof for Capable {
        type Proof = &'static str;
        fn proof_mut(&mut self) -> &mut Option<&'static str> {
            &mut self.proof
        }
    }

    impl crate::ext::HasSeenTimes for Capable {
        fn first_seen_unix_ms_mut(&mut self) -> &mut Option<u64> {
            &mut self.first
        }
        fn last_seen_unix_ms_mut(&mut self) -> &mut Option<u64> {
            &mut self.last
        }
    }

    #[test]
    fn capability_builders() {
        let finding = Finding::<Capable>::new(
            "c",
            "t",
            Severity::Low,
            Confidence::Firm,
            Location::file("f"),
        )
        .push_taxonomy(TaxonomyRef::cwe(79))
        .with_cwe("CWE-79")
        .with_cwe("CWE-80")
        .with_cwe("CWE-80")
        .with_exchanges(vec![1])
        .push_exchange(2)
        .with_proof("p")
        .with_first_seen_unix_ms(10)
        .with_last_seen_unix_ms(20);
        assert_eq!(
            finding.taxonomy,
            [TaxonomyRef::cwe(79), TaxonomyRef::cwe(80)]
        );
        assert_eq!(
            finding.ext,
            Capable {
                cwe: Some("CWE-80".to_owned()),
                exchanges: vec![1, 2],
                proof: Some("p"),
                first: Some(10),
                last: Some(20),
            }
        );
    }

    #[test]
    fn fingerprint_ignores_non_identity_members() {
        let plain = finding();
        let rich = finding()
            .push_evidence(Evidence::new("a", "b"))
            .with_cvss(Cvss::new("v", 1.0))
            .with_ext(Ext {
                steps: vec!["s".to_owned()],
            });
        let mut retitled = plain.clone();
        retitled.title = "Other".to_owned();
        retitled.severity = Severity::Critical;
        assert_eq!(rich.fingerprint(), plain.fingerprint());
        assert_eq!(retitled.fingerprint(), plain.fingerprint());
        let mut moved = plain.clone();
        moved.location = Location::url("https://shop.test/t?q=x").with_parameter("q");
        assert_ne!(moved.fingerprint(), plain.fingerprint());
    }

    #[test]
    fn cvss_validation_and_equality() {
        assert!(Cvss::try_new("v", 0.0).is_ok());
        assert!(Cvss::try_new("v", 10.0).is_ok());
        for bad in [-0.1, 10.1, f64::NAN, f64::INFINITY] {
            assert!(Cvss::try_new("v", bad).is_err(), "{bad}");
        }
        assert_eq!(Cvss::new("v", f64::NAN), Cvss::new("v", f64::NAN));
        assert_ne!(Cvss::new("v", 0.0), Cvss::new("v", -0.0));
        let hash = |cvss: &Cvss| {
            use std::collections::hash_map::DefaultHasher;
            let mut hasher = DefaultHasher::new();
            cvss.hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(hash(&Cvss::new("v", 9.8)), hash(&Cvss::new("v", 9.8)));
    }

    #[cfg(feature = "schemars")]
    #[test]
    fn json_schema_describes_the_shape() {
        let schema = serde_json::to_value(schemars::schema_for!(Finding)).unwrap();
        let properties = &schema["properties"];
        for member in ["check_id", "severity", "location", "taxonomy", "cvss"] {
            assert!(properties.get(member).is_some(), "{member}");
        }
        let required = schema["required"].as_array().unwrap();
        assert!(required.iter().any(|member| member == "check_id"));
        assert!(!required.iter().any(|member| member == "taxonomy"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_shape() {
        let finding = finding().push_taxonomy(TaxonomyRef::cwe(79));
        assert_eq!(
            serde_json::to_string(&finding).unwrap(),
            concat!(
                r#"{"check_id":"xss.reflected","title":"Reflected XSS","severity":"high","#,
                r#""confidence":"firm","location":{"location_kind":"url","url":"https://shop.test/s?q=x","parameter":"q"},"#,
                r#""evidence":[],"taxonomy":[{"framework":"cwe","id":"CWE-79"}]}"#
            )
        );
        let back: Finding =
            serde_json::from_str(&serde_json::to_string(&finding).unwrap()).unwrap();
        assert_eq!(back, finding);

        let extended = finding.with_ext(Ext {
            steps: vec!["s".to_owned()],
        });
        let json = serde_json::to_value(&extended).unwrap();
        assert_eq!(json["steps"][0], "s");
        assert_eq!(
            serde_json::from_value::<Finding<Ext>>(json).unwrap(),
            extended
        );
    }
}
