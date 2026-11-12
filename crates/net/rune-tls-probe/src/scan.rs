//! The scan planner: which hello to send next, given the answers so far.

use std::collections::VecDeque;

use rune_tls_hello::{AlertDescription, CipherSuite, ProtocolVersion};

use crate::report::{Observed, Report, VersionResult};
use crate::suites::{legacy_suites, tls13_suites};
use crate::{Offer, Outcome};

/// Every version the scanner knows, newest first.
pub const ALL_VERSIONS: [ProtocolVersion; 5] = [
    ProtocolVersion::TLS_1_3,
    ProtocolVersion::TLS_1_2,
    ProtocolVersion::TLS_1_1,
    ProtocolVersion::TLS_1_0,
    ProtocolVersion::SSL_3_0,
];

/// What to scan.
///
/// ```
/// use rune_tls_hello::ProtocolVersion;
/// use rune_tls_probe::ScanOptions;
///
/// // Versions only, no cipher enumeration: one or a few hellos per version.
/// let quick = ScanOptions::default()
///     .with_versions([ProtocolVersion::TLS_1_1, ProtocolVersion::TLS_1_0])
///     .with_enumerate_ciphers(false);
/// assert!(!quick.enumerate_ciphers);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScanOptions {
    /// Versions to probe. Default: SSL 3.0 to TLS 1.3. Probed newest
    /// first whatever the order given.
    pub versions: Vec<ProtocolVersion>,
    /// List every accepted suite per version, not just whether the version
    /// is accepted. Default `true`.
    pub enumerate_ciphers: bool,
    /// Most cipher suites in one hello. Default 128; the registry is
    /// offered in chunks of this size, which keeps hellos under the sizes
    /// some old servers mishandle.
    pub max_suites_per_hello: usize,
    /// Most hellos one scan sends. Default 512; a scan that hits it is
    /// marked [`Report::truncated`].
    pub max_attempts: usize,
    /// SNI host name for the hellos; IP literals are not sent.
    pub server_name: Option<String>,
    /// Test `TLS_FALLBACK_SCSV`, compression and secure renegotiation.
    /// Default `true`.
    pub extra_checks: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            versions: ALL_VERSIONS.to_vec(),
            enumerate_ciphers: true,
            max_suites_per_hello: 128,
            max_attempts: 512,
            server_name: None,
            extra_checks: true,
        }
    }
}

impl ScanOptions {
    /// Sets [`ScanOptions::versions`].
    #[must_use]
    pub fn with_versions(mut self, versions: impl IntoIterator<Item = ProtocolVersion>) -> Self {
        self.versions = versions.into_iter().collect();
        self
    }

    /// Sets [`ScanOptions::enumerate_ciphers`].
    #[must_use]
    pub const fn with_enumerate_ciphers(mut self, enumerate: bool) -> Self {
        self.enumerate_ciphers = enumerate;
        self
    }

    /// Sets [`ScanOptions::max_suites_per_hello`] (at least 1).
    #[must_use]
    pub const fn with_max_suites_per_hello(mut self, max: usize) -> Self {
        self.max_suites_per_hello = max;
        self
    }

    /// Sets [`ScanOptions::max_attempts`].
    #[must_use]
    pub const fn with_max_attempts(mut self, max: usize) -> Self {
        self.max_attempts = max;
        self
    }

    /// Sets [`ScanOptions::server_name`].
    #[must_use]
    pub fn with_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = Some(name.into());
        self
    }

    /// Sets [`ScanOptions::extra_checks`].
    #[must_use]
    pub const fn with_extra_checks(mut self, extra: bool) -> Self {
        self.extra_checks = extra;
        self
    }
}

/// What the pending offer is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Version(usize),
    Fallback(ProtocolVersion),
    Compression(ProtocolVersion),
}

/// Per-version enumeration state.
#[derive(Debug)]
struct Lane {
    result: VersionResult,
    chunks: VecDeque<Vec<CipherSuite>>,
    done: bool,
}

/// A sans-I/O TLS scan: asks for one hello at a time and builds a
/// [`Report`] from the answers.
///
/// Drive it with any transport: open a connection per [`Offer`], send
/// [`Offer::to_records`], read with a [`ResponseReader`](crate::ResponseReader),
/// close, and [`record`](Scanner::record) the [`Outcome`]. The tokio
/// [`scan`](crate::scan) function does exactly that over
/// `rune-service-probe`'s runner.
///
/// Per version, the registry's suites are offered in chunks; each accepted
/// suite is removed and the rest offered again, until the server refuses
/// the chunk. The order suites come out in is the server's preference
/// among what was offered.
///
/// ```
/// use rune_tls_hello::{CipherSuite, ProtocolVersion, ServerHello};
/// use rune_tls_probe::{Outcome, ResponseReader, ScanOptions, Scanner};
///
/// // A TLS 1.0-only server that accepts one suite and refuses the rest.
/// fn server(offer: &rune_tls_probe::Offer) -> Outcome {
///     let suite = CipherSuite(0x002f);
///     if offer.version == ProtocolVersion::TLS_1_0 && offer.cipher_suites.contains(&suite) {
///         let hello = ServerHello::new().with_legacy_version(ProtocolVersion::TLS_1_0).with_cipher_suite(suite);
///         let wire = hello.to_records(ProtocolVersion::TLS_1_0, 16_384).unwrap();
///         ResponseReader::new().feed(&wire).unwrap()
///     } else {
///         ResponseReader::new().feed(&[21, 3, 1, 0, 2, 2, 40]).unwrap() // handshake_failure
///     }
/// }
///
/// let mut scanner = Scanner::new(ScanOptions::default());
/// while let Some(offer) = scanner.next_offer() {
///     let outcome = server(&offer);
///     scanner.record(&outcome);
/// }
/// let report = scanner.finish();
/// assert_eq!(report.supported_versions(), [ProtocolVersion::TLS_1_0]);
/// assert_eq!(report.version(ProtocolVersion::TLS_1_0).unwrap().cipher_suites, [CipherSuite(0x002f)]);
/// ```
#[derive(Debug)]
pub struct Scanner {
    options: ScanOptions,
    lanes: Vec<Lane>,
    pending: Option<(Step, Offer)>,
    extras: VecDeque<Step>,
    extras_planned: bool,
    report: Report,
}

impl Scanner {
    /// A scan with these options.
    #[must_use]
    pub fn new(options: ScanOptions) -> Self {
        let mut versions = options.versions.clone();
        versions.sort_unstable_by(|a, b| b.cmp(a));
        versions.dedup();
        let chunk = options.max_suites_per_hello.max(1);
        let lanes = versions
            .into_iter()
            .map(|version| {
                let suites: Vec<CipherSuite> = if version >= ProtocolVersion::TLS_1_3 {
                    tls13_suites().collect()
                } else {
                    legacy_suites().collect()
                };
                Lane {
                    result: VersionResult::new(version),
                    chunks: suites.chunks(chunk).map(<[CipherSuite]>::to_vec).collect(),
                    done: false,
                }
            })
            .collect();
        Self {
            options,
            lanes,
            pending: None,
            extras: VecDeque::new(),
            extras_planned: false,
            report: Report::default(),
        }
    }

    /// The next hello to send, or `None` when the scan is complete. Asking
    /// again before [`Scanner::record`] returns the same offer.
    pub fn next_offer(&mut self) -> Option<Offer> {
        if let Some((_, offer)) = &self.pending {
            return Some(offer.clone());
        }
        if self.report.attempts >= self.options.max_attempts {
            self.report.truncated = self.lanes.iter().any(|lane| !lane.done)
                || !self.extras.is_empty()
                || (!self.extras_planned && self.options.extra_checks);
            return None;
        }
        let (step, offer) = self.plan()?;
        self.pending = Some((step, offer.clone()));
        Some(offer)
    }

    /// Records the server's answer to the last offer. Ignored when no
    /// offer is pending.
    pub fn record(&mut self, outcome: &Outcome) {
        let Some((step, offer)) = self.pending.take() else {
            return;
        };
        self.report.attempts += 1;
        if let Outcome::Unreachable { reason } = outcome {
            self.note(format!("{}: connection failed: {reason}", offer.version));
        }
        match step {
            Step::Version(index) => self.record_version(index, &offer, outcome),
            Step::Fallback(version) => {
                self.report.fallback_scsv =
                    if outcome.is_alert(AlertDescription::INAPPROPRIATE_FALLBACK) {
                        Observed::Yes
                    } else if outcome.accepted().is_some_and(|a| a.version == version) {
                        Observed::No
                    } else {
                        Observed::Inconclusive
                    };
            }
            Step::Compression(version) => {
                self.report.compression = match outcome.accepted() {
                    Some(a) if a.version == version && a.compression_method == 1 => Observed::Yes,
                    Some(a) if a.version == version && a.compression_method == 0 => Observed::No,
                    _ => Observed::Inconclusive,
                };
            }
        }
    }

    /// The report so far; complete once [`Scanner::next_offer`] has
    /// returned `None`.
    #[must_use]
    pub fn finish(mut self) -> Report {
        self.report.versions = self.lanes.into_iter().map(|lane| lane.result).collect();
        self.report
    }

    fn plan(&mut self) -> Option<(Step, Offer)> {
        let enumerate = self.options.enumerate_ciphers;
        let mut next = None;
        for (index, lane) in self.lanes.iter_mut().enumerate() {
            if lane.done {
                continue;
            }
            if lane.result.supported && !enumerate {
                lane.done = true;
                continue;
            }
            let Some(chunk) = lane.chunks.front() else {
                lane.done = true;
                lane.result.complete = true;
                continue;
            };
            next = Some((index, lane.result.version, chunk.clone()));
            break;
        }
        if let Some((index, version, chunk)) = next {
            return Some((Step::Version(index), self.offer(version, chunk)));
        }
        if !self.options.extra_checks {
            return None;
        }
        if !self.extras_planned {
            self.extras_planned = true;
            self.plan_extras();
        }
        let step = self.extras.pop_front()?;
        let version = match step {
            Step::Fallback(version) | Step::Compression(version) => version,
            Step::Version(_) => return None,
        };
        let suites = self
            .lane(version)
            .map(|lane| lane.result.cipher_suites.clone())?;
        let offer = self.offer(version, suites);
        let offer = if matches!(step, Step::Fallback(_)) {
            offer.with_fallback_scsv(true)
        } else {
            offer.with_compression(true)
        };
        Some((step, offer))
    }

    /// Fallback SCSV: offer the second-newest supported version with the
    /// signal. Compression: offer DEFLATE at the newest legacy version.
    fn plan_extras(&mut self) {
        let supported = self.report_supported();
        if let Some(&below) = supported.get(1) {
            self.extras.push_back(Step::Fallback(below));
        } else {
            self.report.fallback_scsv = Observed::NotApplicable;
        }
        let newest_legacy = supported
            .iter()
            .copied()
            .find(|v| *v < ProtocolVersion::TLS_1_3);
        if let Some(version) = newest_legacy {
            self.extras.push_back(Step::Compression(version));
            let lane = self.lane(version);
            self.report.secure_renegotiation =
                match lane.and_then(|l| l.result.secure_renegotiation) {
                    Some(true) => Observed::Yes,
                    Some(false) => Observed::No,
                    None => Observed::Inconclusive,
                };
        } else {
            self.report.compression = Observed::NotApplicable;
            self.report.secure_renegotiation = Observed::NotApplicable;
        }
    }

    fn report_supported(&self) -> Vec<ProtocolVersion> {
        self.lanes
            .iter()
            .filter(|lane| lane.result.supported)
            .map(|lane| lane.result.version)
            .collect()
    }

    fn lane(&self, version: ProtocolVersion) -> Option<&Lane> {
        self.lanes
            .iter()
            .find(|lane| lane.result.version == version)
    }

    fn offer(&self, version: ProtocolVersion, suites: Vec<CipherSuite>) -> Offer {
        let offer = Offer::new(version, suites);
        match &self.options.server_name {
            Some(name) => offer.with_server_name(name.clone()),
            None => offer,
        }
    }

    fn record_version(&mut self, index: usize, offer: &Offer, outcome: &Outcome) {
        let mut note = None;
        let Some(lane) = self.lanes.get_mut(index) else {
            return;
        };
        let version = lane.result.version;
        match outcome.accepted() {
            Some(accepted) if accepted.version == version => {
                let suite = accepted.cipher_suite;
                if !lane.result.supported {
                    lane.result.supported = true;
                    lane.result.secure_renegotiation = Some(accepted.secure_renegotiation);
                    lane.result.downgrade_sentinel = accepted.downgrade_sentinel;
                }
                if offer.cipher_suites.contains(&suite) {
                    if !lane.result.cipher_suites.contains(&suite) {
                        lane.result.cipher_suites.push(suite);
                    }
                    if let Some(chunk) = lane.chunks.front_mut() {
                        chunk.retain(|s| *s != suite);
                        if chunk.is_empty() {
                            lane.chunks.pop_front();
                        }
                    }
                } else {
                    // Picking a suite that was not offered breaks the
                    // protocol; stop this chunk rather than loop on it.
                    note = Some(format!(
                        "{version}: server selected {} which was not offered",
                        crate::suite_label(suite)
                    ));
                    lane.chunks.pop_front();
                }
            }
            _ => {
                // Refused, or negotiated another version: nothing in this
                // chunk is accepted at this version.
                lane.chunks.pop_front();
            }
        }
        if let Some(note) = note {
            self.note(note);
        }
    }

    fn note(&mut self, note: String) {
        // Keep the report bounded however the server misbehaves.
        if self.report.anomalies.len() < 32 {
            self.report.anomalies.push(note);
        }
    }
}
