//! Configuration errors reported when a [`Helmet`](crate::Helmet) is built.

/// A configured header value that would be broken or unsafe on the wire.
///
/// Returned by [`Helmet::validate`](crate::Helmet::validate),
/// [`HelmetLayer::new`](crate::HelmetLayer::new) and
/// [`HelmetOverride::replace`](crate::HelmetOverride::replace), so a typo
/// fails at startup instead of shipping a header browsers ignore.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A CSP does not parse (empty, duplicate directive, bad source, ...).
    #[error("invalid {header}: {source}")]
    Csp {
        /// `Content-Security-Policy` or `Content-Security-Policy-Report-Only`.
        header: &'static str,
        /// What the CSP parser found.
        source: rune_csp::Error,
    },
    /// A CSP directive no specification defines (usually a typo).
    #[error("unknown directive {name:?} in {header}")]
    UnknownCspDirective {
        /// The header the policy belongs to.
        header: &'static str,
        /// Lowercase directive name.
        name: String,
    },
    /// A CSP holds a hard-coded `'nonce-...'`. A nonce that never changes
    /// lets an attacker reuse it; use [`CspBuilder::script_nonce`] instead.
    ///
    /// [`CspBuilder::script_nonce`]: crate::CspBuilder::script_nonce
    #[error("{header} has a fixed nonce in {directive}; use a per-request nonce")]
    StaticCspNonce {
        /// The header the policy belongs to.
        header: &'static str,
        /// The directive holding the nonce.
        directive: String,
    },
    /// `'strict-dynamic'` without a nonce or hash in the same directive,
    /// which blocks every script.
    #[error("'strict-dynamic' in {directive} of {header} needs a nonce or a hash")]
    StrictDynamicWithoutNonce {
        /// The header the policy belongs to.
        header: &'static str,
        /// The directive holding `'strict-dynamic'`.
        directive: String,
    },
    /// The `Permissions-Policy` value is not a valid structured-field
    /// dictionary, so browsers would drop all of it.
    #[error("invalid Permissions-Policy: {0}")]
    PermissionsPolicy(#[from] rune_permissions_policy::Error),
    /// [`Hsts::preload`](crate::Hsts::preload) is set but the header does
    /// not meet the preload list's requirements.
    #[error("HSTS preload requirements not met: {reasons}")]
    HstsPreload {
        /// The unmet requirements, separated by `"; "`.
        reasons: String,
    },
    /// A `Reporting-Endpoints` entry has a bad name or URL.
    #[error("invalid reporting endpoint {name:?}: {reason}")]
    InvalidReportingEndpoint {
        /// The endpoint name as given.
        name: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A header reports to an endpoint name that is not configured with
    /// [`Helmet::reporting_endpoint`](crate::Helmet::reporting_endpoint).
    #[error("{header} reports to {name:?}, which is not a configured reporting endpoint")]
    UnknownReportingEndpoint {
        /// The header holding the reference.
        header: &'static str,
        /// The endpoint name referenced.
        name: String,
    },
    /// A value has characters an HTTP header cannot carry.
    #[error("the value for {header} is not a valid header value")]
    InvalidHeaderValue {
        /// The header name.
        header: &'static str,
    },
}
