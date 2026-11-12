//! Matching a certificate against the host a client connected to.

use std::net::IpAddr;

use rune_host_match::rune_psl::List;

use crate::CertSummary;

/// How [`Certificate::matches_host_with`](crate::Certificate::matches_host_with)
/// matches names.
///
/// DNS names follow [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525)
/// through [`rune_host_match::CertName`]: a wildcard only as the whole
/// left-most label, covering exactly one label. Unicode host names are
/// converted to A-labels with UTS #46 (`rune-idna`) first. IP addresses
/// match `iPAddress` SAN entries only, never DNS names or the common name.
///
/// ```
/// use rune_x509::HostOptions;
///
/// let browser = HostOptions::default();
/// assert!(browser.reject_public_suffix_wildcards);
/// assert!(!browser.common_name_fallback);
/// let legacy = HostOptions::default().with_common_name_fallback(true);
/// assert!(legacy.common_name_fallback);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct HostOptions {
    /// Ignore wildcard names whose base is an ICANN public suffix
    /// (`*.co.uk`), as browsers do. Default `true`.
    pub reject_public_suffix_wildcards: bool,
    /// When the certificate has no `dNSName` SAN, fall back to the
    /// subject common names (the pre-RFC 2818 behaviour that RFC 9525
    /// removed). Default `false`.
    pub common_name_fallback: bool,
}

impl Default for HostOptions {
    fn default() -> Self {
        Self {
            reject_public_suffix_wildcards: true,
            common_name_fallback: false,
        }
    }
}

impl HostOptions {
    /// Sets [`HostOptions::reject_public_suffix_wildcards`].
    #[must_use]
    pub const fn with_reject_public_suffix_wildcards(mut self, reject: bool) -> Self {
        self.reject_public_suffix_wildcards = reject;
        self
    }

    /// Sets [`HostOptions::common_name_fallback`].
    #[must_use]
    pub const fn with_common_name_fallback(mut self, fallback: bool) -> Self {
        self.common_name_fallback = fallback;
        self
    }
}

/// Parses `host` as an IP literal, with or without `[...]`.
pub fn ip_literal(host: &str) -> Option<IpAddr> {
    let inner = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    inner.parse().ok()
}

pub fn matches(summary: &CertSummary, host: &str, options: HostOptions) -> bool {
    let host = host.trim();
    if let Some(ip) = ip_literal(host) {
        return summary.ip_addresses().any(|san| san == ip);
    }
    let Ok(ascii) = rune_idna::to_ascii(host, &rune_idna::Options::default()) else {
        return false;
    };
    let mut names: Vec<&str> = summary.dns_names().collect();
    if names.is_empty() && options.common_name_fallback {
        names = summary
            .subject_common_names
            .iter()
            .map(String::as_str)
            .collect();
    }
    if options.reject_public_suffix_wildcards {
        let icann = List::embedded().with_private_rules(false);
        rune_host_match::cert_names_match_with_psl(names, &ascii, &icann)
    } else {
        rune_host_match::cert_names_match(names, &ascii)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_literals() {
        assert_eq!(ip_literal("192.0.2.1"), Some("192.0.2.1".parse().unwrap()));
        assert_eq!(ip_literal("[::1]"), Some("::1".parse().unwrap()));
        assert_eq!(ip_literal("::1"), Some("::1".parse().unwrap()));
        assert_eq!(ip_literal("example.com"), None);
        assert_eq!(ip_literal("[example.com]"), None);
    }
}
