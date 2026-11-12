//! The crate's error type.

use rune_dns_wire::{Name, RecordType};

/// A boxed resolver error, as carried by [`Error::Resolver`].
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The domain given as text is not a valid (internationalized) domain
    /// name.
    #[error("invalid domain {domain:?}: {source}")]
    InvalidDomain {
        /// The domain as given.
        domain: String,
        /// Why IDNA processing rejected it.
        #[source]
        source: rune_idna::Error,
    },

    /// A name could not be built, usually because a probe label made it
    /// longer than 255 octets.
    #[error("invalid name: {0}")]
    Name(#[from] rune_dns_wire::Error),

    /// The caller-supplied resolver failed.
    #[error("resolving {name} {rtype} failed: {source}")]
    Resolver {
        /// The name being resolved.
        name: Name,
        /// The record type queried.
        rtype: RecordType,
        /// The resolver's error.
        #[source]
        source: BoxError,
    },

    /// Every probe under `level` came back with a server failure (anything
    /// other than `NOERROR` or `NXDOMAIN`), so whether it has a wildcard is
    /// unknown.
    #[error("every wildcard probe under {level} failed; wildcard status unknown")]
    Inconclusive {
        /// The parent name whose children were probed.
        level: Name,
    },
}
