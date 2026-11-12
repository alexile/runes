//! The crate's single error type.

use rune_secret_ref::{SecretError, SecretRef};

/// A boxed error from a pluggable backend, such as an HTTP transport.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Why a provider could not resolve a secret.
///
/// No message ever contains secret material: errors name the reference
/// (`vault:kv/app#token`), never the value it points at, and backend errors
/// that carry raw secret bytes (such as a keyring entry that is not UTF-8)
/// are reduced to a description before they get here.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProviderError {
    /// Parsing or resolving the reference itself failed (see
    /// [`SecretError`]); also used for the shared checks on resolved values
    /// (empty, too large, not UTF-8).
    #[error(transparent)]
    Ref(#[from] SecretError),
    /// No registered provider handles the reference's scheme.
    #[error("no secret provider is configured for `{scheme}:` references")]
    NoProvider {
        /// The reference scheme.
        scheme: &'static str,
    },
    /// A provider was asked for a reference whose scheme it does not
    /// handle.
    #[error("the {provider} secret provider cannot resolve `{scheme}:` references")]
    WrongScheme {
        /// The provider's name, such as `vault`.
        provider: &'static str,
        /// The reference scheme it was given.
        scheme: &'static str,
    },
    /// The backend has no secret at the referenced location.
    #[error("secret `{reference}` was not found")]
    NotFound {
        /// The reference.
        reference: SecretRef,
    },
    /// The backend refused access to the secret (bad or expired token,
    /// missing policy, locked keychain).
    #[error("access to secret `{reference}` was denied")]
    PermissionDenied {
        /// The reference.
        reference: SecretRef,
    },
    /// The reference is well-formed for `rune-secret-ref` but not for this
    /// provider (for example a vault path with a `..` segment).
    #[error("invalid `{scheme}:` reference for this provider: {reason}")]
    InvalidReference {
        /// The reference scheme.
        scheme: &'static str,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The provider's configuration is invalid (for example a vault
    /// address that is not an `http(s)://` URL).
    #[error("invalid secret provider configuration: {0}")]
    Config(&'static str),
    /// The secret holds several fields and the reference does not say which
    /// one to use (`vault:kv/app#field`).
    #[error("secret `{reference}` has several fields; name one with `#field`")]
    AmbiguousField {
        /// The reference.
        reference: SecretRef,
    },
    /// The named field is absent from the secret.
    #[error("secret `{reference}` has no field `{field}`")]
    MissingField {
        /// The reference.
        reference: SecretRef,
        /// The field name.
        field: String,
    },
    /// The field holds a number, an object or another non-string value.
    #[error("field `{field}` of secret `{reference}` is not a string")]
    NotAString {
        /// The reference.
        reference: SecretRef,
        /// The field name.
        field: String,
    },
    /// The backend answered with an unexpected HTTP status.
    #[error("secret backend returned HTTP {status} for `{reference}`")]
    HttpStatus {
        /// The reference.
        reference: SecretRef,
        /// The HTTP status code.
        status: u16,
    },
    /// The backend's response could not be understood.
    #[error("unexpected secret backend response for `{reference}`: {reason}")]
    InvalidResponse {
        /// The reference.
        reference: SecretRef,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The transport to the backend failed (connection refused, TLS,
    /// timeout).
    #[error("cannot reach the secret backend for `{reference}`: {source}")]
    Transport {
        /// The reference.
        reference: SecretRef,
        /// The transport's error.
        #[source]
        source: BoxError,
    },
    /// Any other backend failure, already reduced to a message that holds
    /// no secret material.
    #[error("secret backend failed for `{reference}`: {message}")]
    Backend {
        /// The reference.
        reference: SecretRef,
        /// What went wrong.
        message: String,
    },
}
