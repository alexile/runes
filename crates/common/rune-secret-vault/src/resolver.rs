//! [`SecretResolver`]: dispatches each reference to the provider for its
//! scheme.

use std::fmt;

use rune_secret_ref::{SecretRef, SecretValue};

use crate::{ProviderError, SecretProvider};

type DynProvider = Box<dyn SecretProvider + Send + Sync>;

/// A set of providers, tried in registration order; the first one that
/// [handles](SecretProvider::handles) a reference's scheme resolves it.
///
/// A resolver is itself a [`SecretProvider`], so it can be wrapped in a
/// [`CachedProvider`](crate::CachedProvider).
///
/// ```
/// use rune_secret_vault::{EnvProvider, FileProvider, ProviderError, SecretResolver};
///
/// let resolver = SecretResolver::new()
///     .with_provider(EnvProvider::new(|_| Some("from-env".to_owned())))
///     .with_provider(FileProvider::default());
///
/// assert_eq!(resolver.resolve_str("env:TOKEN")?.expose(), "from-env");
/// assert!(matches!(
///     resolver.resolve_str("vault:kv/app#token"),
///     Err(ProviderError::NoProvider { scheme: "vault" })
/// ));
/// # Ok::<(), ProviderError>(())
/// ```
#[derive(Default)]
pub struct SecretResolver {
    providers: Vec<DynProvider>,
}

impl SecretResolver {
    /// An empty resolver; every reference fails with
    /// [`ProviderError::NoProvider`] until providers are added.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a provider after the existing ones.
    #[must_use]
    pub fn with_provider(mut self, provider: impl SecretProvider + Send + Sync + 'static) -> Self {
        self.push(provider);
        self
    }

    /// Adds a provider after the existing ones.
    pub fn push(&mut self, provider: impl SecretProvider + Send + Sync + 'static) {
        self.providers.push(Box::new(provider));
    }

    /// The number of registered providers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    /// Whether no provider is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// Parses `text` as a [`SecretRef`] and resolves it.
    ///
    /// # Errors
    ///
    /// [`ProviderError::Ref`] when the text is not a reference (an inline
    /// secret is refused without being echoed), otherwise as
    /// [`SecretProvider::resolve`].
    pub fn resolve_str(&self, text: &str) -> Result<SecretValue, ProviderError> {
        self.resolve(&text.parse()?)
    }
}

impl SecretProvider for SecretResolver {
    fn handles(&self, scheme: &str) -> bool {
        self.providers
            .iter()
            .any(|provider| provider.handles(scheme))
    }

    fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, ProviderError> {
        let scheme = reference.scheme();
        self.providers
            .iter()
            .find(|provider| provider.handles(scheme))
            .ok_or(ProviderError::NoProvider { scheme })?
            .resolve(reference)
    }
}

impl fmt::Debug for SecretResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretResolver")
            .field("providers", &self.providers.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EnvProvider;

    #[test]
    fn first_matching_provider_wins() {
        let resolver = SecretResolver::new()
            .with_provider(EnvProvider::new(|_| Some("first".to_owned())))
            .with_provider(EnvProvider::new(|_| Some("second".to_owned())));
        assert_eq!(resolver.len(), 2);
        assert!(!resolver.is_empty());
        assert!(resolver.handles("env"));
        assert!(!resolver.handles("keychain"));
        assert_eq!(resolver.resolve_str("env:X").unwrap().expose(), "first");
        assert_eq!(format!("{resolver:?}"), "SecretResolver { providers: 2 }");
    }

    #[test]
    fn empty_resolver_and_inline_text() {
        let resolver = SecretResolver::new();
        assert!(resolver.is_empty());
        assert!(matches!(
            resolver.resolve_str("env:X"),
            Err(ProviderError::NoProvider { scheme: "env" })
        ));
        let error = resolver.resolve_str("sk-live-abcdef").unwrap_err();
        assert!(!error.to_string().contains("sk-live-abcdef"));
    }
}
