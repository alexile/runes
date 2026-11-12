//! The [`SecretProvider`] trait and the local providers (env, file, command).

use std::fmt;
use std::rc::Rc;
use std::sync::Arc;

#[cfg(any(feature = "keyring", feature = "vault"))]
use rune_secret_ref::SecretError;
use rune_secret_ref::{ResolveOptions, SecretRef, SecretValue};

use crate::ProviderError;

/// A source of secrets for one or more [`SecretRef`] schemes.
///
/// Providers are synchronous: resolution usually happens once at start-up
/// and the result is cached (see [`CachedProvider`](crate::CachedProvider)).
/// From async code, call them through `spawn_blocking` when the backend
/// does I/O.
///
/// Implementations must never log, print or put into an error the value
/// they resolve; hand it out only as a [`SecretValue`].
pub trait SecretProvider {
    /// Whether this provider resolves references with this scheme
    /// (`env`, `file`, `cmd`, `keychain`, `vault`).
    fn handles(&self, scheme: &str) -> bool;

    /// Resolves the reference.
    ///
    /// # Errors
    ///
    /// [`ProviderError::WrongScheme`] when [`handles`](Self::handles) is
    /// false for the reference's scheme, otherwise a backend-specific
    /// [`ProviderError`] that names the reference but not the secret.
    fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, ProviderError>;
}

macro_rules! forward_provider {
    ($($wrapper:ty),*) => {$(
        impl<P: SecretProvider + ?Sized> SecretProvider for $wrapper {
            fn handles(&self, scheme: &str) -> bool {
                (**self).handles(scheme)
            }

            fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, ProviderError> {
                (**self).resolve(reference)
            }
        }
    )*};
}

forward_provider!(&P, Box<P>, Arc<P>, Rc<P>);

/// Checks that `reference` has the scheme a provider expects.
pub fn expect_scheme(provider: &'static str, reference: &SecretRef) -> Result<(), ProviderError> {
    if reference.scheme() == provider {
        Ok(())
    } else {
        Err(ProviderError::WrongScheme {
            provider,
            scheme: reference.scheme(),
        })
    }
}

/// The checks every remote value goes through: not empty, at most
/// `max_len` bytes.
#[cfg(any(feature = "keyring", feature = "vault"))]
pub fn check_value(
    reference: &SecretRef,
    value: String,
    max_len: usize,
) -> Result<SecretValue, ProviderError> {
    // Wrap first so the value is wiped on drop (with the `zeroize` feature
    // of rune-secret-ref) on every path, including the error ones.
    let value = SecretValue::from(value);
    if value.expose().is_empty() {
        return Err(SecretError::Empty {
            reference: reference.clone(),
        }
        .into());
    }
    if value.expose().len() > max_len {
        return Err(SecretError::TooLarge {
            reference: reference.clone(),
            limit: max_len,
        }
        .into());
    }
    Ok(value)
}

/// Resolves `env:VAR` through a lookup function.
///
/// The library never reads the process environment on its own: pass
/// `|name| std::env::var(name).ok()` for the real one, or a map in tests.
///
/// ```
/// use rune_secret_vault::{EnvProvider, SecretProvider};
///
/// let provider = EnvProvider::new(|name| (name == "TOKEN").then(|| "t0k".to_owned()));
/// let token = provider.resolve(&"env:TOKEN".parse()?)?;
/// assert_eq!(token.expose(), "t0k");
/// # Ok::<(), rune_secret_vault::ProviderError>(())
/// ```
#[derive(Clone)]
pub struct EnvProvider<F> {
    lookup: F,
}

impl<F: Fn(&str) -> Option<String>> EnvProvider<F> {
    /// A provider that looks variables up with `lookup`.
    pub const fn new(lookup: F) -> Self {
        Self { lookup }
    }
}

impl<F> fmt::Debug for EnvProvider<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvProvider").finish_non_exhaustive()
    }
}

impl<F: Fn(&str) -> Option<String>> SecretProvider for EnvProvider<F> {
    fn handles(&self, scheme: &str) -> bool {
        scheme == "env"
    }

    fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, ProviderError> {
        expect_scheme("env", reference)?;
        Ok(reference.resolve(&ResolveOptions::default(), &self.lookup)?)
    }
}

/// Resolves `file:PATH` with `rune-secret-ref`'s rules.
///
/// One trailing newline is stripped, relative paths join
/// [`ResolveOptions::base_dir`], and on unix the file must not be readable
/// by group or others (unless
/// [`ResolveOptions::check_file_permissions`] is off).
#[derive(Clone, Debug, Default)]
pub struct FileProvider {
    options: ResolveOptions,
}

impl FileProvider {
    /// A provider that reads files with these options.
    #[must_use]
    pub const fn new(options: ResolveOptions) -> Self {
        Self { options }
    }
}

impl SecretProvider for FileProvider {
    fn handles(&self, scheme: &str) -> bool {
        scheme == "file"
    }

    fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, ProviderError> {
        expect_scheme("file", reference)?;
        Ok(reference.resolve(&self.options, |_| None)?)
    }
}

/// Resolves `cmd:PROGRAM ARG…` by running the program (no shell) and
/// reading its standard output.
///
/// Constructing this provider *is* the opt-in to running commands named in
/// configuration, so register it only for configuration the user owns.
/// Timeout, size limit and working directory come from the
/// [`ResolveOptions`]; its `allow_command` flag is forced on.
#[derive(Clone, Debug)]
pub struct CommandProvider {
    options: ResolveOptions,
}

impl CommandProvider {
    /// A provider that runs commands with these options.
    #[must_use]
    pub const fn new(options: ResolveOptions) -> Self {
        Self {
            options: options.with_allow_command(true),
        }
    }
}

impl SecretProvider for CommandProvider {
    fn handles(&self, scheme: &str) -> bool {
        scheme == "cmd"
    }

    fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, ProviderError> {
        expect_scheme("cmd", reference)?;
        Ok(reference.resolve(&self.options, |_| None)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_secret_ref::SecretError;

    fn reference(text: &str) -> SecretRef {
        text.parse().unwrap()
    }

    #[test]
    fn env_provider_resolves_and_rejects_other_schemes() {
        let provider = EnvProvider::new(|name| (name == "A").then(|| "v".to_owned()));
        assert!(provider.handles("env"));
        assert!(!provider.handles("file"));
        assert_eq!(provider.resolve(&reference("env:A")).unwrap().expose(), "v");
        assert!(matches!(
            provider.resolve(&reference("env:B")),
            Err(ProviderError::Ref(SecretError::EnvUnset(_)))
        ));
        assert!(matches!(
            provider.resolve(&reference("vault:kv/x")),
            Err(ProviderError::WrongScheme {
                provider: "env",
                scheme: "vault"
            })
        ));
        assert_eq!(format!("{provider:?}"), "EnvProvider { .. }");
    }

    #[test]
    fn wrappers_forward() {
        let provider = Arc::new(EnvProvider::new(|_| Some("v".to_owned())));
        let boxed: Box<dyn SecretProvider> = Box::new(Arc::clone(&provider));
        assert!(boxed.handles("env"));
        assert_eq!(boxed.resolve(&reference("env:X")).unwrap().expose(), "v");
        assert!(SecretProvider::handles(&&*provider, "env"));
    }

    #[cfg(any(feature = "keyring", feature = "vault"))]
    #[test]
    fn check_value_enforces_limits() {
        let r = reference("vault:kv/x");
        assert!(matches!(
            check_value(&r, String::new(), 8),
            Err(ProviderError::Ref(SecretError::Empty { .. }))
        ));
        assert!(matches!(
            check_value(&r, "123456789".into(), 8),
            Err(ProviderError::Ref(SecretError::TooLarge { limit: 8, .. }))
        ));
        assert_eq!(
            check_value(&r, "12345678".into(), 8).unwrap().expose(),
            "12345678"
        );
    }
}
