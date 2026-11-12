//! [`KeyringProvider`]: `keychain:service/account` from an OS credential
//! store.

use std::fmt;
use std::sync::Arc;

use keyring_core::{CredentialStore, Error as KeyringError};
use rune_secret_ref::{SecretError, SecretRef, SecretValue};

use crate::provider::{check_value, expect_scheme};
use crate::{ProviderError, SecretProvider};

/// Resolves `keychain:SERVICE/ACCOUNT` from a [`keyring_core`] credential
/// store.
///
/// Bring your own store: `apple-native-keyring-store` (macOS keychain),
/// `windows-native-keyring-store` (Credential Manager),
/// `zbus-secret-service-keyring-store` or `linux-keyutils-keyring-store`
/// (Linux), or [`keyring_core::mock::Store`] in tests. The provider uses
/// the store it is given and never touches keyring-core's process-wide
/// default store unless you ask for it with
/// [`from_default_store`](Self::from_default_store).
///
/// ```
/// use keyring_core::api::CredentialStoreApi as _;
/// use rune_secret_vault::{KeyringProvider, SecretProvider};
///
/// let store = keyring_core::mock::Store::new().unwrap();
/// store.build("myapp", "api", None).unwrap().set_password("k3y").unwrap();
///
/// let provider = KeyringProvider::new(store);
/// let key = provider.resolve(&"keychain:myapp/api".parse()?)?;
/// assert_eq!(key.expose(), "k3y");
/// # Ok::<(), rune_secret_vault::ProviderError>(())
/// ```
#[derive(Clone)]
pub struct KeyringProvider {
    store: Arc<CredentialStore>,
    max_len: usize,
}

impl KeyringProvider {
    /// A provider reading from `store`, accepting secrets up to 64 KiB.
    #[must_use]
    pub fn new(store: Arc<CredentialStore>) -> Self {
        Self {
            store,
            max_len: 64 * 1024,
        }
    }

    /// A provider reading from keyring-core's default store, if the
    /// application has set one with [`keyring_core::set_default_store`].
    #[must_use]
    pub fn from_default_store() -> Option<Self> {
        keyring_core::get_default_store().map(Self::new)
    }

    /// Sets the largest secret accepted, in bytes. Default 64 KiB.
    #[must_use]
    pub const fn with_max_len(mut self, max_len: usize) -> Self {
        self.max_len = max_len;
        self
    }

    /// The credential store.
    #[must_use]
    pub fn store(&self) -> &Arc<CredentialStore> {
        &self.store
    }
}

impl fmt::Debug for KeyringProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyringProvider")
            .field("store", &self.store.vendor())
            .field("max_len", &self.max_len)
            .finish()
    }
}

impl SecretProvider for KeyringProvider {
    fn handles(&self, scheme: &str) -> bool {
        scheme == "keychain"
    }

    fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, ProviderError> {
        expect_scheme("keychain", reference)?;
        let SecretRef::Keychain { service, account } = reference else {
            return Err(ProviderError::WrongScheme {
                provider: "keychain",
                scheme: reference.scheme(),
            });
        };
        let password = self
            .store
            .build(service, account, None)
            .and_then(|entry| entry.get_password())
            .map_err(|error| map_error(reference, error))?;
        check_value(reference, password, self.max_len)
    }
}

/// Converts a keyring error without keeping any raw credential bytes it
/// carries (`BadEncoding`, `BadDataFormat`).
fn map_error(reference: &SecretRef, error: KeyringError) -> ProviderError {
    let backend = |message: String| ProviderError::Backend {
        reference: reference.clone(),
        message,
    };
    match error {
        KeyringError::NoEntry => ProviderError::NotFound {
            reference: reference.clone(),
        },
        KeyringError::NoStorageAccess(_) => ProviderError::PermissionDenied {
            reference: reference.clone(),
        },
        KeyringError::BadEncoding(_) => ProviderError::Ref(SecretError::NotUtf8 {
            reference: reference.clone(),
        }),
        KeyringError::BadDataFormat(..) => {
            backend("the stored credential is not in the format the store expects".to_owned())
        }
        KeyringError::Ambiguous(entries) => backend(format!(
            "{} credentials match; the reference must name exactly one",
            entries.len()
        )),
        KeyringError::PlatformFailure(source) => backend(format!("platform failure: {source}")),
        KeyringError::NoDefaultStore => backend("no default credential store is set".to_owned()),
        KeyringError::TooLong(attribute, limit) => backend(format!(
            "`{attribute}` is longer than the store's limit of {limit}"
        )),
        KeyringError::Invalid(parameter, reason) => {
            backend(format!("invalid `{parameter}`: {reason}"))
        }
        KeyringError::BadStoreFormat(reason) => backend(format!("bad store format: {reason}")),
        KeyringError::NotSupportedByStore(reason) => backend(format!("not supported: {reason}")),
        _ => backend("unrecognised keyring error".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use keyring_core::api::CredentialStoreApi as _;
    use keyring_core::mock;

    use super::*;

    const SECRET: &str = "kr-s3cret-Value";

    fn reference(text: &str) -> SecretRef {
        text.parse().unwrap()
    }

    fn store_with(service: &str, account: &str, password: &str) -> Arc<CredentialStore> {
        let store = mock::Store::new().unwrap();
        store
            .build(service, account, None)
            .unwrap()
            .set_password(password)
            .unwrap();
        store
    }

    #[test]
    fn resolves_an_entry() {
        let provider = KeyringProvider::new(store_with("svc", "acct/sub", SECRET));
        assert!(provider.handles("keychain"));
        let value = provider
            .resolve(&reference("keychain:svc/acct/sub"))
            .unwrap();
        assert_eq!(value.expose(), SECRET);
        assert!(!format!("{value:?} {provider:?}").contains(SECRET));
    }

    #[test]
    fn missing_entry_is_not_found() {
        let provider = KeyringProvider::new(mock::Store::new().unwrap());
        let error = provider
            .resolve(&reference("keychain:svc/none"))
            .unwrap_err();
        assert!(matches!(error, ProviderError::NotFound { .. }), "{error}");
        assert!(error.to_string().contains("keychain:svc/none"));
    }

    #[test]
    fn enforces_size_limit_and_scheme() {
        let provider = KeyringProvider::new(store_with("s", "a", SECRET)).with_max_len(4);
        assert!(matches!(
            provider.resolve(&reference("keychain:s/a")),
            Err(ProviderError::Ref(SecretError::TooLarge { limit: 4, .. }))
        ));
        assert!(matches!(
            provider.resolve(&reference("env:X")),
            Err(ProviderError::WrongScheme { .. })
        ));
    }

    #[test]
    fn errors_never_carry_raw_bytes() {
        let r = reference("keychain:s/a");
        let error = map_error(&r, KeyringError::BadEncoding(SECRET.as_bytes().to_vec()));
        assert!(matches!(
            error,
            ProviderError::Ref(SecretError::NotUtf8 { .. })
        ));
        let error = map_error(
            &r,
            KeyringError::BadDataFormat(SECRET.as_bytes().to_vec(), "x".into()),
        );
        let text = format!("{error} {error:?}");
        assert!(!text.contains(SECRET), "{text}");
        assert!(matches!(
            map_error(&r, KeyringError::NoStorageAccess("locked".into())),
            ProviderError::PermissionDenied { .. }
        ));
    }
}
