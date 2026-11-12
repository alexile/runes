//! Local providers end to end, through the resolver and the cache.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use std::fs;
use std::time::Duration;

use rune_secret_vault::{
    CachedProvider, CommandProvider, EnvProvider, FileProvider, ProviderError, ResolveOptions,
    SecretError, SecretProvider, SecretResolver,
};

const SECRET: &str = "file-s3cret-Value";

#[test]
fn file_provider_reads_relative_to_base_dir() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    fs::write(&path, format!("{SECRET}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let provider = FileProvider::new(ResolveOptions::default().with_base_dir(dir.path()));
    assert!(provider.handles("file"));
    let value = provider.resolve(&"file:token".parse().unwrap()).unwrap();
    assert_eq!(value.expose(), SECRET);
    assert!(!format!("{value:?} {value}").contains(SECRET));

    let error = provider
        .resolve(&"file:missing".parse().unwrap())
        .unwrap_err();
    assert!(matches!(
        error,
        ProviderError::Ref(SecretError::FileRead { .. })
    ));
}

#[cfg(unix)]
#[test]
fn command_provider_is_an_explicit_opt_in() {
    let resolver = SecretResolver::new()
        .with_provider(CommandProvider::new(ResolveOptions::default()))
        .with_provider(FileProvider::default());
    let value = resolver.resolve_str("cmd:echo from-cmd").unwrap();
    assert_eq!(value.expose(), "from-cmd");

    // Without the command provider, `cmd:` has no provider.
    let resolver = SecretResolver::new().with_provider(FileProvider::default());
    assert!(matches!(
        resolver.resolve_str("cmd:echo x"),
        Err(ProviderError::NoProvider { scheme: "cmd" })
    ));
}

#[test]
fn cached_resolver_routes_by_scheme() {
    let resolver = SecretResolver::new()
        .with_provider(EnvProvider::new(|name| {
            (name == "A").then(|| "a".to_owned())
        }))
        .with_provider(FileProvider::default());
    let cached = CachedProvider::new(resolver, Duration::from_secs(60));
    assert!(cached.handles("env") && cached.handles("file") && !cached.handles("vault"));
    assert_eq!(
        cached.resolve(&"env:A".parse().unwrap()).unwrap().expose(),
        "a"
    );
    assert!(matches!(
        cached.resolve(&"keychain:s/a".parse().unwrap()),
        Err(ProviderError::NoProvider { scheme: "keychain" })
    ));
    assert_eq!(cached.len(), 1);
}
